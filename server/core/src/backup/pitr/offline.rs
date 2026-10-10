//! Offline commands that change the database outside the archive.
//!
//! The `db-scan quarantine-id2entry` and `restore-quarantined` repair commands move an
//! entry in or out of `id2entry` directly, without a transaction the backend could archive.
//! Replaying the archive across such a change would rebuild a database that disagrees with
//! the one the server went on with, so the change is recorded as a gap: recovery never
//! replays across it, and only a base backup taken after it makes later points
//! recoverable.

use std::time::Duration;

use kubidm_proto::backup::PitrWalGap;
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::{defer_gap, format_ts_rfc3339, WalGap, WalGapReason};

use super::store::PitrStore;
use super::{blocking, PitrError, PitrSettings};
use crate::config::Configuration;

/// Where [`note_offline_change`] recorded the gap of an offline change.
#[derive(Debug, PartialEq, Eq)]
pub enum OfflineChangeRecord {
    /// In the manifest of the archive.
    Recorded,
    /// In the WAL directory, for the server to record at its first archive
    /// synchronisation: the archive has no manifest yet, or could not be updated. Recovery
    /// honours it from there as well.
    HandedOver,
    /// Nowhere: WAL archiving is not configured.
    NotConfigured,
}

/// The gap an offline change of the database leaves in the archive: the database last
/// committed a transaction at `db_ts_max`, and the change happened at `now`, before any
/// later transaction. A base backup whose watermark is `db_ts_max` may have been taken on
/// either side of the change, so it can not replay past it either.
fn offline_change_gap(db_ts_max: Duration, now: Duration, command: &str) -> PitrWalGap {
    let from_ts = db_ts_max + Duration::from_nanos(1);
    PitrWalGap {
        from_ts,
        until_ts: now.max(from_ts),
        reason: format!("{command} changed the database outside the WAL archive"),
    }
}

/// Before an offline command changes the database described by `config` outside the
/// archive (see the module documentation): when WAL archiving is configured, record a gap
/// from just after `db_ts_max`, the last transaction the database committed, up to now, so
/// that recovery never replays across the change. `command` names the command for the
/// operator.
///
/// The gap is recorded in the archive's manifest, or, when the archive has no manifest yet
/// or can not be updated, handed to the server through its WAL directory. Fails only when
/// neither worked; the caller must then leave the database alone.
pub async fn note_offline_change(
    config: &Configuration,
    db_ts_max: Duration,
    command: &str,
) -> Result<OfflineChangeRecord, PitrError> {
    let Some(settings) = PitrSettings::from_config(config)? else {
        return Ok(OfflineChangeRecord::NotConfigured);
    };
    record_offline_change(
        &settings,
        offline_change_gap(db_ts_max, duration_from_epoch_now(), command),
    )
    .await
}

/// Record `gap` in the archive at `settings`, or hand it over through the WAL directory.
pub(super) async fn record_offline_change(
    settings: &PitrSettings,
    gap: PitrWalGap,
) -> Result<OfflineChangeRecord, PitrError> {
    let recorded = async {
        let store = PitrStore::open(&settings.location).await?;
        let Some(mut manifest) = store.load_manifest().await? else {
            return Ok(false);
        };
        manifest.add_gap(gap.clone());
        store.save_manifest(&mut manifest, gap.until_ts).await?;
        Ok::<_, PitrError>(true)
    }
    .await;
    match recorded {
        Ok(true) => {
            warn!(
                from = %format_ts_rfc3339(gap.from_ts),
                until = %format_ts_rfc3339(gap.until_ts),
                archive = %settings.location,
                "Gap recorded in the WAL archive: point-in-time recovery does not replay across \
                 this change; take an online backup after starting the server"
            );
            return Ok(OfflineChangeRecord::Recorded);
        }
        Ok(false) => {}
        Err(err) => warn!(
            %err,
            archive = %settings.location,
            "The WAL archive could not record the change; it is handed to the server through \
             its WAL directory"
        ),
    }

    let local_dir = settings.local_dir.clone();
    let deferred = WalGap {
        from_ts: gap.from_ts,
        until_ts: Some(gap.until_ts),
        reason: WalGapReason::OfflineChange,
    };
    blocking(move || Ok(defer_gap(&local_dir, deferred)?)).await?;
    warn!(
        from = %format_ts_rfc3339(gap.from_ts),
        until = %format_ts_rfc3339(gap.until_ts),
        wal_directory = %settings.local_dir.display(),
        "Gap handed to the server: point-in-time recovery does not replay across this change; \
         take an online backup after starting the server"
    );
    Ok(OfflineChangeRecord::HandedOver)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use kubidm_proto::backup::{
        BackupEncryptionConfig, PitrManifest, WalArchiveConfig, PITR_MANIFEST_KEY,
    };
    use kubidmd_lib::repl::wal::{read_local_events, read_pending_events, segment_file_name};
    use uuid::Uuid;

    use super::super::recover::fold_local_events;
    use super::super::test_util::*;
    use super::super::{plan_recovery, BaseLocation, PitrLocation, RecoveryTargetSpec};
    use super::*;

    fn settings(dir: &std::path::Path) -> PitrSettings {
        let wal_dir = dir.join("wal");
        PitrSettings {
            wal: WalArchiveConfig {
                enabled: true,
                local_path: Some(wal_dir.clone()),
                ..WalArchiveConfig::default()
            },
            local_dir: wal_dir.clone(),
            location: PitrLocation::Local(wal_dir),
            bases: BaseLocation::Local(dir.join("backups")),
            encryption: BackupEncryptionConfig::default(),
        }
    }

    /// A manifest with a base at 100 and a segment up to 200.
    fn archived() -> PitrManifest {
        let mut manifest = PitrManifest::new(Uuid::nil());
        manifest.add_base_backup(base("backup-2024-01-01T00:00:00Z.json.gz", 100));
        manifest.add_segment(segment(
            &segment_file_name(Uuid::nil(), Duration::from_secs(110)),
            110,
            200,
        ));
        manifest
    }

    fn assert_change_blocks_recovery(manifest: &PitrManifest) {
        // Up to the last transaction before the change: recoverable.
        let plan = plan_recovery(
            manifest,
            &RecoveryTargetSpec::Time("1970-01-01T00:03:20Z".to_string()),
        )
        .expect("a target before the change");
        assert_eq!(plan.target.ts, Duration::from_secs(200));
        // Past it: refused, and the latest point stops right before it.
        assert!(matches!(
            plan_recovery(
                manifest,
                &RecoveryTargetSpec::Time("1970-01-01T00:05:00Z".to_string())
            ),
            Err(PitrError::NotRecoverable(msg)) if msg.contains("db-scan")
        ));
        assert_eq!(
            manifest.latest_recoverable_ts(),
            Some(Duration::from_secs(200))
        );
    }

    #[tokio::test]
    async fn test_offline_change_is_a_gap_in_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(dir.path());
        let store = PitrStore::open(&settings.location).await.unwrap();
        store
            .save_manifest(&mut archived(), Duration::from_secs(250))
            .await
            .unwrap();

        let gap = offline_change_gap(
            Duration::from_secs(200),
            Duration::from_secs(300),
            "db-scan quarantine-id2entry",
        );
        assert_eq!(
            record_offline_change(&settings, gap).await.unwrap(),
            OfflineChangeRecord::Recorded
        );
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.gaps.len(), 1);
        assert_eq!(
            manifest.gaps[0].from_ts,
            Duration::from_secs(200) + Duration::from_nanos(1)
        );
        assert_eq!(manifest.gaps[0].until_ts, Duration::from_secs(300));
        assert_change_blocks_recovery(&manifest);
        assert!(read_pending_events(&settings.local_dir).is_empty());
    }

    #[tokio::test]
    async fn test_offline_change_is_handed_over_when_the_archive_can_not_take_it() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(dir.path());
        fs::create_dir_all(&settings.local_dir).unwrap();
        // A manifest that can not be read.
        fs::write(settings.local_dir.join(PITR_MANIFEST_KEY), b"{ damaged").unwrap();

        let gap = offline_change_gap(
            Duration::from_secs(200),
            Duration::from_secs(300),
            "db-scan restore-quarantined",
        );
        assert_eq!(
            record_offline_change(&settings, gap).await.unwrap(),
            OfflineChangeRecord::HandedOver
        );
        let events = read_local_events(&settings.local_dir);
        assert_eq!(events.gaps.len(), 1);
        assert_eq!(events.gaps[0].reason, WalGapReason::OfflineChange);

        // Recovery folds what the WAL directory holds into the archive it reads.
        let mut manifest = archived();
        fold_local_events(&mut manifest, &events, Duration::from_secs(400));
        assert!(matches!(
            plan_recovery(
                &manifest,
                &RecoveryTargetSpec::Time("1970-01-01T00:05:00Z".to_string())
            ),
            Err(PitrError::NotRecoverable(_))
        ));

        // A second change adds to the events already pending.
        let gap = offline_change_gap(
            Duration::from_secs(300),
            Duration::from_secs(350),
            "db-scan quarantine-id2entry",
        );
        record_offline_change(&settings, gap).await.unwrap();
        assert_eq!(read_local_events(&settings.local_dir).gaps.len(), 2);
    }

    #[tokio::test]
    async fn test_offline_change_before_the_first_archive_run_is_handed_over() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(dir.path());
        let gap = offline_change_gap(
            Duration::from_secs(200),
            Duration::from_secs(300),
            "db-scan quarantine-id2entry",
        );
        assert_eq!(
            record_offline_change(&settings, gap).await.unwrap(),
            OfflineChangeRecord::HandedOver
        );
        assert_eq!(read_local_events(&settings.local_dir).gaps.len(), 1);
    }
}
