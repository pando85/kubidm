//! Offline commands that change, or capture, the database outside the archive.
//!
//! The `db-scan quarantine-id2entry` and `restore-quarantined` repair commands move an
//! entry in or out of `id2entry` directly, without a transaction the backend could archive.
//! Replaying the archive across such a change would rebuild a database that disagrees with
//! the one the server went on with, so the change is recorded as a gap: recovery never
//! replays across it, and only a base backup taken after it makes later points
//! recoverable.
//!
//! A manual `kubidmd database backup` captures the database exactly like an online backup
//! does: one read transaction, whose last committed transaction is the CID watermark the
//! backup records. Written into the local base backup directory under a backup name, it is
//! a base like any other. The command may run next to a running server, which owns the
//! manifest, so it never writes the manifest itself: it hands the base over through the
//! WAL directory ([`HANDED_OVER_BASES_DIR`]), the server indexes it at its next archive run,
//! and recovery reads it from there meanwhile.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kubidm_proto::backup::{PitrBaseBackup, PitrManifest, PitrWalGap};
use kubidmd_lib::be::BackupStructuralReport;
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::{
    defer_gap, format_ts_rfc3339, write_file_durably, WalGap, WalGapReason,
};

use super::store::PitrStore;
use super::{blocking, BaseLocation, PitrError, PitrSettings};
use crate::backup::{backup_name_timestamp, is_backup_artifact_name};
use crate::config::Configuration;

/// The directory, inside the WAL directory, where manual backups are handed over as bases:
/// one `<backup name>.json` file per base, holding its [`PitrBaseBackup`] record.
pub const HANDED_OVER_BASES_DIR: &str = ".handed-over-bases";

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

/// What [`note_manual_backup`] made of a manual backup.
#[derive(Debug, PartialEq, Eq)]
pub enum ManualBase {
    /// Handed over as a base with this CID watermark (RFC3339).
    HandedOver { watermark: String },
    /// Not a base, for the reason given: recovery could not find it.
    NotABase(String),
    /// WAL archiving is not configured.
    NotConfigured,
}

/// After a manual backup was written and verified at `path`: when WAL archiving is
/// configured and the backup is one recovery can find (in the local base backup directory,
/// under a backup name), hand it over as a base with the watermark of `report`, see the
/// module documentation. Otherwise say why it is not one.
pub async fn note_manual_backup(
    config: &Configuration,
    path: &Path,
    report: &BackupStructuralReport,
) -> Result<ManualBase, PitrError> {
    let Some(settings) = PitrSettings::from_config(config)? else {
        return Ok(ManualBase::NotConfigured);
    };
    let BaseLocation::Local(base_dir) = &settings.bases else {
        return Ok(ManualBase::NotABase(format!(
            "the base backups are the online backups in {}; a manual backup is only a base \
             when the base backups are local",
            settings.bases
        )));
    };
    let Some(key) = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| is_backup_artifact_name(name))
    else {
        return Ok(ManualBase::NotABase(
            "its name is not a backup name: name it backup-<RFC3339 UTC time>.json, then .gz \
             when compressed and .enc when encrypted"
                .to_string(),
        ));
    };
    let same_dir = {
        let (base_dir, dir) = (
            base_dir.clone(),
            path.parent().map(Path::to_path_buf).unwrap_or_default(),
        );
        blocking(move || Ok(same_directory(&base_dir, &dir))).await?
    };
    if !same_dir {
        return Ok(ManualBase::NotABase(format!(
            "it is not in the base backup directory {}",
            base_dir.display()
        )));
    }
    let base = manual_base(key, report)?;
    let watermark = format_ts_rfc3339(base.watermark_ts);
    let local_dir = settings.local_dir.clone();
    blocking(move || hand_over_base(&local_dir, &base)).await?;
    info!(
        key,
        %watermark,
        "Manual backup handed over to the WAL archive as a point-in-time recovery base"
    );
    Ok(ManualBase::HandedOver { watermark })
}

/// Whether `a` and `b` name the same existing directory.
fn same_directory(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// The base record of the manual backup `key` whose content `report` describes.
fn manual_base(key: &str, report: &BackupStructuralReport) -> Result<PitrBaseBackup, PitrError> {
    let watermark_ts = report
        .db_ts_max
        .ok_or_else(|| PitrError::Manifest(format!("backup {key} records no CID watermark")))?;
    let server_version = report
        .version
        .clone()
        .ok_or_else(|| PitrError::Manifest(format!("backup {key} records no server version")))?;
    Ok(PitrBaseBackup {
        key: key.to_string(),
        timestamp: backup_name_timestamp(key).unwrap_or_default().to_string(),
        watermark_ts,
        server_version,
        server_uuid: report.db_s_uuid,
    })
}

/// Write `base` into the hand-over directory of the WAL directory `local_dir`.
fn hand_over_base(local_dir: &Path, base: &PitrBaseBackup) -> Result<(), PitrError> {
    let dir = local_dir.join(HANDED_OVER_BASES_DIR);
    fs::create_dir_all(&dir)?;
    let data = serde_json::to_vec_pretty(base)
        .map_err(|err| PitrError::Manifest(format!("unable to serialise: {err}")))?;
    Ok(write_file_durably(
        &dir,
        &format!("{}.json", base.key),
        &data,
    )?)
}

/// The bases handed over in the WAL directory `local_dir`, with the file each came from.
/// A file that can not be read, or names something else than a backup, is skipped with a
/// warning and left in place.
pub(super) fn read_handed_over_bases(local_dir: &Path) -> Vec<(PathBuf, PitrBaseBackup)> {
    let dir = local_dir.join(HANDED_OVER_BASES_DIR);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut bases = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let base = fs::read(&path)
            .map_err(|err| err.to_string())
            .and_then(|data| {
                serde_json::from_slice::<PitrBaseBackup>(&data).map_err(|err| err.to_string())
            });
        match base {
            Ok(base) if is_backup_artifact_name(&base.key) => bases.push((path, base)),
            Ok(base) => warn!(
                path = %path.display(),
                key = %base.key,
                "A handed over base names something else than a backup; ignored"
            ),
            Err(err) => warn!(
                %err,
                path = %path.display(),
                "A handed over base can not be read; ignored"
            ),
        }
    }
    bases.sort_by_key(|(_, base)| base.watermark_ts);
    bases
}

/// Add the handed over bases of `handed_over` that belong to the archive of `manifest`.
/// Returns the files of the bases that were added, and of those that never can be, which
/// may go once the manifest is saved. A base that does not exist (any more) is not added;
/// the index drops what the base location does not hold anyway.
pub(super) fn adopt_handed_over_bases(
    manifest: &mut PitrManifest,
    handed_over: Vec<(PathBuf, PitrBaseBackup)>,
    held: Option<&[String]>,
) -> Vec<PathBuf> {
    let mut settled = Vec::new();
    for (path, base) in handed_over {
        if let Some(server_uuid) = base
            .server_uuid
            .filter(|uuid| !manifest.knows_server(*uuid))
        {
            error!(
                key = %base.key,
                %server_uuid,
                archive = %manifest.server_uuid,
                "A handed over base was taken from another server's database; not indexed"
            );
            settled.push(path);
            continue;
        }
        if held.is_some_and(|held| !held.contains(&base.key)) {
            warn!(key = %base.key, "A handed over base no longer exists; not indexed");
            settled.push(path);
            continue;
        }
        if !manifest.base_backups.contains(&base) {
            info!(
                key = %base.key,
                watermark = %format_ts_rfc3339(base.watermark_ts),
                "Manual backup used as a point-in-time recovery base"
            );
            manifest.add_base_backup(base);
        }
        settled.push(path);
    }
    settled
}

/// Remove the hand-over files `paths`, once the manifest records what they held.
pub(super) fn forget_handed_over_bases(paths: &[PathBuf]) {
    for path in paths {
        if let Err(err) = fs::remove_file(path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(%err, path = %path.display(), "Unable to remove a handed over base");
            }
        }
    }
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

    fn config_for(settings: &PitrSettings, db_dir: &std::path::Path) -> Configuration {
        let BaseLocation::Local(base_dir) = &settings.bases else {
            panic!("local bases expected");
        };
        let mut config = Configuration::new_for_test();
        config.db_path = Some(db_dir.join("kubidm.db"));
        config.online_backup = Some(crate::config::OnlineBackup {
            path: Some(base_dir.clone()),
            wal_archive: Some(settings.wal.clone()),
            ..crate::config::OnlineBackup::default()
        });
        config
    }

    #[tokio::test]
    async fn test_manual_backup_in_the_base_directory_is_handed_over_as_a_base() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(dir.path());
        let config = config_for(&settings, dir.path());
        let BaseLocation::Local(base_dir) = settings.bases.clone() else {
            panic!("local bases expected");
        };
        fs::create_dir_all(&base_dir).unwrap();
        let server = Uuid::new_v4();
        let key = "backup-2026-10-10T10:00:00.000000000Z.json.gz";
        fs::write(base_dir.join(key), b"backup").unwrap();

        // Not a base: elsewhere, or not under a backup name. Nothing is handed over.
        let elsewhere = dir.path().join(key);
        fs::write(&elsewhere, b"backup").unwrap();
        assert!(matches!(
            note_manual_backup(&config, &elsewhere, &report(500, server)).await,
            Ok(ManualBase::NotABase(reason)) if reason.contains("base backup directory")
        ));
        let unnamed = base_dir.join("before-upgrade.json.gz");
        fs::write(&unnamed, b"backup").unwrap();
        assert!(matches!(
            note_manual_backup(&config, &unnamed, &report(500, server)).await,
            Ok(ManualBase::NotABase(reason)) if reason.contains("backup name")
        ));
        assert!(read_handed_over_bases(&settings.local_dir).is_empty());
        // Without WAL archiving, nothing to do.
        assert_eq!(
            note_manual_backup(
                &Configuration::new_for_test(),
                &base_dir.join(key),
                &report(500, server)
            )
            .await
            .unwrap(),
            ManualBase::NotConfigured
        );

        // In the base directory, under a backup name (reached through another path): a
        // base with the watermark of its content.
        let through_dot = base_dir.join(".").join(key);
        assert_eq!(
            note_manual_backup(&config, &through_dot, &report(500, server))
                .await
                .unwrap(),
            ManualBase::HandedOver {
                watermark: format_ts_rfc3339(Duration::from_secs(500))
            }
        );
        let handed_over = read_handed_over_bases(&settings.local_dir);
        assert_eq!(handed_over.len(), 1);
        assert_eq!(handed_over[0].1.key, key);
        assert_eq!(handed_over[0].1.watermark_ts, Duration::from_secs(500));
        assert_eq!(handed_over[0].1.server_uuid, Some(server));
        assert_eq!(handed_over[0].1.timestamp, "2026-10-10T10:00:00.000000000Z");

        // The archive of the server adopts it; one of another server is refused, and one
        // whose file is gone is not indexed. Every hand-over file is settled.
        let mut other = handed_over[0].1.clone();
        other.key = "backup-2026-10-10T11:00:00.000000000Z.json.gz".to_string();
        other.server_uuid = Some(Uuid::new_v4());
        let mut gone = handed_over[0].1.clone();
        gone.key = "backup-2026-10-10T12:00:00.000000000Z.json.gz".to_string();
        let mut manifest = PitrManifest::new(server);
        let held = vec![key.to_string(), other.key.clone()];
        let settled = adopt_handed_over_bases(
            &mut manifest,
            vec![
                handed_over[0].clone(),
                (dir.path().join("other.json"), other),
                (dir.path().join("gone.json"), gone),
            ],
            Some(&held),
        );
        assert_eq!(settled.len(), 3);
        assert_eq!(manifest.base_backups.len(), 1);
        assert_eq!(manifest.base_backups[0].key, key);
        forget_handed_over_bases(&settled);
        assert!(read_handed_over_bases(&settings.local_dir).is_empty());
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
