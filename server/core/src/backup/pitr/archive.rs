//! The running server's archive task: closing, archiving and pruning segments, and
//! indexing base backups.

use std::sync::Arc;
use std::time::Duration;

use kubidm_proto::backup::{
    PitrBaseBackup, PitrManifest, PitrWalGap, WalSegment, PITR_MANIFEST_KEY,
};
use kubidmd_lib::be::{BackupStructuralReport, SharedWalArchiver};
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::{format_ts_rfc3339, list_segments, remove_segment, WalGap};
use tokio::sync::broadcast;
use tokio::time::{interval, MissedTickBehavior};
use uuid::Uuid;

use super::store::PitrStore;
use super::{blocking, BaseLocation, PitrError, PitrLocation, PitrSettings};
use crate::backup::BackupEncryptor;
use crate::CoreAction;

/// Load the manifest at `store`, or start a new one for `server_uuid`; the flag says
/// whether it existed. A manifest of another server is refused, so that two servers never
/// share one archive.
async fn load_or_new_manifest(
    store: &PitrStore,
    location: &PitrLocation,
    server_uuid: Uuid,
) -> Result<(PitrManifest, bool), PitrError> {
    match store.load_manifest().await? {
        Some(manifest) if manifest.server_uuid != server_uuid => Err(PitrError::Manifest(format!(
            "{PITR_MANIFEST_KEY} at {location} belongs to server {}, this server is \
                 {server_uuid}; refusing to mix archives. Give this server its own location.",
            manifest.server_uuid
        ))),
        Some(manifest) => Ok((manifest, true)),
        None => Ok((PitrManifest::new(server_uuid), false)),
    }
}

/// The manifest record of a gap the archiver reported at `now`.
fn manifest_gap(gap: &WalGap, now: Duration) -> PitrWalGap {
    PitrWalGap {
        from_ts: gap.from_ts,
        until_ts: gap.until_ts.unwrap_or(now).max(gap.from_ts),
        reason: gap.reason.to_string(),
    }
}

/// Add the gaps the archiver reported to `manifest`. Returns whether there were any.
fn record_gaps(manifest: &mut PitrManifest, gaps: &[WalGap], now: Duration) -> bool {
    for gap in gaps {
        let gap = manifest_gap(gap, now);
        error!(
            from = %format_ts_rfc3339(gap.from_ts),
            until = %format_ts_rfc3339(gap.until_ts),
            reason = %gap.reason,
            "WAL archive gap recorded: point-in-time recovery across it needs a base backup \
             taken after it"
        );
        manifest.add_gap(gap);
    }
    !gaps.is_empty()
}

/// Drop the timeline breaks and gaps no retained history needs any more. Returns whether
/// any was dropped.
fn prune_markers(manifest: &mut PitrManifest) -> bool {
    let markers_before = (manifest.timeline_breaks.len(), manifest.gaps.len());
    manifest.prune_timeline_breaks();
    manifest.prune_gaps();
    (manifest.timeline_breaks.len(), manifest.gaps.len()) != markers_before
}

/// What [`PitrArchive::archive_pending`] archived, and the error that stopped it.
#[derive(Default)]
struct ArchivedSegments {
    /// The local segments whose archived copy the manifest now names.
    segments: Vec<WalSegment>,
    error: Option<PitrError>,
}

/// The outcome of one archive synchronisation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PitrSyncReport {
    /// Whether the open segment was closed by this run.
    pub flushed: bool,
    /// Segments added to the manifest (uploaded, for the S3 location).
    pub archived: usize,
    /// Segments removed by retention.
    pub deleted: usize,
    /// Segments copied to replication regions.
    pub replicated: usize,
    /// Replication regions the archive could not be mirrored to in this run.
    pub region_errors: usize,
}

/// The running server's archive: the backend's archiver plus the location segments go to.
pub struct PitrArchive {
    pub(super) settings: PitrSettings,
    pub(super) archiver: SharedWalArchiver,
    /// Serialises the read-modify-write cycles on the manifest between the periodic
    /// synchronisation and base backup registration.
    manifest_lock: tokio::sync::Mutex<()>,
}

impl PitrArchive {
    pub fn new(settings: PitrSettings, archiver: SharedWalArchiver) -> Self {
        Self {
            settings,
            archiver,
            manifest_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn settings(&self) -> &PitrSettings {
        &self.settings
    }

    pub fn interval(&self) -> Duration {
        self.settings.wal.segment_interval()
    }

    fn server_uuid(&self) -> Uuid {
        self.lock_archiver().server_uuid()
    }

    /// Close the open segment when it is stale (or always, with `force_flush`), move every
    /// closed segment to the location, apply retention and save the manifest.
    pub async fn sync(
        &self,
        now: Duration,
        force_flush: bool,
    ) -> Result<PitrSyncReport, PitrError> {
        let _guard = self.manifest_lock.lock().await;
        let mut report = PitrSyncReport::default();

        // Closing a segment writes a file; keep it off the async runtime.
        let archiver = self.archiver.clone();
        let flushed = tokio::task::spawn_blocking(move || {
            let mut archiver = archiver
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if force_flush {
                archiver.flush_current_segment()
            } else {
                archiver.flush_if_stale(now)
            }
        })
        .await
        .map_err(|err| PitrError::Manifest(format!("flush task failed: {err}")))??;
        report.flushed = flushed.is_some();

        // Gaps the archiver noticed go into the manifest with this run, and back to the
        // archiver when the run fails, so that none is ever forgotten.
        let gaps = self.lock_archiver().take_gaps();
        let mut gaps_recorded = false;
        let result = self
            .sync_locked(now, &gaps, &mut gaps_recorded, &mut report)
            .await;
        if !gaps_recorded && !gaps.is_empty() {
            self.lock_archiver().restore_gaps(gaps);
        }
        result.map(|()| report)
    }

    /// At shutdown: hand the gaps that could not be recorded to the next start.
    pub fn defer_gaps_to_next_start(&self) {
        if let Err(err) = self.lock_archiver().defer_gaps_to_next_start() {
            error!(
                %err,
                "Unable to hand the WAL archive gaps to the next start; point-in-time recovery \
                 may replay across them. Take a new online backup."
            );
        }
    }

    fn lock_archiver(&self) -> std::sync::MutexGuard<'_, kubidmd_lib::repl::wal::WalArchiver> {
        self.archiver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// One synchronisation, in steps that each say whether they changed the manifest:
    /// record the gaps, archive the pending segments (saving the manifest before any local
    /// copy goes), apply retention, prune the markers no history needs any more, save, and
    /// mirror the result to the replication regions.
    async fn sync_locked(
        &self,
        now: Duration,
        gaps: &[WalGap],
        gaps_recorded: &mut bool,
        report: &mut PitrSyncReport,
    ) -> Result<(), PitrError> {
        let local_segments = {
            let local_dir = self.settings.local_dir.clone();
            blocking(move || Ok(list_segments(&local_dir)?)).await?
        };
        let store = PitrStore::open(&self.settings.location).await?;
        let server_uuid = self.server_uuid();
        let (mut manifest, existed) =
            load_or_new_manifest(&store, &self.settings.location, server_uuid).await?;
        let mut changed = !existed;

        changed |= record_gaps(&mut manifest, gaps, now);

        let pending = self.pending_segments(&store, &manifest, local_segments, server_uuid);
        let archived = self.archive_pending(&store, &mut manifest, pending).await;

        if !archived.segments.is_empty() || changed {
            store.save_manifest(&mut manifest).await?;
            *gaps_recorded = true;
            changed = false;
            report.archived = archived.segments.len();
            self.cleanup_local(&store, &archived.segments).await?;
        }
        if let Some(err) = archived.error {
            return Err(err);
        }

        changed |= self
            .apply_retention(&store, &mut manifest, now, report)
            .await?;
        changed |= prune_markers(&mut manifest);

        if changed {
            store.save_manifest(&mut manifest).await?;
        }
        *gaps_recorded = true;

        self.replicate(&store, &mut manifest, now, report).await;

        Ok(())
    }

    /// Whether archiving moves a segment out of the local directory: when it is uploaded
    /// to S3 or encrypted, since the plaintext copy must not outlive its archived copy.
    fn moves_segments(&self, store: &PitrStore) -> bool {
        store.is_s3() || self.settings.encryption.enabled
    }

    /// The closed local segments to archive in this run. For the local location this is
    /// only an index update of the segments the manifest does not know yet, unless the
    /// segment is encrypted into `<segment>.enc`; for S3 it is the upload. Every segment
    /// that moves is archived again while its local copy is there, since a segment stays
    /// local only until its archiving and the manifest update succeeded.
    fn pending_segments(
        &self,
        store: &PitrStore,
        manifest: &PitrManifest,
        local_segments: Vec<WalSegment>,
        server_uuid: Uuid,
    ) -> Vec<WalSegment> {
        let moves_segments = self.moves_segments(store);
        local_segments
            .into_iter()
            .filter(|segment| {
                if segment.server_uuid != server_uuid {
                    warn!(
                        segment = %segment.segment_id,
                        "WAL segment of another server in {}, not archived",
                        self.settings.local_dir.display()
                    );
                    return false;
                }
                moves_segments || !manifest.has_segment(&segment.segment_id)
            })
            .collect()
    }

    /// Archive `pending` in order and add each archived segment to `manifest`. The first
    /// failure stops the run; the segments archived before it are returned with it, so
    /// that the manifest naming them is saved. Without the encryption key nothing is
    /// archived: a segment is never archived in plaintext while encryption is enabled.
    async fn archive_pending(
        &self,
        store: &PitrStore,
        manifest: &mut PitrManifest,
        pending: Vec<WalSegment>,
    ) -> ArchivedSegments {
        let mut archived = ArchivedSegments::default();
        if pending.is_empty() {
            return archived;
        }
        let local_dir = &self.settings.local_dir;
        // The key is obtained once per run, and only when there is something to encrypt.
        let encryptor = if self.settings.encryption.enabled {
            match BackupEncryptor::from_config(&self.settings.encryption).await {
                Ok(encryptor) => encryptor,
                Err(err) => {
                    let err = PitrError::Encryption(format!(
                        "unable to obtain the backup encryption key; {} WAL segments stay in {} \
                         until it is available: {err}",
                        pending.len(),
                        local_dir.display()
                    ));
                    error!(%err, "Unable to archive WAL segments");
                    archived.error = Some(err);
                    return archived;
                }
            }
        } else {
            None
        };

        for segment in pending {
            match store
                .put_segment(local_dir, &segment, encryptor.as_ref())
                .await
            {
                Ok(stored) => {
                    manifest.add_segment(stored);
                    archived.segments.push(segment);
                }
                Err(err) => {
                    error!(%err, segment = %segment.segment_id, "Unable to archive WAL segment");
                    archived.error = Some(err);
                    break;
                }
            }
        }
        archived
    }

    /// Once the manifest naming their archived copies is saved, remove the local copies of
    /// the segments that moved.
    async fn cleanup_local(
        &self,
        store: &PitrStore,
        archived: &[WalSegment],
    ) -> Result<(), PitrError> {
        if archived.is_empty() {
            return Ok(());
        }
        if self.moves_segments(store) {
            let local_dir = self.settings.local_dir.clone();
            let ids: Vec<String> = archived.iter().map(|s| s.segment_id.clone()).collect();
            blocking(move || {
                for id in ids {
                    remove_segment(&local_dir, &id)?;
                }
                Ok(())
            })
            .await?;
        }
        info!(
            archived = archived.len(),
            location = %self.settings.location,
            "WAL segments archived"
        );
        Ok(())
    }

    /// Retention. Base backups that backup retention removed drop out of the index, and
    /// segments that are both older than the retention period and not needed by the
    /// oldest remaining base backup are deleted. Returns whether the manifest changed.
    async fn apply_retention(
        &self,
        store: &PitrStore,
        manifest: &mut PitrManifest,
        now: Duration,
        report: &mut PitrSyncReport,
    ) -> Result<bool, PitrError> {
        let existing_bases = self.settings.bases.list_keys().await?;
        let bases_before = manifest.base_backups.len();
        manifest.retain_base_backups(&existing_bases);
        let mut changed = manifest.base_backups.len() != bases_before;

        for segment_id in select_segments_to_delete(manifest, now, self.settings.wal.retention()) {
            let Some(segment) = manifest.segment(&segment_id).cloned() else {
                continue;
            };
            match store
                .delete_segment(&self.settings.local_dir, &segment)
                .await
            {
                Ok(()) => {
                    info!(segment = %segment.segment_id, "Expired WAL segment deleted");
                    manifest.remove_segment(&segment.segment_id);
                    report.deleted += 1;
                    changed = true;
                }
                Err(err) => {
                    error!(%err, segment = %segment.segment_id, "Unable to delete expired WAL segment");
                }
            }
        }
        Ok(changed)
    }

    /// Record a base backup that was just written to `location`. A backup written
    /// anywhere else than the configured base location is ignored, since recovery could
    /// not find it.
    pub async fn register_base_backup(
        &self,
        location: &BaseLocation,
        key: &str,
        timestamp: &str,
        report: &BackupStructuralReport,
    ) -> Result<(), PitrError> {
        if location != &self.settings.bases {
            debug!(
                key,
                %location,
                "Base backup written to another location than the configured one, not indexed"
            );
            return Ok(());
        }
        let watermark_ts = report.db_ts_max.ok_or_else(|| {
            PitrError::Manifest(format!("base backup {key} records no CID watermark"))
        })?;
        let server_version = report.version.clone().ok_or_else(|| {
            PitrError::Manifest(format!("base backup {key} records no server version"))
        })?;

        let _guard = self.manifest_lock.lock().await;
        let store = PitrStore::open(&self.settings.location).await?;
        let server_uuid = self.server_uuid();
        if let Some(db_s_uuid) = report.db_s_uuid {
            if db_s_uuid != server_uuid {
                return Err(PitrError::Manifest(format!(
                    "base backup {key} was written by server {db_s_uuid}, this archive belongs to {server_uuid}"
                )));
            }
        }
        let (mut manifest, _) =
            load_or_new_manifest(&store, &self.settings.location, server_uuid).await?;
        manifest.add_base_backup(PitrBaseBackup {
            key: key.to_string(),
            timestamp: timestamp.to_string(),
            watermark_ts,
            server_version,
        });
        store.save_manifest(&mut manifest).await?;
        info!(
            key,
            watermark = %format_ts_rfc3339(watermark_ts),
            "Base backup indexed for point-in-time recovery"
        );
        self.replicate(
            &store,
            &mut manifest,
            duration_from_epoch_now(),
            &mut PitrSyncReport::default(),
        )
        .await;
        Ok(())
    }

    /// [`Self::register_base_backup`] for callers that must not fail because of it: an
    /// error is logged, since the backup itself succeeded.
    pub async fn register_base_backup_logged(
        &self,
        location: &BaseLocation,
        key: &str,
        timestamp: &str,
        report: &BackupStructuralReport,
    ) {
        if let Err(err) = self
            .register_base_backup(location, key, timestamp, report)
            .await
        {
            error!(
                %err,
                key,
                "Unable to index the base backup for point-in-time recovery; recovery can only \
                 start from earlier base backups"
            );
        }
    }
}

/// The segments retention removes: older than `retention` relative to `now`, and never
/// one that holds records after the watermark of the oldest base backup still available,
/// since that base needs them to reach any later point. Without any base backup only the
/// age counts.
pub fn select_segments_to_delete(
    manifest: &PitrManifest,
    now: Duration,
    retention: Duration,
) -> Vec<String> {
    let cutoff = now.saturating_sub(retention);
    let guard = manifest.oldest_base_backup().map(|base| base.watermark_ts);
    manifest
        .segments
        .iter()
        .filter(|segment| segment.end_ts < cutoff)
        .filter(|segment| guard.is_none_or(|watermark| segment.end_ts <= watermark))
        .map(|segment| segment.segment_id.clone())
        .collect()
}

/// Start the task that synchronises the archive every segment interval. The final
/// synchronisation at shutdown is done by the core handle once every other task, and so
/// every writer, has stopped.
pub(crate) fn start_wal_archive_task(
    archive: Arc<PitrArchive>,
    mut rx: broadcast::Receiver<CoreAction>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut inter = interval(archive.interval());
        inter.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // The first tick completes immediately: archive what a previous run left behind.
        loop {
            tokio::select! {
                Ok(action) = rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                        CoreAction::Reload => continue,
                    }
                }
                _ = inter.tick() => {
                    if let Err(err) = archive.sync(duration_from_epoch_now(), false).await {
                        error!(%err, "WAL archive synchronisation failed");
                    }
                }
            }
        }
        info!("Stopped {}", crate::TaskName::WalArchive);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    use kubidm_proto::backup::{BackupEncryptionConfig, WalArchiveConfig};
    use kubidmd_lib::repl::cid::Cid;
    use kubidmd_lib::repl::wal::{WalArchiver, WalPendingOp};

    use super::super::recover::record_timeline_break;
    use super::super::test_util::*;
    use super::super::{plan_recovery, resolve_target, RecoveryTargetSpec};

    #[test]
    fn test_select_segments_to_delete_respects_retention_and_base_guard() {
        let m = manifest();
        let retention = Duration::from_secs(DAY);

        // Nothing is older than a day yet.
        assert!(select_segments_to_delete(&m, Duration::from_secs(1000), retention).is_empty());

        // Everything is older than a day, but every segment holds records after the
        // watermark of the oldest base backup (100), which needs them. Nothing goes.
        assert!(
            select_segments_to_delete(&m, Duration::from_secs(DAY + 5000), retention).is_empty()
        );

        // Once backup-1 is gone the oldest base is backup-2 (400): s1 is fully contained
        // in it, s2 straddles it and s3 follows it.
        let mut m2 = m.clone();
        m2.retain_base_backups(&["backup-2".to_string()]);
        assert_eq!(
            select_segments_to_delete(&m2, Duration::from_secs(DAY + 5000), retention),
            vec!["s1".to_string()]
        );

        // Within the retention period nothing is deleted even when covered by the base.
        assert!(
            select_segments_to_delete(&m2, Duration::from_secs(DAY + 150), retention).is_empty()
        );

        // Without any base backup only the age counts.
        let mut m3 = m.clone();
        m3.retain_base_backups(&[]);
        assert_eq!(
            select_segments_to_delete(&m3, Duration::from_secs(DAY + 500), retention),
            vec!["s1".to_string(), "s2".to_string()]
        );
    }

    #[tokio::test]
    async fn test_local_archive_sync_register_retention_and_breaks() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let server = Uuid::new_v4();
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            s3: None,
            retention_days: 1,
            segment_size_bytes: 1024 * 1024,
            segment_interval_seconds: 60,
            local_path: Some(wal_dir.clone()),
        };
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::new(wal_cfg.clone(), server, wal_dir.clone()).unwrap(),
        ));
        let bases = BaseLocation::Local(backup_dir.clone());
        let settings = PitrSettings {
            wal: wal_cfg,
            local_dir: wal_dir.clone(),
            location: PitrLocation::Local(wal_dir.clone()),
            bases: bases.clone(),
            encryption: BackupEncryptionConfig::default(),
        };
        let archive = PitrArchive::new(settings.clone(), archiver.clone());

        // A sync with nothing pending claims the location with an empty manifest.
        let report_sync = archive
            .sync(Duration::from_secs(1000), false)
            .await
            .unwrap();
        assert_eq!(report_sync, PitrSyncReport::default());
        let store = PitrStore::open(&archive.settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.server_uuid, server);
        assert!(manifest.segments.is_empty());

        // A base backup taken to the configured location is indexed with its watermark;
        // one taken anywhere else is not.
        let key = "backup-2024-01-01T00:00:00Z.json";
        fs::write(backup_dir.join(key), b"{}").unwrap();
        archive
            .register_base_backup(&bases, key, "2024-01-01T00:00:00Z", &report(1000, server))
            .await
            .unwrap();
        archive
            .register_base_backup(
                &BaseLocation::Local(dir.path().join("elsewhere")),
                "ignored.json",
                "t",
                &report(1000, server),
            )
            .await
            .unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.base_backups.len(), 1);
        assert_eq!(
            manifest.base_backups[0].watermark_ts,
            Duration::from_secs(1000)
        );

        // A backup of another server is refused.
        assert!(matches!(
            archive
                .register_base_backup(&bases, "other.json", "t", &report(1000, Uuid::new_v4()))
                .await,
            Err(PitrError::Manifest(_))
        ));

        // Records committed after the base; a forced sync closes the segment and indexes
        // it, leaving the file in place for the local location.
        archiver
            .lock()
            .unwrap()
            .append_transaction(
                &Cid {
                    ts: Duration::from_secs(1100),
                    s_uuid: server,
                },
                false,
                vec![(
                    1,
                    WalPendingOp::Create {
                        entry_uuid: Uuid::new_v4(),
                        entry_data: b"{}".to_vec(),
                    },
                )],
            )
            .unwrap();
        let report_sync = archive.sync(Duration::from_secs(1100), true).await.unwrap();
        assert!(report_sync.flushed);
        assert_eq!(report_sync.archived, 1);
        assert_eq!(report_sync.deleted, 0);
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.segments.len(), 1);
        assert_eq!(manifest.segments[0].start_ts, Duration::from_secs(1100));
        assert!(wal_dir.join(&manifest.segments[0].segment_id).is_file());
        assert_eq!(
            manifest.recoverable_window(),
            Some((Duration::from_secs(1000), Duration::from_secs(1100)))
        );

        // A second sync without new records changes nothing and does not duplicate.
        let report_sync = archive
            .sync(Duration::from_secs(1200), false)
            .await
            .unwrap();
        assert_eq!(report_sync, PitrSyncReport::default());
        assert_eq!(
            store.load_manifest().await.unwrap().unwrap().segments.len(),
            1
        );

        // The recovery plan pairs the base with the segment.
        let plan = plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.base.key, key);
        assert_eq!(plan.segments.len(), 1);

        // A restore to the base abandons the history after its watermark.
        record_timeline_break(&settings, Duration::from_secs(1000), "restore")
            .await
            .unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.timeline_breaks.len(), 1);
        assert!(manifest.is_abandoned(Duration::from_secs(1100)));
        // The abandoned range reaches at least to now, past every archived record.
        assert!(manifest.timeline_breaks[0].until_ts > Duration::from_secs(1100));
        let plan = plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.target.ts, Duration::from_secs(1000));

        // Retention: the segment is newer than the only base backup, so even a day later
        // it stays. Once the base backup disappears from disk it drops out of the index,
        // and the segment, now older than retention with no base guarding it, is deleted
        // together with the break no archived history precedes any more.
        let report_sync = archive
            .sync(Duration::from_secs(1100 + 2 * DAY), false)
            .await
            .unwrap();
        assert_eq!(report_sync.deleted, 0);
        fs::remove_file(backup_dir.join(key)).unwrap();
        let report_sync = archive
            .sync(Duration::from_secs(1100 + 2 * DAY), false)
            .await
            .unwrap();
        assert_eq!(report_sync.deleted, 1);
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert!(manifest.base_backups.is_empty());
        assert!(manifest.segments.is_empty());
        assert!(manifest.timeline_breaks.is_empty());
        assert!(list_segments(&wal_dir).unwrap().is_empty());

        // A manifest of another server is never mixed with this one.
        let mut foreign = PitrManifest::new(Uuid::new_v4());
        store.save_manifest(&mut foreign).await.unwrap();
        assert!(matches!(
            archive.sync(Duration::from_secs(1), false).await,
            Err(PitrError::Manifest(_))
        ));
    }

    #[tokio::test]
    async fn test_sync_records_archiver_gaps_and_recovery_refuses_to_cross_them() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let server = Uuid::new_v4();
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            local_path: Some(wal_dir.clone()),
            ..WalArchiveConfig::default()
        };
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::new(wal_cfg.clone(), server, wal_dir.clone()).unwrap(),
        ));
        let bases = BaseLocation::Local(backup_dir.clone());
        let archive = PitrArchive::new(
            PitrSettings {
                wal: wal_cfg,
                local_dir: wal_dir.clone(),
                location: PitrLocation::Local(wal_dir.clone()),
                bases: bases.clone(),
                encryption: BackupEncryptionConfig::default(),
            },
            archiver.clone(),
        );
        let key = "backup-2024-01-01T00:00:00Z.json";
        fs::write(backup_dir.join(key), b"{}").unwrap();
        archive
            .register_base_backup(&bases, key, "t", &report(1000, server))
            .await
            .unwrap();

        let append = |secs: u64| {
            archiver
                .lock()
                .unwrap()
                .append_transaction(
                    &Cid {
                        ts: Duration::from_secs(secs),
                        s_uuid: server,
                    },
                    false,
                    vec![(
                        secs,
                        WalPendingOp::Delete {
                            entry_uuid: Uuid::new_v4(),
                        },
                    )],
                )
                .unwrap();
        };
        append(1100);
        // The transaction at 1200 was committed but could not be archived.
        archiver
            .lock()
            .unwrap()
            .note_failure(Some(Duration::from_secs(1200)));
        append(1300);

        archive.sync(Duration::from_secs(1400), true).await.unwrap();
        assert!(archiver.lock().unwrap().take_gaps().is_empty());
        let store = PitrStore::open(&archive.settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.gaps.len(), 1);
        assert_eq!(manifest.gaps[0].from_ts, Duration::from_secs(1200));
        assert_eq!(manifest.gaps[0].until_ts, Duration::from_secs(1200));

        // Before the gap: fine. Across it: refused, naming the latest safe point.
        plan_recovery(
            &manifest,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(1150))),
        )
        .unwrap();
        let err = plan_recovery(
            &manifest,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(1300))),
        )
        .unwrap_err();
        assert!(matches!(err, PitrError::NotRecoverable(_)), "{err}");
        assert!(err.to_string().contains("missing"), "{err}");
        let latest = resolve_target(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert!(latest.ts < Duration::from_secs(1200));
        plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();

        // A base backup taken after the gap makes the later points recoverable again.
        let key2 = "backup-2024-01-02T00:00:00Z.json";
        fs::write(backup_dir.join(key2), b"{}").unwrap();
        archive
            .register_base_backup(&bases, key2, "t", &report(1250, server))
            .await
            .unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        let plan = plan_recovery(
            &manifest,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(1300))),
        )
        .unwrap();
        assert_eq!(plan.base.key, key2);
    }
}
