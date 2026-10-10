//! The running server's archive task: closing, archiving and pruning segments, and
//! indexing base backups.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kubidm_proto::backup::{
    PitrBaseBackup, PitrManifest, PitrServerUuidChange, PitrWalGap, WalSegment, PITR_MANIFEST_KEY,
};
use kubidmd_lib::be::{lock_wal, BackupStructuralReport, SharedWalArchiver};
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::{
    format_ts_rfc3339, parse_segment_file_name, quarantine_segment, rebuild_sidecar,
    remove_segment, scan_segments, write_closed_segments, WalArchiver, WalGap, WalPendingEvents,
    WalServerUuidChange,
};
use tokio::sync::broadcast;
use tokio::time::{interval, MissedTickBehavior};
use uuid::Uuid;

use super::offline::{adopt_handed_over_bases, forget_handed_over_bases, read_handed_over_bases};
use super::recover::{apply_restore, RestoreRecord};
use super::store::{read_local_segment, PitrStore};
use super::{blocking, BaseLocation, PitrError, PitrLocation, PitrSettings};
use crate::backup::BackupEncryptor;
use crate::CoreAction;

/// The manifest record of a change of the server identity the archiver reported.
pub(super) fn manifest_uuid_change(change: &WalServerUuidChange) -> PitrServerUuidChange {
    PitrServerUuidChange {
        from_server_uuid: change.from,
        to_server_uuid: change.to,
        at_ts: change.at_ts,
        reason: "replication refresh".to_string(),
    }
}

/// Load the manifest at `store`, or start a new one, and apply to it the restores the
/// archive could not record when they happened, then the changes of the server identity,
/// of `events`; the flag says whether it changed (a new manifest always does). The manifest
/// must then belong to `server_uuid`: one of another server is refused, so that two
/// servers never share one archive. A server that changed its identity (a replication
/// refresh, a restore or recovery of a backup with another server uuid) keeps its archive,
/// since the change was recorded where it happened, or is one of these events.
async fn load_or_new_manifest(
    store: &PitrStore,
    location: &PitrLocation,
    server_uuid: Uuid,
    events: &WalPendingEvents,
) -> Result<(PitrManifest, bool), PitrError> {
    let changes = &events.server_uuid_changes;
    let (mut manifest, mut changed) = match store.load_manifest().await? {
        Some(mut manifest) => {
            // A restore abandons the history of an archive, and of the WAL directory.
            let mut changed = false;
            for restore in &events.restores {
                changed |= apply_restore(&mut manifest, restore) != RestoreRecord::AlreadyRecorded;
            }
            (manifest, changed)
        }
        None => match events
            .restores
            .first()
            .and_then(|restore| restore.local_server_uuid)
        {
            // The stopped server left history in the WAL directory that no archive holds
            // yet: the archive starts with it, abandoned by the restore.
            Some(local_server_uuid) => {
                let mut manifest = PitrManifest::new(local_server_uuid);
                for restore in &events.restores {
                    apply_restore(&mut manifest, restore);
                }
                (manifest, true)
            }
            None => (
                PitrManifest::new(changes.first().map_or(server_uuid, |change| change.from)),
                true,
            ),
        },
    };
    for change in changes {
        let change = manifest_uuid_change(change);
        let applied = manifest.apply_server_uuid_change(&change).map_err(|err| {
            PitrError::Manifest(format!("{PITR_MANIFEST_KEY} at {location}: {err}"))
        })?;
        if applied {
            warn!(
                from = %change.from_server_uuid,
                to = %change.to_server_uuid,
                at = %format_ts_rfc3339(change.at_ts),
                "The WAL archive continues under the new server uuid; recovery never replays \
                 across the change from a base backup taken before it"
            );
        }
        changed |= applied;
    }
    if manifest.server_uuid != server_uuid {
        return Err(PitrError::Manifest(format!(
            "{PITR_MANIFEST_KEY} at {location} belongs to server {}, this server is \
             {server_uuid}; refusing to mix archives. Give this server its own location.",
            manifest.server_uuid
        )));
    }
    Ok((manifest, changed))
}

/// The manifest record of a gap the archiver reported at `now`.
pub(super) fn manifest_gap(gap: &WalGap, now: Duration) -> PitrWalGap {
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
    /// Whether a damaged segment was set aside and recorded as a gap.
    quarantined: bool,
    error: Option<PitrError>,
}

/// What [`PitrArchive::repair_local`] did.
#[derive(Default)]
struct RepairedSegments {
    /// Segments whose sidecar was rebuilt.
    segments: Vec<WalSegment>,
    /// The ranges of the segments set aside.
    gaps: Vec<PitrWalGap>,
}

/// The outcome of one archive synchronisation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PitrSyncReport {
    /// Whether the open segment was closed by this run.
    pub flushed: bool,
    /// Whether closed segments could not be written to the local directory. They stay in
    /// memory and the next run retries them.
    pub flush_failed: bool,
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
    /// The archive location, opened (its S3 client built) once.
    store: tokio::sync::OnceCell<PitrStore>,
    /// The stores of the replication regions, by region name, built once.
    pub(super) region_stores: tokio::sync::Mutex<BTreeMap<String, PitrStore>>,
    /// When the replication last compared the sidecars of every segment copy, see
    /// [`Self::replicate`].
    pub(super) last_deep_check: std::sync::Mutex<Option<Duration>>,
    /// The encryptor segments were last sealed with. It is kept while the configured key
    /// stays the same, so that the segments of a server run share one encryption session.
    encryptor: tokio::sync::Mutex<Option<BackupEncryptor>>,
}

impl PitrArchive {
    pub fn new(settings: PitrSettings, archiver: SharedWalArchiver) -> Self {
        Self {
            settings,
            archiver,
            manifest_lock: tokio::sync::Mutex::new(()),
            store: tokio::sync::OnceCell::new(),
            region_stores: tokio::sync::Mutex::new(BTreeMap::new()),
            last_deep_check: std::sync::Mutex::new(None),
            encryptor: tokio::sync::Mutex::new(None),
        }
    }

    /// The encryptor segments are sealed with: the configured key, obtained again for every
    /// run so that a rotated key is picked up, and the encryptor of the earlier runs as long
    /// as it holds the same key, which keeps its encryption session. None when encryption
    /// is not enabled.
    async fn segment_encryptor(&self) -> Result<Option<BackupEncryptor>, PitrError> {
        let Some(configured) = BackupEncryptor::from_config(&self.settings.encryption)
            .await
            .map_err(|err| PitrError::Encryption(err.to_string()))?
        else {
            return Ok(None);
        };
        let mut kept = self.encryptor.lock().await;
        match kept.as_ref() {
            Some(kept) if kept.same_key(&configured) => Ok(Some(kept.clone())),
            _ => {
                *kept = Some(configured.clone());
                Ok(Some(configured))
            }
        }
    }

    /// The archive location; its S3 client is built at the first use and then reused.
    async fn store(&self) -> Result<&PitrStore, PitrError> {
        self.store
            .get_or_try_init(|| PitrStore::open(&self.settings.location))
            .await
    }

    pub fn settings(&self) -> &PitrSettings {
        &self.settings
    }

    pub fn interval(&self) -> Duration {
        self.settings.wal.segment_interval()
    }

    /// Run `work` on the archiver off the async runtime: its lock is held by write
    /// commits while they close a segment, which must never stall a runtime worker.
    async fn with_archiver<T, F>(&self, work: F) -> Result<T, PitrError>
    where
        F: FnOnce(&mut WalArchiver) -> Result<T, PitrError> + Send + 'static,
        T: Send + 'static,
    {
        let archiver = self.archiver.clone();
        blocking(move || work(&mut lock_wal(&archiver))).await
    }

    /// Write the closed segments of the archiver, off the async runtime and without
    /// holding the archiver lock while they are compressed and written.
    async fn write_closed_segments(&self, now: Duration) -> Result<bool, PitrError> {
        let archiver = self.archiver.clone();
        blocking(move || Ok(write_closed_segments(&archiver, now, true)?.is_some())).await
    }

    /// Close the open segment when it is stale (or always, with `force_flush`), move every
    /// closed segment to the location, apply retention and save the manifest.
    ///
    /// A segment that can not be written to the local directory does not stop the run:
    /// the segments already there are still archived and removed locally, which is what
    /// frees the space a full disk needs, and the write is retried at the end. Its error
    /// is returned once the rest of the run is done.
    pub async fn sync(
        &self,
        now: Duration,
        force_flush: bool,
    ) -> Result<PitrSyncReport, PitrError> {
        let _guard = self.manifest_lock.lock().await;
        let mut report = PitrSyncReport::default();

        let (sealed, events, server_uuid) = self
            .with_archiver(move |archiver| {
                let sealed = if force_flush {
                    archiver.seal_current()
                } else {
                    archiver.seal_if_stale(now)
                };
                Ok((sealed, archiver.pending_events(), archiver.server_uuid()))
            })
            .await?;
        report.flushed = sealed;
        let mut flush_error = self.write_closed_segments(now).await.err();
        if let Some(err) = &flush_error {
            report.flush_failed = true;
            warn!(%err, "Unable to write the closed WAL segments; archiving what is already written");
        }

        // The events the archiver noticed go into the manifest with this run. They stay
        // pending in the archiver, on disk, until a saved manifest records them.
        let mut events_recorded = false;
        let mut result = self
            .sync_locked(now, &events, server_uuid, &mut events_recorded, &mut report)
            .await;
        if events_recorded && !events.is_empty() {
            self.with_archiver(move |archiver| Ok(archiver.acknowledge_events(&events)?))
                .await
                .unwrap_or_else(|err| {
                    // They are recorded twice at worst, which changes nothing.
                    warn!(%err, "Unable to forget the WAL archive events the manifest records");
                });
        }

        // The archiving may have freed the space the write needed: try it again, and
        // archive what it wrote.
        if flush_error.is_some() && result.is_ok() {
            match self.write_closed_segments(now).await {
                Ok(written) => {
                    flush_error = None;
                    report.flush_failed = false;
                    if written {
                        result = self
                            .sync_locked(
                                now,
                                &WalPendingEvents::default(),
                                server_uuid,
                                &mut false,
                                &mut report,
                            )
                            .await;
                    }
                }
                Err(err) => flush_error = Some(err),
            }
        }

        result?;
        match flush_error {
            Some(err) => Err(err),
            None => Ok(report),
        }
    }

    /// At shutdown: make sure the events no manifest records yet are on disk for the next
    /// start.
    pub fn persist_pending_events(&self) {
        if let Err(err) = lock_wal(&self.archiver).persist_pending_events() {
            error!(
                %err,
                "Unable to hand the pending WAL archive events to the next start; \
                 point-in-time recovery may replay across their gaps. Take a new online backup."
            );
        }
    }

    /// One synchronisation, in steps that each say whether they changed the manifest:
    /// record the gaps, archive the pending segments (saving the manifest before any local
    /// copy goes), apply retention, prune the markers no history needs any more, save, and
    /// mirror the result to the replication regions.
    async fn sync_locked(
        &self,
        now: Duration,
        events: &WalPendingEvents,
        server_uuid: Uuid,
        events_recorded: &mut bool,
        report: &mut PitrSyncReport,
    ) -> Result<(), PitrError> {
        let scan = {
            let local_dir = self.settings.local_dir.clone();
            blocking(move || Ok(scan_segments(&local_dir)?)).await?
        };
        let store = self.store().await?;
        let (mut manifest, mut changed) =
            load_or_new_manifest(store, &self.settings.location, server_uuid, events).await?;

        changed |= record_gaps(&mut manifest, &events.gaps, now);
        let settled_bases = self.adopt_manual_bases(&mut manifest).await?;
        changed |= !settled_bases.is_empty();
        let mut local_segments = scan.segments;
        if !scan.unreadable.is_empty() {
            let repaired = self.repair_local(scan.unreadable, now).await?;
            changed |= !repaired.gaps.is_empty();
            for gap in repaired.gaps {
                manifest.add_gap(gap);
            }
            local_segments.extend(repaired.segments);
            local_segments.sort_by_key(|segment| segment.start_ts);
        }

        let pending = self.pending_segments(store, &manifest, local_segments);
        let archived = self
            .archive_pending(store, &mut manifest, pending, now)
            .await;
        changed |= archived.quarantined;

        if !archived.segments.is_empty() || changed {
            store.save_manifest(&mut manifest, now).await?;
            *events_recorded = true;
            changed = false;
            report.archived += archived.segments.len();
            self.cleanup_local(store, &archived.segments).await?;
        }
        if !settled_bases.is_empty() {
            blocking(move || {
                forget_handed_over_bases(&settled_bases);
                Ok(())
            })
            .await?;
        }
        if let Some(err) = archived.error {
            return Err(err);
        }

        changed |= self
            .apply_retention(store, &mut manifest, now, report)
            .await?;
        changed |= prune_markers(&mut manifest);

        if changed {
            store.save_manifest(&mut manifest, now).await?;
        }
        *events_recorded = true;

        self.replicate(store, &mut manifest, now, report).await;

        Ok(())
    }

    /// Index the manual backups handed over as bases since the last run, see
    /// [`super::offline`]. Returns the hand-over files the manifest settles once saved.
    async fn adopt_manual_bases(
        &self,
        manifest: &mut PitrManifest,
    ) -> Result<Vec<std::path::PathBuf>, PitrError> {
        let handed_over = {
            let local_dir = self.settings.local_dir.clone();
            blocking(move || Ok(read_handed_over_bases(&local_dir))).await?
        };
        if handed_over.is_empty() {
            return Ok(Vec::new());
        }
        // A base that can not be checked now is indexed anyway: retention drops it from the
        // index once its location is listed and it is not there.
        let held = self
            .settings
            .bases
            .list_keys()
            .await
            .inspect_err(|err| warn!(%err, "Unable to list the base backups"))
            .ok();
        Ok(adopt_handed_over_bases(
            manifest,
            handed_over,
            held.as_deref(),
        ))
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
    ) -> Vec<WalSegment> {
        let moves_segments = self.moves_segments(store);
        local_segments
            .into_iter()
            .filter(|segment| {
                // Segments written before a change of identity are archived as well.
                if !manifest.knows_server(segment.server_uuid) {
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
    ///
    /// A segment whose local copy does not match its sidecar (torn by a crash, damaged on
    /// disk) is set aside and its range recorded as a gap, so that it does not hold up
    /// every segment after it.
    async fn archive_pending(
        &self,
        store: &PitrStore,
        manifest: &mut PitrManifest,
        pending: Vec<WalSegment>,
        now: Duration,
    ) -> ArchivedSegments {
        let mut archived = ArchivedSegments::default();
        if pending.is_empty() {
            return archived;
        }
        let local_dir = &self.settings.local_dir;
        // The key is obtained once per run, and only when there is something to encrypt.
        let encryptor = if self.settings.encryption.enabled {
            match self.segment_encryptor().await {
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
            let result = match read_local_segment(local_dir, &segment).await {
                Ok(Some(data)) => {
                    store
                        .put_segment(&segment, data, encryptor.as_ref(), now)
                        .await
                }
                // Removed since the directory was listed: nothing to archive.
                Ok(None) => continue,
                Err(PitrError::CorruptSegment(msg)) => {
                    match self.quarantine(&segment.segment_id).await {
                        Ok(()) => {
                            error!(
                                segment = %segment.segment_id,
                                reason = %msg,
                                "WAL ARCHIVE HOLE: a closed WAL segment is damaged and was set \
                                 aside; point-in-time recovery can not replay its transactions \
                                 until a new base backup is taken"
                            );
                            manifest.add_gap(PitrWalGap {
                                from_ts: segment.start_ts,
                                until_ts: segment.end_ts,
                                reason: format!("segment {} was damaged", segment.segment_id),
                            });
                            archived.quarantined = true;
                            continue;
                        }
                        Err(err) => Err(err),
                    }
                }
                Err(err) => Err(err),
            };
            match result {
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

    /// Move the local segment `segment_id` aside.
    async fn quarantine(&self, segment_id: &str) -> Result<(), PitrError> {
        let local_dir = self.settings.local_dir.clone();
        let segment_id = segment_id.to_string();
        blocking(move || Ok(quarantine_segment(&local_dir, &segment_id)?)).await
    }

    /// Deal with the local segments whose sidecar can not be read: a complete segment file
    /// gets its sidecar back, any other is set aside and recorded as a gap from its start
    /// up to `now`, since where it ended is unknown.
    async fn repair_local(
        &self,
        unreadable: Vec<String>,
        now: Duration,
    ) -> Result<RepairedSegments, PitrError> {
        let local_dir = self.settings.local_dir.clone();
        blocking(move || {
            let mut repaired = RepairedSegments::default();
            for segment_id in unreadable {
                match rebuild_sidecar(&local_dir, &segment_id) {
                    Ok(segment) => {
                        warn!(segment = %segment_id, "WAL segment sidecar rebuilt from the segment");
                        repaired.segments.push(segment);
                    }
                    Err(err) => {
                        quarantine_segment(&local_dir, &segment_id)?;
                        error!(
                            %err,
                            segment = %segment_id,
                            "WAL ARCHIVE HOLE: a closed WAL segment and its sidecar are damaged \
                             and were set aside; point-in-time recovery can not replay its \
                             transactions until a new base backup is taken"
                        );
                        let from_ts = parse_segment_file_name(&segment_id)
                            .map(|(_, start_ts)| start_ts)
                            .unwrap_or_default();
                        repaired.gaps.push(PitrWalGap {
                            from_ts,
                            until_ts: now.max(from_ts),
                            reason: format!("segment {segment_id} was damaged"),
                        });
                    }
                }
            }
            Ok(repaired)
        })
        .await
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
        // Base backups that can not be listed are kept for now: that only keeps more
        // segments, and must not stop the archiving.
        let bases_before = manifest.base_backups.len();
        match self.settings.bases.list_keys().await {
            Ok(existing_bases) => manifest.retain_base_backups(&existing_bases),
            Err(err) => warn!(
                %err,
                bases = %self.settings.bases,
                "Unable to list the base backups; the index keeps them until the next run"
            ),
        }
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
        self.register_base_backup_at(duration_from_epoch_now(), location, key, timestamp, report)
            .await
    }

    /// [`Self::register_base_backup`] at `now`, the clock everything the registration
    /// records and the retention of the regions it replicates to go by.
    pub(super) async fn register_base_backup_at(
        &self,
        now: Duration,
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
        let store = self.store().await?;
        // The restores and identity changes the archiver holds are applied first: a backup
        // taken right after a replication refresh carries the new server uuid already.
        let (server_uuid, events) = self
            .with_archiver(|archiver| {
                let pending = archiver.pending_events();
                Ok((
                    archiver.server_uuid(),
                    WalPendingEvents {
                        server_uuid_changes: pending.server_uuid_changes,
                        restores: pending.restores,
                        ..WalPendingEvents::default()
                    },
                ))
            })
            .await?;
        if let Some(db_s_uuid) = report.db_s_uuid {
            if db_s_uuid != server_uuid {
                return Err(PitrError::Manifest(format!(
                    "base backup {key} was written by server {db_s_uuid}, this archive belongs to {server_uuid}"
                )));
            }
        }
        let (mut manifest, _) =
            load_or_new_manifest(store, &self.settings.location, server_uuid, &events).await?;
        manifest.add_base_backup(PitrBaseBackup {
            key: key.to_string(),
            timestamp: timestamp.to_string(),
            watermark_ts,
            server_version,
            server_uuid: report.db_s_uuid,
        });
        store.save_manifest(&mut manifest, now).await?;
        if !events.is_empty() {
            self.with_archiver(move |archiver| Ok(archiver.acknowledge_events(&events)?))
                .await
                .unwrap_or_else(|err| {
                    warn!(
                        %err,
                        "Unable to forget the restores and server uuid changes the manifest \
                         records"
                    );
                });
        }
        info!(
            key,
            watermark = %format_ts_rfc3339(watermark_ts),
            "Base backup indexed for point-in-time recovery"
        );
        self.replicate(store, &mut manifest, now, &mut PitrSyncReport::default())
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
    use kubidmd_lib::repl::wal::{
        list_segments, segment_file_name, segment_meta_path, WalArchiver, WalPendingOp,
        WAL_QUARANTINE_SUFFIX,
    };

    use super::super::recover::{record_timeline_break, RestoredDatabase};
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
            ..WalArchiveConfig::default()
        };
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg.clone(), server, wal_dir.clone(), None).unwrap(),
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
            .register_base_backup_at(
                Duration::from_secs(1000),
                &bases,
                key,
                "2024-01-01T00:00:00Z",
                &report(1000, server),
            )
            .await
            .unwrap();
        archive
            .register_base_backup_at(
                Duration::from_secs(1000),
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
                .register_base_backup_at(
                    Duration::from_secs(1000),
                    &bases,
                    "other.json",
                    "t",
                    &report(1000, Uuid::new_v4())
                )
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
        let restored = RestoredDatabase {
            after_ts: Duration::from_secs(1000),
            server_uuid: server,
            reason: "restore",
            now: Duration::from_secs(1150),
        };
        record_timeline_break(&settings, &restored).await.unwrap();
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
        store
            .save_manifest(&mut foreign, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(
            archive.sync(Duration::from_secs(1), false).await,
            Err(PitrError::Manifest(_))
        ));
    }

    #[tokio::test]
    async fn test_sync_archives_written_segments_when_closing_one_fails() {
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
            WalArchiver::open(wal_cfg.clone(), server, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(
            PitrSettings {
                wal: wal_cfg,
                local_dir: wal_dir.clone(),
                location: PitrLocation::Local(wal_dir.clone()),
                bases: BaseLocation::Local(backup_dir),
                encryption: BackupEncryptionConfig::default(),
            },
            archiver.clone(),
        );

        // A segment closed on disk but not archived yet, then records whose segment can
        // not be written: a directory is in the way of its file.
        append_create(&archiver, server, 1100, b"written");
        archiver.lock().unwrap().flush_current_segment().unwrap();
        append_create(&archiver, server, 1200, b"stuck");
        let blocker = wal_dir.join(segment_file_name(server, Duration::from_secs(1200)));
        fs::create_dir(&blocker).unwrap();
        fs::write(blocker.join("x"), b"x").unwrap();

        // The run reports the failure, but archives the segment already written first.
        assert!(matches!(
            archive.sync(Duration::from_secs(1300), true).await,
            Err(PitrError::Wal(_))
        ));
        let store = PitrStore::open(&archive.settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        let starts: Vec<Duration> = manifest.segments.iter().map(|s| s.start_ts).collect();
        assert_eq!(starts, vec![Duration::from_secs(1100)]);
        assert!(archiver.lock().unwrap().has_pending_records());

        // Once the obstacle is gone the kept records are written and archived.
        fs::remove_dir_all(&blocker).unwrap();
        let report = archive
            .sync(Duration::from_secs(1400), false)
            .await
            .unwrap();
        assert_eq!(report.archived, 1);
        assert!(!report.flush_failed);
        assert!(!archiver.lock().unwrap().has_pending_records());
        assert_eq!(
            store.load_manifest().await.unwrap().unwrap().segments.len(),
            2
        );
    }

    #[tokio::test]
    async fn test_sync_sets_damaged_segments_aside_and_archives_the_next_ones() {
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
            WalArchiver::open(wal_cfg.clone(), server, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(
            PitrSettings {
                wal: wal_cfg,
                local_dir: wal_dir.clone(),
                location: PitrLocation::Local(wal_dir.clone()),
                bases: BaseLocation::Local(backup_dir.clone()),
                encryption: BackupEncryptionConfig::default(),
            },
            archiver.clone(),
        );
        let key = "backup-2024-01-01T00:00:00Z.json";
        fs::write(backup_dir.join(key), b"{}").unwrap();
        archive
            .register_base_backup_at(
                Duration::from_secs(1000),
                &BaseLocation::Local(backup_dir),
                key,
                "t",
                &report(1000, server),
            )
            .await
            .unwrap();

        // Four closed segments: one torn after its sidecar was written, one whose sidecar
        // is torn but whose content is complete, one with both torn, and a good one.
        let mut ids = Vec::new();
        for secs in [1100, 1200, 1300, 1400] {
            append_create(&archiver, server, secs, b"x");
            let segment = archiver
                .lock()
                .unwrap()
                .flush_current_segment()
                .unwrap()
                .unwrap();
            ids.push(segment.segment_id);
        }
        fs::write(wal_dir.join(&ids[0]), b"torn").unwrap();
        fs::write(segment_meta_path(&wal_dir, &ids[1]), b"{").unwrap();
        fs::write(segment_meta_path(&wal_dir, &ids[2]), b"{").unwrap();
        fs::write(wal_dir.join(&ids[2]), b"torn").unwrap();

        archive
            .sync(Duration::from_secs(1500), false)
            .await
            .unwrap();
        let store = PitrStore::open(&archive.settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        let archived: Vec<&str> = manifest
            .segments
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert_eq!(archived, vec![ids[1].as_str(), ids[3].as_str()]);
        let gaps: Vec<(u64, u64)> = manifest
            .gaps
            .iter()
            .map(|gap| (gap.from_ts.as_secs(), gap.until_ts.as_secs()))
            .collect();
        assert_eq!(gaps, vec![(1100, 1100), (1300, 1500)]);
        for id in [&ids[0], &ids[2]] {
            assert!(wal_dir
                .join(format!("{id}{WAL_QUARANTINE_SUFFIX}"))
                .is_file());
        }
    }

    #[tokio::test]
    async fn test_manifest_naming_paths_outside_the_archive_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = PitrStore::Local {
            dir: dir.path().to_path_buf(),
        };
        let mut manifest = PitrManifest::new(Uuid::new_v4());
        let mut forged = segment("ignored", 1, 2);
        forged.segment_id = "../kubidm.db".to_string();
        manifest.add_segment(forged);
        store
            .save_manifest(&mut manifest, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(
            store.load_manifest().await,
            Err(PitrError::Manifest(msg)) if msg.contains("invalid segment")
        ));

        let mut manifest = PitrManifest::new(Uuid::new_v4());
        manifest.add_base_backup(base("../../etc/passwd", 1));
        store
            .save_manifest(&mut manifest, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(
            store.load_manifest().await,
            Err(PitrError::Manifest(msg)) if msg.contains("invalid base backup")
        ));
    }

    #[tokio::test]
    async fn test_archive_follows_a_server_uuid_change_and_recovery_never_crosses_it() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let old_uuid = Uuid::new_v4();
        let new_uuid = Uuid::new_v4();
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            local_path: Some(wal_dir.clone()),
            ..WalArchiveConfig::default()
        };
        let settings = PitrSettings {
            wal: wal_cfg.clone(),
            local_dir: wal_dir.clone(),
            location: PitrLocation::Local(wal_dir.clone()),
            bases: BaseLocation::Local(backup_dir.clone()),
            encryption: BackupEncryptionConfig::default(),
        };
        let bases = settings.bases.clone();
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg.clone(), old_uuid, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings.clone(), archiver.clone());
        let key1 = "backup-2024-01-01T00:00:00Z.json";
        fs::write(backup_dir.join(key1), b"{}").unwrap();
        archive
            .register_base_backup_at(
                Duration::from_secs(1000),
                &bases,
                key1,
                "t",
                &report(1000, old_uuid),
            )
            .await
            .unwrap();
        append_create(&archiver, old_uuid, 1100, b"before");
        archive.sync(Duration::from_secs(1150), true).await.unwrap();

        // A replication refresh at 1200 resets the server uuid. The server stops before
        // any synchronisation and starts again under the new uuid.
        archiver
            .lock()
            .unwrap()
            .change_server_uuid(new_uuid, Some(Duration::from_secs(1200)));
        append_create(&archiver, new_uuid, 1200, b"refresh");
        archiver.lock().unwrap().flush_current_segment().unwrap();
        drop(archive);
        drop(archiver);
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg, new_uuid, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings, archiver.clone());

        // The archive follows the server under its new identity instead of refusing it.
        append_create(&archiver, new_uuid, 1300, b"after");
        let report_sync = archive.sync(Duration::from_secs(1350), true).await.unwrap();
        assert_eq!(report_sync.archived, 2);
        assert!(archiver.lock().unwrap().pending_events().is_empty());
        let store = PitrStore::open(&archive.settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.server_uuid, new_uuid);
        assert!(manifest.knows_server(old_uuid));
        assert_eq!(manifest.server_uuid_changes.len(), 1);
        assert_eq!(
            manifest.server_uuid_changes[0].at_ts,
            Duration::from_secs(1200)
        );

        // The base of the old identity recovers up to just before the refresh, never past
        // it: the refresh replaced the database and its identity.
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
        assert!(err.to_string().contains("changed its identity"), "{err}");
        assert!(
            resolve_target(&manifest, &RecoveryTargetSpec::Latest)
                .unwrap()
                .ts
                < Duration::from_secs(1200)
        );
        // A CID of the earlier identity is still a valid target.
        let cid = Cid {
            ts: Duration::from_secs(1150),
            s_uuid: old_uuid,
        };
        resolve_target(&manifest, &RecoveryTargetSpec::Cid(cid.to_string())).unwrap();

        // A backup taken under the new identity is indexed and recovers past the refresh.
        let key2 = "backup-2024-01-02T00:00:00Z.json";
        fs::write(backup_dir.join(key2), b"{}").unwrap();
        archive
            .register_base_backup_at(
                Duration::from_secs(1250),
                &bases,
                key2,
                "t",
                &report(1250, new_uuid),
            )
            .await
            .unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        let plan = plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.base.key, key2);
        assert_eq!(plan.target.ts, Duration::from_secs(1300));

        // A manifest of a server that is not in the lineage is still refused.
        let mut foreign = PitrManifest::new(Uuid::new_v4());
        store
            .save_manifest(&mut foreign, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(
            archive.sync(Duration::from_secs(1400), false).await,
            Err(PitrError::Manifest(_))
        ));
    }

    #[tokio::test]
    async fn test_a_restore_the_archive_misses_is_recorded_by_the_first_sync() {
        use std::collections::BTreeMap;
        use std::sync::atomic::{AtomicBool, Ordering};

        use super::super::recover::AbandonedHistory;
        use crate::backup::s3::fake_s3;

        // An S3 archive that can be taken down.
        let objects = Arc::new(Mutex::new(BTreeMap::new()));
        let down = Arc::new(AtomicBool::new(false));
        let fake = {
            let store = fake_s3::store(Arc::clone(&objects));
            let down = Arc::clone(&down);
            fake_s3::FakeS3::start(Arc::new(move |request: &fake_s3::Recorded| {
                if down.load(Ordering::SeqCst) {
                    fake_s3::error(403, "AccessDenied")
                } else {
                    store(request)
                }
            }))
            .await
        };
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let (u1, u2) = (Uuid::new_v4(), Uuid::new_v4());
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            local_path: Some(wal_dir.clone()),
            ..WalArchiveConfig::default()
        };
        let settings = PitrSettings {
            wal: wal_cfg.clone(),
            local_dir: wal_dir.clone(),
            location: PitrLocation::S3(fake.config("bucket")),
            bases: BaseLocation::Local(backup_dir.clone()),
            encryption: BackupEncryptionConfig::default(),
        };
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg.clone(), u1, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings.clone(), archiver.clone());
        let key = "backup-2024-01-01T00:00:00Z.json";
        fs::write(backup_dir.join(key), b"{}").unwrap();
        archive
            .register_base_backup_at(
                Duration::from_secs(1000),
                &settings.bases,
                key,
                "t",
                &report(1000, u1),
            )
            .await
            .unwrap();
        append_create(&archiver, u1, 1100, b"before the refresh");
        // A replication refresh after the backup: the archive continues under U2.
        archiver
            .lock()
            .unwrap()
            .change_server_uuid(u2, Some(Duration::from_secs(1200)));
        append_create(&archiver, u2, 1250, b"after the refresh");
        archive.sync(Duration::from_secs(1300), true).await.unwrap();
        drop(archive);
        drop(archiver);

        // The backup of U1 is restored while the archive is unreachable.
        down.store(true, Ordering::SeqCst);
        let restored = RestoredDatabase {
            after_ts: Duration::from_secs(1000),
            server_uuid: u1,
            reason: "restore",
            now: Duration::from_secs(1400),
        };
        assert!(matches!(
            record_timeline_break(&settings, &restored).await,
            Ok(AbandonedHistory::Deferred(_))
        ));
        down.store(false, Ordering::SeqCst);

        // The server starts on the restored database, under U1, and archives again.
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg, u1, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings.clone(), archiver.clone());
        append_create(&archiver, u1, 1500, b"new history");
        archive.sync(Duration::from_secs(1600), true).await.unwrap();
        assert!(archiver.lock().unwrap().pending_events().is_empty());

        let store = PitrStore::open(&settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.server_uuid, u1);
        assert_eq!(manifest.timeline_breaks.len(), 1);
        assert_eq!(
            manifest.timeline_breaks[0].after_ts,
            Duration::from_secs(1000)
        );
        assert!(manifest.timeline_breaks[0].until_ts >= Duration::from_secs(1400));
        // The new history replays on the restored base, never the abandoned one.
        let plan = plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.base.key, key);
        assert_eq!(plan.target.ts, Duration::from_secs(1500));

        // Synchronising again records nothing twice.
        archive.sync(Duration::from_secs(1700), true).await.unwrap();
        let again = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(again.timeline_breaks, manifest.timeline_breaks);
        assert_eq!(again.server_uuid_changes, manifest.server_uuid_changes);
    }

    #[tokio::test]
    async fn test_a_restore_before_anything_was_archived_discards_the_old_events() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let (x, a, b) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            local_path: Some(wal_dir.clone()),
            ..WalArchiveConfig::default()
        };
        let settings = PitrSettings {
            wal: wal_cfg.clone(),
            local_dir: wal_dir.clone(),
            location: PitrLocation::Local(wal_dir.clone()),
            bases: BaseLocation::Local(backup_dir.clone()),
            encryption: BackupEncryptionConfig::default(),
        };

        // A server that never reached its archive: refreshed from X to A, and stopped with
        // records in memory.
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg.clone(), x, wal_dir.clone(), None).unwrap(),
        ));
        archiver
            .lock()
            .unwrap()
            .change_server_uuid(a, Some(Duration::from_secs(1000)));
        append_create(&archiver, a, 1100, b"never archived");
        drop(archiver);

        // A backup of B is restored.
        let restored = RestoredDatabase {
            after_ts: Duration::from_secs(900),
            server_uuid: b,
            reason: "restore",
            now: Duration::from_secs(1200),
        };
        assert!(matches!(
            record_timeline_break(&settings, &restored).await,
            Ok(super::super::recover::AbandonedHistory::Recorded)
        ));

        // The server started on it reports nothing of the old server, and archives.
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg, b, wal_dir.clone(), None).unwrap(),
        ));
        assert!(archiver.lock().unwrap().pending_events().is_empty());
        let archive = PitrArchive::new(settings.clone(), archiver.clone());
        append_create(&archiver, b, 1300, b"new history");
        archive.sync(Duration::from_secs(1400), true).await.unwrap();
        let store = PitrStore::open(&settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.server_uuid, b);
        assert!(manifest.gaps.is_empty(), "{:?}", manifest.gaps);
    }

    /// A server whose archive was never reachable keeps its closed segments in its WAL
    /// directory. A restore then meets an archive without a manifest, recorded at once or
    /// handed to the server, and the archive must start with it: those segments are
    /// archived as abandoned history, never replayed onto the restored backup, and a
    /// restored backup of another server still archives them.
    async fn restore_into_an_archive_without_a_manifest(deferred: bool, other_server: bool) {
        use std::collections::BTreeMap;
        use std::sync::atomic::{AtomicBool, Ordering};

        use super::super::recover::AbandonedHistory;
        use crate::backup::s3::fake_s3;

        let objects = Arc::new(Mutex::new(BTreeMap::new()));
        let down = Arc::new(AtomicBool::new(true));
        let fake = {
            let store = fake_s3::store(Arc::clone(&objects));
            let down = Arc::clone(&down);
            fake_s3::FakeS3::start(Arc::new(move |request: &fake_s3::Recorded| {
                if down.load(Ordering::SeqCst) {
                    fake_s3::error(403, "AccessDenied")
                } else {
                    store(request)
                }
            }))
            .await
        };
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let x = Uuid::new_v4();
        let restored_uuid = if other_server { Uuid::new_v4() } else { x };
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            local_path: Some(wal_dir.clone()),
            ..WalArchiveConfig::default()
        };
        let settings = PitrSettings {
            wal: wal_cfg.clone(),
            local_dir: wal_dir.clone(),
            location: PitrLocation::S3(fake.config("bucket")),
            bases: BaseLocation::Local(backup_dir.clone()),
            encryption: BackupEncryptionConfig::default(),
        };

        // The server never reaches its archive: its segments stay in the WAL directory.
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg.clone(), x, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings.clone(), archiver.clone());
        append_create(&archiver, x, 1100, b"abandoned");
        append_create(&archiver, x, 1200, b"abandoned too");
        assert!(archive.sync(Duration::from_secs(1300), true).await.is_err());
        assert_eq!(list_segments(&wal_dir).unwrap().len(), 1);
        drop(archive);
        drop(archiver);

        // A backup with the watermark 1000 is restored.
        down.store(deferred, Ordering::SeqCst);
        let restored = RestoredDatabase {
            after_ts: Duration::from_secs(1000),
            server_uuid: restored_uuid,
            reason: "restore",
            now: Duration::from_secs(1400),
        };
        let history = record_timeline_break(&settings, &restored).await.unwrap();
        assert_eq!(
            matches!(history, AbandonedHistory::Deferred(_)),
            deferred,
            "{history:?}"
        );
        down.store(false, Ordering::SeqCst);

        // The server starts on it, archives the old segments, and the restored backup is
        // indexed before anything new is committed.
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg, restored_uuid, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings.clone(), archiver.clone());
        archive.sync(Duration::from_secs(1500), true).await.unwrap();
        let key = "backup-2024-01-01T00:00:00Z.json";
        fs::write(backup_dir.join(key), b"{}").unwrap();
        archive
            .register_base_backup_at(
                Duration::from_secs(1500),
                &settings.bases,
                key,
                "t",
                &report(1000, restored_uuid),
            )
            .await
            .unwrap();

        assert!(list_segments(&wal_dir).unwrap().is_empty());
        let store = PitrStore::open(&settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.server_uuid, restored_uuid);
        assert!(manifest.knows_server(x));
        assert_eq!(manifest.segments.len(), 1);
        assert_eq!(manifest.timeline_breaks.len(), 1);
        assert!(manifest.is_abandoned(Duration::from_secs(1200)));
        // Recovery never replays the abandoned history onto the restored backup.
        let plan = plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.base.key, key);
        assert_eq!(plan.target.ts, Duration::from_secs(1000));
    }

    #[tokio::test]
    async fn test_a_restore_into_an_archive_without_a_manifest_abandons_the_local_history() {
        restore_into_an_archive_without_a_manifest(false, false).await;
        restore_into_an_archive_without_a_manifest(true, false).await;
        restore_into_an_archive_without_a_manifest(false, true).await;
        restore_into_an_archive_without_a_manifest(true, true).await;
    }

    #[tokio::test]
    async fn test_a_restore_is_recorded_despite_an_unreadable_local_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let (u1, u2) = (Uuid::new_v4(), Uuid::new_v4());
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            local_path: Some(wal_dir.clone()),
            ..WalArchiveConfig::default()
        };
        let settings = PitrSettings {
            wal: wal_cfg.clone(),
            local_dir: wal_dir.clone(),
            location: PitrLocation::Local(wal_dir.clone()),
            bases: BaseLocation::Local(backup_dir.clone()),
            encryption: BackupEncryptionConfig::default(),
        };
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg.clone(), u2, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings.clone(), archiver.clone());
        archive
            .sync(Duration::from_secs(1000), false)
            .await
            .unwrap();

        // The server of U2 stops with a closed segment whose sidecar is damaged.
        append_create(&archiver, u2, 1100, b"x");
        let segment = archiver
            .lock()
            .unwrap()
            .flush_current_segment()
            .unwrap()
            .unwrap();
        fs::write(segment_meta_path(&wal_dir, &segment.segment_id), b"{").unwrap();
        drop(archive);
        drop(archiver);

        // A backup of U1 is restored: the archive records it and continues under U1.
        let restored = RestoredDatabase {
            after_ts: Duration::from_secs(900),
            server_uuid: u1,
            reason: "restore",
            now: Duration::from_secs(1200),
        };
        assert!(matches!(
            record_timeline_break(&settings, &restored).await,
            Ok(super::super::recover::AbandonedHistory::Recorded)
        ));
        let store = PitrStore::open(&settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.server_uuid, u1);
        assert!(manifest.is_abandoned(Duration::from_secs(1100)));

        // The server started on it archives, its sidecar repaired or the segment set aside.
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg, u1, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings, archiver.clone());
        append_create(&archiver, u1, 1300, b"new history");
        archive.sync(Duration::from_secs(1400), true).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.server_uuid, u1);
        assert!(manifest
            .segments
            .iter()
            .any(|segment| segment.start_ts == Duration::from_secs(1300)));
    }

    #[tokio::test]
    async fn test_restore_takes_over_what_the_stopped_server_left_behind() {
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
        let settings = PitrSettings {
            wal: wal_cfg.clone(),
            local_dir: wal_dir.clone(),
            location: PitrLocation::Local(wal_dir.clone()),
            bases: BaseLocation::Local(backup_dir.clone()),
            encryption: BackupEncryptionConfig::default(),
        };
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg.clone(), server, wal_dir.clone(), None).unwrap(),
        ));
        let archive = PitrArchive::new(settings.clone(), archiver.clone());
        let key = "backup-2024-01-01T00:00:00Z.json";
        fs::write(backup_dir.join(key), b"{}").unwrap();
        archive
            .register_base_backup_at(
                Duration::from_secs(1000),
                &settings.bases,
                key,
                "t",
                &report(1000, server),
            )
            .await
            .unwrap();
        append_create(&archiver, server, 1100, b"archived");
        archive.sync(Duration::from_secs(1150), true).await.unwrap();

        // The server notices a failed transaction at 1200, keeps records of 1300 in memory,
        // and dies before any synchronisation.
        archiver
            .lock()
            .unwrap()
            .note_failure(Some(Duration::from_secs(1200)));
        append_create(&archiver, server, 1300, b"lost");
        drop(archive);
        drop(archiver);

        // A recovery to 1100 abandons everything after it. What the dead server left
        // behind is recorded as part of that history, and is gone from the directory.
        let restored = RestoredDatabase {
            after_ts: Duration::from_secs(1100),
            server_uuid: server,
            reason: "recover",
            now: Duration::from_secs(1400),
        };
        record_timeline_break(&settings, &restored).await.unwrap();
        let store = PitrStore::open(&settings.location).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        let gaps: Vec<(u64, u64)> = manifest
            .gaps
            .iter()
            .map(|gap| (gap.from_ts.as_secs(), gap.until_ts.as_secs()))
            .collect();
        assert_eq!(gaps, vec![(1200, 1200), (1300, 1400)]);
        assert!(manifest.timeline_breaks[0].until_ts >= Duration::from_secs(1400));

        // The server started on the recovered database reports nothing of it.
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::open(wal_cfg, server, wal_dir.clone(), None).unwrap(),
        ));
        assert!(archiver.lock().unwrap().pending_events().is_empty());

        // Its new history is recoverable from the old base: those gaps lie in the
        // abandoned history, which is never replayed.
        let archive = PitrArchive::new(settings, archiver.clone());
        append_create(&archiver, server, 1500, b"new history");
        archive.sync(Duration::from_secs(1600), true).await.unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        let plan = plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.base.key, key);
        assert_eq!(plan.target.ts, Duration::from_secs(1500));
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
            WalArchiver::open(wal_cfg.clone(), server, wal_dir.clone(), None).unwrap(),
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
            .register_base_backup_at(
                Duration::from_secs(1000),
                &bases,
                key,
                "t",
                &report(1000, server),
            )
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
        assert!(archiver.lock().unwrap().pending_events().is_empty());
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
            .register_base_backup_at(
                Duration::from_secs(1250),
                &bases,
                key2,
                "t",
                &report(1250, server),
            )
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
