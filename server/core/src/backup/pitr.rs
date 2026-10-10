//! Point-in-time recovery (PITR) on top of the backend's WAL archive.
//!
//! The backend (`kubidmd_lib::repl::wal`) writes closed WAL segments to a local directory.
//! This module owns everything above that:
//!
//! - the periodic task that closes stale segments, uploads closed segments to S3 (or keeps
//!   them in the local directory when no S3 location is configured), applies retention and
//!   keeps the `pitr-manifest.json` index accurate;
//! - registering every successful online base backup in the manifest together with its CID
//!   watermark, so that recovery can pair a base with the segments that follow it;
//! - recording the history a restore or a recovery abandons, so that a later recovery never
//!   replays it;
//! - the `kubidmd database pitr-list` and `kubidmd database recover` commands.
//!
//! Recovery restores the newest base backup whose watermark is at or before the target,
//! then replays every archived record with a CID above the watermark and at or below the
//! target, in CID order, in the same database transaction as the restore.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kubidm_proto::backup::{
    PitrBaseBackup, PitrManifest, PitrTimelineBreak, PitrWalGap, S3Config, WalArchiveConfig,
    WalSegment, PITR_MANIFEST_KEY,
};
use kubidm_proto::internal::OperationError;
use kubidmd_lib::be::{BackupStructuralReport, SharedWalArchiver, WalApplyReport};
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::{
    format_ts_rfc3339, list_segments, parse_recovery_target_cid, parse_recovery_target_time,
    parse_segment, remove_segment, select_records, WalEntryRecord, WalError, WalGap,
};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tokio::time::{interval, MissedTickBehavior};
use uuid::Uuid;

use crate::backup::{is_backup_artifact_name, S3BackupError, S3ClientWrapper};
use crate::config::Configuration;
use crate::CoreAction;

#[derive(Debug)]
pub enum PitrError {
    Config(String),
    Wal(WalError),
    S3(S3BackupError),
    Io(std::io::Error),
    Manifest(String),
    Target(String),
    NotRecoverable(String),
    Operation(OperationError),
}

impl fmt::Display for PitrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PitrError::Config(msg) => write!(f, "PITR configuration error: {msg}"),
            PitrError::Wal(err) => write!(f, "{err}"),
            PitrError::S3(err) => write!(f, "{err}"),
            PitrError::Io(err) => write!(f, "PITR IO error: {err}"),
            PitrError::Manifest(msg) => write!(f, "PITR manifest error: {msg}"),
            PitrError::Target(msg) => write!(f, "invalid recovery target: {msg}"),
            PitrError::NotRecoverable(msg) => write!(f, "not recoverable: {msg}"),
            PitrError::Operation(err) => write!(f, "PITR database error: {err:?}"),
        }
    }
}

impl std::error::Error for PitrError {}

impl From<WalError> for PitrError {
    fn from(err: WalError) -> Self {
        PitrError::Wal(err)
    }
}

impl From<S3BackupError> for PitrError {
    fn from(err: S3BackupError) -> Self {
        PitrError::S3(err)
    }
}

impl From<std::io::Error> for PitrError {
    fn from(err: std::io::Error) -> Self {
        PitrError::Io(err)
    }
}

impl From<OperationError> for PitrError {
    fn from(err: OperationError) -> Self {
        PitrError::Operation(err)
    }
}

/// Where closed segments and the manifest are kept.
// Built once from the configuration; boxing the S3 variant would only add noise.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PitrLocation {
    /// No S3 location is configured: segments stay in the local WAL directory and the
    /// manifest is written next to them.
    Local(PathBuf),
    /// Segments are uploaded under `<path_prefix>/wal/` and the manifest to
    /// `<path_prefix>/pitr-manifest.json`.
    S3(S3Config),
}

impl fmt::Display for PitrLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PitrLocation::Local(dir) => write!(f, "{}", dir.display()),
            PitrLocation::S3(config) => fmt_s3_location(f, config),
        }
    }
}

/// Where the online backup writes the base backups recovery starts from.
// Built once from the configuration; boxing the S3 variant would only add noise.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseLocation {
    /// The local online backup directory (`online_backup.path`).
    Local(PathBuf),
    /// The online backup S3 location (`[online_backup.s3]`).
    S3(S3Config),
}

impl fmt::Display for BaseLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseLocation::Local(dir) => write!(f, "{}", dir.display()),
            BaseLocation::S3(config) => fmt_s3_location(f, config),
        }
    }
}

fn fmt_s3_location(f: &mut fmt::Formatter<'_>, config: &S3Config) -> fmt::Result {
    match config
        .path_prefix
        .as_deref()
        .map(|prefix| prefix.trim_matches('/'))
        .filter(|prefix| !prefix.is_empty())
    {
        Some(prefix) => write!(f, "s3://{}/{prefix}", config.bucket),
        None => write!(f, "s3://{}", config.bucket),
    }
}

/// The settings PITR derives from the server configuration.
#[derive(Debug, Clone)]
pub struct PitrSettings {
    pub wal: WalArchiveConfig,
    /// Where the backend writes closed segments.
    pub local_dir: PathBuf,
    /// Where segments and the manifest are archived.
    pub location: PitrLocation,
    /// Where the base backups are. S3 when `[online_backup.s3]` is configured, since an
    /// off-host copy is what disaster recovery needs; the local directory otherwise.
    pub bases: BaseLocation,
}

impl PitrSettings {
    /// The PITR settings of `config`, or None when WAL archiving is not enabled.
    pub fn from_config(config: &Configuration) -> Result<Option<Self>, PitrError> {
        let Some(online_backup) = config.online_backup.as_ref() else {
            return Ok(None);
        };
        let Some(wal) = online_backup.wal_archive.as_ref().filter(|w| w.enabled) else {
            return Ok(None);
        };

        let local_dir = match &wal.local_path {
            Some(path) => path.clone(),
            None => {
                let db_path = config.db_path.as_ref().ok_or_else(|| {
                    PitrError::Config(
                        "wal_archive.local_path must be set when db_path is unset".to_string(),
                    )
                })?;
                db_path
                    .parent()
                    .map(|parent| parent.join("wal"))
                    .ok_or_else(|| {
                        PitrError::Config(
                            "db_path has no parent directory; set wal_archive.local_path"
                                .to_string(),
                        )
                    })?
            }
        };

        let location = match wal.s3.clone().or_else(|| online_backup.s3.clone()) {
            Some(s3) => PitrLocation::S3(s3),
            None => PitrLocation::Local(local_dir.clone()),
        };

        let bases = match (&online_backup.s3, &online_backup.path) {
            (Some(s3), _) => BaseLocation::S3(s3.clone()),
            (None, Some(path)) => BaseLocation::Local(path.clone()),
            (None, None) => return Err(PitrError::Config(
                "WAL archiving needs base backups: set online_backup.path or [online_backup.s3]"
                    .to_string(),
            )),
        };

        Ok(Some(PitrSettings {
            wal: wal.clone(),
            local_dir,
            location,
            bases,
        }))
    }

    /// The WAL configuration the backend archives with: the configured one with the
    /// segment directory resolved, so that the backend and this module agree on it.
    pub fn backend_wal_config(&self) -> WalArchiveConfig {
        WalArchiveConfig {
            local_path: Some(self.local_dir.clone()),
            ..self.wal.clone()
        }
    }
}

/// A base backup fetched for recovery. The S3 variant is removed when dropped.
enum FetchedBase {
    Local(PathBuf),
    S3(crate::FetchedS3Backup),
}

impl FetchedBase {
    fn path(&self) -> &Path {
        match self {
            FetchedBase::Local(path) => path,
            FetchedBase::S3(fetched) => &fetched.path,
        }
    }
}

impl BaseLocation {
    /// The keys of the base backups that currently exist at this location.
    async fn list_keys(&self) -> Result<Vec<String>, PitrError> {
        let mut keys = match self {
            BaseLocation::Local(dir) => {
                if !dir.exists() {
                    return Ok(Vec::new());
                }
                let mut keys = Vec::new();
                for entry in fs::read_dir(dir)? {
                    let entry = entry?;
                    if let Some(name) = entry.file_name().to_str() {
                        if is_backup_artifact_name(name) {
                            keys.push(name.to_string());
                        }
                    }
                }
                keys
            }
            BaseLocation::S3(config) => S3ClientWrapper::new(config.clone())
                .await?
                .list_backups()
                .await?
                .into_iter()
                .filter(|key| is_backup_artifact_name(key))
                .collect(),
        };
        keys.sort();
        Ok(keys)
    }

    async fn fetch(&self, base: &PitrBaseBackup) -> Result<FetchedBase, PitrError> {
        match self {
            BaseLocation::Local(dir) => {
                let path = dir.join(&base.key);
                if !path.is_file() {
                    return Err(PitrError::NotRecoverable(format!(
                        "base backup {} is missing",
                        path.display()
                    )));
                }
                Ok(FetchedBase::Local(path))
            }
            BaseLocation::S3(config) => {
                let fetched = crate::fetch_s3_backup(config.clone(), &base.key).await?;
                Ok(FetchedBase::S3(fetched))
            }
        }
    }
}

/// Reads and writes the archive at a [`PitrLocation`].
enum PitrStore {
    Local { dir: PathBuf },
    S3 { client: Box<S3ClientWrapper> },
}

impl PitrStore {
    async fn open(location: &PitrLocation) -> Result<Self, PitrError> {
        match location {
            PitrLocation::Local(dir) => Ok(PitrStore::Local { dir: dir.clone() }),
            PitrLocation::S3(config) => Ok(PitrStore::S3 {
                client: Box::new(S3ClientWrapper::new(config.clone()).await?),
            }),
        }
    }

    fn is_s3(&self) -> bool {
        matches!(self, PitrStore::S3 { .. })
    }

    async fn load_manifest(&self) -> Result<Option<PitrManifest>, PitrError> {
        let data = match self {
            PitrStore::Local { dir } => {
                let path = dir.join(PITR_MANIFEST_KEY);
                if !path.exists() {
                    return Ok(None);
                }
                fs::read(&path)?
            }
            PitrStore::S3 { client } => {
                match client.download_backup_if_exists(PITR_MANIFEST_KEY).await? {
                    Some((data, _)) => data,
                    None => return Ok(None),
                }
            }
        };
        let manifest: PitrManifest = serde_json::from_slice(&data).map_err(|err| {
            PitrError::Manifest(format!("{PITR_MANIFEST_KEY} is not readable: {err}"))
        })?;
        Ok(Some(manifest))
    }

    async fn save_manifest(&self, manifest: &mut PitrManifest) -> Result<(), PitrError> {
        let now = format_ts_rfc3339(duration_from_epoch_now());
        manifest.updated_at = now.clone();
        let data = serde_json::to_vec_pretty(manifest)
            .map_err(|err| PitrError::Manifest(format!("unable to serialise: {err}")))?;
        match self {
            PitrStore::Local { dir } => {
                fs::create_dir_all(dir)?;
                let path = dir.join(PITR_MANIFEST_KEY);
                let tmp = dir.join(format!("{PITR_MANIFEST_KEY}.tmp"));
                fs::write(&tmp, &data)?;
                fs::rename(&tmp, &path)?;
            }
            PitrStore::S3 { client } => {
                client
                    .upload_backup(
                        &data,
                        PITR_MANIFEST_KEY,
                        &now,
                        kubidm_proto::backup::BackupCompression::NoCompression,
                        None,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Make the closed segment in `local_dir` available at the location. A no-op for the
    /// local location, where the segment already is where it belongs.
    async fn put_segment(&self, local_dir: &Path, segment: &WalSegment) -> Result<(), PitrError> {
        let PitrStore::S3 { client } = self else {
            return Ok(());
        };
        let data = fs::read(local_dir.join(&segment.segment_id))?;
        verify_segment_checksum(segment, &data)?;
        client
            .upload_backup(
                &data,
                &segment.object_key(),
                &segment.created_at,
                segment.compression,
                None,
            )
            .await?;
        Ok(())
    }

    async fn delete_segment(
        &self,
        local_dir: &Path,
        segment: &WalSegment,
    ) -> Result<(), PitrError> {
        match self {
            PitrStore::Local { .. } => remove_segment(local_dir, &segment.segment_id)?,
            PitrStore::S3 { client } => client.delete_backup(&segment.object_key()).await?,
        }
        Ok(())
    }

    /// Read a segment from the archive, or from `local_dir` when `local` says it has not
    /// been archived yet.
    async fn fetch_segment(
        &self,
        local_dir: &Path,
        segment: &WalSegment,
        local: bool,
    ) -> Result<Vec<u8>, PitrError> {
        let data = match self {
            PitrStore::S3 { client } if !local => {
                client.download_backup(&segment.object_key()).await?.0
            }
            _ => fs::read(local_dir.join(&segment.segment_id))?,
        };
        verify_segment_checksum(segment, &data)?;
        Ok(data)
    }
}

fn verify_segment_checksum(segment: &WalSegment, data: &[u8]) -> Result<(), PitrError> {
    let actual = hex::encode(Sha256::digest(data));
    if actual != segment.checksum_sha256 {
        return Err(PitrError::NotRecoverable(format!(
            "segment {} is corrupted: expected sha256 {}, got {actual}",
            segment.segment_id, segment.checksum_sha256
        )));
    }
    Ok(())
}

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

/// The outcome of one archive synchronisation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PitrSyncReport {
    /// Whether the open segment was closed by this run.
    pub flushed: bool,
    /// Segments added to the manifest (uploaded, for the S3 location).
    pub archived: usize,
    /// Segments removed by retention.
    pub deleted: usize,
}

/// The running server's archive: the backend's archiver plus the location segments go to.
pub struct PitrArchive {
    settings: PitrSettings,
    archiver: SharedWalArchiver,
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

    async fn sync_locked(
        &self,
        now: Duration,
        gaps: &[WalGap],
        gaps_recorded: &mut bool,
        report: &mut PitrSyncReport,
    ) -> Result<(), PitrError> {
        let local_dir = &self.settings.local_dir;
        let local_segments = list_segments(local_dir)?;
        let store = PitrStore::open(&self.settings.location).await?;
        let server_uuid = self.server_uuid();
        let (mut manifest, existed) =
            load_or_new_manifest(&store, &self.settings.location, server_uuid).await?;
        let mut changed = !existed;

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
            changed = true;
        }

        // Segments the manifest does not know yet. For the local location this is only an
        // index update; for S3 it is the upload, and every local segment is uploaded since
        // a segment stays local only until its upload and the manifest update succeeded. A
        // failure leaves the segment in the local directory for the next run.
        let mut archived: Vec<WalSegment> = Vec::new();
        let mut upload_error = None;
        for segment in local_segments {
            if segment.server_uuid != server_uuid {
                warn!(
                    segment = %segment.segment_id,
                    "WAL segment of another server in {}, not archived",
                    local_dir.display()
                );
                continue;
            }
            let known = manifest
                .segments
                .iter()
                .any(|known| known.segment_id == segment.segment_id);
            if known && !store.is_s3() {
                continue;
            }
            if let Err(err) = store.put_segment(local_dir, &segment).await {
                error!(%err, segment = %segment.segment_id, "Unable to archive WAL segment");
                upload_error = Some(err);
                break;
            }
            manifest.add_segment(segment.clone());
            archived.push(segment);
        }

        if !archived.is_empty() || changed {
            store.save_manifest(&mut manifest).await?;
            *gaps_recorded = true;
            changed = false;
            report.archived = archived.len();
            if store.is_s3() {
                for segment in &archived {
                    remove_segment(local_dir, &segment.segment_id)?;
                }
            }
            if !archived.is_empty() {
                info!(
                    archived = archived.len(),
                    location = %self.settings.location,
                    "WAL segments archived"
                );
            }
        }

        if let Some(err) = upload_error {
            return Err(err);
        }

        // Retention. Base backups that backup retention removed drop out of the index, and
        // segments that are both older than the retention period and not needed by the
        // oldest remaining base backup are deleted.
        let existing_bases = self.settings.bases.list_keys().await?;
        let bases_before = manifest.base_backups.len();
        manifest.retain_base_backups(&existing_bases);
        changed |= manifest.base_backups.len() != bases_before;

        for segment_id in select_segments_to_delete(&manifest, now, self.settings.wal.retention()) {
            let Some(segment) = manifest
                .segments
                .iter()
                .find(|s| s.segment_id == segment_id)
                .cloned()
            else {
                continue;
            };
            match store.delete_segment(local_dir, &segment).await {
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

        let markers_before = (manifest.timeline_breaks.len(), manifest.gaps.len());
        manifest.prune_timeline_breaks();
        manifest.prune_gaps();
        changed |= (manifest.timeline_breaks.len(), manifest.gaps.len()) != markers_before;

        if changed {
            store.save_manifest(&mut manifest).await?;
        }
        *gaps_recorded = true;

        Ok(())
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

// === recovery ===

/// What the operator asked `recover` to reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryTargetSpec {
    /// An RFC3339 timestamp.
    Time(String),
    /// A CID as the server prints it.
    Cid(String),
    Latest,
}

impl fmt::Display for RecoveryTargetSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryTargetSpec::Time(t) => write!(f, "time {t}"),
            RecoveryTargetSpec::Cid(c) => write!(f, "transaction {c}"),
            RecoveryTargetSpec::Latest => write!(f, "latest"),
        }
    }
}

/// The CID timestamp a target resolves to against a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub ts: Duration,
    /// Set when the target lies after the last archived record, so that the result is the
    /// latest recoverable state rather than the exact point asked for.
    pub clamped_to_latest: bool,
}

pub fn resolve_target(
    manifest: &PitrManifest,
    target: &RecoveryTargetSpec,
) -> Result<ResolvedTarget, PitrError> {
    let (earliest, latest) = manifest.recoverable_window().ok_or_else(|| {
        PitrError::NotRecoverable(
            "the archive holds no base backup; recovery becomes possible after the first \
             online backup taken with WAL archiving enabled"
                .to_string(),
        )
    })?;

    let ts = match target {
        RecoveryTargetSpec::Time(timestamp) => parse_recovery_target_time(timestamp)
            .map_err(|err| PitrError::Target(err.to_string()))?,
        RecoveryTargetSpec::Cid(cid) => {
            let cid =
                parse_recovery_target_cid(cid).map_err(|err| PitrError::Target(err.to_string()))?;
            if cid.s_uuid != manifest.server_uuid {
                return Err(PitrError::Target(format!(
                    "CID belongs to server {}, the archive belongs to server {}",
                    cid.s_uuid, manifest.server_uuid
                )));
            }
            cid.ts
        }
        RecoveryTargetSpec::Latest => latest,
    };

    if ts < earliest {
        return Err(PitrError::NotRecoverable(format!(
            "target {} is before the oldest base backup ({})",
            format_ts_rfc3339(ts),
            format_ts_rfc3339(earliest)
        )));
    }

    Ok(ResolvedTarget {
        ts,
        clamped_to_latest: ts > latest,
    })
}

/// The base backup and segments a recovery to `target` uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub target: ResolvedTarget,
    pub base: PitrBaseBackup,
    pub segments: Vec<WalSegment>,
}

pub fn plan_recovery(
    manifest: &PitrManifest,
    target: &RecoveryTargetSpec,
) -> Result<RecoveryPlan, PitrError> {
    let resolved = resolve_target(manifest, target)?;
    let base = manifest
        .base_backup_for(resolved.ts)
        .cloned()
        .ok_or_else(|| {
            PitrError::NotRecoverable(format!(
                "no base backup at or before {}",
                format_ts_rfc3339(resolved.ts)
            ))
        })?;
    if let Some(gap) = manifest.gap_blocking(base.watermark_ts, resolved.ts) {
        let latest = manifest
            .latest_recoverable_ts()
            .map(format_ts_rfc3339)
            .unwrap_or_else(|| "none".to_string());
        return Err(PitrError::NotRecoverable(format!(
            "the archive is missing the transactions from {} to {} ({}); replaying base backup \
             {} up to {} would skip them. Choose a target before the gap (the latest \
             recoverable point is {latest}), or one after a base backup taken after the gap",
            format_ts_rfc3339(gap.from_ts),
            format_ts_rfc3339(gap.until_ts),
            gap.reason,
            base.key,
            format_ts_rfc3339(resolved.ts),
        )));
    }
    let segments = manifest
        .segments_between(base.watermark_ts, resolved.ts)
        .into_iter()
        .cloned()
        .collect();
    Ok(RecoveryPlan {
        target: resolved,
        base,
        segments,
    })
}

/// The records of `file_entries` a recovery to `plan` replays: after the base watermark,
/// at or before the target, and not part of history a restore or recovery abandoned.
pub fn records_to_replay<'a>(
    manifest: &'a PitrManifest,
    plan: &'a RecoveryPlan,
    file_entries: &'a [WalEntryRecord],
) -> impl Iterator<Item = &'a WalEntryRecord> + 'a {
    select_records(file_entries, plan.base.watermark_ts, plan.target.ts)
        .filter(|record| !manifest.is_abandoned(record.ts()))
}

/// The outcome of `recover`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOutcome {
    pub plan: RecoveryPlan,
    pub records: usize,
    /// The CID timestamp the database represents after recovery: the last record applied,
    /// or the base watermark when no record followed it.
    pub recovered_ts: Duration,
    pub dry_run: bool,
    pub apply: Option<WalApplyReport>,
}

/// The archive as recovery sees it: the manifest, plus the closed segments of the same
/// server still in the local WAL directory that were never archived (the server stopped
/// before its next synchronisation, or their upload failed).
struct OpenedArchive {
    settings: PitrSettings,
    store: PitrStore,
    manifest: PitrManifest,
    /// Ids of the segments that are only in the local WAL directory.
    local_only: BTreeSet<String>,
}

/// Open the archive described by `config` and load its manifest.
async fn open_archive(config: &Configuration) -> Result<OpenedArchive, PitrError> {
    let settings = PitrSettings::from_config(config)?.ok_or_else(|| {
        PitrError::Config(
            "online_backup.wal_archive is not enabled; it tells the command where the archive is"
                .to_string(),
        )
    })?;
    let store = PitrStore::open(&settings.location).await?;
    let mut manifest = store.load_manifest().await?.ok_or_else(|| {
        PitrError::NotRecoverable(format!(
            "no {PITR_MANIFEST_KEY} at {}; nothing has been archived",
            settings.location
        ))
    })?;

    let mut local_only = BTreeSet::new();
    for segment in list_segments(&settings.local_dir)? {
        if segment.server_uuid != manifest.server_uuid
            || manifest
                .segments
                .iter()
                .any(|known| known.segment_id == segment.segment_id)
        {
            continue;
        }
        local_only.insert(segment.segment_id.clone());
        manifest.add_segment(segment);
    }

    Ok(OpenedArchive {
        settings,
        store,
        manifest,
        local_only,
    })
}

/// `kubidmd database pitr-list`: print the base backups, segments and the recoverable
/// window. Returns false when nothing is recoverable or the archive could not be read.
pub async fn pitr_list_server_core(config: &Configuration) -> bool {
    let OpenedArchive {
        settings,
        manifest,
        local_only,
        ..
    } = match open_archive(config).await {
        Ok(opened) => opened,
        Err(err) => {
            error!(%err, "Unable to read the PITR archive");
            println!("PITR archive: unavailable ({err})");
            return false;
        }
    };

    println!("PITR archive at {}:", settings.location);
    println!("  Server:       {}", manifest.server_uuid);
    println!("  Base backups: {}", settings.bases);
    if !manifest.updated_at.is_empty() {
        println!("  Updated:      {}", manifest.updated_at);
    }

    println!();
    if manifest.base_backups.is_empty() {
        println!("Base backups: (none)");
    } else {
        let key_width = manifest
            .base_backups
            .iter()
            .map(|b| b.key.len())
            .max()
            .unwrap_or(0)
            .max("KEY".len());
        println!("Base backups:");
        println!(
            "  {:<key_width$}  {:<35}  {:<35}  VERSION",
            "KEY", "TAKEN", "WATERMARK"
        );
        for base in &manifest.base_backups {
            println!(
                "  {:<key_width$}  {:<35}  {:<35}  {}",
                base.key,
                base.timestamp,
                format_ts_rfc3339(base.watermark_ts),
                base.server_version
            );
        }
    }

    println!();
    if manifest.segments.is_empty() {
        println!("WAL segments: (none)");
    } else {
        let key_width = manifest
            .segments
            .iter()
            .map(|s| s.segment_id.len())
            .max()
            .unwrap_or(0)
            .max("SEGMENT".len());
        println!("WAL segments:");
        println!(
            "  {:<key_width$}  {:<35}  {:<35}  {:>8}  {:>12}",
            "SEGMENT", "FROM", "TO", "RECORDS", "SIZE_BYTES"
        );
        for segment in &manifest.segments {
            println!(
                "  {:<key_width$}  {:<35}  {:<35}  {:>8}  {:>12}{}",
                segment.segment_id,
                format_ts_rfc3339(segment.start_ts),
                format_ts_rfc3339(segment.end_ts),
                segment.entry_count,
                segment.size_bytes,
                if local_only.contains(&segment.segment_id) {
                    "  (local, not archived yet)"
                } else {
                    ""
                }
            );
        }
    }

    if !manifest.gaps.is_empty() {
        println!();
        println!("Gaps (recovery can not replay across them):");
        for gap in &manifest.gaps {
            println!(
                "  {} to {} ({})",
                format_ts_rfc3339(gap.from_ts),
                format_ts_rfc3339(gap.until_ts),
                gap.reason
            );
        }
    }

    if !manifest.timeline_breaks.is_empty() {
        println!();
        println!("Abandoned history (never replayed):");
        for timeline_break in &manifest.timeline_breaks {
            println!(
                "  after {} up to {} ({} at {})",
                format_ts_rfc3339(timeline_break.after_ts),
                format_ts_rfc3339(timeline_break.until_ts),
                timeline_break.reason,
                timeline_break.at
            );
        }
    }

    println!();
    match manifest.recoverable_window() {
        Some((earliest, latest)) => {
            println!(
                "Recoverable window: {} to {}",
                format_ts_rfc3339(earliest),
                format_ts_rfc3339(latest)
            );
            true
        }
        None => {
            println!("Recoverable window: none (no base backup has been indexed)");
            false
        }
    }
}

/// Fetch and parse the segments of `plan`, returning the records to replay in CID order.
async fn load_records(
    opened: &OpenedArchive,
    plan: &RecoveryPlan,
) -> Result<Vec<WalEntryRecord>, PitrError> {
    let mut records: Vec<WalEntryRecord> = Vec::new();
    for segment in &plan.segments {
        if segment.server_version != env!("KUBIDM_PKG_SERIES") {
            return Err(PitrError::NotRecoverable(format!(
                "segment {} was written by server version {} and can not be replayed by version {}",
                segment.segment_id,
                segment.server_version,
                env!("KUBIDM_PKG_SERIES")
            )));
        }
        let data = opened
            .store
            .fetch_segment(
                &opened.settings.local_dir,
                segment,
                opened.local_only.contains(&segment.segment_id),
            )
            .await?;
        let file = parse_segment(&data, segment.compression)?;
        if file.server_uuid != opened.manifest.server_uuid {
            return Err(PitrError::NotRecoverable(format!(
                "segment {} belongs to server {}, the archive belongs to {}",
                segment.segment_id, file.server_uuid, opened.manifest.server_uuid
            )));
        }
        records.extend(records_to_replay(&opened.manifest, plan, &file.entries).cloned());
    }
    records.sort_by_key(|record| (record.cid_ts, record.entry_id));
    Ok(records)
}

fn print_plan(opened: &OpenedArchive, plan: &RecoveryPlan, records: usize, recovered_ts: Duration) {
    eprintln!("Recovery plan:");
    eprintln!("  Archive:      {}", opened.settings.location);
    eprintln!("  Target:       {}", format_ts_rfc3339(plan.target.ts));
    if plan.target.clamped_to_latest {
        eprintln!(
            "                (after the last archived record; the result is the latest recoverable state)"
        );
    }
    if opened.manifest.is_abandoned(plan.target.ts) {
        eprintln!(
            "                (inside history an earlier restore or recovery abandoned; the result is the state it restored)"
        );
    }
    eprintln!(
        "  Base backup:  {} at {} (watermark {})",
        plan.base.key,
        opened.settings.bases,
        format_ts_rfc3339(plan.base.watermark_ts)
    );
    if plan.segments.is_empty() {
        eprintln!("  Segments:     none (the base backup already represents the target)");
    } else {
        eprintln!("  Segments:     {}", plan.segments.len());
        for segment in &plan.segments {
            eprintln!(
                "    {} ({} to {}, {} records){}",
                segment.segment_id,
                format_ts_rfc3339(segment.start_ts),
                format_ts_rfc3339(segment.end_ts),
                segment.entry_count,
                if opened.local_only.contains(&segment.segment_id) {
                    ", local"
                } else {
                    ""
                }
            );
        }
    }
    eprintln!("  Records:      {records} to replay");
    eprintln!("  Result:       {}", format_ts_rfc3339(recovered_ts));
}

/// `kubidmd database recover`: recover the database described by `config` to `target`.
///
/// Offline only, like `restore`. The newest base backup at or before the target is
/// restored into the configured database and the WAL records between its watermark and
/// the target are applied in the same database transaction, so a failure leaves the
/// database untouched. The database is then reindexed, booted and verified exactly as
/// `verify-backup --level full` does, and the history after the recovered point is
/// recorded as abandoned in the manifest. `dry_run` prints the plan and changes nothing.
pub async fn pitr_recover_server_core(
    config: &Configuration,
    target: &RecoveryTargetSpec,
    dry_run: bool,
) -> Result<RecoveryOutcome, PitrError> {
    let opened = open_archive(config).await?;
    let plan = plan_recovery(&opened.manifest, target)?;

    if plan.base.server_version != env!("KUBIDM_PKG_SERIES") {
        return Err(PitrError::NotRecoverable(format!(
            "base backup {} was written by server version {} and can not be restored by version {}",
            plan.base.key,
            plan.base.server_version,
            env!("KUBIDM_PKG_SERIES")
        )));
    }

    // Reading segments changes nothing, so the dry run can report the exact record count.
    let records = load_records(&opened, &plan).await?;
    let recovered_ts = records
        .last()
        .map(WalEntryRecord::ts)
        .unwrap_or(plan.base.watermark_ts);
    print_plan(&opened, &plan, records.len(), recovered_ts);

    if dry_run {
        eprintln!("Dry run: no changes were made.");
        return Ok(RecoveryOutcome {
            plan,
            records: records.len(),
            recovered_ts,
            dry_run: true,
            apply: None,
        });
    }

    let db_path = config
        .db_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "(in memory)".to_string());

    let base = opened.settings.bases.fetch(&plan.base).await?;

    info!(
        "Restoring base backup {} and replaying {} WAL records into {db_path}",
        plan.base.key,
        records.len()
    );
    let apply = crate::restore_and_replay(config, base.path(), &records)
        .await
        .map_err(|err| {
            error!(
                ?err,
                "Recovery failed; the database at {db_path} was not changed unless the error \
                 says otherwise"
            );
            PitrError::Operation(err)
        })?
        .apply;
    drop(base);

    if let Some(report) = &apply {
        info!(
            applied = report.applied,
            created = report.created,
            modified = report.modified,
            deleted = report.deleted,
            "WAL records replayed"
        );
    }

    info!("Verifying the recovered database ...");
    let consistency_errors = crate::verify_booted_database(config)
        .await
        .map_err(PitrError::Operation)?;
    if !consistency_errors.is_empty() {
        for err in &consistency_errors {
            error!(?err, "Recovered database consistency error");
        }
        error!(
            "RECOVERY INCOMPLETE: the recovered database at {db_path} failed its consistency \
             verification. Do not start the server on it; recover to another point or restore a backup."
        );
        return Err(PitrError::Operation(OperationError::ConsistencyError(
            consistency_errors,
        )));
    }

    record_timeline_break(&opened.settings, recovered_ts, "recover")
        .await
        .inspect_err(|err| {
            error!(
                %err,
                "The database at {db_path} WAS recovered, but the abandoned history could not \
                 be recorded in the archive. A later recovery past this point could replay it: \
                 take a new online backup right after starting the server, and recover only to \
                 points after it."
            );
        })?;

    eprintln!(
        "Recovered {db_path} to {} ({} records replayed on {})",
        format_ts_rfc3339(recovered_ts),
        records.len(),
        plan.base.key
    );

    Ok(RecoveryOutcome {
        plan,
        records: records.len(),
        recovered_ts,
        dry_run: false,
        apply,
    })
}

/// Record in the archive that the database was restored or recovered to `after_ts`, so
/// that everything archived after that point up to now is never replayed again. `until_ts`
/// also covers any CID the archive holds, in case the clock of the old server was ahead.
async fn record_timeline_break(
    settings: &PitrSettings,
    after_ts: Duration,
    reason: &str,
) -> Result<(), PitrError> {
    let store = PitrStore::open(&settings.location).await?;
    let Some(mut manifest) = store.load_manifest().await? else {
        // Nothing was ever archived, so there is no history to abandon.
        return Ok(());
    };
    let now = duration_from_epoch_now();
    let local_segments = list_segments(&settings.local_dir)?;
    let until_ts = manifest
        .segments
        .iter()
        .chain(local_segments.iter())
        .map(|s| s.end_ts)
        .chain(manifest.base_backups.iter().map(|b| b.watermark_ts))
        .fold(now, Duration::max);
    manifest.add_timeline_break(PitrTimelineBreak {
        after_ts,
        until_ts,
        at: format_ts_rfc3339(now),
        reason: reason.to_string(),
    });
    store.save_manifest(&mut manifest).await?;
    info!(
        after = %format_ts_rfc3339(after_ts),
        until = %format_ts_rfc3339(until_ts),
        "Abandoned history recorded in the PITR archive"
    );
    Ok(())
}

/// After `kubidmd database restore` or `restore-s3`: when WAL archiving is configured,
/// record that the history after the watermark of the restored backup was abandoned.
/// Without WAL archiving this does nothing.
pub async fn note_restore(config: &Configuration, watermark: Duration) -> Result<(), PitrError> {
    let Some(settings) = PitrSettings::from_config(config)? else {
        return Ok(());
    };
    record_timeline_break(&settings, watermark, "restore").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use kubidm_proto::backup::BackupCompression;
    use kubidmd_lib::repl::cid::Cid;
    use kubidmd_lib::repl::wal::{WalArchiver, WalOperationRecord, WalPendingOp};
    use std::sync::Mutex;

    fn segment(id: &str, start: u64, end: u64) -> WalSegment {
        WalSegment {
            segment_id: id.to_string(),
            server_uuid: Uuid::nil(),
            start_ts: Duration::from_secs(start),
            end_ts: Duration::from_secs(end),
            first_cid: String::new(),
            last_cid: String::new(),
            entry_count: 1,
            checksum_sha256: String::new(),
            size_bytes: 1,
            compression: BackupCompression::Gzip,
            server_version: env!("KUBIDM_PKG_SERIES").to_string(),
            created_at: String::new(),
        }
    }

    fn base(key: &str, watermark: u64) -> PitrBaseBackup {
        PitrBaseBackup {
            key: key.to_string(),
            timestamp: String::new(),
            watermark_ts: Duration::from_secs(watermark),
            server_version: env!("KUBIDM_PKG_SERIES").to_string(),
        }
    }

    fn manifest() -> PitrManifest {
        let mut m = PitrManifest::new(Uuid::nil());
        m.add_base_backup(base("backup-1", 100));
        m.add_base_backup(base("backup-2", 400));
        m.add_segment(segment("s1", 110, 200));
        m.add_segment(segment("s2", 210, 450));
        m.add_segment(segment("s3", 460, 600));
        m
    }

    const DAY: u64 = 86400;

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

    #[test]
    fn test_resolve_target() {
        let m = manifest();

        let latest = resolve_target(&m, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(latest.ts, Duration::from_secs(600));
        assert!(!latest.clamped_to_latest);

        let t = resolve_target(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(250))),
        )
        .unwrap();
        assert_eq!(t.ts, Duration::from_secs(250));
        assert!(!t.clamped_to_latest);

        // After the last record: allowed, flagged.
        let t = resolve_target(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(700))),
        )
        .unwrap();
        assert!(t.clamped_to_latest);

        // Before the oldest base: refused.
        assert!(matches!(
            resolve_target(
                &m,
                &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(50)))
            ),
            Err(PitrError::NotRecoverable(_))
        ));

        // Garbage: refused.
        assert!(matches!(
            resolve_target(&m, &RecoveryTargetSpec::Time("yesterday".to_string())),
            Err(PitrError::Target(_))
        ));

        // A CID of this server resolves to its timestamp; another server's is refused.
        let cid = Cid {
            ts: Duration::from_secs(300),
            s_uuid: Uuid::nil(),
        };
        let t = resolve_target(&m, &RecoveryTargetSpec::Cid(cid.to_string())).unwrap();
        assert_eq!(t.ts, Duration::from_secs(300));
        let foreign = Cid {
            ts: Duration::from_secs(300),
            s_uuid: Uuid::new_v4(),
        };
        assert!(matches!(
            resolve_target(&m, &RecoveryTargetSpec::Cid(foreign.to_string())),
            Err(PitrError::Target(_))
        ));

        // No base backup at all: nothing is recoverable.
        let empty = PitrManifest::new(Uuid::nil());
        assert!(matches!(
            resolve_target(&empty, &RecoveryTargetSpec::Latest),
            Err(PitrError::NotRecoverable(_))
        ));
    }

    #[test]
    fn test_plan_recovery_selects_base_and_segments() {
        let m = manifest();

        let plan = plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(250))),
        )
        .unwrap();
        assert_eq!(plan.base.key, "backup-1");
        let ids: Vec<&str> = plan
            .segments
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s1", "s2"]);

        // At exactly the watermark of backup-2 that base is used; s2 straddles the
        // watermark and is read, its records filtered.
        let plan = plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(400))),
        )
        .unwrap();
        assert_eq!(plan.base.key, "backup-2");
        let ids: Vec<&str> = plan
            .segments
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s2"]);

        let plan = plan_recovery(&m, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.base.key, "backup-2");
        let ids: Vec<&str> = plan
            .segments
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s2", "s3"]);
    }

    #[test]
    fn test_records_to_replay_skip_watermark_target_and_abandoned_history() {
        let mut m = manifest();
        let record = |secs: u64| WalEntryRecord {
            cid_ts: Duration::from_secs(secs).as_nanos() as u64,
            cid_server: Uuid::nil(),
            entry_id: secs,
            entry_uuid: Uuid::new_v4(),
            operation: WalOperationRecord::Delete,
        };
        let entries: Vec<WalEntryRecord> = [90, 100, 150, 250, 350, 500]
            .into_iter()
            .map(record)
            .collect();

        let plan = plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(350))),
        )
        .unwrap();
        let ids: Vec<u64> = records_to_replay(&m, &plan, &entries)
            .map(|r| r.entry_id)
            .collect();
        assert_eq!(ids, vec![150, 250, 350]);

        // A recovery to 160 abandoned (160, 300]: the record at 250 is never replayed and
        // backup-2 (400) is untouched since it lies after the abandoned range.
        m.add_timeline_break(PitrTimelineBreak {
            after_ts: Duration::from_secs(160),
            until_ts: Duration::from_secs(300),
            at: String::new(),
            reason: "recover".to_string(),
        });
        let plan = plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(350))),
        )
        .unwrap();
        assert_eq!(plan.base.key, "backup-1");
        let ids: Vec<u64> = records_to_replay(&m, &plan, &entries)
            .map(|r| r.entry_id)
            .collect();
        assert_eq!(ids, vec![150, 350]);
    }

    #[test]
    fn test_pitr_settings_from_config() {
        use crate::config::OnlineBackup;
        let mut config = Configuration::new_for_test();
        assert!(PitrSettings::from_config(&config).unwrap().is_none());

        config.db_path = Some(PathBuf::from("/var/lib/kubidm/kubidm.db"));
        config.online_backup = Some(OnlineBackup {
            path: Some(PathBuf::from("/var/lib/kubidm/backups")),
            wal_archive: Some(WalArchiveConfig {
                enabled: true,
                ..WalArchiveConfig::default()
            }),
            ..OnlineBackup::default()
        });
        let settings = PitrSettings::from_config(&config).unwrap().unwrap();
        assert_eq!(settings.local_dir, PathBuf::from("/var/lib/kubidm/wal"));
        assert_eq!(
            settings.location,
            PitrLocation::Local(PathBuf::from("/var/lib/kubidm/wal"))
        );
        assert_eq!(
            settings.bases,
            BaseLocation::Local(PathBuf::from("/var/lib/kubidm/backups"))
        );
        assert_eq!(
            settings.backend_wal_config().local_path,
            Some(PathBuf::from("/var/lib/kubidm/wal"))
        );

        // The backup S3 section is the default archive location and holds the bases;
        // wal_archive.s3 only moves the archive.
        let backup_s3 = S3Config::with_bucket("backups".to_string());
        let wal_s3 = S3Config::with_bucket("wal".to_string());
        let online_backup = config.online_backup.as_mut().unwrap();
        online_backup.s3 = Some(backup_s3.clone());
        let settings = PitrSettings::from_config(&config).unwrap().unwrap();
        assert_eq!(settings.location, PitrLocation::S3(backup_s3.clone()));
        assert_eq!(settings.bases, BaseLocation::S3(backup_s3.clone()));
        config
            .online_backup
            .as_mut()
            .unwrap()
            .wal_archive
            .as_mut()
            .unwrap()
            .s3 = Some(wal_s3.clone());
        let settings = PitrSettings::from_config(&config).unwrap().unwrap();
        assert_eq!(settings.location, PitrLocation::S3(wal_s3));
        assert_eq!(settings.bases, BaseLocation::S3(backup_s3));

        // An explicit local path wins over the database directory.
        config
            .online_backup
            .as_mut()
            .unwrap()
            .wal_archive
            .as_mut()
            .unwrap()
            .local_path = Some(PathBuf::from("/srv/wal"));
        let settings = PitrSettings::from_config(&config).unwrap().unwrap();
        assert_eq!(settings.local_dir, PathBuf::from("/srv/wal"));

        // Disabled: none. In memory without a local path: an error. No base location: an
        // error.
        let wal = config
            .online_backup
            .as_mut()
            .unwrap()
            .wal_archive
            .as_mut()
            .unwrap();
        wal.enabled = false;
        assert!(PitrSettings::from_config(&config).unwrap().is_none());
        let wal = config
            .online_backup
            .as_mut()
            .unwrap()
            .wal_archive
            .as_mut()
            .unwrap();
        wal.enabled = true;
        wal.local_path = None;
        config.db_path = None;
        assert!(matches!(
            PitrSettings::from_config(&config),
            Err(PitrError::Config(_))
        ));
        config.db_path = Some(PathBuf::from("/var/lib/kubidm/kubidm.db"));
        let online_backup = config.online_backup.as_mut().unwrap();
        online_backup.s3 = None;
        online_backup.path = None;
        assert!(matches!(
            PitrSettings::from_config(&config),
            Err(PitrError::Config(_))
        ));
    }

    fn report(ts: u64, server: Uuid) -> BackupStructuralReport {
        BackupStructuralReport {
            entry_count: 1,
            version: Some(env!("KUBIDM_PKG_SERIES").to_string()),
            db_s_uuid: Some(server),
            db_ts_max: Some(Duration::from_secs(ts)),
            errors: Vec::new(),
        }
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

    #[test]
    fn test_verify_segment_checksum() {
        let mut s = segment("s", 1, 2);
        s.checksum_sha256 = hex::encode(Sha256::digest(b"data"));
        assert!(verify_segment_checksum(&s, b"data").is_ok());
        assert!(matches!(
            verify_segment_checksum(&s, b"other"),
            Err(PitrError::NotRecoverable(_))
        ));
    }

    #[test]
    fn test_location_display() {
        let mut s3 = S3Config::with_bucket("bucket".to_string());
        assert_eq!(PitrLocation::S3(s3.clone()).to_string(), "s3://bucket");
        s3.path_prefix = Some("/prod/".to_string());
        assert_eq!(BaseLocation::S3(s3).to_string(), "s3://bucket/prod");
        assert_eq!(
            PitrLocation::Local(PathBuf::from("/var/lib/kubidm/wal")).to_string(),
            "/var/lib/kubidm/wal"
        );
    }
}
