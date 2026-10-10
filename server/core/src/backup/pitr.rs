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
//!
//! Segments hold the full state of every changed entry, credentials included, so they get
//! the protection of the backups:
//!
//! - with `[online_backup.encryption]` enabled, a closed segment is sealed with the backup
//!   encryption scheme before it is archived (uploaded to S3, or kept as `<segment>.enc` in
//!   the local WAL directory) and the plaintext copy is removed; recovery decrypts it;
//! - when the S3 location of the archive replicates its backups to regions, the archive
//!   (segments, then the manifest) is mirrored to every region after each synchronisation,
//!   and `recover --region` / `pitr-list --region` read a region's copy.
//!
//! The manifest is never encrypted: it holds CID ranges, checksums, object keys and key
//! identifiers, no directory content.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kubidm_proto::backup::{
    is_encrypted_backup_name, BackupEncryptionConfig, PitrBaseBackup, PitrManifest,
    PitrTimelineBreak, PitrWalGap, ReplicationConfig, ReplicationRegionConfig, S3Config,
    WalArchiveConfig, WalSegment, PITR_MANIFEST_KEY, WAL_SEGMENT_KEY_PREFIX,
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

use crate::backup::{
    is_backup_artifact_name, is_encrypted_artifact, read_encryption_header, seal_backup_async,
    BackupEncryptor, S3BackupError, S3ClientWrapper,
};
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
    /// The backup encryption key could not be obtained, or does not open a segment.
    Encryption(String),
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
            PitrError::Encryption(msg) => write!(f, "PITR encryption error: {msg}"),
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

/// Run file I/O, segment parsing and cryptography on the blocking thread pool, so that the
/// archive task and the recovery commands never stall the async runtime.
async fn blocking<T, F>(work: F) -> Result<T, PitrError>
where
    F: FnOnce() -> Result<T, PitrError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| PitrError::Io(std::io::Error::other(err)))?
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
    /// The backup encryption settings. When enabled, archived segments are encrypted with
    /// them exactly like backups.
    pub encryption: BackupEncryptionConfig,
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
            encryption: online_backup.encryption.clone(),
        }))
    }

    /// The replication section the archive is mirrored with: the enabled replication of
    /// the S3 location the archive is uploaded to. A local archive is never replicated.
    pub fn replication(&self) -> Option<&ReplicationConfig> {
        match &self.location {
            PitrLocation::S3(config) => config
                .replication
                .as_ref()
                .filter(|replication| replication.enabled),
            PitrLocation::Local(_) => None,
        }
    }

    /// These settings with the archive, and the base backups when they are in S3, read from
    /// the copies held by the replication region `name`. The region is looked up whether or
    /// not replication is enabled, so that a replica stays a recovery source after
    /// replication was switched off, as for `restore-s3 --region`.
    pub fn for_region(&self, name: &str) -> Result<Self, PitrError> {
        let PitrLocation::S3(wal_s3) = &self.location else {
            return Err(PitrError::Config(format!(
                "the WAL archive is kept in the local directory {}; only an archive in S3 is \
                 replicated to regions",
                self.local_dir.display()
            )));
        };
        let wal_region = find_region(wal_s3, name).ok_or_else(|| {
            PitrError::Config(format!(
                "no replication region named '{name}' is configured for the S3 location of \
                 the WAL archive ({})",
                self.location
            ))
        })?;
        let bases = match &self.bases {
            BaseLocation::S3(base_s3) => BaseLocation::S3(
                find_region(base_s3, name)
                    .ok_or_else(|| {
                        PitrError::Config(format!(
                            "no replication region named '{name}' is configured in \
                             [online_backup.s3], where the base backups are"
                        ))
                    })?
                    .to_s3_config(),
            ),
            BaseLocation::Local(dir) => BaseLocation::Local(dir.clone()),
        };
        Ok(Self {
            location: PitrLocation::S3(wal_region.to_s3_config()),
            bases,
            ..self.clone()
        })
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

/// The replication region `name` of `config`, whether or not replication is enabled.
fn find_region<'a>(config: &'a S3Config, name: &str) -> Option<&'a ReplicationRegionConfig> {
    config
        .replication
        .as_ref()
        .and_then(|replication| replication.regions.iter().find(|r| r.region == name))
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
                let dir = dir.clone();
                blocking(move || {
                    let mut keys = Vec::new();
                    if !dir.exists() {
                        return Ok(keys);
                    }
                    for entry in fs::read_dir(&dir)? {
                        let entry = entry?;
                        if let Some(name) = entry.file_name().to_str() {
                            if is_backup_artifact_name(name) {
                                keys.push(name.to_string());
                            }
                        }
                    }
                    Ok(keys)
                })
                .await?
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
                let read = blocking(move || {
                    if !path.exists() {
                        return Ok(None);
                    }
                    Ok(Some(fs::read(&path)?))
                })
                .await?;
                match read {
                    Some(data) => data,
                    None => return Ok(None),
                }
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
                let dir = dir.clone();
                blocking(move || {
                    fs::create_dir_all(&dir)?;
                    let path = dir.join(PITR_MANIFEST_KEY);
                    let tmp = dir.join(format!("{PITR_MANIFEST_KEY}.tmp"));
                    fs::write(&tmp, &data)?;
                    fs::rename(&tmp, &path)?;
                    Ok(())
                })
                .await?;
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

    /// Archive the closed segment in `local_dir` and return it as the manifest records it.
    ///
    /// With an `encryptor` the segment is sealed with the backup encryption scheme first
    /// and stored as `<segment>.enc`: uploaded to S3, or written next to the plaintext in
    /// the local directory, whose plaintext copy the caller removes once the manifest
    /// records the encrypted one. Without one, the segment is uploaded as it is to S3, and
    /// the local location has nothing to do: the segment already is where it belongs.
    async fn put_segment(
        &self,
        local_dir: &Path,
        segment: &WalSegment,
        encryptor: Option<&BackupEncryptor>,
    ) -> Result<WalSegment, PitrError> {
        if !self.is_s3() && encryptor.is_none() {
            return Ok(segment.clone());
        }
        let path = local_dir.join(&segment.segment_id);
        let data = blocking(move || Ok(fs::read(path)?)).await?;
        verify_segment_checksum(segment, &data)?;

        let mut archived = WalSegment {
            encryption_key: None,
            ..segment.clone()
        };
        let stored = match encryptor {
            Some(encryptor) => {
                archived.encryption_key = Some(encryptor.key_identifier().to_string());
                seal_backup_async(data, segment.compression, Some(encryptor))
                    .await
                    .map_err(|err| {
                        PitrError::Encryption(format!(
                            "unable to encrypt segment {}: {err}",
                            segment.segment_id
                        ))
                    })?
            }
            None => data,
        };

        match self {
            PitrStore::Local { dir } => {
                let path = dir.join(archived.stored_name());
                let tmp = dir.join(format!("{}.tmp", archived.stored_name()));
                blocking(move || {
                    fs::write(&tmp, &stored)?;
                    fs::rename(&tmp, &path)?;
                    Ok(())
                })
                .await?;
            }
            PitrStore::S3 { client } => {
                client
                    .upload_backup(
                        &stored,
                        &archived.object_key(),
                        &segment.created_at,
                        segment.compression,
                        archived.encryption_key.as_deref(),
                    )
                    .await?;
            }
        }
        Ok(archived)
    }

    async fn delete_segment(
        &self,
        local_dir: &Path,
        segment: &WalSegment,
    ) -> Result<(), PitrError> {
        match self {
            PitrStore::Local { dir } => {
                let local_dir = local_dir.to_path_buf();
                let segment_id = segment.segment_id.clone();
                let stored = (segment.stored_name() != segment.segment_id)
                    .then(|| dir.join(segment.stored_name()));
                blocking(move || {
                    remove_segment(&local_dir, &segment_id)?;
                    if let Some(stored) = stored.filter(|path| path.exists()) {
                        fs::remove_file(stored)?;
                    }
                    Ok(())
                })
                .await?
            }
            PitrStore::S3 { client } => client.delete_backup(&segment.object_key()).await?,
        }
        Ok(())
    }

    /// Read a segment from the archive, or from `local_dir` when `local` says it has not
    /// been archived yet, decrypt it when it is encrypted, and check it against the
    /// checksum the manifest recorded.
    async fn fetch_segment(
        &self,
        local_dir: &Path,
        segment: &WalSegment,
        local: bool,
        keys: &mut SegmentKeys<'_>,
    ) -> Result<Vec<u8>, PitrError> {
        let data = match self {
            PitrStore::S3 { client } if !local => {
                client.download_backup(&segment.object_key()).await?.0
            }
            PitrStore::Local { dir } if !local => {
                let path = dir.join(segment.stored_name());
                blocking(move || Ok(fs::read(path)?)).await?
            }
            _ => {
                let path = local_dir.join(&segment.segment_id);
                blocking(move || Ok(fs::read(path)?)).await?
            }
        };
        let plaintext = open_segment(segment, data, keys).await?;
        verify_segment_checksum(segment, &plaintext)?;
        Ok(plaintext)
    }
}

/// The backup encryption key recovery decrypts segments with, obtained from the configured
/// key source the first time an encrypted segment needs it, so that recovering a plain
/// archive never touches the key source.
struct SegmentKeys<'a> {
    config: &'a BackupEncryptionConfig,
    encryptor: Option<BackupEncryptor>,
}

impl<'a> SegmentKeys<'a> {
    fn new(config: &'a BackupEncryptionConfig) -> Self {
        Self {
            config,
            encryptor: None,
        }
    }

    async fn get(
        &mut self,
        segment: &WalSegment,
        key_identifier: &str,
    ) -> Result<BackupEncryptor, PitrError> {
        if let Some(encryptor) = &self.encryptor {
            return Ok(encryptor.clone());
        }
        if !self.config.enabled {
            return Err(PitrError::Encryption(format!(
                "segment {} is encrypted with key '{key_identifier}' but backup encryption is \
                 not enabled in the configuration; enable [online_backup.encryption] with the \
                 key that wrote it",
                segment.segment_id
            )));
        }
        let encryptor = BackupEncryptor::from_config(self.config)
            .await
            .map_err(|err| {
                PitrError::Encryption(format!(
                    "segment {} is encrypted with key '{key_identifier}' and the configured key \
                     could not be obtained: {err}",
                    segment.segment_id
                ))
            })?
            .ok_or_else(|| PitrError::Encryption("backup encryption is not enabled".to_string()))?;
        self.encryptor = Some(encryptor.clone());
        Ok(encryptor)
    }
}

/// The plaintext of the archived copy `data` of `segment`. An encrypted container is
/// decrypted, whatever the manifest says. A segment the manifest records as encrypted must
/// be an encrypted container, so that whoever can write to the archive can not swap an
/// encrypted segment for an unauthenticated plain one, as for backups.
async fn open_segment(
    segment: &WalSegment,
    data: Vec<u8>,
    keys: &mut SegmentKeys<'_>,
) -> Result<Vec<u8>, PitrError> {
    if !is_encrypted_artifact(&data) {
        if let Some(key) = &segment.encryption_key {
            return Err(PitrError::NotRecoverable(format!(
                "segment {} is recorded as encrypted with key '{key}' but its archived copy is \
                 not an encrypted container; it may have been replaced, so it is refused",
                segment.segment_id
            )));
        }
        return Ok(data);
    }
    let (header, _) = read_encryption_header(&data).map_err(|err| {
        PitrError::Encryption(format!(
            "segment {} has an unreadable encryption header: {err}",
            segment.segment_id
        ))
    })?;
    let encryptor = keys.get(segment, &header.key_identifier).await?;
    let segment_id = segment.segment_id.clone();
    blocking(move || {
        encryptor
            .decrypt(&data)
            .map(|(plaintext, _)| plaintext)
            .map_err(|err| {
                PitrError::Encryption(format!("unable to decrypt segment {segment_id}: {err}"))
            })
    })
    .await
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
    /// Segments copied to replication regions.
    pub replicated: usize,
    /// Replication regions the archive could not be mirrored to in this run.
    pub region_errors: usize,
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
        let local_segments = {
            let local_dir = local_dir.clone();
            blocking(move || Ok(list_segments(&local_dir)?)).await?
        };
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

        // A segment leaves the local directory once archived when it is uploaded to S3 or
        // encrypted: the plaintext copy must not outlive its archived copy.
        let encrypt = self.settings.encryption.enabled;
        let moves_segments = store.is_s3() || encrypt;

        // Segments the manifest does not know yet. For the local location this is only an
        // index update, unless the segment is encrypted into `<segment>.enc`; for S3 it is
        // the upload. Every segment that moves is archived again while its local copy is
        // there, since a segment stays local only until its archiving and the manifest
        // update succeeded. A failure leaves the segment in the local directory for the
        // next run.
        let pending: Vec<WalSegment> = local_segments
            .into_iter()
            .filter(|segment| {
                if segment.server_uuid != server_uuid {
                    warn!(
                        segment = %segment.segment_id,
                        "WAL segment of another server in {}, not archived",
                        local_dir.display()
                    );
                    return false;
                }
                moves_segments
                    || !manifest
                        .segments
                        .iter()
                        .any(|known| known.segment_id == segment.segment_id)
            })
            .collect();

        let mut archived: Vec<WalSegment> = Vec::new();
        let mut upload_error = None;
        // The key is obtained once per run, and only when there is something to encrypt.
        // Without it nothing is archived: a segment is never archived in plaintext while
        // encryption is enabled.
        let encryptor = if encrypt && !pending.is_empty() {
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
                    upload_error = Some(err);
                    None
                }
            }
        } else {
            None
        };

        if upload_error.is_none() {
            for segment in pending {
                match store
                    .put_segment(local_dir, &segment, encryptor.as_ref())
                    .await
                {
                    Ok(stored) => {
                        manifest.add_segment(stored);
                        archived.push(segment);
                    }
                    Err(err) => {
                        error!(%err, segment = %segment.segment_id, "Unable to archive WAL segment");
                        upload_error = Some(err);
                        break;
                    }
                }
            }
        }

        if !archived.is_empty() || changed {
            store.save_manifest(&mut manifest).await?;
            *gaps_recorded = true;
            changed = false;
            report.archived = archived.len();
            if moves_segments && !archived.is_empty() {
                let local_dir = local_dir.clone();
                let ids: Vec<String> = archived.iter().map(|s| s.segment_id.clone()).collect();
                blocking(move || {
                    for id in ids {
                        remove_segment(&local_dir, &id)?;
                    }
                    Ok(())
                })
                .await?;
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

        self.replicate(&store, &mut manifest, now, report).await;

        Ok(())
    }

    /// Mirror the archive to every region of [`PitrSettings::replication`].
    ///
    /// The segments a region misses are copied from the primary (checked against the
    /// primary's checksum; stored bytes and sidecar unchanged, so encrypted segments stay
    /// encrypted and the region never needs the key). The region's manifest is then the
    /// primary's merged with what only the region still records, so that a region keeps
    /// the history a primary that lost its archive no longer has, and the region applies
    /// the retention rules of the primary to its own copy: base backups it no longer holds
    /// drop out, and segments older than `retention_days` that its oldest base backup does
    /// not need are deleted after the manifest stops naming them.
    ///
    /// Abandoned history and gaps a region records that the primary does not (a recovery
    /// from that region while the primary was unreachable) are merged into the primary
    /// manifest first. A region that fails is logged and retried by the next
    /// synchronisation; it never fails the archiving itself.
    async fn replicate(
        &self,
        store: &PitrStore,
        manifest: &mut PitrManifest,
        now: Duration,
        report: &mut PitrSyncReport,
    ) {
        let (Some(replication), PitrStore::S3 { client }) = (self.settings.replication(), store)
        else {
            return;
        };
        for region in &replication.regions {
            // Where the region keeps its copies of the base backups, for its retention. When
            // the base backups are in another S3 location without this region, the region's
            // index keeps every base it learnt about, which only delays its retention.
            let region_bases = self
                .settings
                .for_region(&region.region)
                .map(|settings| settings.bases)
                .inspect_err(|err| debug!(%err, region = %region.region, "No base backups to prune the region index with"))
                .ok();
            let target = RegionTarget {
                config: region,
                bases: region_bases.as_ref(),
                now,
                retention: self.settings.wal.retention(),
            };
            match replicate_to_region(client, store, manifest, &target).await {
                Ok(copied) => report.replicated += copied,
                Err(err) => {
                    report.region_errors += 1;
                    error!(
                        %err,
                        region = %region.region,
                        bucket = %region.bucket,
                        "Unable to replicate the WAL archive to the region; the next \
                         synchronisation retries"
                    );
                }
            }
        }
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

/// A replication region the archive is mirrored to.
struct RegionTarget<'a> {
    config: &'a ReplicationRegionConfig,
    /// Where the region holds its copies of the base backups, when known.
    bases: Option<&'a BaseLocation>,
    now: Duration,
    retention: Duration,
}

/// Mirror the archive of `primary` (whose manifest is `manifest`) to `target`, see
/// [`PitrArchive::replicate`]. Returns the number of segments copied.
async fn replicate_to_region(
    primary: &S3ClientWrapper,
    store: &PitrStore,
    manifest: &mut PitrManifest,
    target: &RegionTarget<'_>,
) -> Result<usize, PitrError> {
    let region_name = &target.config.region;
    let region_store = PitrStore::S3 {
        client: Box::new(S3ClientWrapper::for_region(target.config).await?),
    };
    let PitrStore::S3 { client: region } = &region_store else {
        return Err(PitrError::Config("region store is not S3".to_string()));
    };

    let region_manifest = region_store.load_manifest().await?;
    if let Some(region_manifest) = &region_manifest {
        if region_manifest.server_uuid != manifest.server_uuid {
            return Err(PitrError::Manifest(format!(
                "{PITR_MANIFEST_KEY} in region {region_name} ({}) belongs to server {}, this \
                 server is {}; refusing to mix archives",
                region.location(),
                region_manifest.server_uuid,
                manifest.server_uuid
            )));
        }
        // Only markers that still concern the primary's history are kept, as its own
        // synchronisation would prune the others right away.
        let markers_before = (manifest.timeline_breaks.clone(), manifest.gaps.clone());
        manifest.merge_markers(region_manifest);
        manifest.prune_timeline_breaks();
        manifest.prune_gaps();
        if (&manifest.timeline_breaks, &manifest.gaps) != (&markers_before.0, &markers_before.1) {
            info!(
                region = %region_name,
                "Abandoned history or gaps recorded in the region merged into the WAL archive"
            );
            store.save_manifest(manifest).await?;
        }
    }

    // Segments first, so that the region's manifest never names a segment it lacks.
    let present: BTreeSet<String> = region
        .list_backups()
        .await?
        .into_iter()
        .filter(|key| key.starts_with(WAL_SEGMENT_KEY_PREFIX))
        .collect();
    let mut copied = 0;
    for segment in &manifest.segments {
        let key = segment.object_key();
        if !present.contains(&key) {
            primary.copy_backup_to(region, &key).await?;
            copied += 1;
        }
    }

    // The region's view: the primary's manifest plus what only the region still records,
    // with the primary's retention rules applied to the region's own copies.
    let mut mirrored = manifest.clone();
    if let Some(region_manifest) = &region_manifest {
        mirrored.merge_from(region_manifest);
    }
    if let Some(bases) = target.bases {
        mirrored.retain_base_backups(&bases.list_keys().await?);
    }
    // A segment the primary still lists stays, or the next run would copy it again.
    let expired: Vec<WalSegment> =
        select_segments_to_delete(&mirrored, target.now, target.retention)
            .into_iter()
            .filter(|id| !manifest.segments.iter().any(|s| &s.segment_id == id))
            .filter_map(|id| {
                mirrored
                    .segments
                    .iter()
                    .find(|s| s.segment_id == id)
                    .cloned()
            })
            .collect();
    for segment in &expired {
        mirrored.remove_segment(&segment.segment_id);
    }
    mirrored.prune_timeline_breaks();
    mirrored.prune_gaps();

    let up_to_date = region_manifest.is_some_and(|mut region_manifest| {
        region_manifest.updated_at.clone_from(&mirrored.updated_at);
        region_manifest == mirrored
    });
    if !up_to_date {
        region_store.save_manifest(&mut mirrored).await?;
    }

    for segment in &expired {
        match region.delete_backup(&segment.object_key()).await {
            Ok(()) => info!(
                region = %region_name,
                segment = %segment.segment_id,
                "Expired WAL segment deleted from the region"
            ),
            Err(err) => warn!(
                %err,
                region = %region_name,
                segment = %segment.segment_id,
                "Unable to delete an expired WAL segment from the region"
            ),
        }
    }

    if copied > 0 {
        info!(region = %region_name, copied, "WAL segments replicated");
    }
    Ok(copied)
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
    /// The settings the archive is read with: those of the configuration, or those of the
    /// replication region it is read from.
    settings: PitrSettings,
    /// The settings of the primary archive, when the archive is read from a region.
    primary: Option<PitrSettings>,
    store: PitrStore,
    manifest: PitrManifest,
    /// Ids of the segments that are only in the local WAL directory.
    local_only: BTreeSet<String>,
}

/// Open the archive described by `config`, or its copy in the replication region `region`,
/// and load its manifest.
async fn open_archive(
    config: &Configuration,
    region: Option<&str>,
) -> Result<OpenedArchive, PitrError> {
    let configured = PitrSettings::from_config(config)?.ok_or_else(|| {
        PitrError::Config(
            "online_backup.wal_archive is not enabled; it tells the command where the archive is"
                .to_string(),
        )
    })?;
    let (settings, primary) = match region {
        Some(name) => (configured.for_region(name)?, Some(configured)),
        None => (configured, None),
    };
    let store = PitrStore::open(&settings.location).await?;
    let mut manifest = store.load_manifest().await?.ok_or_else(|| {
        PitrError::NotRecoverable(format!(
            "no {PITR_MANIFEST_KEY} at {}; nothing has been archived",
            settings.location
        ))
    })?;

    // A region prunes its base backups on its own; recovery from it can only start from
    // the base backups it actually holds.
    if primary.is_some() {
        let held = settings.bases.list_keys().await?;
        let indexed = manifest.base_backups.len();
        manifest.retain_base_backups(&held);
        if manifest.base_backups.len() != indexed {
            warn!(
                missing = indexed - manifest.base_backups.len(),
                bases = %settings.bases,
                "Base backups indexed by the archive are missing in the region and are not used"
            );
        }
    }

    let mut local_only = BTreeSet::new();
    let local_segments = {
        let local_dir = settings.local_dir.clone();
        blocking(move || Ok(list_segments(&local_dir)?)).await?
    };
    for segment in local_segments {
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
        primary,
        store,
        manifest,
        local_only,
    })
}

/// `kubidmd database pitr-list`: print the base backups, segments and the recoverable
/// window. Returns false when nothing is recoverable or the archive could not be read.
pub async fn pitr_list_server_core(config: &Configuration, region: Option<&str>) -> bool {
    let OpenedArchive {
        settings,
        manifest,
        local_only,
        ..
    } = match open_archive(config, region).await {
        Ok(opened) => opened,
        Err(err) => {
            error!(%err, "Unable to read the PITR archive");
            println!("PITR archive: unavailable ({err})");
            return false;
        }
    };

    match region {
        Some(region) => println!("PITR archive at {} (region {region}):", settings.location),
        None => println!("PITR archive at {}:", settings.location),
    }
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
                "  {:<key_width$}  {:<35}  {:<35}  {}{}",
                base.key,
                base.timestamp,
                format_ts_rfc3339(base.watermark_ts),
                base.server_version,
                if is_encrypted_backup_name(&base.key) {
                    "  (encrypted)"
                } else {
                    ""
                }
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
            let note = if local_only.contains(&segment.segment_id) {
                "  (local, not archived yet)".to_string()
            } else if let Some(key) = &segment.encryption_key {
                format!("  (encrypted, key '{key}')")
            } else {
                String::new()
            };
            println!(
                "  {:<key_width$}  {:<35}  {:<35}  {:>8}  {:>12}{note}",
                segment.segment_id,
                format_ts_rfc3339(segment.start_ts),
                format_ts_rfc3339(segment.end_ts),
                segment.entry_count,
                segment.size_bytes,
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
    let mut keys = SegmentKeys::new(&opened.settings.encryption);
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
                &mut keys,
            )
            .await?;
        let compression = segment.compression;
        let file = blocking(move || Ok(parse_segment(&data, compression)?)).await?;
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
                } else if segment.encryption_key.is_some() {
                    ", encrypted"
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
    region: Option<&str>,
) -> Result<RecoveryOutcome, PitrError> {
    let opened = open_archive(config, region).await?;
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

    // Recovered from a region: the primary archive, which the recovered server archives
    // into, must learn about the abandoned history too. It is often unreachable when a
    // region is used, so this is best effort; the server merges what the region recorded
    // into the primary archive at its first synchronisation that reaches both.
    if let Some(primary) = &opened.primary {
        if let Err(err) = record_timeline_break(primary, recovered_ts, "recover").await {
            warn!(
                %err,
                "The abandoned history was recorded in the region, but not in the primary WAL \
                 archive at {}. The server merges it into the primary archive once it reaches \
                 both; until then take a new online backup right after starting the server.",
                primary.location
            );
        }
    }

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
    let local_segments = {
        let local_dir = settings.local_dir.clone();
        blocking(move || Ok(list_segments(&local_dir)?)).await?
    };
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
            encryption_key: None,
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

    fn fast_encryption(passphrase_file: &Path) -> BackupEncryptionConfig {
        BackupEncryptionConfig {
            enabled: true,
            key_source: kubidm_proto::backup::EncryptionKeySource::Passphrase,
            key_derivation: kubidm_proto::backup::KeyDerivationParams {
                m_cost: crate::backup::MIN_KDF_M_COST,
                t_cost: 1,
                p_cost: 1,
            },
            key_identifier: Some("unit-wal-key".to_string()),
            passphrase_file: Some(passphrase_file.to_path_buf()),
        }
    }

    fn append_create(archiver: &SharedWalArchiver, server: Uuid, secs: u64, data: &[u8]) {
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
                    WalPendingOp::Create {
                        entry_uuid: Uuid::new_v4(),
                        entry_data: data.to_vec(),
                    },
                )],
            )
            .unwrap();
    }

    fn opened(settings: &PitrSettings, manifest: PitrManifest) -> OpenedArchive {
        let PitrLocation::Local(dir) = &settings.location else {
            panic!("local settings expected");
        };
        OpenedArchive {
            settings: settings.clone(),
            primary: None,
            store: PitrStore::Local { dir: dir.clone() },
            manifest,
            local_only: BTreeSet::new(),
        }
    }

    #[tokio::test]
    async fn test_local_archive_encrypts_segments_and_recovery_decrypts_them() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let passphrase = dir.path().join("passphrase");
        fs::write(&passphrase, "unit test wal passphrase\n").unwrap();
        let wrong_passphrase = dir.path().join("wrong-passphrase");
        fs::write(&wrong_passphrase, "another passphrase\n").unwrap();

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
        let plain_settings = PitrSettings {
            wal: wal_cfg,
            local_dir: wal_dir.clone(),
            location: PitrLocation::Local(wal_dir.clone()),
            bases: bases.clone(),
            encryption: BackupEncryptionConfig::default(),
        };
        let encrypted_settings = PitrSettings {
            encryption: fast_encryption(&passphrase),
            ..plain_settings.clone()
        };
        let store = PitrStore::open(&plain_settings.location).await.unwrap();

        // Before encryption is enabled: a base and a plain segment, kept as it is.
        let plain_archive = PitrArchive::new(plain_settings.clone(), archiver.clone());
        let key = "backup-2024-01-01T00:00:00Z.json.gz.enc";
        fs::write(backup_dir.join(key), b"base").unwrap();
        plain_archive
            .register_base_backup(&bases, key, "2024-01-01T00:00:00Z", &report(1000, server))
            .await
            .unwrap();
        append_create(&archiver, server, 1100, b"credential before encryption");
        plain_archive
            .sync(Duration::from_secs(1100), true)
            .await
            .unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.segments.len(), 1);
        assert!(manifest.segments[0].encryption_key.is_none());
        assert_eq!(list_segments(&wal_dir).unwrap().len(), 1);

        // The key source is unavailable: nothing is archived in plaintext, the new segment
        // stays where the backend wrote it, and the run fails.
        let unavailable = PitrArchive::new(
            PitrSettings {
                encryption: fast_encryption(&dir.path().join("missing-passphrase")),
                ..plain_settings.clone()
            },
            archiver.clone(),
        );
        append_create(&archiver, server, 1200, b"credential after encryption");
        assert!(matches!(
            unavailable.sync(Duration::from_secs(1200), true).await,
            Err(PitrError::Encryption(_))
        ));
        assert_eq!(list_segments(&wal_dir).unwrap().len(), 2);
        assert_eq!(
            store.load_manifest().await.unwrap().unwrap().segments.len(),
            1
        );

        // With the key: both segments, the one archived before encryption was enabled
        // included, are sealed into `<segment>.enc` and their plaintext copies removed.
        let archive = PitrArchive::new(encrypted_settings.clone(), archiver.clone());
        let report_sync = archive
            .sync(Duration::from_secs(1300), false)
            .await
            .unwrap();
        assert_eq!(report_sync.archived, 2);
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.segments.len(), 2);
        for segment in &manifest.segments {
            assert_eq!(segment.encryption_key.as_deref(), Some("unit-wal-key"));
            let stored = wal_dir.join(segment.stored_name());
            assert!(stored.to_string_lossy().ends_with(".json.gz.enc"));
            assert!(is_encrypted_artifact(&fs::read(&stored).unwrap()));
            assert!(!wal_dir.join(&segment.segment_id).exists());
        }
        assert!(list_segments(&wal_dir).unwrap().is_empty());
        // A further run has nothing to do.
        let report_sync = archive
            .sync(Duration::from_secs(1400), false)
            .await
            .unwrap();
        assert_eq!(report_sync.archived, 0);

        // Recovery decrypts the segments and checks them against the plaintext checksums.
        let plan = plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.segments.len(), 2);
        let records = load_records(&opened(&encrypted_settings, manifest.clone()), &plan)
            .await
            .unwrap();
        let payloads: Vec<&[u8]> = records
            .iter()
            .map(|record| match &record.operation {
                WalOperationRecord::Create { entry_data } => entry_data.as_slice(),
                other => panic!("unexpected record {other:?}"),
            })
            .collect();
        assert_eq!(
            payloads,
            vec![
                b"credential before encryption".as_slice(),
                b"credential after encryption".as_slice()
            ]
        );

        // Without encryption enabled, or with another key, recovery refuses with a message
        // naming the key the segment needs.
        match load_records(&opened(&plain_settings, manifest.clone()), &plan).await {
            Err(PitrError::Encryption(msg)) => {
                assert!(
                    msg.contains("unit-wal-key") && msg.contains("not enabled"),
                    "{msg}"
                )
            }
            other => panic!("expected an encryption error, got {other:?}"),
        }
        let wrong_key = PitrSettings {
            encryption: fast_encryption(&wrong_passphrase),
            ..plain_settings.clone()
        };
        assert!(matches!(
            load_records(&opened(&wrong_key, manifest.clone()), &plan).await,
            Err(PitrError::Encryption(_))
        ));

        // A plain file in place of an encrypted segment is refused.
        let swapped = wal_dir.join(manifest.segments[0].stored_name());
        let original = fs::read(&swapped).unwrap();
        fs::write(&swapped, b"not encrypted").unwrap();
        assert!(matches!(
            load_records(&opened(&encrypted_settings, manifest.clone()), &plan).await,
            Err(PitrError::NotRecoverable(msg)) if msg.contains("not an encrypted container")
        ));
        fs::write(&swapped, original).unwrap();

        // Retention deletes the encrypted copy.
        store
            .delete_segment(&wal_dir, &manifest.segments[0])
            .await
            .unwrap();
        assert!(!swapped.exists());
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
