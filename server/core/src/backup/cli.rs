//! The offline backup commands of `kubidmd database`: taking, restoring, verifying and
//! listing backups, locally and in S3, and reporting the state of cross-region
//! replication. They only depend on the configuration, never on a running server.

use std::{
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};

use bytes::Bytes;
use kubidm_proto::{
    backup::{
        is_encrypted_backup_name, BackupCompression, ReplicationConfig, ReplicationHealthCheck,
        ReplicationRegionConfig, ReplicationStatus, S3BackupMetadata, S3Config,
        BACKUP_ENCRYPTED_SUFFIX,
    },
    internal::OperationError,
};
use kubidmd_lib::{
    be::{verify_backup_structure, BackendTransaction, BackupStructuralReport},
    schema::Schema,
};
use time::format_description::well_known::Rfc3339;

use super::{
    backup_identity, backup_name_timestamp, compare_backup_names, is_backup_artifact_name,
    lag_metrics_from_health, open_backup_file_with_config,
    pitr::{self, AbandonedHistory},
    region_is_healthy,
    restore::{
        backup_encryption_config, restore_and_replay_commit, restore_database, CommittedRestore,
        RestoreOutcome,
    },
    run_blocking, s3_location, seal_backup_async, verify_backup_output_async,
    write_verified_local_backup_async, BackupEncryptor, BackupVerifyError, S3BackupError,
    S3ClientWrapper,
};
use crate::{config::Configuration, setup_backend, verify_booted_database};

/// Take an offline backup of the database described by `config` into `dst_path`, or to
/// stdout without a path. The backup uses the compression and the client-side encryption
/// of the `[online_backup]` section, so it is interchangeable with an online backup.
///
/// `stdout_name` is the name a backup written to stdout will be stored under. It is checked
/// like a destination path, and an encrypted backup records its timestamp, so that it
/// opens under a `backup-<timestamp>` name; it is ignored with a `dst_path`.
///
/// Returns true when the backup was written and verified. Every failure, including a
/// database that can not be opened and a destination that already exists, returns false,
/// which the command turns into a non-zero exit code.
pub async fn backup_server_core(
    config: &Configuration,
    dst_path: Option<&Path>,
    stdout_name: Option<&str>,
) -> bool {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return false;
        }
    };

    let compression = match config.online_backup.as_ref() {
        Some(backup_config) => backup_config.compression,
        None => BackupCompression::default(),
    };

    // The key is obtained before the database is opened so that a missing key fails
    // without touching anything.
    let encryptor = match backup_encryption_config(config) {
        Some(encryption) => match BackupEncryptor::from_config(encryption).await {
            Ok(encryptor) => encryptor,
            Err(err) => {
                error!(%err, "Backup failed: unable to obtain the backup encryption key");
                return false;
            }
        },
        None => None,
    };

    // The name the backup is stored under, when it is known.
    let name = dst_path.or(stdout_name.map(Path::new));
    if let Some(name) = name {
        if let Err(reason) = check_backup_destination_name(name, compression, encryptor.is_some()) {
            error!("Backup failed: {reason}");
            return false;
        }
    } else if encryptor.is_some() {
        warn!(
            "The encrypted backup written to stdout records no timestamp, so it only opens \
             under a name that claims none: stored as backup-<timestamp>{}{BACKUP_ENCRYPTED_SUFFIX}, \
             restore refuses it. Pass --name with the name it will be stored under.",
            compression.suffix()
        );
    }
    if let Some(dst_path) = dst_path {
        if dst_path.exists() {
            error!(
                "Backup failed: backup file {} already exists, will not overwrite it.",
                dst_path.display()
            );
            return false;
        }
    }

    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Backup failed: unable to open the database: {:?}", e);
            return false;
        }
    };

    // The backup is produced in memory first so that it can be encrypted and so that only
    // a verified backup is ever emitted to stdout. Serialising and compressing the whole
    // database is blocking work, so it runs on the blocking thread pool.
    let backup_data = tokio::task::spawn_blocking(move || {
        let mut be_ro_txn = be.read().inspect_err(|err| {
            error!(?err, "Unable to proceed, backend read transaction failure.");
        })?;
        let mut backup_data = Vec::new();
        be_ro_txn.backup(&mut backup_data, compression)?;
        // Let the txn abort, even on success.
        Ok::<_, OperationError>(backup_data)
    })
    .await;
    let backup_data = match backup_data {
        Ok(Ok(backup_data)) => backup_data,
        Ok(Err(e)) => {
            error!("Backup failed: {:?}", e);
            return false;
        }
        Err(err) => {
            error!(%err, "Backup failed: the backup task failed");
            return false;
        }
    };

    // Written to stdout without a name, the backup claims no timestamp.
    let identity = backup_identity(name.unwrap_or(Path::new("")));
    let artifact =
        match seal_backup_async(backup_data, compression, encryptor.as_ref(), identity).await {
            Ok(artifact) => artifact,
            Err(err) => {
                error!(%err, "Backup failed: unable to encrypt the backup");
                return false;
            }
        };

    let artifact = Bytes::from(artifact);
    if let Some(dst_path) = dst_path {
        // Written next to the destination, synced and read back before it gets its name,
        // so the destination only ever holds a complete, verified backup. A rejected
        // artifact is kept under an `.invalid` suffix for inspection.
        if !report_backup_verification(
            write_verified_local_backup_async(dst_path, artifact, compression, encryptor.as_ref())
                .await,
        ) {
            return false;
        }
        info!("Backup written to {}", dst_path.display());
    } else {
        if !report_backup_verification(
            verify_backup_output_async(artifact.clone(), name, compression, encryptor.as_ref())
                .await,
        ) {
            return false;
        }

        let mut stdout = std::io::stdout().lock();
        if let Err(err) = stdout.write_all(&artifact).and_then(|()| stdout.flush()) {
            error!(?err, "Backup failed: unable to write to stdout");
            return false;
        }
    };

    if let Some(encryptor) = &encryptor {
        eprintln!("Backup encrypted with key '{}'", encryptor.key_identifier());
    }
    info!("Backup success!");
    true
}

/// Check the destination of a manual backup against what will be written to it, before
/// anything is: restore and `verify-backup` take a plain backup's compression from its
/// name and refuse a plain backup named as an encrypted one, so such a name would hold a
/// backup that can not be restored. An encrypted backup records its compression itself
/// and is recognised by its content, so a name without the encrypted suffix only warns.
fn check_backup_destination_name(
    dst_path: &Path,
    compression: BackupCompression,
    encrypted: bool,
) -> Result<(), String> {
    let name = dst_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let named_encrypted = is_encrypted_backup_name(name);

    if encrypted {
        if !named_encrypted {
            warn!(
                "Backup encryption is enabled: {} will hold an encrypted artifact although \
                 its name does not end in {BACKUP_ENCRYPTED_SUFFIX}",
                dst_path.display()
            );
        }
        return Ok(());
    }

    if named_encrypted {
        return Err(format!(
            "{} ends in {BACKUP_ENCRYPTED_SUFFIX} but backup encryption is not enabled; \
             restore refuses a plain backup under an encrypted name",
            dst_path.display()
        ));
    }

    let named_compression = BackupCompression::identify_name(name);
    if named_compression != compression {
        return Err(format!(
            "{} is named as a {named_compression} backup but the configured compression is \
             {compression}; restore takes the compression of a plain backup from its name, \
             so name it with the suffix '.json{}'",
            dst_path.display(),
            compression.suffix()
        ));
    }

    Ok(())
}

/// Print the outcome of the post-write verification of a manual backup. Returns whether
/// the backup passed; a rejected backup fails the command, as a failed write does.
fn report_backup_verification(verified: Result<BackupStructuralReport, BackupVerifyError>) -> bool {
    match verified {
        Ok(report) => {
            eprintln!(
                "Backup verified: {} entries, written by server version {}",
                report.entry_count,
                report.version.as_deref().unwrap_or("unknown")
            );
            true
        }
        Err(err) => {
            error!("Backup failed verification: {err}");
            eprintln!("Backup verification: FAIL");
            for reason in &err.reasons {
                eprintln!("  - {reason}");
            }
            if let Some(path) = &err.quarantined_to {
                eprintln!("  The rejected artifact was kept as {}", path.display());
            }
            false
        }
    }
}

/// How a restore that restored the database ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreStatus {
    /// The database was restored, and when WAL archiving is configured, the archive
    /// recorded that the history after the restored backup was abandoned.
    Complete,
    /// The database was restored and committed, but the WAL archive could not record the
    /// abandoned history, typically because the archive's location is unavailable, as when
    /// restoring from a replication region while the primary bucket is down. The restore
    /// must not be repeated or rolled back. The restore is handed to the server, which
    /// records it at its first synchronisation that reaches the archive; should even that
    /// fail, a new online backup after the server start makes point-in-time recovery safe
    /// again.
    WalArchiveNotUpdated,
}

impl RestoreStatus {
    /// The exit code of a restore command that ended this way: 0 when complete, 2 when the
    /// database was restored but the WAL archive was not updated, so that automation can
    /// tell it apart from a failed restore, which exits with 1.
    pub fn exit_code(self) -> u8 {
        match self {
            RestoreStatus::Complete => 0,
            RestoreStatus::WalArchiveNotUpdated => 2,
        }
    }
}

/// Restore the backup at `dst_path` into the database described by `config`, the
/// `database restore` command. Fails when the database was not restored, or when it was
/// restored but could not be reindexed, which the error log reports as a changed database.
pub async fn restore_server_core(
    config: &Configuration,
    dst_path: &Path,
) -> Result<RestoreStatus, OperationError> {
    let committed = restore_and_replay_commit(config, dst_path, Vec::new()).await?;
    finish_restore(config, committed).await
}

/// The steps of a restore after its commit. The database holds the backup from here on,
/// so the history after it is abandoned whatever happens next: that is recorded first,
/// then the database is reindexed.
async fn finish_restore(
    config: &Configuration,
    committed: CommittedRestore,
) -> Result<RestoreStatus, OperationError> {
    let status = note_restore_in_wal_archive(config, &committed.outcome).await;
    committed.reindex(config).await.inspect_err(|_| {
        error!("Run `kubidmd database reindex` before starting the server");
    })?;
    Ok(status)
}

/// After a restore of the configured database, record in the WAL archive (when one is
/// configured) that the history after the restored backup was abandoned, so that a later
/// point-in-time recovery never replays it.
async fn note_restore_in_wal_archive(
    config: &Configuration,
    outcome: &RestoreOutcome,
) -> RestoreStatus {
    match pitr::note_restore(config, outcome.watermark, outcome.server_uuid).await {
        Ok(AbandonedHistory::Recorded) => RestoreStatus::Complete,
        Ok(AbandonedHistory::Deferred(err)) => {
            warn!(
                %err,
                "The database WAS restored; do not restore it again. The WAL archive could not \
                 be updated, as when restoring from a replication region while the primary is \
                 down: the server records the abandoned history in the archive at its first \
                 synchronisation that reaches it."
            );
            RestoreStatus::WalArchiveNotUpdated
        }
        Err(err) => {
            error!(
                %err,
                "The database WAS restored; do not restore it again. The abandoned history \
                 could not be recorded in the WAL archive nor handed to the server. A later \
                 point-in-time recovery past this point could replay it: take a new online \
                 backup right after starting the server."
            );
            RestoreStatus::WalArchiveNotUpdated
        }
    }
}

/// How deeply `verify_backup_server_core` inspects a backup artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupVerifyLevel {
    /// Parse the artifact and check its format, entry count and server version. This
    /// never opens a database and can not prove that the backup is restorable.
    Structural,
    /// Everything in `Structural`, then restore the artifact into a scratch database
    /// through the production restore path, re-open that database as a server start
    /// would and run the full database consistency verification on it.
    Full,
}

/// Verify a backup artifact. Returns true when the backup passed every check of the
/// requested level. The database referenced by `config` is never opened: full
/// verification restores into a temporary directory that is removed afterwards.
pub async fn verify_backup_server_core(
    config: &Configuration,
    backup_path: &Path,
    level: BackupVerifyLevel,
) -> bool {
    let opened =
        match open_backup_file_with_config(backup_path, backup_encryption_config(config)).await {
            Ok(opened) => opened,
            Err(err) => {
                error!(%err, "Unable to open backup {}", backup_path.display());
                eprintln!("Backup structural verification: FAIL");
                eprintln!("  - unable to open {}: {err}", backup_path.display());
                return false;
            }
        };
    let encryption_key = opened.key_identifier().map(str::to_string);

    // Decompressing and parsing the whole backup is blocking work.
    let compression = opened.compression;
    let reader = opened.reader;
    let parsed =
        tokio::task::spawn_blocking(move || verify_backup_structure(reader, compression)).await;
    let report = match parsed {
        Ok(report) => report,
        Err(err) => {
            eprintln!("Backup structural verification: FAIL");
            eprintln!("  - the verification task failed: {err}");
            return false;
        }
    };

    eprintln!(
        "Backup structural verification: {}",
        pass_fail(report.is_valid())
    );
    eprintln!(
        "  Encrypted: {}",
        match &encryption_key {
            Some(key) => format!("yes, key '{key}'"),
            None => "no".to_string(),
        }
    );
    eprintln!("  Entries: {}", report.entry_count);
    eprintln!(
        "  Written by server version: {}",
        report.version.as_deref().unwrap_or("unknown")
    );
    for issue in &report.errors {
        eprintln!("  - {issue}");
    }

    if !report.is_valid() || level == BackupVerifyLevel::Structural {
        return report.is_valid();
    }

    let scratch_dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => {
            error!(?err, "Unable to create a scratch directory");
            eprintln!("Backup restore verification: FAIL");
            eprintln!("  - unable to create a scratch directory: {err}");
            return false;
        }
    };

    let mut scratch_config = config.clone();
    scratch_config.db_path = Some(scratch_dir.path().join("verify.db"));

    info!(
        "Restoring backup into scratch database in {}",
        scratch_dir.path().display()
    );

    if let Err(err) = restore_database(&scratch_config, backup_path).await {
        eprintln!("Backup restore verification: FAIL");
        eprintln!("  - restore failed: {err:?}");
        return false;
    }

    // Boot the restored database from scratch exactly as a server start would. The
    // restore above ran in this process, so its backend still carries in-memory state
    // from before the restore (such as the RUV). A fresh boot is what proves the
    // database starts into a consistent state.
    let consistency_errors = match verify_booted_database(&scratch_config).await {
        Ok(errors) => errors,
        Err(err) => {
            eprintln!("Backup restore verification: FAIL");
            eprintln!("  - restored database could not be opened: {err:?}");
            return false;
        }
    };

    eprintln!(
        "Backup restore verification: {}",
        pass_fail(consistency_errors.is_empty())
    );
    for err in &consistency_errors {
        eprintln!("  - {err:?}");
    }

    consistency_errors.is_empty()
}

fn pass_fail(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

/// The `[[online_backup.s3.replication.regions]]` entries of the configuration, whether
/// or not replication is enabled: a replica stays a valid recovery source after
/// replication has been switched off.
fn configured_replication_regions(config: &Configuration) -> &[ReplicationRegionConfig] {
    config
        .online_backup
        .as_ref()
        .and_then(|backup| backup.s3.as_ref())
        .and_then(|s3| s3.replication.as_ref())
        .map(|replication| replication.regions.as_slice())
        .unwrap_or_default()
}

/// The replication region named `name`, as selected by `--region` on the recovery
/// commands. The error is logged before it is returned.
fn replication_region<'a>(
    config: &'a Configuration,
    name: &str,
) -> Result<&'a ReplicationRegionConfig, OperationError> {
    let regions = configured_replication_regions(config);
    regions
        .iter()
        .find(|region| region.name() == name)
        .ok_or_else(|| {
            if regions.is_empty() {
                error!(
                    "--region {name}: no replication region is configured under \
                     [online_backup.s3.replication], so there is no replica to target."
                );
            } else {
                let names: Vec<&str> = regions.iter().map(|r| r.name()).collect();
                error!(
                    "--region {name}: no replication region of that name is configured. \
                     Configured regions: {}",
                    names.join(", ")
                );
            }
            OperationError::InvalidState
        })
}

/// Resolve the S3 configuration an offline recovery command (`restore-s3`, `verify-s3`,
/// `list-backups`) uses.
///
/// Without `region`, that is the `[online_backup.s3]` section of the server configuration
/// (the primary). With `region`, it is the `[[online_backup.s3.replication.regions]]` entry
/// of that name: the replica's bucket, endpoint, prefix, credentials and encryption, so a
/// backup can be recovered from a replica while the primary is unavailable. `bucket` and
/// `endpoint` then override whichever was selected. Without a configured section and
/// without `region`, `bucket` must be given; credentials and region then come from the
/// SDK's default provider chain.
pub fn s3_config_for_cli(
    config: &Configuration,
    bucket: Option<String>,
    region: Option<&str>,
    endpoint: Option<String>,
) -> Result<S3Config, OperationError> {
    let configured = match region {
        Some(name) => Some(replication_region(config, name)?.to_s3_config()),
        None => config
            .online_backup
            .as_ref()
            .and_then(|backup| backup.s3.clone()),
    };

    let mut s3_config = match (configured, bucket) {
        (Some(mut s3_config), bucket) => {
            if let Some(bucket) = bucket {
                s3_config.bucket = bucket;
            }
            s3_config
        }
        (None, Some(bucket)) => S3Config::with_bucket(bucket),
        (None, None) => {
            error!(
                "No [online_backup.s3] section is present in the configuration and no \
                 --bucket was given. Unable to locate the S3 backups."
            );
            return Err(OperationError::InvalidState);
        }
    };

    if let Some(endpoint) = endpoint {
        s3_config.endpoint = Some(endpoint);
    }

    Ok(s3_config)
}

/// A backup downloaded from S3 into a temporary directory. The directory, and with it the
/// downloaded artifact, is removed when this value is dropped.
pub(crate) struct FetchedS3Backup {
    _scratch_dir: tempfile::TempDir,
    pub(crate) path: PathBuf,
    pub(crate) metadata: S3BackupMetadata,
}

/// Download the backup `key` from S3, verifying its SHA-256 against the metadata sidecar,
/// into a temporary file. The file is named so that `BackupCompression::identify_file`
/// recognises the compression recorded in the metadata and so that an encrypted artifact
/// carries the `.enc` suffix, which lets the local restore and verification paths treat it
/// exactly like a local artifact (the encrypted container is recognised by its content,
/// the name only keeps it consistent).
pub(crate) async fn fetch_s3_backup(
    s3_config: S3Config,
    key: &str,
) -> Result<FetchedS3Backup, S3BackupError> {
    let client = S3ClientWrapper::new(s3_config).await?;
    let (data, metadata) = client.download_backup(key).await?;

    let scratch_dir = tempfile::tempdir()?;
    // The requested key counts as well as the sidecar: the sidecar is not authenticated, so
    // an object requested as `.enc` must be an encrypted container whatever it says.
    let encryption_suffix = if metadata.encrypted || is_encrypted_backup_name(key) {
        BACKUP_ENCRYPTED_SUFFIX
    } else {
        ""
    };
    // An encrypted backup records the timestamp of the name it was written under, so the
    // download keeps the timestamp of the key: an older backup stored under a newer key is
    // refused like a local one.
    let stem = match backup_name_timestamp(key.rsplit('/').next().unwrap_or(key)) {
        Some(timestamp) => format!("backup-{timestamp}"),
        None => "backup".to_string(),
    };
    let path = scratch_dir.path().join(format!(
        "{stem}.json{}{encryption_suffix}",
        metadata.compression.suffix()
    ));
    let write_to = path.clone();
    run_blocking(move || std::fs::write(write_to, data)).await?;

    info!(
        key,
        size_bytes = metadata.size_bytes,
        checksum_sha256 = %metadata.checksum_sha256,
        timestamp = %metadata.timestamp,
        encrypted = metadata.encrypted,
        encryption_key = ?metadata.key_identifier,
        "Downloaded S3 backup to {}",
        path.display()
    );

    Ok(FetchedS3Backup {
        _scratch_dir: scratch_dir,
        path,
        metadata,
    })
}

/// Restore the backup stored under `key` in S3 into the database described by `config`.
/// The artifact is downloaded, its SHA-256 is checked against the metadata sidecar, and it
/// is then restored through `restore_database`. The database is not touched when the
/// download or the checksum check fails.
pub async fn restore_s3_database(
    config: &Configuration,
    s3_config: S3Config,
    key: &str,
) -> Result<RestoreStatus, OperationError> {
    let fetched = fetch_s3_backup(s3_config, key).await.map_err(|err| {
        error!(%err, "Unable to download backup {key} from S3");
        OperationError::InvalidState
    })?;

    info!(
        "Restoring S3 backup {key} ({} bytes, sha256 {})",
        fetched.metadata.size_bytes, fetched.metadata.checksum_sha256
    );

    let committed = restore_and_replay_commit(config, &fetched.path, Vec::new()).await?;
    // Remove the downloaded artifact.
    drop(fetched);
    finish_restore(config, committed).await
}

/// Verify the backup stored under `key` in S3. The SHA-256 of the stored object is checked
/// against its metadata sidecar first; when it matches, the downloaded artifact goes
/// through `verify_backup_server_core` at the requested level. Returns true when every
/// check passed. The database referenced by `config` is never opened.
pub async fn verify_s3_backup_server_core(
    config: &Configuration,
    s3_config: S3Config,
    key: &str,
    level: BackupVerifyLevel,
) -> bool {
    let fetched = match fetch_s3_backup(s3_config, key).await {
        Ok(fetched) => fetched,
        Err(S3BackupError::InvalidChecksum { expected, actual }) => {
            eprintln!("S3 checksum verification: FAIL");
            eprintln!("  - {key}: expected sha256 {expected}, got {actual}");
            return false;
        }
        Err(err) => {
            eprintln!("S3 download: FAIL - {err}");
            return false;
        }
    };

    eprintln!("S3 checksum verification: PASS");
    eprintln!("  Key: {key}");
    eprintln!("  Size: {} bytes", fetched.metadata.size_bytes);
    eprintln!("  SHA-256: {}", fetched.metadata.checksum_sha256);
    eprintln!("  Uploaded: {}", fetched.metadata.timestamp);
    if fetched.metadata.encrypted {
        eprintln!(
            "  Encrypted: yes, key '{}'",
            fetched
                .metadata
                .key_identifier
                .as_deref()
                .unwrap_or("unknown")
        );
    }

    verify_backup_server_core(config, &fetched.path, level).await
}

/// List the backups in the configured locations: the local online backup directory and the
/// S3 prefix, or, with `region`, the prefix of that replication region instead of the
/// primary. A location that is not configured is reported as such. Returns false only when
/// a configured location could not be read, or when `region` names no configured region.
pub async fn list_backups_server_core(
    config: &Configuration,
    local_only: bool,
    s3_only: bool,
    region: Option<&str>,
) -> bool {
    // A replica holds no local backups, so a region listing is an S3 listing.
    let s3_only = s3_only || region.is_some();
    let mut ok = true;

    if !s3_only {
        ok &= list_local_backups(config);
    }

    if !local_only {
        if !s3_only {
            println!();
        }
        ok &= list_s3_backups(config, region).await;
    }

    ok
}

fn list_local_backups(config: &Configuration) -> bool {
    let Some(path) = config
        .online_backup
        .as_ref()
        .and_then(|backup| backup.path.as_ref())
    else {
        println!("Local backups: none configured");
        return true;
    };

    println!("Local backups in {}:", path.display());

    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) => {
            error!(?err, "Unable to read backup directory {}", path.display());
            println!("  error: unable to read {}: {err}", path.display());
            return false;
        }
    };

    let mut rows: Vec<(String, u64, String, &str)> = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                error!(?err, "Unable to read backup directory {}", path.display());
                println!("  error: unable to read {}: {err}", path.display());
                return false;
            }
        };

        let entry_path = entry.path();
        let Some(name) = entry_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !entry_path.is_file() || !is_backup_artifact_name(name) {
            continue;
        }

        let (size, modified) = match entry.metadata() {
            Ok(metadata) => (
                metadata.len(),
                metadata
                    .modified()
                    .map(format_system_time)
                    .unwrap_or_else(|_| "unknown".to_string()),
            ),
            Err(err) => {
                error!(?err, "Unable to read metadata of {}", entry_path.display());
                println!("  error: unable to read {}: {err}", entry_path.display());
                return false;
            }
        };
        let encrypted = if is_encrypted_backup_name(name) {
            "yes"
        } else {
            "no"
        };
        rows.push((name.to_string(), size, modified, encrypted));
    }

    if rows.is_empty() {
        println!("  (no backups)");
        return true;
    }

    rows.sort_by(|a, b| compare_backup_names(&a.0, &b.0));
    let name_width = rows
        .iter()
        .map(|(name, _, _, _)| name.len())
        .max()
        .unwrap_or(0);
    println!(
        "  {:<name_width$}  {:>12}  {:<20}  ENCRYPTED",
        "NAME", "SIZE_BYTES", "MODIFIED"
    );
    for (name, size, modified, encrypted) in rows {
        println!("  {name:<name_width$}  {size:>12}  {modified:<20}  {encrypted}");
    }

    true
}

async fn list_s3_backups(config: &Configuration, region: Option<&str>) -> bool {
    let s3_config = match region {
        Some(name) => match replication_region(config, name) {
            Ok(region_config) => region_config.to_s3_config(),
            Err(_) => {
                println!("S3 backups in region {name}: no such replication region is configured");
                return false;
            }
        },
        None => match config
            .online_backup
            .as_ref()
            .and_then(|backup| backup.s3.clone())
        {
            Some(s3_config) => s3_config,
            None => {
                println!("S3 backups: none configured");
                return true;
            }
        },
    };

    let location = s3_location(&s3_config);
    match region {
        Some(name) => println!("S3 backups in region {name} ({location}):"),
        None => println!("S3 backups in {location}:"),
    }

    let client = match S3ClientWrapper::new(s3_config).await {
        Ok(client) => client,
        Err(err) => {
            error!(%err, "Unable to create the S3 client");
            println!("  error: unable to create the S3 client: {err}");
            return false;
        }
    };

    let listing = match client.list_backup_listing().await {
        Ok(listing) => listing,
        Err(err) => {
            error!(%err, "Unable to list S3 backups");
            println!("  error: unable to list {location}: {err}");
            return false;
        }
    };
    let keys = listing.complete;

    if !listing.incomplete.is_empty() {
        // Not a failure: the retention of the next backup removes them.
        println!(
            "  note: {} backup object(s) without metadata, left by failed uploads, are not \
             listed: {}",
            listing.incomplete.len(),
            listing.incomplete.join(", ")
        );
    }

    if keys.is_empty() {
        println!("  (no backups)");
        return true;
    }

    // Fetch every sidecar first so that the columns can be sized to the content.
    let mut ok = true;
    let mut rows: Vec<(String, Result<S3BackupMetadata, S3BackupError>)> = Vec::new();
    for key in keys {
        let metadata = client.get_backup_metadata(&key).await;
        if let Err(err) = &metadata {
            error!(%err, "Unable to read the metadata of S3 backup {key}");
            ok = false;
        }
        rows.push((key, metadata));
    }

    let key_width = rows.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    let time_width = rows
        .iter()
        .filter_map(|(_, metadata)| metadata.as_ref().ok())
        .map(|metadata| metadata.timestamp.len())
        .max()
        .unwrap_or(0)
        .max("UPLOADED".len());
    println!(
        "  {:<key_width$}  {:>12}  {:<time_width$}  {:<12}  ENCRYPTED",
        "KEY", "SIZE_BYTES", "UPLOADED", "SHA256"
    );
    for (key, metadata) in rows {
        match metadata {
            Ok(metadata) => {
                let short_checksum: String = metadata.checksum_sha256.chars().take(12).collect();
                let encrypted = match (metadata.encrypted, &metadata.key_identifier) {
                    (true, Some(key_identifier)) => format!("yes, key '{key_identifier}'"),
                    (true, None) => "yes".to_string(),
                    (false, _) => "no".to_string(),
                };
                println!(
                    "  {key:<key_width$}  {:>12}  {:<time_width$}  {short_checksum:<12}  {encrypted}",
                    metadata.size_bytes, metadata.timestamp
                );
            }
            Err(err) => println!("  {key:<key_width$}  metadata unavailable: {err}"),
        }
    }

    ok
}

/// Report the state of cross-region backup replication: for every configured region,
/// which of the primary's backups it holds intact, its newest backup and how far it lags
/// behind the primary. `detailed` adds the lag metrics of every region. The database is
/// never opened, so the command can run next to a running server.
///
/// Returns false when replication is not configured or disabled, when the primary bucket
/// can not be listed, or when any region is unhealthy, so the exit code of
/// `replicate-status` is usable from monitoring.
pub async fn replicate_status_server_core(config: &Configuration, detailed: bool) -> bool {
    let Some(s3_config) = config
        .online_backup
        .as_ref()
        .and_then(|backup| backup.s3.clone())
    else {
        println!("Cross-region backup replication: not configured ([online_backup.s3] is absent)");
        return false;
    };

    let Some(replication) = s3_config
        .replication
        .clone()
        .filter(|replication| replication.enabled)
    else {
        println!(
            "Cross-region backup replication: not configured ([online_backup.s3.replication] \
             is absent or disabled)"
        );
        return false;
    };

    let primary = s3_location(&s3_config);
    let client = match S3ClientWrapper::new(s3_config).await {
        Ok(client) => client,
        Err(err) => {
            error!(%err, "Unable to create the S3 client");
            println!("Cross-region backup replication: unable to create the S3 client: {err}");
            return false;
        }
    };

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let health = match client
        .check_replication_health(&replication, Some(&now))
        .await
    {
        Ok(health) => health,
        Err(err) => {
            error!(%err, "Unable to list the primary backups in {primary}");
            println!(
                "Cross-region backup replication: unable to list the primary backups in \
                 {primary}: {err}"
            );
            return false;
        }
    };

    print!(
        "{}",
        format_replication_report(&primary, &health, &replication, detailed)
    );

    !health.regions.is_empty() && health.unhealthy_regions == 0
}

/// The text `replicate-status` prints for a health check.
fn format_replication_report(
    primary: &str,
    health: &ReplicationHealthCheck,
    replication: &ReplicationConfig,
    detailed: bool,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    // Writing to a String can not fail; the results are ignored on purpose.
    let _ = writeln!(
        out,
        "Cross-region backup replication: {}",
        health.overall_status
    );
    let _ = writeln!(out, "  Primary: {primary}");
    if !health.last_check_timestamp.is_empty() {
        let _ = writeln!(out, "  Checked: {}", health.last_check_timestamp);
    }
    let _ = writeln!(
        out,
        "  Regions: {} healthy, {} unhealthy",
        health.healthy_regions, health.unhealthy_regions
    );

    if health.regions.is_empty() {
        return out;
    }

    let short_status = |status: &ReplicationStatus| -> &'static str {
        match status {
            ReplicationStatus::NotConfigured => "Not Configured",
            ReplicationStatus::Pending => "Pending",
            ReplicationStatus::InProgress => "In Progress",
            ReplicationStatus::Completed => "Completed",
            ReplicationStatus::Failed { .. } => "Failed",
            ReplicationStatus::Degraded { .. } => "Degraded",
        }
    };
    let newest = |region: &kubidm_proto::backup::ReplicationRegionStatus| -> String {
        region
            .last_sync_backup_id
            .clone()
            .unwrap_or_else(|| "-".to_string())
    };
    let lag = |region: &kubidm_proto::backup::ReplicationRegionStatus| -> String {
        region
            .lag_seconds
            .map(|lag| format!("{lag}s"))
            .unwrap_or_else(|| "-".to_string())
    };

    let width = |header: &str, values: &mut dyn Iterator<Item = usize>| -> usize {
        values.max().unwrap_or(0).max(header.len())
    };
    let region_width = width(
        "REGION",
        &mut health.regions.iter().map(|region| region.region.len()),
    );
    let bucket_width = width(
        "BUCKET",
        &mut health.regions.iter().map(|region| region.bucket.len()),
    );
    let status_width = width(
        "STATUS",
        &mut health
            .regions
            .iter()
            .map(|region| short_status(&region.status).len()),
    );
    let newest_width = width(
        "NEWEST",
        &mut health.regions.iter().map(|region| newest(region).len()),
    );

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {:<region_width$}  {:<bucket_width$}  {:<status_width$}  {:>10}  {:>7}  {:<newest_width$}  LAG",
        "REGION", "BUCKET", "STATUS", "REPLICATED", "PENDING", "NEWEST"
    );
    for region in &health.regions {
        let _ = writeln!(
            out,
            "  {:<region_width$}  {:<bucket_width$}  {:<status_width$}  {:>10}  {:>7}  {:<newest_width$}  {}",
            region.region,
            region.bucket,
            short_status(&region.status),
            region.backups_replicated,
            region.pending_backups,
            newest(region),
            lag(region)
        );
        if !region_is_healthy(region) {
            let _ = writeln!(out, "    {}", region.status);
        }
    }

    if detailed {
        let _ = writeln!(out);
        let _ = writeln!(out, "  Lag metrics:");
        let metrics = lag_metrics_from_health(health, replication);
        for (metric, region) in metrics.iter().zip(&health.regions) {
            let _ = writeln!(
                out,
                "    {}: lag {}, pending {}, newest replicated {}, bytes replicated {}, \
                 check interval {}s",
                metric.region,
                // The metric reports an unknown lag (the region holds none of the primary's
                // backups) as 0; the report says it is unknown.
                lag(region),
                metric.pending_backups,
                metric.last_backup_timestamp.as_deref().unwrap_or("-"),
                region.bytes_replicated,
                metric.replication_delay_seconds
            );
            if let Some(error) = &region.last_error {
                let _ = writeln!(out, "      last error: {error}");
            }
        }
    }

    out
}

/// Format a file modification time as an RFC3339 UTC timestamp with second precision.
fn format_system_time(time: SystemTime) -> String {
    let datetime = time::OffsetDateTime::from(time);
    datetime
        .replace_nanosecond(0)
        .unwrap_or(datetime)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OnlineBackup;
    use kubidm_proto::backup::{ReplicationRegionStatus, S3Credentials};

    fn region(name: &str, bucket: &str) -> ReplicationRegionConfig {
        ReplicationRegionConfig {
            name: None,
            region: name.to_string(),
            endpoint: Some(format!("https://s3.{name}.example.com")),
            bucket: bucket.to_string(),
            path_prefix: Some("dr".to_string()),
            credentials: Some(S3Credentials {
                access_key_id: format!("{name}-key"),
                secret_access_key: format!("{name}-secret"),
                session_token: None,
            }),
            server_side_encryption: None,
            storage_class: "STANDARD_IA".to_string(),
            kms_key_id: None,
        }
    }

    fn config_with_s3(replication: Option<ReplicationConfig>) -> Configuration {
        let s3 = S3Config {
            bucket: "primary".to_string(),
            region: Some("us-east-1".to_string()),
            endpoint: Some("https://s3.primary.example.com".to_string()),
            path_prefix: Some("prod".to_string()),
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            replication,
        };
        Configuration {
            online_backup: Some(OnlineBackup {
                s3: Some(s3),
                ..OnlineBackup::default()
            }),
            ..Configuration::new_for_test()
        }
    }

    fn replication(enabled: bool) -> ReplicationConfig {
        ReplicationConfig {
            enabled,
            regions: vec![
                region("eu-west-1", "primary-eu"),
                region("ap-southeast-1", "primary-ap"),
            ],
            ..ReplicationConfig::default()
        }
    }

    #[test]
    fn restore_status_exit_codes_tell_a_restored_database_apart() {
        assert_eq!(RestoreStatus::Complete.exit_code(), 0);
        // Restored, but the archive was not updated: neither success nor the failure (1)
        // that automation would retry or roll back.
        assert_eq!(RestoreStatus::WalArchiveNotUpdated.exit_code(), 2);
    }

    #[tokio::test]
    async fn manual_backup_reports_every_failure() {
        let dir = tempfile::tempdir().expect("tempdir");

        // The destination exists: nothing is written, and the command fails.
        let existing = dir.path().join("kubidm.json.gz");
        std::fs::write(&existing, b"an older backup").expect("write");
        let config = Configuration::new_for_test();
        assert!(!backup_server_core(&config, Some(&existing), None).await);
        assert_eq!(std::fs::read(&existing).expect("read"), b"an older backup");

        // The database can not be opened.
        let config = Configuration {
            db_path: Some(dir.path().join("missing").join("kubidm.db")),
            ..Configuration::new_for_test()
        };
        let dest = dir.path().join("new.json.gz");
        assert!(!backup_server_core(&config, Some(&dest), None).await);
        assert!(!dest.exists());

        // The name a backup to stdout will be stored under is checked like a path, before
        // anything is written: a gzip backup can not be stored as plain JSON.
        let config = Configuration::new_for_test();
        assert!(!backup_server_core(&config, None, Some("backup-2024-01-01T22:00:00Z.json")).await);
    }

    #[test]
    fn manual_backup_refuses_a_destination_restore_could_not_read() {
        let gzip = BackupCompression::Gzip;
        let plain = BackupCompression::NoCompression;

        // Names that announce what is written are accepted.
        assert!(check_backup_destination_name(Path::new("/b/kubidm.json.gz"), gzip, false).is_ok());
        assert!(check_backup_destination_name(Path::new("/b/kubidm.json"), plain, false).is_ok());
        assert!(
            check_backup_destination_name(Path::new("/b/kubidm.json.gz.enc"), gzip, true).is_ok()
        );
        // An encrypted backup records its compression, and is recognised by its content.
        assert!(check_backup_destination_name(Path::new("/b/kubidm.json"), gzip, true).is_ok());

        // Gzip under a plain name would be parsed as plain JSON on restore.
        let err = check_backup_destination_name(Path::new("/b/kubidm.json"), gzip, false)
            .expect_err("a gzip backup under a plain name must be refused");
        assert!(err.contains(".json.gz"), "{err}");
        // And the other way round.
        assert!(
            check_backup_destination_name(Path::new("/b/kubidm.json.gz"), plain, false).is_err()
        );
        // A plain backup under an encrypted name is refused by restore.
        let err = check_backup_destination_name(Path::new("/b/kubidm.json.gz.enc"), gzip, false)
            .expect_err("a plain backup under an encrypted name must be refused");
        assert!(err.contains("not enabled"), "{err}");
    }

    #[test]
    fn s3_config_for_cli_uses_the_primary_without_region() {
        let config = config_with_s3(Some(replication(true)));
        let s3 = s3_config_for_cli(&config, None, None, None).expect("primary");
        assert_eq!(s3.bucket, "primary");
        assert_eq!(s3.path_prefix.as_deref(), Some("prod"));
        assert_eq!(
            s3.endpoint.as_deref(),
            Some("https://s3.primary.example.com")
        );

        // Overrides replace the selected settings.
        let s3 = s3_config_for_cli(
            &config,
            Some("other".to_string()),
            None,
            Some("https://alt.example.com".to_string()),
        )
        .expect("primary with overrides");
        assert_eq!(s3.bucket, "other");
        assert_eq!(s3.endpoint.as_deref(), Some("https://alt.example.com"));
        assert_eq!(s3.path_prefix.as_deref(), Some("prod"));
    }

    #[test]
    fn s3_config_for_cli_targets_the_named_region() {
        let config = config_with_s3(Some(replication(true)));
        let s3 = s3_config_for_cli(&config, None, Some("ap-southeast-1"), None).expect("region");
        assert_eq!(s3.bucket, "primary-ap");
        assert_eq!(s3.region.as_deref(), Some("ap-southeast-1"));
        assert_eq!(
            s3.endpoint.as_deref(),
            Some("https://s3.ap-southeast-1.example.com")
        );
        assert_eq!(s3.path_prefix.as_deref(), Some("dr"));
        assert_eq!(
            s3.credentials.as_ref().map(|c| c.access_key_id.as_str()),
            Some("ap-southeast-1-key")
        );
        assert_eq!(s3.storage_class, "STANDARD_IA");
        assert!(s3.replication.is_none());

        // --bucket and --endpoint override the region's settings too.
        let s3 = s3_config_for_cli(
            &config,
            Some("restored-copy".to_string()),
            Some("eu-west-1"),
            Some("https://mirror.example.com".to_string()),
        )
        .expect("region with overrides");
        assert_eq!(s3.bucket, "restored-copy");
        assert_eq!(s3.endpoint.as_deref(), Some("https://mirror.example.com"));
        assert_eq!(s3.region.as_deref(), Some("eu-west-1"));

        // A named replica is selected by its name and still signs for its region.
        let mut named = replication(true);
        named.regions[1].name = Some("ap-dr".to_string());
        let config = config_with_s3(Some(named));
        let s3 = s3_config_for_cli(&config, None, Some("ap-dr"), None).expect("named region");
        assert_eq!(s3.bucket, "primary-ap");
        assert_eq!(s3.region.as_deref(), Some("ap-southeast-1"));
        assert!(s3_config_for_cli(&config, None, Some("ap-southeast-1"), None).is_err());
    }

    #[test]
    fn s3_config_for_cli_region_works_while_replication_is_disabled() {
        // A replica remains a recovery source after replication has been switched off.
        let config = config_with_s3(Some(replication(false)));
        let s3 = s3_config_for_cli(&config, None, Some("eu-west-1"), None)
            .expect("region of a disabled replication section");
        assert_eq!(s3.bucket, "primary-eu");
    }

    #[test]
    fn s3_config_for_cli_rejects_an_unknown_region() {
        let config = config_with_s3(Some(replication(true)));
        assert!(s3_config_for_cli(&config, None, Some("us-west-2"), None).is_err());

        let config = config_with_s3(None);
        assert!(s3_config_for_cli(&config, None, Some("eu-west-1"), None).is_err());

        // Without replication, --bucket alone can not stand in for a region.
        assert!(s3_config_for_cli(
            &config,
            Some("primary-eu".to_string()),
            Some("eu-west-1"),
            None
        )
        .is_err());
    }

    #[test]
    fn s3_config_for_cli_without_section_needs_a_bucket() {
        let config = Configuration::new_for_test();
        assert!(s3_config_for_cli(&config, None, None, None).is_err());
        let s3 =
            s3_config_for_cli(&config, Some("adhoc".to_string()), None, None).expect("bucket only");
        assert_eq!(s3, S3Config::with_bucket("adhoc".to_string()));
    }

    fn region_status(
        name: &str,
        status: ReplicationStatus,
        replicated: u64,
        pending: u64,
        lag: Option<u64>,
    ) -> ReplicationRegionStatus {
        ReplicationRegionStatus {
            region: name.to_string(),
            bucket: format!("primary-{name}"),
            status,
            last_sync_timestamp: Some("2024-01-03T22:00:00Z".to_string()),
            last_sync_backup_id: Some("backup-2024-01-03T22:00:00Z.json.gz".to_string()),
            lag_seconds: lag,
            bytes_replicated: 4096,
            backups_replicated: replicated,
            pending_backups: pending,
            last_error: None,
        }
    }

    #[test]
    fn replication_report_lists_every_region() {
        let health = ReplicationHealthCheck {
            overall_status: ReplicationStatus::Degraded {
                message: "1 of 2 regions unhealthy".to_string(),
            },
            regions: vec![
                region_status("eu-west-1", ReplicationStatus::Completed, 3, 0, Some(0)),
                region_status(
                    "ap-southeast-1",
                    ReplicationStatus::Degraded {
                        message: "1 of 3 backups not replicated: backup-x is missing".to_string(),
                    },
                    2,
                    1,
                    Some(86400),
                ),
            ],
            total_lag_seconds: 86400,
            max_lag_seconds: 86400,
            healthy_regions: 1,
            unhealthy_regions: 1,
            last_check_timestamp: "2024-01-04T00:00:00Z".to_string(),
        };

        let report =
            format_replication_report("s3://primary/prod", &health, &replication(true), false);
        assert!(
            report.starts_with(
                "Cross-region backup replication: Degraded: 1 of 2 regions unhealthy\n"
            ),
            "{report}"
        );
        assert!(
            report.contains("  Primary: s3://primary/prod\n"),
            "{report}"
        );
        assert!(
            report.contains("  Checked: 2024-01-04T00:00:00Z\n"),
            "{report}"
        );
        assert!(
            report.contains("  Regions: 1 healthy, 1 unhealthy\n"),
            "{report}"
        );
        assert!(report.contains("REGION"), "{report}");
        assert!(report.contains("eu-west-1"), "{report}");
        assert!(report.contains("primary-ap"), "{report}");
        // The full reason is spelled out for the unhealthy region only.
        assert!(
            report.contains("    Degraded: 1 of 3 backups not replicated: backup-x is missing\n"),
            "{report}"
        );
        assert_eq!(report.matches("\n    ").count(), 1, "{report}");
        assert!(report.contains("86400s"), "{report}");
        assert!(!report.contains("Lag metrics"), "{report}");

        let detailed =
            format_replication_report("s3://primary/prod", &health, &replication(true), true);
        assert!(detailed.contains("  Lag metrics:\n"), "{detailed}");
        assert!(
            detailed.contains(
                "    ap-southeast-1: lag 86400s, pending 1, newest replicated \
                 2024-01-03T22:00:00Z, bytes replicated 4096, check interval 300s\n"
            ),
            "{detailed}"
        );
    }

    #[test]
    fn replication_report_shows_an_unknown_lag_as_unknown() {
        let mut failed = region_status(
            "eu-west-1",
            ReplicationStatus::Failed {
                error: "bucket does not exist".to_string(),
            },
            0,
            3,
            None,
        );
        failed.last_sync_backup_id = None;
        failed.last_sync_timestamp = None;
        failed.last_error = Some("bucket does not exist".to_string());
        let health = ReplicationHealthCheck {
            overall_status: ReplicationStatus::Failed {
                error: "all 1 regions unhealthy".to_string(),
            },
            regions: vec![failed],
            total_lag_seconds: 0,
            max_lag_seconds: 0,
            healthy_regions: 0,
            unhealthy_regions: 1,
            last_check_timestamp: String::new(),
        };

        let report = format_replication_report("s3://primary", &health, &replication(true), true);
        assert!(
            report.contains("    eu-west-1: lag -, pending 3, newest replicated -,"),
            "{report}"
        );
        assert!(
            report.contains("      last error: bucket does not exist\n"),
            "{report}"
        );
        assert!(!report.contains("lag 0s"), "{report}");
    }

    #[test]
    fn replication_report_without_regions_has_no_table() {
        let health = ReplicationHealthCheck {
            overall_status: ReplicationStatus::NotConfigured,
            regions: vec![],
            total_lag_seconds: 0,
            max_lag_seconds: 0,
            healthy_regions: 0,
            unhealthy_regions: 0,
            last_check_timestamp: String::new(),
        };
        let report = format_replication_report("s3://primary", &health, &replication(true), true);
        assert_eq!(
            report,
            "Cross-region backup replication: Not Configured\n  Primary: s3://primary\n  \
             Regions: 0 healthy, 0 unhealthy\n"
        );
    }
}
