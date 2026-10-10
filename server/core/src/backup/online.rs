//! The online backup run, shared by the scheduled backup actor and the on-demand
//! triggers of the tests, so that both exercise exactly the same path.
//!
//! A run takes one consistent snapshot of the database, seals it into one artifact
//! (compressed and, when configured, encrypted) and stores that artifact in every
//! configured location: the local backup directory and the S3 prefix. Every location is
//! verified, pruned to its newest `versions` backups and indexed as a point-in-time
//! recovery base on its own, so a failure in one never prevents the other.

use std::path::Path;
use std::sync::Arc;

use kubidm_proto::backup::{BackupCompression, BackupEncryptionConfig, S3Config};
use kubidm_proto::internal::OperationError;
use kubidmd_lib::be::BackupStructuralReport;
use tracing::instrument;

use super::pitr::{BaseLocation, PitrArchive};
use super::{
    backup_artifact_name, backup_timestamp, is_backup_artifact_name, prune_local_backups,
    run_blocking, seal_backup_async, select_backups_to_delete, verify_backup_output_async,
    write_verified_local_backup_async, BackupEncryptor, S3ClientWrapper,
};
use crate::actors::QueryServerReadV1;
use crate::config::OnlineBackup;

/// A backup stored in one location: what it is called and what the structural
/// verification read back from it, including the CID watermark point-in-time recovery
/// indexes.
#[derive(Debug, Clone)]
pub struct OnlineBackupOutcome {
    /// File name (local) or object key relative to the S3 prefix.
    pub key: String,
    /// RFC3339 time of the backup.
    pub timestamp: String,
    pub report: BackupStructuralReport,
}

/// What one online backup run does: where it stores the backup, how many backups every
/// location keeps, how the artifact is compressed and encrypted, and the WAL archive that
/// indexes every stored backup as a point-in-time recovery base.
#[derive(Clone)]
pub(crate) struct OnlineBackupJob {
    pub targets: Vec<BaseLocation>,
    pub versions: usize,
    pub compression: BackupCompression,
    pub encryption: BackupEncryptionConfig,
    pub pitr_archive: Option<Arc<PitrArchive>>,
}

impl OnlineBackupJob {
    /// The job the `[online_backup]` section describes: the local directory when a path
    /// is set, then the S3 prefix when S3 is configured.
    pub fn from_config(config: &OnlineBackup, pitr_archive: Option<Arc<PitrArchive>>) -> Self {
        let mut targets = Vec::with_capacity(2);
        if let Some(path) = &config.path {
            targets.push(BaseLocation::Local(path.clone()));
        }
        if let Some(s3) = &config.s3 {
            targets.push(BaseLocation::S3(s3.clone()));
        }
        Self {
            targets,
            versions: config.versions,
            compression: config.compression,
            encryption: config.encryption.clone(),
            pitr_archive,
        }
    }

    /// Run one online backup. Every target is attempted; the backups stored successfully
    /// are returned in target order. Fails when the artifact can not be produced or when
    /// any target failed, after every target has been attempted.
    #[instrument(level = "info", name = "online_backup", skip_all)]
    pub async fn run(
        &self,
        server: &QueryServerReadV1,
    ) -> Result<Vec<OnlineBackupOutcome>, OperationError> {
        #[allow(clippy::disallowed_methods)]
        // Allowed as this timestamp is only used for the backup name.
        let now = time::OffsetDateTime::now_utc();
        let timestamp = backup_timestamp(now);

        // The key is obtained once per run, before any backup is produced, so that an
        // unavailable key fails the run without leaving a half written artifact behind.
        let encryptor = BackupEncryptor::from_config(&self.encryption)
            .await
            .map_err(|err| {
                error!(%err, "Online backup can not obtain the backup encryption key");
                OperationError::InvalidState
            })?;
        let key = backup_artifact_name(&timestamp, self.compression, encryptor.is_some());

        // One snapshot and one artifact per run: every location holds the same backup.
        let plaintext = server.backup_database(self.compression).await?;
        let artifact = seal_backup_async(plaintext, self.compression, encryptor.as_ref())
            .await
            .map(Arc::new)
            .map_err(|err| {
                error!(%err, "Online backup failed to encrypt the backup");
                OperationError::CryptographyError
            })?;

        let mut outcomes = Vec::with_capacity(self.targets.len());
        let mut failure = None;
        for target in &self.targets {
            let stored = match target {
                BaseLocation::Local(dir) => {
                    self.store_local(dir, &key, &artifact, encryptor.as_ref())
                        .await
                }
                BaseLocation::S3(s3_config) => {
                    self.store_s3(s3_config, &key, &timestamp, &artifact, encryptor.as_ref())
                        .await
                }
            };
            match stored {
                Ok(report) => {
                    if let Some(archive) = &self.pitr_archive {
                        archive
                            .register_base_backup_logged(target, &key, &timestamp, &report)
                            .await;
                    }
                    outcomes.push(OnlineBackupOutcome {
                        key: key.clone(),
                        timestamp: timestamp.clone(),
                        report,
                    });
                }
                Err(err) => {
                    error!(?err, "Online backup to {} failed", target);
                    failure.get_or_insert(err);
                }
            }
        }

        match failure {
            Some(err) => Err(err),
            None => Ok(outcomes),
        }
    }

    /// Write the artifact to `dir` as `key`, verify it and apply the retention.
    async fn store_local(
        &self,
        dir: &Path,
        key: &str,
        artifact: &Arc<Vec<u8>>,
        encryptor: Option<&BackupEncryptor>,
    ) -> Result<BackupStructuralReport, OperationError> {
        let dest_file = dir.join(key);

        // Written to a temporary file, synced and read back before it gets its backup
        // name, so a backup name only ever holds a complete, verified backup. A rejected
        // artifact is kept under an `.invalid` suffix, which the retention matcher
        // ignores, and retention below is skipped so that a failed backup can not cause
        // an older good backup to be removed.
        let report = write_verified_local_backup_async(
            &dest_file,
            Arc::clone(artifact),
            self.compression,
            encryptor,
        )
        .await
        .map_err(|err| {
            error!(
                reasons = ?err.reasons,
                quarantined_to = ?err.quarantined_to,
                "Online backup {} failed",
                dest_file.display()
            );
            OperationError::InvalidState
        })?;
        info!(
            entries = report.entry_count,
            version = ?report.version,
            encryption_key = encryptor.map(BackupEncryptor::key_identifier),
            "Online backup verified"
        );

        // The backup has succeeded: the cleanup only ever logs.
        let (dir, versions, keep) = (dir.to_path_buf(), self.versions, key.to_string());
        if let Err(err) = run_blocking(move || {
            prune_local_backups(&dir, versions, Some(&keep));
            Ok(())
        })
        .await
        {
            error!(?err, "Online backup cleanup failed");
        }

        Ok(report)
    }

    /// Verify the artifact, upload it as `key`, replicate it and apply the retention in
    /// the primary prefix and in every region.
    async fn store_s3(
        &self,
        s3_config: &S3Config,
        key: &str,
        timestamp: &str,
        artifact: &Arc<Vec<u8>>,
        encryptor: Option<&BackupEncryptor>,
    ) -> Result<BackupStructuralReport, OperationError> {
        let s3_client = S3ClientWrapper::new(s3_config.clone())
            .await
            .map_err(|err| {
                error!(%err, "Failed to create the S3 client");
                OperationError::InvalidState
            })?;

        // A backup that can not be read back is never uploaded, so the bucket only ever
        // holds artifacts that passed the same structural checks as `verify-backup`. An
        // encrypted artifact is decrypted for this, which proves the key opens it.
        let report = verify_backup_output_async(
            Arc::clone(artifact),
            Some(Path::new(key)),
            self.compression,
            encryptor,
        )
        .await
        .map_err(|err| {
            error!(
                reasons = ?err.reasons,
                "S3 backup {} failed verification and was not uploaded",
                key
            );
            OperationError::InvalidState
        })?;
        info!(
            entries = report.entry_count,
            version = ?report.version,
            encryption_key = encryptor.map(BackupEncryptor::key_identifier),
            "Online backup verified"
        );

        let metadata = s3_client
            .upload_backup(
                artifact,
                key,
                timestamp,
                self.compression,
                encryptor.map(BackupEncryptor::key_identifier),
            )
            .await
            .map_err(|e| {
                error!("S3 backup upload failed: {}", e);
                OperationError::InvalidState
            })?;

        info!("S3 backup uploaded successfully: {}", key);

        // The backup itself has succeeded at this point: neither replication nor retention
        // may turn it into a failure. Both only log.
        //
        // The replication monitor is the single source of truth for the region copies: it
        // copies whatever a region misses every `sync_interval_seconds`, and
        // `replicate-status` shows what is missing in the meantime. The run makes one
        // attempt per region so that a reachable region holds the backup right away, and
        // never retries or waits, so that a slow or unreachable region can not hold up the
        // schedule or the shutdown. Retention then runs in the primary and in every region
        // the copy reached, so each location keeps its newest `versions` backups
        // independently.
        let mut region_clients = Vec::new();
        for region_config in s3_client
            .replication_config()
            .map(|replication| replication.regions.as_slice())
            .unwrap_or_default()
        {
            let copied = match S3ClientWrapper::for_region(region_config).await {
                Ok(region) => region
                    .upload_with_metadata(artifact, key, &metadata)
                    .await
                    .map(|()| region),
                Err(err) => Err(err),
            };
            match copied {
                Ok(region) => {
                    info!(
                        "Replicated backup {} to region {} ({})",
                        key,
                        region_config.region,
                        region.location()
                    );
                    region_clients.push(region);
                }
                Err(err) => warn!(
                    "S3 backup replication of {} to region {} (bucket {}) failed, the \
                     replication monitor copies it later: {}",
                    key, region_config.region, region_config.bucket, err
                ),
            }
        }

        prune_s3_backups(&s3_client, self.versions, key).await;
        for region_client in &region_clients {
            prune_s3_backups(region_client, self.versions, key).await;
        }

        Ok(report)
    }
}

/// Apply the `versions` retention to the location `client` writes to: the primary prefix
/// or the prefix of a replication region. Only automatically generated backup artifacts
/// are ever deleted, together with their metadata sidecar; the PITR manifest and any other
/// object under the prefix are kept. Failures are logged and never propagated, because the
/// backup that triggered the cleanup has already succeeded. `keep`, that backup, is never
/// deleted.
async fn prune_s3_backups(client: &S3ClientWrapper, versions: usize, keep: &str) {
    let location = client.location();

    let existing = match client.list_backups().await {
        Ok(existing) => existing,
        Err(e) => {
            error!("S3 backup cleanup failed to list {}: {}", location, e);
            return;
        }
    };

    let to_delete = select_backups_to_delete(&existing, versions, Some(keep));
    if to_delete.is_empty() {
        debug!("S3 backup cleanup had no backups to remove in {}", location);
    } else {
        info!(
            "S3 backup cleanup found {} backups in {}, should keep {}, will remove {}",
            existing
                .iter()
                .filter(|key| is_backup_artifact_name(key))
                .count(),
            location,
            versions,
            to_delete.len()
        );
    }

    for key in to_delete {
        match client.delete_backup(&key).await {
            Ok(()) => info!("S3 backup cleanup removed {} from {}", key, location),
            Err(e) => error!(
                "S3 backup cleanup failed to remove {} from {}: {}",
                key, location, e
            ),
        }
    }
}
