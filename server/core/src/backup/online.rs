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

use bytes::Bytes;
use kubidm_proto::backup::{BackupCompression, BackupEncryptionConfig, S3Config};
use kubidm_proto::internal::OperationError;
use kubidmd_lib::be::BackupStructuralReport;
use kubidmd_lib::prelude::duration_from_epoch_now;
use tracing::instrument;

use super::metrics::{BackupDestination, BackupMetrics, VerificationLevel};
use super::pitr::{BaseLocation, PitrArchive};
use super::retention::prune_s3_backups;
use super::{
    backup_artifact_name, backup_identity, backup_timestamp, prune_local_backups, run_blocking,
    seal_backup_async, verify_backup_output_async, write_verified_local_backup_async,
    BackupEncryptor, S3ClientWrapper,
};
use crate::actors::QueryServerReadV1;
use crate::config::OnlineBackup;

/// What one online backup run does: where it stores the backup, how many backups every
/// location keeps, how the artifact is compressed and encrypted, the WAL archive that
/// indexes every stored backup as a point-in-time recovery base, and the metrics that
/// record the outcome in every location.
#[derive(Clone)]
pub(crate) struct OnlineBackupJob {
    pub targets: Vec<BaseLocation>,
    pub versions: usize,
    pub compression: BackupCompression,
    pub encryption: BackupEncryptionConfig,
    pub pitr_archive: Option<Arc<PitrArchive>>,
    pub metrics: Arc<BackupMetrics>,
}

impl OnlineBackupJob {
    /// The job the `[online_backup]` section describes: the local directory when a path
    /// is set, then the S3 prefix when S3 is configured.
    pub fn from_config(
        config: &OnlineBackup,
        pitr_archive: Option<Arc<PitrArchive>>,
        metrics: Arc<BackupMetrics>,
    ) -> Self {
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
            metrics,
        }
    }

    /// Run one online backup. Every target is attempted, and every backup stored is
    /// indexed by the WAL archive. Fails when the artifact can not be produced or when any
    /// target failed, after every target has been attempted. The outcome in every target
    /// is recorded in the metrics: an artifact that can not be produced fails them all.
    #[instrument(level = "info", name = "online_backup", skip_all)]
    pub async fn run(&self, server: &'static QueryServerReadV1) -> Result<(), OperationError> {
        let (key, timestamp, artifact, encryptor) = match self.produce(server).await {
            Ok(produced) => produced,
            Err(err) => {
                let now = duration_from_epoch_now();
                for target in &self.targets {
                    self.metrics
                        .backup_failed(&BackupDestination::from(target), now);
                }
                return Err(err);
            }
        };

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
            let destination = BackupDestination::from(target);
            match stored {
                Ok(report) => {
                    // A target only stores an artifact that passed the structural checks.
                    let now = duration_from_epoch_now();
                    self.metrics.backup_succeeded(&destination, now);
                    self.metrics.verification_succeeded(
                        &destination,
                        VerificationLevel::Structural,
                        now,
                    );
                    if let Some(archive) = &self.pitr_archive {
                        archive
                            .register_base_backup_logged(target, &key, &timestamp, &report)
                            .await;
                    }
                }
                Err(err) => {
                    self.metrics
                        .backup_failed(&destination, duration_from_epoch_now());
                    error!(?err, "Online backup to {} failed", target);
                    failure.get_or_insert(err);
                }
            }
        }

        match failure {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Take the snapshot and seal it into the artifact every target stores. Returns its
    /// name, its timestamp, the artifact and the key it was encrypted with.
    async fn produce(
        &self,
        server: &'static QueryServerReadV1,
    ) -> Result<(String, String, Bytes, Option<BackupEncryptor>), OperationError> {
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

        // One snapshot and one artifact per run: every location holds the same backup,
        // under the same name, which the encrypted artifact is bound to.
        let plaintext = server.backup_database(self.compression).await?;
        let artifact = seal_backup_async(
            plaintext,
            self.compression,
            encryptor.as_ref(),
            backup_identity(Path::new(&key)),
        )
        .await
        .map(Bytes::from)
        .map_err(|err| {
            error!(%err, "Online backup failed to encrypt the backup");
            OperationError::CryptographyError
        })?;

        Ok((key, timestamp, artifact, encryptor))
    }

    /// Write the artifact to `dir` as `key`, verify it and apply the retention.
    async fn store_local(
        &self,
        dir: &Path,
        key: &str,
        artifact: &Bytes,
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
            artifact.clone(),
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
        artifact: &Bytes,
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
            artifact.clone(),
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
            .upload_backup_bytes(
                artifact.clone(),
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
                    .upload_with_metadata(artifact.clone(), key, &metadata)
                    .await
                    .map(|()| region),
                Err(err) => Err(err),
            };
            let destination = BackupDestination::S3Region(region_config.name().to_string());
            match &copied {
                Ok(_) => self
                    .metrics
                    .backup_succeeded(&destination, duration_from_epoch_now()),
                Err(_) => self
                    .metrics
                    .backup_failed(&destination, duration_from_epoch_now()),
            }
            match copied {
                Ok(region) => {
                    info!(
                        "Replicated backup {} to region {} ({})",
                        key,
                        region_config.name(),
                        region.location()
                    );
                    region_clients.push(region);
                }
                Err(err) => warn!(
                    "S3 backup replication of {} to region {} (bucket {}) failed, the \
                     replication monitor copies it later: {}",
                    key,
                    region_config.name(),
                    region_config.bucket,
                    err
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
