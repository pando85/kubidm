//! The production restore path, shared by `kubidmd database restore`, `restore-s3`, the
//! full backup verification and point-in-time recovery.

use std::path::Path;

use kubidm_proto::{backup::BackupEncryptionConfig, internal::OperationError};
use kubidmd_lib::{be::WalApplyReport, prelude::*, repl::wal::WalEntryRecord, schema::Schema};

use super::open_backup_file_with_config;
use crate::{config::Configuration, reindex_inner, setup_backend, utils::touch_file_or_quit};

/// The encryption settings of the server configuration, if any. Backups made from this
/// configuration are encrypted when they are enabled, and encrypted artifacts are opened
/// with the key they name.
pub(crate) fn backup_encryption_config(config: &Configuration) -> Option<&BackupEncryptionConfig> {
    config
        .online_backup
        .as_ref()
        .map(|backup| &backup.encryption)
}

/// Restore the backup at `src_path` into the database described by `config` and
/// reindex it. This is the production restore path. Backup verification shares it so
/// that a verified backup has been exercised exactly as a real restore would.
pub async fn restore_database(
    config: &Configuration,
    src_path: &Path,
) -> Result<(), OperationError> {
    restore_and_replay(config, src_path, &[]).await.map(|_| ())
}

/// What [`restore_and_replay`] did.
pub(crate) struct RestoreOutcome {
    /// The CID watermark of the restored backup.
    pub watermark: Duration,
    /// The WAL records applied on top of it, if any were given.
    pub apply: Option<WalApplyReport>,
}

/// Restore the backup at `src_path` into the database described by `config`, apply
/// `records` on top of it in the same transaction, and reindex. A failure before the
/// commit leaves the database as it was.
pub(crate) async fn restore_and_replay(
    config: &Configuration,
    src_path: &Path,
    records: &[WalEntryRecord],
) -> Result<RestoreOutcome, OperationError> {
    // The artifact is opened before the database is touched, so that a backup that can
    // not be read (missing, or encrypted with a key this configuration does not have)
    // leaves the target database as it was. An encrypted artifact is decrypted with the
    // key the configuration names; the compression then comes from its header, from the
    // file name otherwise.
    let opened = open_backup_file_with_config(src_path, backup_encryption_config(config))
        .await
        .map_err(|err| {
            error!(%err, "Unable to open backup {}", src_path.display());
            OperationError::FsError
        })?;
    if let Some(key_identifier) = opened.key_identifier() {
        info!("Backup is encrypted with key '{key_identifier}'");
    }

    // If it's an in memory database, we don't need to touch anything
    if let Some(db_path) = config.db_path.as_ref() {
        touch_file_or_quit(db_path);
    }

    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = Schema::new().inspect_err(|err| {
        error!(?err, "Failed to setup in memory schema");
    })?;

    let be = setup_backend(config, &schema).inspect_err(|err| {
        error!(?err, "Failed to setup backend");
    })?;

    let mut be_wr_txn = be.write().inspect_err(|err| {
        error!(
            ?err,
            "Unable to proceed, backend write transaction failure."
        );
    })?;

    be_wr_txn
        .restore(opened.reader, opened.compression)
        .inspect_err(|err| {
            error!(?err, "Failed to restore database");
        })?;
    let watermark = be_wr_txn.get_db_ts_max(Duration::ZERO)?;

    let apply = if records.is_empty() {
        None
    } else {
        info!("Replaying {} WAL records ...", records.len());
        Some(be_wr_txn.wal_apply(records).inspect_err(|err| {
            error!(
                ?err,
                "Failed to replay the WAL records; the database was not changed"
            );
        })?)
    };

    be_wr_txn.commit().inspect_err(|err| {
        error!(?err, "Failed to commit the restored database");
    })?;
    info!("Database loaded successfully");

    reindex_inner(be, schema, config).await?;
    Ok(RestoreOutcome { watermark, apply })
}
