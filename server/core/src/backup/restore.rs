//! The production restore path, shared by `kubidmd database restore`, `restore-s3`, the
//! full backup verification and point-in-time recovery.
//!
//! Restoring, replaying, reindexing and booting a database is long, blocking work: it runs
//! on a dedicated thread (`on_database_thread`), never on the async runtime of the
//! command, so that the runtime stays free for the S3 transfers and the timers that run
//! next to it.

use std::future::Future;
use std::io::Read;
use std::path::Path;

use kubidm_proto::{
    backup::{BackupCompression, BackupEncryptionConfig},
    internal::{ConsistencyError, OperationError},
};
use kubidmd_lib::{
    be::{Backend, WalApplyReport},
    prelude::*,
    repl::wal::WalEntryRecord,
    schema::Schema,
};

use super::open_backup_file_with_config;
use crate::{config::Configuration, reindex_inner, setup_backend, utils::touch_file};

/// Name of the thread offline database work runs on.
const DATABASE_THREAD_NAME: &str = "kubidm-offline-db";

/// Run the database work `work` builds on a dedicated thread with a runtime of its own,
/// and wait for it without blocking the caller's runtime.
///
/// The offline restore, replay, reindex and verification hold write transactions and run
/// migrations for as long as the database takes, and parts of them are async only in
/// name. On their own thread they can neither stall the workers of the command's runtime
/// nor depend on them. `work` is called on that thread, so the future it returns needs
/// not be `Send`.
pub(crate) async fn on_database_thread<T, F, Fut>(work: F) -> Result<T, OperationError>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, OperationError>>,
    T: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(DATABASE_THREAD_NAME.to_string())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| {
                    error!(?err, "Unable to start the runtime of the database thread");
                    OperationError::InvalidState
                })
                .and_then(|runtime| runtime.block_on(work()));
            // The caller only goes away when its own runtime shuts down.
            let _ = tx.send(result);
        })
        .map_err(|err| {
            error!(?err, "Unable to start the database thread");
            OperationError::InvalidState
        })?;
    rx.await.map_err(|_| {
        error!("The database thread stopped without a result");
        OperationError::InvalidState
    })?
}

/// Boot the database described by `config` as a server start would and verify it, see
/// [`crate::verify_booted_database`], on the database thread.
pub(crate) async fn verify_booted_database_on_thread(
    config: &Configuration,
) -> Result<Vec<ConsistencyError>, OperationError> {
    let config = config.clone();
    on_database_thread(move || async move { crate::verify_booted_database(&config).await }).await
}

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
    restore_and_replay_commit(config, src_path, Vec::new())
        .await?
        .reindex(config)
        .await
        .map(|_| ())
}

/// What [`restore_and_replay_commit`] did.
pub(crate) struct RestoreOutcome {
    /// The CID watermark of the restored backup.
    pub watermark: Duration,
    /// The server uuid the restored database carries.
    pub server_uuid: Uuid,
    /// The WAL records applied on top of it, if any were given.
    pub apply: Option<WalApplyReport>,
}

/// A database [`restore_and_replay_commit`] restored and committed, not reindexed yet.
pub(crate) struct CommittedRestore {
    pub outcome: RestoreOutcome,
    be: Backend,
    schema: Schema,
}

impl CommittedRestore {
    /// Reindex the restored database, the last step of a restore. A failure leaves the
    /// restored content in place: the database is no longer what it was before.
    pub(crate) async fn reindex(
        self,
        config: &Configuration,
    ) -> Result<RestoreOutcome, OperationError> {
        let Self {
            outcome,
            be,
            schema,
        } = self;
        let config = config.clone();
        on_database_thread(move || async move { reindex_inner(be, schema, &config).await })
            .await
            .inspect_err(|err| {
                error!(?err, "The database WAS restored, but reindexing it failed");
            })?;
        Ok(outcome)
    }
}

/// Restore the backup at `src_path` into the database described by `config` and apply
/// `records` on top of it in the same transaction, up to the commit: the caller learns
/// whether the database was changed, and reindexes it with [`CommittedRestore::reindex`].
/// A failure leaves the database as it was.
pub(crate) async fn restore_and_replay_commit(
    config: &Configuration,
    src_path: &Path,
    records: Vec<WalEntryRecord>,
) -> Result<CommittedRestore, OperationError> {
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

    // Everything from here on is blocking database work.
    let config = config.clone();
    let reader = opened.reader;
    let compression = opened.compression;
    on_database_thread(move || async move {
        restore_and_replay_blocking(&config, reader, compression, records)
    })
    .await
}

/// The database part of [`restore_and_replay_commit`], on the database thread.
fn restore_and_replay_blocking(
    config: &Configuration,
    reader: Box<dyn Read + Send>,
    compression: BackupCompression,
    records: Vec<WalEntryRecord>,
) -> Result<CommittedRestore, OperationError> {
    // If it's an in memory database, we don't need to touch anything. A database file
    // that can not be written fails the restore; it never ends the process, since the
    // scheduled verification restores inside a running server.
    if let Some(db_path) = config.db_path.as_ref() {
        touch_file(db_path).map_err(|_| OperationError::FsError)?;
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

    be_wr_txn.restore(reader, compression).inspect_err(|err| {
        error!(?err, "Failed to restore database");
    })?;
    let watermark = be_wr_txn.get_db_ts_max(Duration::ZERO)?;
    let server_uuid = be_wr_txn.get_db_s_uuid()?;

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

    Ok(CommittedRestore {
        outcome: RestoreOutcome {
            watermark,
            server_uuid,
            apply,
        },
        be,
        schema,
    })
}
