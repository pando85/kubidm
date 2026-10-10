//! These contain the server "cores". These are able to startup the server
//! (bootstrap) to a running state and then execute tasks. This is where modules
//! are logically ordered based on their depenedncies for execution. Some of these
//! are task-only i.e. reindexing, and some of these launch the server into a
//! fully operational state (https, ldap, etc).
//!
//! Generally, this is the "entry point" where the server begins to run, and
//! the entry point for all client traffic which is then directed to the
//! various `actors`.

#![deny(warnings)]
#![allow(clippy::result_large_err)]
#![allow(clippy::result_unit_err)]
#![warn(unused_extern_crates)]
#![warn(unused_imports)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::indexing_slicing)]

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate kubidmd_lib;

mod actors;
pub mod admin;
pub mod backup;
pub mod config;
mod crypto;
mod https;
mod interval;
mod ldaps;
mod repl;
mod tcp;
mod utils;

use crate::{
    actors::{QueryServerReadV1, QueryServerWriteV1},
    admin::AdminActor,
    backup::{
        finalize_local_backup_async, is_backup_artifact_name, lag_metrics_from_health,
        open_backup_file_with_config,
        pitr::{self, BaseLocation, PitrArchive, PitrError, PitrSettings, PitrSyncReport},
        region_is_healthy, run_blocking, s3_location, seal_backup_async,
        verify_backup_output_async, BackupEncryptor, BackupVerifyError, S3BackupError,
        S3ClientWrapper,
    },
    config::{Configuration, ServerRole},
    interval::IntervalActor,
    repl::ReplicationServerHandles,
    utils::touch_file_or_quit,
};
use crypto_glue::{
    s256::{Sha256, Sha256Output},
    traits::Digest,
};
use kubidm_proto::{
    backup::{
        is_encrypted_backup_name, BackupCompression, BackupEncryptionConfig, ReplicationConfig,
        ReplicationHealthCheck, ReplicationRegionConfig, ReplicationStatus, S3BackupMetadata,
        S3Config, WalArchiveConfig, BACKUP_ENCRYPTED_SUFFIX,
    },
    internal::{ConsistencyError, OperationError},
    scim_v1::client::ScimAssertGeneric,
};
use kubidmd_lib::{
    be::{
        verify_backup_structure, Backend, BackendConfig, BackendTransaction,
        BackupStructuralReport, WalApplyReport,
    },
    idm::ldap::LdapServer,
    prelude::*,
    repl::wal::WalEntryRecord,
    schema::Schema,
    status::StatusActor,
    value::CredentialType,
};
use regex::Regex;
use sketching::LoggerType;
use std::{
    collections::BTreeSet,
    fmt::{Display, Formatter},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::SystemTime,
};
use time::format_description::well_known::Rfc3339;
use tokio::{sync::broadcast, task};
use tokio_rustls::TlsAcceptor;

#[cfg(not(target_family = "windows"))]
use libc::umask;

pub const KUBIDM_PKG_VERSION: &str = env!("KUBIDM_PKG_VERSION");

// === internal setup helpers

fn setup_backend(config: &Configuration, schema: &Schema) -> Result<Backend, OperationError> {
    setup_backend_vacuum(config, schema, false)
}

fn setup_backend_vacuum(
    config: &Configuration,
    schema: &Schema,
    vacuum: bool,
) -> Result<Backend, OperationError> {
    setup_backend_inner(config, schema, vacuum, None)
}

/// The backend of a running server. With `wal_archive`, every committed write is archived
/// for point-in-time recovery. The offline tools never archive: what they write is either
/// discarded or recorded by the recovery itself.
fn setup_backend_inner(
    config: &Configuration,
    schema: &Schema,
    vacuum: bool,
    wal_archive: Option<WalArchiveConfig>,
) -> Result<Backend, OperationError> {
    // Limit the scope of the schema txn.
    // let schema_txn = task::block_on(schema.write());
    let schema_txn = schema.write();
    let idxmeta = schema_txn.reload_idxmeta();

    let pool_size: u32 = config.threads as u32;

    let cfg = BackendConfig::new(
        config.db_path.as_deref(),
        pool_size,
        config.db_fs_type.unwrap_or_default(),
        config.db_arc_size,
    )
    .with_wal_archive(wal_archive);

    Backend::new(cfg, idxmeta, vacuum)
}

/// The backend of an offline command that commits writes outside of a restore or a
/// recovery (a domain rename, a reindex that runs migrations). When WAL archiving is
/// configured those writes are archived exactly like the running server's, so that
/// point-in-time recovery does not miss them. The returned guard closes the open segment
/// when the command ends; the next server start archives it. A command that exits the
/// process early leaves the segment open, which the next start reports as a gap.
fn setup_backend_archived(
    config: &Configuration,
    schema: &Schema,
) -> Result<(Backend, OfflineWalGuard), OperationError> {
    let wal = PitrSettings::from_config(config)
        .map_err(|err| {
            error!(%err, "Invalid WAL archive configuration");
            OperationError::InvalidState
        })?
        .map(|settings| settings.backend_wal_config());
    let be = setup_backend_inner(config, schema, false, wal)?;
    let guard = OfflineWalGuard(be.wal_archiver());
    Ok((be, guard))
}

/// Closes the open WAL segment of an offline command when dropped.
struct OfflineWalGuard(Option<kubidmd_lib::be::SharedWalArchiver>);

impl Drop for OfflineWalGuard {
    fn drop(&mut self) {
        if let Some(archiver) = self.0.take() {
            let mut archiver = archiver
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Err(err) = archiver.flush_current_segment() {
                error!(
                    %err,
                    "Unable to close the WAL segment of this command; the next server start \
                     reports its transactions as a gap in the archive"
                );
            }
            // Gaps are recorded in the archive index by the running server.
            if let Err(err) = archiver.defer_gaps_to_next_start() {
                error!(%err, "Unable to hand the WAL archive gaps to the next server start");
            }
        }
    }
}

// TODO #54: We could move most of the be/schema/qs setup and startup
// outside of this call, then pass in "what we need" in a cloneable
// form, this way we could have separate Idm vs Qs threads, and dedicated
// threads for write vs read
async fn setup_qs_idms(
    be: Backend,
    schema: Schema,
    config: &Configuration,
) -> Result<(QueryServer, IdmServer, IdmServerDelayed, IdmServerAudit), OperationError> {
    let curtime = duration_from_epoch_now();
    // Create a query_server implementation
    let query_server = QueryServer::new(be, schema, config.domain.clone(), curtime)?;

    // TODO #62: Should the IDM parts be broken out to the IdmServer?
    // What's important about this initial setup here is that it also triggers
    // the schema and acp reload, so they are now configured correctly!
    // Initialise the schema core.
    //
    // Now search for the schema itself, and validate that the system
    // in memory matches the BE on disk, and that it's syntactically correct.
    // Write it out if changes are needed.
    query_server
        .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
        .await?;

    // We generate a SINGLE idms only!
    let is_integration_test = config.integration_test_config.is_some();
    let (idms, idms_delayed, idms_audit) = IdmServer::new(
        query_server.clone(),
        &config.origin,
        is_integration_test,
        curtime,
    )
    .await?;

    Ok((query_server, idms, idms_delayed, idms_audit))
}

async fn setup_qs(
    be: Backend,
    schema: Schema,
    config: &Configuration,
) -> Result<QueryServer, OperationError> {
    let curtime = duration_from_epoch_now();
    // Create a query_server implementation
    let query_server = QueryServer::new(be, schema, config.domain.clone(), curtime)?;

    // TODO #62: Should the IDM parts be broken out to the IdmServer?
    // What's important about this initial setup here is that it also triggers
    // the schema and acp reload, so they are now configured correctly!
    // Initialise the schema core.
    //
    // Now search for the schema itself, and validate that the system
    // in memory matches the BE on disk, and that it's syntactically correct.
    // Write it out if changes are needed.
    query_server
        .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
        .await?;

    Ok(query_server)
}

macro_rules! dbscan_setup_be {
    (
        $config:expr
    ) => {{
        let schema = match Schema::new() {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to setup in memory schema: {:?}", e);
                std::process::exit(1);
            }
        };

        match setup_backend($config, &schema) {
            Ok(be) => be,
            Err(e) => {
                error!("Failed to setup BE: {:?}", e);
                return;
            }
        }
    }};
}

pub fn dbscan_list_indexes_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_indexes() {
        Ok(mut idx_list) => {
            idx_list.sort_unstable();
            idx_list.iter().for_each(|idx_name| {
                println!("{idx_name}");
            })
        }
        Err(e) => {
            error!("Failed to retrieve index list: {:?}", e);
        }
    };
}

pub fn dbscan_list_id2entry_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_id2entry() {
        Ok(mut id_list) => {
            id_list.sort_unstable_by_key(|k| k.0);
            id_list.iter().for_each(|(id, value)| {
                println!("{id:>8}: {value}");
            })
        }
        Err(e) => {
            error!("Failed to retrieve id2entry list: {:?}", e);
        }
    };
}

pub fn dbscan_list_index_analysis_core(config: &Configuration) {
    let _be = dbscan_setup_be!(config);
    // TBD in after slopes merge.
}

pub fn dbscan_list_index_core(config: &Configuration, index_name: &str) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_index_content(index_name) {
        Ok(mut idx_list) => {
            idx_list.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            idx_list.iter().for_each(|(key, value)| {
                println!("{key:>50}: {value:?}");
            })
        }
        Err(e) => {
            error!("Failed to retrieve index list: {:?}", e);
        }
    };
}

pub fn dbscan_get_id2entry_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.get_id2entry(id) {
        Ok((id, value)) => println!("{id:>8}: {value}"),
        Err(e) => {
            error!("Failed to retrieve id2entry value: {:?}", e);
        }
    };
}

pub fn dbscan_quarantine_id2entry_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_wrtxn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    match be_wrtxn
        .quarantine_entry(id)
        .and_then(|_| be_wrtxn.commit())
    {
        Ok(()) => {
            println!("quarantined - {id:>8}")
        }
        Err(e) => {
            error!("Failed to quarantine id2entry value: {:?}", e);
        }
    };
}

pub fn dbscan_list_quarantined_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_quarantined() {
        Ok(mut id_list) => {
            id_list.sort_unstable_by_key(|k| k.0);
            id_list.iter().for_each(|(id, value)| {
                println!("{id:>8}: {value}");
            })
        }
        Err(e) => {
            error!("Failed to retrieve id2entry list: {:?}", e);
        }
    };
}

pub fn dbscan_restore_quarantined_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_wrtxn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    match be_wrtxn
        .restore_quarantined(id)
        .and_then(|_| be_wrtxn.commit())
    {
        Ok(()) => {
            println!("restored - {id:>8}")
        }
        Err(e) => {
            error!("Failed to restore quarantined id2entry value: {:?}", e);
        }
    };
}

/// The encryption settings of the server configuration, if any. Backups made from this
/// configuration are encrypted when they are enabled, and encrypted artifacts are opened
/// with the key they name.
fn backup_encryption_config(config: &Configuration) -> Option<&BackupEncryptionConfig> {
    config
        .online_backup
        .as_ref()
        .map(|backup| &backup.encryption)
}

/// Take an offline backup of the database described by `config` into `dst_path`, or to
/// stdout without a path. The backup uses the compression and the client-side encryption
/// of the `[online_backup]` section, so it is interchangeable with an online backup.
pub async fn backup_server_core(config: &Configuration, dst_path: Option<&Path>) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
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
                std::process::exit(1);
            }
        },
        None => None,
    };

    if let (Some(dst_path), Some(_)) = (dst_path, &encryptor) {
        if !dst_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_encrypted_backup_name)
        {
            warn!(
                "Backup encryption is enabled: {} will hold an encrypted artifact although \
                 its name does not end in {BACKUP_ENCRYPTED_SUFFIX}",
                dst_path.display()
            );
        }
    }

    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    if let Some(dst_path) = dst_path {
        if dst_path.exists() {
            error!(
                "backup file {} already exists, will not overwrite it.",
                dst_path.display()
            );
            return;
        }
    }

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
            std::process::exit(1);
        }
        Err(err) => {
            error!(%err, "Backup failed: the backup task failed");
            std::process::exit(1);
        }
    };

    let artifact = match seal_backup_async(backup_data, compression, encryptor.as_ref()).await {
        Ok(artifact) => artifact,
        Err(err) => {
            error!(%err, "Backup failed: unable to encrypt the backup");
            std::process::exit(1);
        }
    };

    if let Some(dst_path) = dst_path {
        let write_to = dst_path.to_path_buf();
        if let Err(err) = run_blocking(move || std::fs::write(write_to, artifact)).await {
            error!(
                ?err,
                "Backup failed: unable to write {}",
                dst_path.display()
            );
            std::process::exit(1);
        }
        info!("Backup written to {}", dst_path.display());

        // Read the artifact back before announcing it. A rejected artifact is kept under
        // an `.invalid` suffix for inspection.
        report_backup_verification(
            finalize_local_backup_async(dst_path, compression, encryptor.as_ref()).await,
        );
    } else {
        let artifact = Arc::new(artifact);
        report_backup_verification(
            verify_backup_output_async(Arc::clone(&artifact), compression, encryptor.as_ref())
                .await,
        );

        let mut stdout = std::io::stdout().lock();
        if let Err(err) = stdout.write_all(&artifact).and_then(|()| stdout.flush()) {
            error!(?err, "Backup failed: unable to write to stdout");
            std::process::exit(1);
        }
    };

    if let Some(encryptor) = &encryptor {
        eprintln!("Backup encrypted with key '{}'", encryptor.key_identifier());
    }
    info!("Backup success!");
}

/// Print the outcome of the post-write verification of a manual backup. A rejected backup
/// terminates the process with a non-zero exit code, as a failed write does.
fn report_backup_verification(verified: Result<BackupStructuralReport, BackupVerifyError>) {
    match verified {
        Ok(report) => {
            eprintln!(
                "Backup verified: {} entries, written by server version {}",
                report.entry_count,
                report.version.as_deref().unwrap_or("unknown")
            );
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
            std::process::exit(1);
        }
    }
}

pub async fn restore_server_core(config: &Configuration, dst_path: &Path) {
    let committed = match restore_and_replay_commit(config, dst_path, Vec::new()).await {
        Ok(committed) => committed,
        Err(_) => std::process::exit(1),
    };

    // The database holds the backup from here on, so the history after it is abandoned
    // whatever happens next.
    let noted = note_restore_in_wal_archive(config, &committed.outcome).await;
    if committed.reindex(config).await.is_err() || noted.is_err() {
        std::process::exit(1);
    }

    info!("✅ Restore Success!");
}

/// After a restore of the configured database, record in the WAL archive (when one is
/// configured) that the history after the restored backup was abandoned, so that a later
/// point-in-time recovery never replays it.
async fn note_restore_in_wal_archive(
    config: &Configuration,
    outcome: &RestoreOutcome,
) -> Result<(), OperationError> {
    pitr::note_restore(config, outcome.watermark, outcome.server_uuid)
        .await
        .map_err(|err| {
            error!(
                %err,
                "The database WAS restored, but the abandoned history could not be recorded in \
                 the WAL archive. A later point-in-time recovery past this point could replay it: \
                 take a new online backup right after starting the server."
            );
            OperationError::InvalidState
        })
}

/// Restore the backup at `src_path` into the database described by `config` and
/// reindex it. This is the production restore path. Backup verification shares it so
/// that a verified backup has been exercised exactly as a real restore would.
pub async fn restore_database(
    config: &Configuration,
    src_path: &Path,
) -> Result<(), OperationError> {
    restore_and_replay(config, src_path, Vec::new())
        .await
        .map(|_| ())
}

/// What [`restore_and_replay`] did.
pub(crate) struct RestoreOutcome {
    /// The CID watermark of the restored backup.
    pub watermark: Duration,
    /// The server uuid the restored database carries.
    pub server_uuid: uuid::Uuid,
    /// The WAL records applied on top of it, if any were given.
    pub apply: Option<WalApplyReport>,
}

/// Restore the backup at `src_path` into the database described by `config`, apply
/// `records` on top of it in the same transaction, and reindex. A failure before the
/// commit leaves the database as it was.
pub(crate) async fn restore_and_replay(
    config: &Configuration,
    src_path: &Path,
    records: Vec<WalEntryRecord>,
) -> Result<RestoreOutcome, OperationError> {
    restore_and_replay_commit(config, src_path, records)
        .await?
        .reindex(config)
        .await
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
        reindex_inner(self.be, self.schema, config)
            .await
            .inspect_err(|err| {
                error!(
                    ?err,
                    "The database WAS restored, but reindexing it failed; run \
                     `kubidmd database reindex` before starting the server"
                );
            })?;
        Ok(self.outcome)
    }
}

/// [`restore_and_replay`] up to the commit: the caller learns whether the database was
/// changed, and reindexes it with [`CommittedRestore::reindex`]. A failure leaves the
/// database as it was.
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
        Ok(Ok(report)) => report,
        Ok(Err(err)) => {
            eprintln!("Backup structural verification: FAIL");
            eprintln!("  - artifact could not be parsed as a kubidm backup: {err:?}");
            return false;
        }
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
        .find(|region| region.region == name)
        .ok_or_else(|| {
            if regions.is_empty() {
                error!(
                    "--region {name}: no replication region is configured under \
                     [online_backup.s3.replication], so there is no replica to target."
                );
            } else {
                let names: Vec<&str> = regions.iter().map(|r| r.region.as_str()).collect();
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
struct FetchedS3Backup {
    _scratch_dir: tempfile::TempDir,
    path: PathBuf,
    metadata: S3BackupMetadata,
}

/// Download the backup `key` from S3, verifying its SHA-256 against the metadata sidecar,
/// into a temporary file. The file is named so that `BackupCompression::identify_file`
/// recognises the compression recorded in the metadata and so that an encrypted artifact
/// carries the `.enc` suffix, which lets the local restore and verification paths treat it
/// exactly like a local artifact (the encrypted container is recognised by its content,
/// the name only keeps it consistent).
async fn fetch_s3_backup(s3_config: S3Config, key: &str) -> Result<FetchedS3Backup, S3BackupError> {
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
    let path = scratch_dir.path().join(format!(
        "backup.json{}{encryption_suffix}",
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
) -> Result<(), OperationError> {
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

    // The database holds the backup from here on, so the history after it is abandoned
    // whatever happens next.
    let noted = note_restore_in_wal_archive(config, &committed.outcome).await;
    committed.reindex(config).await?;
    noted
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

    rows.sort();
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

    let mut keys: Vec<String> = match client.list_backups().await {
        Ok(keys) => keys
            .into_iter()
            .filter(|key| is_backup_artifact_name(key))
            .collect(),
        Err(err) => {
            error!(%err, "Unable to list S3 backups");
            println!("  error: unable to list {location}: {err}");
            return false;
        }
    };

    if keys.is_empty() {
        println!("  (no backups)");
        return true;
    }

    keys.sort();

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

pub async fn reindex_server_core(config: &Configuration) {
    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    // Booting the query server may run migrations, which are archived.
    let (be, _wal_guard) = match setup_backend_archived(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    if reindex_inner(be, schema, config).await.is_err() {
        std::process::exit(1);
    }

    info!("✅ Reindex Success!");
}

async fn reindex_inner(
    be: Backend,
    schema: Schema,
    config: &Configuration,
) -> Result<(), OperationError> {
    info!("Start Index Phase 1 ...");
    // Reindex only the core schema attributes to bootstrap the process.
    let mut be_wr_txn = be.write().inspect_err(|err| {
        error!(
            ?err,
            "Unable to proceed, backend write transaction failure."
        );
    })?;

    be_wr_txn
        .reindex(true)
        .and_then(|_| be_wr_txn.commit())
        .inspect_err(|err| {
            error!(?err, "Failed to reindex database");
        })?;
    info!("Index Phase 1 Success!");

    // Now that's done, setup a minimal qs and reindex from that.
    debug!("Attempting to init query server ...");

    let (qs, _idms, _idms_delayed, _idms_audit) =
        setup_qs_idms(be, schema, config).await.inspect_err(|err| {
            error!(?err, "Unable to setup query server or idm server");
        })?;
    debug!("Init Query Server Success!");

    info!("Start Index Phase 2 ...");

    let mut qs_write = qs
        .write(duration_from_epoch_now())
        .await
        .inspect_err(|err| {
            error!(?err, "Unable to acquire write transaction");
        })?;

    qs_write
        .reindex(true)
        .and_then(|_| qs_write.commit())
        .inspect_err(|err| {
            error!(?err, "Reindex failed");
        })?;
    info!("Index Phase 2 Success!");

    Ok(())
}

pub fn vacuum_server_core(config: &Configuration) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {e:?}");
            std::process::exit(1);
        }
    };

    // The schema doesn't matter here. Vacuum is run as part of db open to avoid
    // locking.
    let r = setup_backend_vacuum(config, &schema, true);

    match r {
        Ok(_) => eprintln!("Vacuum Success!"),
        Err(e) => {
            eprintln!("Vacuum failed: {e:?}");
            std::process::exit(1);
        }
    };
}

pub async fn domain_rename_core(config: &Configuration) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {e:?}");
            std::process::exit(1);
        }
    };

    // Start the backend. The rename is archived for point-in-time recovery.
    let (be, _wal_guard) = match setup_backend_archived(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    // Setup the qs, and perform any migrations and changes we may have.
    let qs = match setup_qs(be, schema, config).await {
        Ok(t) => t,
        Err(e) => {
            error!("Unable to setup query server -> {:?}", e);
            return;
        }
    };

    let new_domain_name = config.domain.as_str();

    // make sure we're actually changing the domain name...
    match qs.read().await.map(|qs| qs.get_domain_name().to_string()) {
        Ok(old_domain_name) => {
            admin_info!(?old_domain_name, ?new_domain_name);
            if old_domain_name == new_domain_name {
                admin_info!("Domain name not changing, stopping.");
                return;
            }
            admin_debug!(
                "Domain name is changing from {:?} to {:?}",
                old_domain_name,
                new_domain_name
            );
        }
        Err(e) => {
            admin_error!("Failed to query domain name, quitting! -> {:?}", e);
            return;
        }
    }

    let Ok(mut qs_write) = qs.write(duration_from_epoch_now()).await else {
        error!("Unable to acquire write transaction");
        return;
    };
    let r = qs_write
        .danger_domain_rename(new_domain_name)
        .and_then(|_| qs_write.commit());

    match r {
        Ok(_) => info!("Domain Rename Success!"),
        Err(e) => {
            error!("Domain Rename Failed - Rollback has occurred: {:?}", e);
            std::process::exit(1);
        }
    };
}

/// Open the in-memory schema and the backend described by `config` without starting a
/// server. This is the common first step of the offline database tools.
fn open_schema_and_backend(config: &Configuration) -> Result<(Schema, Backend), OperationError> {
    let schema = Schema::new().inspect_err(|err| {
        error!(?err, "Failed to setup in memory schema");
    })?;

    let be = setup_backend(config, &schema).inspect_err(|err| {
        error!(?err, "Failed to setup BE");
    })?;

    Ok((schema, be))
}

/// Collect the consistency errors reported by a query server.
fn collect_consistency_errors(results: Vec<Result<(), ConsistencyError>>) -> Vec<ConsistencyError> {
    results.into_iter().filter_map(Result::err).collect()
}

/// Run the full consistency verification on the database described by `config` without
/// booting a server: no migrations are run and the stored entries are not modified. This
/// is the implementation of `kubidmd database verify`. Returns the consistency errors
/// found, which is empty for a healthy database.
pub async fn verify_database(
    config: &Configuration,
) -> Result<Vec<ConsistencyError>, OperationError> {
    let curtime = duration_from_epoch_now();
    // setup the qs - without initialise!
    let (schema_mem, be) = open_schema_and_backend(config)?;

    let server =
        QueryServer::new(be, schema_mem, config.domain.clone(), curtime).inspect_err(|err| {
            error!(?err, "Failed to setup query server");
        })?;

    // Run verifications.
    Ok(collect_consistency_errors(server.verify().await))

    // Now add IDM server verifications?
}

pub async fn verify_server_core(config: &Configuration) {
    match verify_database(config).await {
        Ok(errors) if errors.is_empty() => {
            eprintln!("Verification passed!");
            std::process::exit(0);
        }
        Ok(errors) => {
            for err in errors {
                error!("{:?}", err);
            }
            std::process::exit(1);
        }
        Err(err) => {
            error!(?err, "Unable to verify the database");
            std::process::exit(1);
        }
    }
}

/// Boot the database described by `config` exactly as a server start would, including
/// the startup migrations, then run the full consistency verification on it. Returns the
/// consistency errors found, which is empty for a healthy database.
pub async fn verify_booted_database(
    config: &Configuration,
) -> Result<Vec<ConsistencyError>, OperationError> {
    let (schema, be) = open_schema_and_backend(config)?;

    let server = setup_qs(be, schema, config).await.inspect_err(|err| {
        error!(?err, "Failed to start query server");
    })?;

    Ok(collect_consistency_errors(server.verify().await))
}

pub fn cert_generate_core(config: &Configuration) {
    // Get the cert root

    let (tls_key_path, tls_chain_path) = match &config.tls_config {
        Some(tls_config) => (tls_config.key.as_path(), tls_config.chain.as_path()),
        None => {
            error!("Unable to find TLS configuration");
            std::process::exit(1);
        }
    };

    if tls_key_path.exists() && tls_chain_path.exists() {
        info!(
            "TLS key and chain already exist - remove them first if you intend to regenerate these"
        );
        return;
    }

    let origin_domain = match config.origin.domain() {
        Some(val) => val,
        None => {
            error!("origin does not contain a valid domain");
            std::process::exit(1);
        }
    };

    let cert_root = match tls_key_path.parent() {
        Some(parent) => parent,
        None => {
            error!("Unable to find parent directory of {:?}", tls_key_path);
            std::process::exit(1);
        }
    };

    let ca_cert = cert_root.join("ca.pem");
    let ca_key = cert_root.join("cakey.pem");
    let tls_cert_path = cert_root.join("cert.pem");

    let ca_handle = if !ca_cert.exists() || !ca_key.exists() {
        // Generate the CA again.
        let ca_handle = match crypto::build_ca() {
            Ok(ca_handle) => ca_handle,
            Err(e) => {
                error!(err = ?e, "Failed to build CA");
                std::process::exit(1);
            }
        };

        if crypto::write_ca(ca_key, ca_cert, &ca_handle).is_err() {
            error!("Failed to write CA");
            std::process::exit(1);
        }

        ca_handle
    } else {
        match crypto::load_ca(ca_key, ca_cert) {
            Ok(ca_handle) => ca_handle,
            Err(_) => {
                error!("Failed to load CA");
                std::process::exit(1);
            }
        }
    };

    if !tls_key_path.exists() || !tls_chain_path.exists() || !tls_cert_path.exists() {
        // Generate the cert from the ca.
        let cert_handle = match crypto::build_cert(origin_domain, &ca_handle) {
            Ok(cert_handle) => cert_handle,
            Err(e) => {
                error!(err = ?e, "Failed to build certificate");
                std::process::exit(1);
            }
        };

        if crypto::write_cert(tls_key_path, tls_chain_path, tls_cert_path, &cert_handle).is_err() {
            error!("Failed to write certificates");
            std::process::exit(1);
        }
    }
    info!("certificate generation complete");
}

static MIGRATION_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^\\d\\d-.*\\.h?json$").expect("Invalid SPN regex found")
});

struct ScimMigration {
    path: PathBuf,
    hash: Sha256Output,
    assertions: ScimAssertGeneric,
}

async fn migration_reload_supervisor(
    mut broadcast_rx: broadcast::Receiver<CoreAction>,
    server_write_ref: &'static QueryServerWriteV1,
    migration_path: PathBuf,
) {
    loop {
        tokio::select! {
            Ok(action) = broadcast_rx.recv() => {
                match action {
                    CoreAction::Shutdown => break,
                    CoreAction::Reload => {
                        // Read the migrations.
                        // Apply them.
                        let eventid = Uuid::new_v4();
                        migration_apply(
                            eventid,
                            server_write_ref,
                            migration_path.as_path(),
                        ).await;

                        info!("Migration reload complete");
                    },
                }
            }
        }
    }
    info!("Stopped {}", TaskName::MigrationReload);
}

#[instrument(
    level = "info",
    fields(uuid = ?eventid),
    skip_all,
)]
async fn migration_apply(
    eventid: Uuid,
    server_write_ref: &'static QueryServerWriteV1,
    migration_path: &Path,
) {
    if !migration_path.exists() {
        info!(migration_path = %migration_path.display(), "Migration path does not exist - migrations will be skipped.");
        return;
    }

    let mut dir_ents = match tokio::fs::read_dir(migration_path).await {
        Ok(dir_ents) => dir_ents,
        Err(err) => {
            error!(?err, "Unable to read migration directory.");
            let diag = kubidm_lib_file_permissions::diagnose_path(migration_path);
            info!(%diag);
            return;
        }
    };

    let mut migration_paths = Vec::with_capacity(8);

    loop {
        match dir_ents.next_entry().await {
            Ok(Some(dir_ent)) => migration_paths.push(dir_ent.path()),
            Ok(None) => {
                // Complete,
                break;
            }
            Err(err) => {
                error!(?err, "Unable to read directory entries.");
                return;
            }
        }
    }

    // Filter these.

    let mut migration_paths: Vec<_> = migration_paths.into_iter()
        .filter(|path| {
            if !path.is_file() {
                info!(path = %path.display(), "ignoring path that is not a file.");
                return false;
            }

            let Some(file_name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
                info!(path = %path.display(), "ignoring path that has no file name, or is not a valid utf-8 file name.");
                return false;
            };

            if !MIGRATION_PATH_RE.is_match(file_name) {
                info!(path = %path.display(), "ignoring file that does not match naming pattern.");
                info!("expected pattern 'XX-NAME.json' where XX are two numbers, followed by a hypen, with the file extension .json");
                return false;
            }

            true
        })
        .collect();

    migration_paths.sort_unstable();
    let mut migrations = Vec::with_capacity(migration_paths.len());

    for migration_path in migration_paths {
        info!(path = %migration_path.display(), "examining migration");

        let migration_content = match tokio::fs::read(&migration_path).await {
            Ok(bytes) => bytes,
            Err(err) => {
                error!(?err, "Unable to read migration - it will be ignored.");
                let diag = kubidm_lib_file_permissions::diagnose_path(&migration_path);
                info!(%diag);
                continue;
            }
        };

        // Is it valid json?
        let assertions: ScimAssertGeneric = match serde_hjson::from_slice(&migration_content) {
            Ok(assertions) => assertions,
            Err(err) => {
                error!(?err, path = %migration_path.display(), "Invalid JSON SCIM Assertion");
                continue;
            }
        };

        // Hash the content.
        let mut hasher = Sha256::new();
        hasher.update(&migration_content);
        let migration_hash: Sha256Output = hasher.finalize();

        migrations.push(ScimMigration {
            path: migration_path,
            hash: migration_hash,
            assertions,
        });
    }

    let mut migration_ids = BTreeSet::new();
    for migration in &migrations {
        // BTreeSet returns false on duplicate value insertion.
        if !migration_ids.insert(migration.assertions.id) {
            error!(path = %migration.path.display(), uuid = ?migration.assertions.id, "Duplicate migration UUID found, refusing to proceed!!! All migrations must have a unique ID!!!");
            return;
        }
    }

    // Okay, we're setup to go - apply them all. Note that we do these
    // separately, each migration occurs in its own transaction.
    for ScimMigration {
        path,
        hash,
        assertions,
    } in migrations
    {
        if let Err(err) = server_write_ref
            .handle_scim_migration_apply(eventid, assertions, hash)
            .await
        {
            error!(?err, path = %path.display(), "Failed to apply migration");
        };
    }
}

#[derive(Clone, Debug)]
pub enum CoreAction {
    Shutdown,
    Reload,
}

pub(crate) enum TaskName {
    AdminSocket,
    AuditdActor,
    BackupActor,
    BackupReplicationMonitor,
    DelayedActionActor,
    HttpsServer,
    IntervalActor,
    LdapActor,
    ReplicationSupervisor,
    TlsAcceptorReload,
    MigrationReload,
    WalArchive,
}

impl Display for TaskName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TaskName::AdminSocket => "Admin Socket",
                TaskName::AuditdActor => "Auditd Actor",
                TaskName::BackupActor => "Backup Actor",
                TaskName::BackupReplicationMonitor => "Backup Replication Monitor",
                TaskName::DelayedActionActor => "Delayed Action Actor",
                TaskName::HttpsServer => "HTTPS Server",
                TaskName::IntervalActor => "Interval Actor",
                TaskName::LdapActor => "LDAP Acceptor Actor",
                TaskName::ReplicationSupervisor => "Replication Supervisor",
                TaskName::TlsAcceptorReload => "TlsAcceptor Reload Monitor",
                TaskName::MigrationReload => "Migration Reload Monitor",
                TaskName::WalArchive => "WAL Archive",
            }
        )
    }
}

pub struct CoreHandle {
    clean_shutdown: bool,
    tx: broadcast::Sender<CoreAction>,
    /// This stores a name for the handle, and the handle itself so we can tell which failed/succeeded at the end.
    handles: Vec<(TaskName, task::JoinHandle<()>)>,
    server_read_ref: &'static QueryServerReadV1,
    /// The WAL archive, when point-in-time recovery is enabled.
    pitr_archive: Option<Arc<PitrArchive>>,
}

impl CoreHandle {
    pub fn subscribe(&mut self) -> broadcast::Receiver<CoreAction> {
        self.tx.subscribe()
    }

    pub async fn shutdown(&mut self) {
        if self.tx.send(CoreAction::Shutdown).is_err() {
            eprintln!("No receivers acked shutdown request. Treating as unclean.");
            return;
        }

        // Wait on the handles.
        while let Some((handle_name, handle)) = self.handles.pop() {
            debug!("Waiting for {handle_name} ...");
            if let Err(error) = handle.await {
                eprintln!("Task {handle_name} failed to finish: {error:?}");
            }
        }

        // Every task that can write has stopped: close the open WAL segment and archive
        // it, so that a clean shutdown loses no committed transaction.
        if let Some(archive) = &self.pitr_archive {
            match archive.sync(duration_from_epoch_now(), true).await {
                Ok(report) => debug!(?report, "WAL archive synchronised at shutdown"),
                Err(err) => error!(
                    %err,
                    "WAL archive synchronisation at shutdown failed; the closed segments stay in \
                     {} and are archived at the next start",
                    archive.settings().local_dir.display()
                ),
            }
            archive.defer_gaps_to_next_start();
        }

        self.clean_shutdown = true;
    }

    /// Close the open WAL segment and archive every closed one now, as the periodic WAL
    /// archive task and the shutdown do. None when WAL archiving is not enabled. This
    /// exists so tests can archive on demand.
    pub async fn sync_wal_archive(&self) -> Option<Result<PitrSyncReport, PitrError>> {
        match &self.pitr_archive {
            Some(archive) => Some(archive.sync(duration_from_epoch_now(), true).await),
            None => None,
        }
    }

    pub async fn reload(&mut self) {
        if self.tx.send(CoreAction::Reload).is_err() {
            eprintln!("No receivers acked reload request.");
        }
    }

    /// Run an online backup now, through the same code path the scheduled online backup
    /// uses. `versions` is the number of backups to keep in `outpath`. This exists so
    /// tests can exercise the production backup path on demand.
    pub async fn trigger_online_backup(
        &self,
        outpath: &Path,
        versions: usize,
        compression: BackupCompression,
        encryption: &BackupEncryptionConfig,
    ) -> Result<(), OperationError> {
        let outcome = self
            .server_read_ref
            .handle_online_backup(
                kubidmd_lib::event::OnlineBackupEvent::new(),
                outpath,
                versions,
                compression,
                encryption,
                None,
            )
            .await?;
        if let Some(archive) = &self.pitr_archive {
            archive
                .register_base_backup_logged(
                    &BaseLocation::Local(outpath.to_path_buf()),
                    &outcome.key,
                    &outcome.timestamp,
                    &outcome.report,
                )
                .await;
        }
        Ok(())
    }

    /// Run an online backup to S3 now, through the same code path the scheduled S3 backup
    /// uses, including retention of `versions` backups under the configured prefix. This
    /// exists so tests can exercise the production S3 backup path on demand.
    pub async fn trigger_s3_backup(
        &self,
        s3_config: S3Config,
        versions: usize,
        compression: BackupCompression,
        encryption: &BackupEncryptionConfig,
    ) -> Result<(), OperationError> {
        let client = S3ClientWrapper::new(s3_config.clone())
            .await
            .map_err(|err| {
                error!(%err, "Unable to create the S3 client");
                OperationError::InvalidState
            })?;

        let outcome = self
            .server_read_ref
            .handle_online_backup(
                kubidmd_lib::event::OnlineBackupEvent::new(),
                Path::new("s3://backup"),
                versions,
                compression,
                encryption,
                Some(client),
            )
            .await?;
        if let Some(archive) = &self.pitr_archive {
            archive
                .register_base_backup_logged(
                    &BaseLocation::S3(s3_config),
                    &outcome.key,
                    &outcome.timestamp,
                    &outcome.report,
                )
                .await;
        }
        Ok(())
    }
}

impl Drop for CoreHandle {
    fn drop(&mut self) {
        if !self.clean_shutdown {
            eprintln!("⚠️  UNCLEAN SHUTDOWN OCCURRED ⚠️ ");
        }
        // Can't enable yet until we clean up unix_int cache layer test
        // debug_assert!(self.clean_shutdown);
    }
}

#[allow(clippy::result_unit_err)]
pub async fn create_server_core(
    config: Configuration,
    config_test: bool,
) -> Result<CoreHandle, ()> {
    // Until this point, we probably want to write to the log macro fns.
    let (mut broadcast_tx, _broadcast_rx) = broadcast::channel(4);

    if config.integration_test_config.is_some() {
        warn!("RUNNING IN INTEGRATION TEST MODE.");
        warn!("IF YOU SEE THIS IN PRODUCTION YOU MUST CONTACT SUPPORT IMMEDIATELY.");
    } else if config.tls_config.is_none() {
        // TLS is great! We won't run without it.
        error!("Running without TLS is not supported! Quitting!");
        return Err(());
    }

    info!(
        "Starting kubidm with {}configuration: {}",
        if config_test { "TEST " } else { "" },
        config
    );
    // Setup umask, so that every we touch or create is secure.
    #[cfg(not(target_family = "windows"))]
    unsafe {
        umask(0o0027)
    };

    // Setup TLS (if any)
    let maybe_tls_acceptor = match crypto::setup_tls(&config.tls_config) {
        Ok(tls_acc) => tls_acc,
        Err(err) => {
            error!(?err, "Failed to configure TLS acceptor");
            return Err(());
        }
    };

    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return Err(());
        }
    };

    // Point-in-time recovery: the backend archives every committed write. A config test
    // validates the settings but must not create the WAL directory.
    let pitr_settings = match PitrSettings::from_config(&config) {
        Ok(settings) => settings,
        Err(err) => {
            error!(%err, "Invalid WAL archive configuration");
            return Err(());
        }
    };
    let backend_wal_config = match (&pitr_settings, config_test) {
        (Some(settings), false) => Some(settings.backend_wal_config()),
        _ => None,
    };

    // Setup the be for the qs.
    let be = match setup_backend_inner(&config, &schema, false, backend_wal_config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE -> {:?}", e);
            return Err(());
        }
    };
    let pitr_archive = match (pitr_settings, be.wal_archiver()) {
        (Some(settings), Some(archiver)) => {
            info!(
                location = %settings.location,
                bases = %settings.bases,
                "Point-in-time recovery: archiving committed writes"
            );
            Some(Arc::new(PitrArchive::new(settings, archiver)))
        }
        _ => None,
    };
    // Start the IDM server.
    let (_qs, idms, idms_delayed, idms_audit) = match setup_qs_idms(be, schema, &config).await {
        Ok(t) => t,
        Err(e) => {
            error!("Unable to setup query server or idm server -> {:?}", e);
            return Err(());
        }
    };

    // Any pre-start tasks here.
    if let Some(itc) = &config.integration_test_config {
        let Ok(mut idms_prox_write) = idms.proxy_write(duration_from_epoch_now()).await else {
            error!("Unable to acquire write transaction");
            return Err(());
        };
        // We need to set the admin pw.
        match idms_prox_write.recover_account(&itc.admin_user, Some(&itc.admin_password)) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST {} account -> {:?}",
                    &itc.admin_user, e
                );
                return Err(());
            }
        };
        // set the idm_admin account password
        match idms_prox_write.recover_account(&itc.idm_admin_user, Some(&itc.idm_admin_password)) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST {} account -> {:?}",
                    &itc.idm_admin_user, e
                );
                return Err(());
            }
        };

        // Add admin to idm_admins to allow tests more flexibility wrt to permissions.
        // This way our default access controls can be stricter to prevent lateral
        // movement.
        match idms_prox_write.qs_write.internal_modify_uuid(
            UUID_IDM_ADMINS,
            &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ADMIN)),
        ) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST admin as member of idm_admins -> {:?}",
                    e
                );
                return Err(());
            }
        };

        match idms_prox_write.qs_write.internal_modify_uuid(
            UUID_IDM_ALL_PERSONS,
            &ModifyList::new_purge_and_set(
                Attribute::CredentialTypeMinimum,
                CredentialType::Any.into(),
            ),
        ) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST default credential policy -> {:?}",
                    e
                );
                return Err(());
            }
        };

        match idms_prox_write.commit() {
            Ok(_) => {}
            Err(e) => {
                error!("Unable to commit INTEGRATION TEST setup -> {:?}", e);
                return Err(());
            }
        }
    }

    let ldap = match LdapServer::new(&idms).await {
        Ok(l) => l,
        Err(e) => {
            error!("Unable to start LdapServer -> {:?}", e);
            return Err(());
        }
    };

    // Arc the idms and ldap
    let idms_arc = Arc::new(idms);
    let ldap_arc = Arc::new(ldap);

    // Pass it to the actor for threading.
    // Start the read query server with the given be path: future config
    let server_read_ref = QueryServerReadV1::start_static(idms_arc.clone(), ldap_arc.clone());

    // Create the server async write entry point.
    let server_write_ref = QueryServerWriteV1::start_static(idms_arc.clone());

    let mut handles: Vec<(TaskName, task::JoinHandle<()>)> = Vec::with_capacity(16);

    let startup_success = if config_test {
        info!("This config rocks! 🪨 ");
        Ok(())
    } else {
        launch_server_tasks(
            &mut handles,
            &config,
            &mut broadcast_tx,
            idms_delayed,
            idms_audit,
            server_read_ref,
            server_write_ref,
            idms_arc,
            maybe_tls_acceptor,
            pitr_archive.clone(),
        )
        .await
    };

    let mut server_ctx = CoreHandle {
        clean_shutdown: false,
        tx: broadcast_tx,
        handles,
        server_read_ref,
        pitr_archive,
    };

    if startup_success.is_ok() {
        Ok(server_ctx)
    } else {
        server_ctx.shutdown().await;
        Err(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn launch_server_tasks(
    handles: &mut Vec<(TaskName, task::JoinHandle<()>)>,

    config: &Configuration,
    broadcast_tx: &mut broadcast::Sender<CoreAction>,

    mut idms_delayed: IdmServerDelayed,
    mut idms_audit: IdmServerAudit,

    server_read_ref: &'static QueryServerReadV1,
    server_write_ref: &'static QueryServerWriteV1,

    idms_arc: Arc<IdmServer>,

    maybe_tls_acceptor: Option<TlsAcceptor>,

    pitr_archive: Option<Arc<PitrArchive>>,
) -> Result<(), ()> {
    let status_ref = StatusActor::start();
    let tracker = status_ref.get_tracker_clone();

    // Delayed actions
    let mut broadcast_rx = broadcast_tx.subscribe();

    let delayed_handle = task::spawn(async move {
        let mut buffer = Vec::with_capacity(DELAYED_ACTION_BATCH_SIZE);
        loop {
            tokio::select! {
                added = idms_delayed.recv_many(&mut buffer) => {
                    if added == 0 {
                        // Channel has closed, stop the task.
                        break
                    }
                    server_write_ref.handle_delayedaction(&mut buffer).await;
                }
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                        CoreAction::Reload => {},
                    }
                }
            }
        }
        info!("Stopped {}", TaskName::DelayedActionActor);
    });

    handles.push((TaskName::DelayedActionActor, delayed_handle));

    // Auditing tasks
    let mut broadcast_rx = broadcast_tx.subscribe();

    let auditd_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                        CoreAction::Reload => {},
                    }
                }
                audit_event = idms_audit.audit_rx().recv() => {
                    match serde_json::to_string(&audit_event) {
                        Ok(audit_event) => {
                            warn!(%audit_event);
                        }
                        Err(e) => {
                            error!(err=?e, "Unable to process audit event to json.");
                            warn!(?audit_event, json=false);
                        }
                    }

                }
            }
        }
        info!("Stopped {}", TaskName::AuditdActor);
    });

    handles.push((TaskName::AuditdActor, auditd_handle));

    // WAL archiving runs in every mode, integration tests included: it only ships what
    // the backend already recorded.
    if let Some(archive) = &pitr_archive {
        let wal_handle = pitr::start_wal_archive_task(archive.clone(), broadcast_tx.subscribe());
        handles.push((TaskName::WalArchive, wal_handle));
    }

    // Run the migrations *once*, only in production though.
    let migration_path = config
        .migration_path
        .clone()
        .unwrap_or(PathBuf::from(env!("KUBIDM_SERVER_MIGRATION_PATH")));

    if config.integration_test_config.is_none() {
        let eventid = Uuid::new_v4();
        migration_apply(eventid, server_write_ref, migration_path.as_path()).await;

        let replication_configured = config.repl_config.is_some();
        tracker.mark_startup_complete(replication_configured);

        // Skip all these handles in integration test mode.

        // Setup the Migration Reload Trigger.
        let broadcast_rx = broadcast_tx.subscribe();
        let migration_reload_handle = task::spawn(async move {
            migration_reload_supervisor(broadcast_rx, server_write_ref, migration_path).await
        });

        handles.push((TaskName::MigrationReload, migration_reload_handle));

        // Setup timed events associated to the write thread
        let interval_handle = IntervalActor::start(server_write_ref, broadcast_tx.subscribe());

        handles.push((TaskName::IntervalActor, interval_handle));

        // Setup timed events associated to the read thread
        match &config.online_backup {
            Some(online_backup_config) => {
                if online_backup_config.enabled {
                    let backup_handles = IntervalActor::start_online_backup(
                        server_read_ref,
                        online_backup_config,
                        pitr_archive.clone(),
                        broadcast_tx.subscribe(),
                    )?;
                    handles.extend(backup_handles);
                } else {
                    debug!("Backups disabled");
                }
            }
            None => {
                debug!("Online backup not configured, skipping");
            }
        };

        // If we have replication configured, setup the listener with its initial replication
        // map (if any).
        let maybe_repl_ctrl_tx = match &config.repl_config {
            Some(rc) => {
                // ⚠️  only start the sockets and listeners in non-config-test modes.
                let repl_server_handles = repl::create_repl_server(
                    idms_arc.clone(),
                    rc,
                    broadcast_tx.subscribe(),
                    tracker.clone(),
                )
                .await?;

                let ReplicationServerHandles {
                    repl_handle,
                    ctrl_tx,
                } = repl_server_handles;

                handles.push((TaskName::ReplicationSupervisor, repl_handle));

                Some(ctrl_tx)
            }
            None => {
                debug!("Replication not configured, skipping");
                None
            }
        };

        let broadcast_tx_ = broadcast_tx.clone();

        let admin_handle = AdminActor::create_admin_sock(
            config.adminbindpath.as_str(),
            server_write_ref,
            server_read_ref,
            broadcast_tx_,
            maybe_repl_ctrl_tx,
        )
        .await?;

        handles.push((TaskName::AdminSocket, admin_handle));
    } else {
        let replication_configured = config.repl_config.is_some();
        tracker.mark_startup_complete(replication_configured);
    }

    // Setup a TLS Acceptor Reload trigger.

    let mut broadcast_rx = broadcast_tx.subscribe();
    let tls_config = config.tls_config.clone();

    let (tls_acceptor_reload_tx, _tls_acceptor_reload_rx) = broadcast::channel(1);
    let tls_acceptor_reload_tx_c = tls_acceptor_reload_tx.clone();

    let tls_acceptor_reload_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                        CoreAction::Reload => {
                            let tls_acceptor = match crypto::setup_tls(&tls_config) {
                                Ok(Some(tls_acc)) => tls_acc,
                                Ok(None) => {
                                    warn!("TLS not configured, ignoring reload request.");
                                    continue;
                                }
                                Err(err) => {
                                    error!(?err, "Failed to configure and reload TLS acceptor");
                                    continue;
                                }
                            };

                            // We don't log here as the receivers will notify when they have completed
                            // the reload.
                            if tls_acceptor_reload_tx_c.send(tls_acceptor).is_err() {
                                error!("TLS acceptor did not accept the reload, the server may have failed!");
                            };
                            info!("TLS acceptor reload notification sent");
                        },
                    }
                }
            }
        }
        info!("Stopped {}", TaskName::TlsAcceptorReload);
    });

    handles.push((TaskName::TlsAcceptorReload, tls_acceptor_reload_handle));

    // If we have been requested to init LDAP, configure it now.
    match &config.ldapbindaddress {
        Some(la) => {
            let logging_pipeline = match config.otel_grpc_endpoint {
                Some(_) => LoggerType::OpenTelemetry,
                None => LoggerType::TracingForest,
            };
            let opt_ldap_ssl_acceptor = maybe_tls_acceptor.clone();

            let ldap_handles = ldaps::create_ldap_server(
                la,
                opt_ldap_ssl_acceptor,
                server_read_ref,
                broadcast_tx,
                &tls_acceptor_reload_tx,
                Arc::new(config.ldap_client_address_info.trusted_tcp_info()),
                logging_pipeline,
            )
            .await?;
            for ldap_handle in ldap_handles {
                handles.push((TaskName::LdapActor, ldap_handle));
            }
        }
        None => {
            debug!("LDAP not requested, skipping");
        }
    };

    // Finally launch the https tasks.
    let http_handles: Vec<task::JoinHandle<()>> = https::create_https_server(
        config.clone(),
        status_ref,
        server_write_ref,
        server_read_ref,
        broadcast_tx.clone(),
        maybe_tls_acceptor,
        &tls_acceptor_reload_tx,
    )
    .await
    .inspect_err(|err| {
        error!(?err, "Failed to start HTTPS server");
    })?;

    if config.role != ServerRole::WriteReplicaNoUI {
        admin_info!("Ready to rock! 🪨  UI available at: {}", config.origin);
    } else {
        admin_info!("Ready to rock! 🪨 ");
    }

    for http_handle in http_handles {
        handles.push((TaskName::HttpsServer, http_handle))
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OnlineBackup;
    use kubidm_proto::backup::{ReplicationRegionStatus, S3Credentials};

    fn region(name: &str, bucket: &str) -> ReplicationRegionConfig {
        ReplicationRegionConfig {
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
