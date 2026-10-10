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

pub use crate::backup::{
    cli::{
        backup_server_core, list_backups_server_core, replicate_status_server_core,
        restore_s3_database, restore_server_core, s3_config_for_cli, verify_backup_server_core,
        verify_s3_backup_server_core, BackupVerifyLevel, RestoreStatus,
    },
    restore::restore_database,
};
use crate::{
    actors::{QueryServerReadV1, QueryServerWriteV1},
    admin::AdminActor,
    backup::{
        online::OnlineBackupJob,
        pitr::{self, BaseLocation, PitrArchive, PitrError, PitrSettings, PitrSyncReport},
    },
    config::{Configuration, ServerRole},
    interval::IntervalActor,
    repl::ReplicationServerHandles,
};
use crypto_glue::{
    s256::{Sha256, Sha256Output},
    traits::Digest,
};
use kubidm_proto::{
    backup::{BackupCompression, BackupEncryptionConfig, S3Config, WalArchiveConfig},
    internal::{ConsistencyError, OperationError},
    scim_v1::client::ScimAssertGeneric,
};
use kubidmd_lib::{
    be::{Backend, BackendConfig, BackendWriteTransaction},
    idm::ldap::LdapServer,
    prelude::*,
    schema::Schema,
    status::StatusActor,
    value::CredentialType,
};
use regex::Regex;
use sketching::LoggerType;
use std::{
    collections::BTreeSet,
    fmt::{Display, Formatter},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
};
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
            if let Err(err) = archiver.persist_pending_events() {
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

pub async fn dbscan_quarantine_id2entry_core(config: &Configuration, id: u64) {
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

    if !note_dbscan_change(config, &mut be_wrtxn, "db-scan quarantine-id2entry").await {
        return;
    }

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

/// Before a `db-scan` command changes the database outside a transaction the WAL archive
/// could record: record the change as a gap in the archive, when WAL archiving is
/// configured, so that point-in-time recovery never replays across it. Returns false, after
/// logging why, when the gap could not be recorded; the command must then not change the
/// database.
async fn note_dbscan_change(
    config: &Configuration,
    be_wrtxn: &mut BackendWriteTransaction<'_>,
    command: &str,
) -> bool {
    let db_ts_max = match be_wrtxn.get_db_ts_max(Duration::ZERO) {
        Ok(db_ts_max) => db_ts_max,
        Err(err) => {
            error!(?err, "Unable to read the last transaction of the database");
            return false;
        }
    };
    match pitr::note_offline_change(config, db_ts_max, command).await {
        Ok(_) => true,
        Err(err) => {
            error!(
                %err,
                "The change could not be recorded in the WAL archive nor handed to the server, \
                 so point-in-time recovery could replay across it; the database was not changed"
            );
            false
        }
    }
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

pub async fn dbscan_restore_quarantined_core(config: &Configuration, id: u64) {
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

    if !note_dbscan_change(config, &mut be_wrtxn, "db-scan restore-quarantined").await {
        return;
    }

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
            archive.persist_pending_events();
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
        self.trigger_backup(
            BaseLocation::Local(outpath.to_path_buf()),
            versions,
            compression,
            encryption,
        )
        .await
    }

    /// Run an online backup to S3 now, through the same code path the scheduled S3 backup
    /// uses, including replication and retention of `versions` backups under the
    /// configured prefix. This exists so tests can exercise the production S3 backup path
    /// on demand.
    pub async fn trigger_s3_backup(
        &self,
        s3_config: S3Config,
        versions: usize,
        compression: BackupCompression,
        encryption: &BackupEncryptionConfig,
    ) -> Result<(), OperationError> {
        self.trigger_backup(
            BaseLocation::S3(s3_config),
            versions,
            compression,
            encryption,
        )
        .await
    }

    async fn trigger_backup(
        &self,
        target: BaseLocation,
        versions: usize,
        compression: BackupCompression,
        encryption: &BackupEncryptionConfig,
    ) -> Result<(), OperationError> {
        OnlineBackupJob {
            targets: vec![target],
            versions,
            compression,
            encryption: encryption.clone(),
            pitr_archive: self.pitr_archive.clone(),
        }
        .run(self.server_read_ref)
        .await
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
