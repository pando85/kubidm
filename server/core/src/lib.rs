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
        finalize_local_backup, is_backup_artifact_name, open_backup_file_with_config, seal_backup,
        verify_backup_output, BackupEncryptor, BackupVerifyError, S3BackupError, S3ClientWrapper,
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
        is_encrypted_backup_name, BackupCompression, BackupEncryptionConfig, S3BackupMetadata,
        S3Config, BACKUP_ENCRYPTED_SUFFIX,
    },
    internal::{ConsistencyError, OperationError},
    scim_v1::client::ScimAssertGeneric,
};
use kubidmd_lib::{
    be::{
        verify_backup_structure, Backend, BackendConfig, BackendTransaction, BackupStructuralReport,
    },
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
    );

    Backend::new(cfg, idxmeta, vacuum)
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

    let mut be_ro_txn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
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
    // a verified backup is ever emitted to stdout.
    let mut backup_data = Vec::new();
    if let Err(e) = be_ro_txn.backup(&mut backup_data, compression) {
        error!("Backup failed: {:?}", e);
        std::process::exit(1);
    }
    // Let the txn abort, even on success.
    drop(be_ro_txn);

    let artifact = match seal_backup(backup_data, compression, encryptor.as_ref()) {
        Ok(artifact) => artifact,
        Err(err) => {
            error!(%err, "Backup failed: unable to encrypt the backup");
            std::process::exit(1);
        }
    };

    if let Some(dst_path) = dst_path {
        if let Err(err) = std::fs::write(dst_path, &artifact) {
            error!(
                ?err,
                "Backup failed: unable to write {}",
                dst_path.display()
            );
            std::process::exit(1);
        }
        drop(artifact);
        info!("Backup written to {}", dst_path.display());

        // Read the artifact back before announcing it. A rejected artifact is kept under
        // an `.invalid` suffix for inspection.
        report_backup_verification(finalize_local_backup(
            dst_path,
            compression,
            encryptor.as_ref(),
        ));
    } else {
        report_backup_verification(verify_backup_output(
            &artifact,
            compression,
            encryptor.as_ref(),
        ));

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
    if restore_database(config, dst_path).await.is_err() {
        std::process::exit(1);
    }

    info!("✅ Restore Success!");
}

/// Restore the backup at `src_path` into the database described by `config` and
/// reindex it. This is the production restore path. Backup verification shares it so
/// that a verified backup has been exercised exactly as a real restore would.
pub async fn restore_database(
    config: &Configuration,
    src_path: &Path,
) -> Result<(), OperationError> {
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
        .and_then(|_| be_wr_txn.commit())
        .inspect_err(|err| {
            error!(?err, "Failed to restore database");
        })?;
    info!("Database loaded successfully");

    reindex_inner(be, schema, config).await
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

    let report = match verify_backup_structure(opened.reader, opened.compression) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("Backup structural verification: FAIL");
            eprintln!("  - artifact could not be parsed as a kubidm backup: {err:?}");
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

/// Resolve the S3 configuration an offline recovery command (`restore-s3`, `verify-s3`)
/// uses: the `[online_backup.s3]` section of the server configuration with `bucket`,
/// `region` and `endpoint` replaced by any command line override. Without a configured
/// section, `bucket` must be given; credentials and region then come from the SDK's
/// default provider chain.
pub fn s3_config_for_cli(
    config: &Configuration,
    bucket: Option<String>,
    region: Option<String>,
    endpoint: Option<String>,
) -> Result<S3Config, OperationError> {
    let configured = config
        .online_backup
        .as_ref()
        .and_then(|backup| backup.s3.clone());

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

    if let Some(region) = region {
        s3_config.region = Some(region);
    }
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
    let encryption_suffix = if metadata.encrypted {
        BACKUP_ENCRYPTED_SUFFIX
    } else {
        ""
    };
    let path = scratch_dir.path().join(format!(
        "backup.json{}{encryption_suffix}",
        metadata.compression.suffix()
    ));
    std::fs::write(&path, &data)?;

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

    restore_database(config, &fetched.path).await
    // `fetched` is dropped here, removing the downloaded artifact.
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
/// S3 prefix. A location that is not configured is reported as such. Returns false only when
/// a configured location could not be read.
pub async fn list_backups_server_core(
    config: &Configuration,
    local_only: bool,
    s3_only: bool,
) -> bool {
    let mut ok = true;

    if !s3_only {
        ok &= list_local_backups(config);
    }

    if !local_only {
        if !s3_only {
            println!();
        }
        ok &= list_s3_backups(config).await;
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

async fn list_s3_backups(config: &Configuration) -> bool {
    let Some(s3_config) = config
        .online_backup
        .as_ref()
        .and_then(|backup| backup.s3.clone())
    else {
        println!("S3 backups: none configured");
        return true;
    };

    let location = match &s3_config.path_prefix {
        Some(prefix) => format!("s3://{}/{}", s3_config.bucket, prefix.trim_end_matches('/')),
        None => format!("s3://{}", s3_config.bucket),
    };
    println!("S3 backups in {location}:");

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

    let be = match setup_backend(config, &schema) {
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

    // Start the backend.
    let be = match setup_backend(config, &schema) {
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
    DelayedActionActor,
    HttpsServer,
    IntervalActor,
    LdapActor,
    ReplicationSupervisor,
    TlsAcceptorReload,
    MigrationReload,
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
                TaskName::DelayedActionActor => "Delayed Action Actor",
                TaskName::HttpsServer => "HTTPS Server",
                TaskName::IntervalActor => "Interval Actor",
                TaskName::LdapActor => "LDAP Acceptor Actor",
                TaskName::ReplicationSupervisor => "Replication Supervisor",
                TaskName::TlsAcceptorReload => "TlsAcceptor Reload Monitor",
                TaskName::MigrationReload => "Migration Reload Monitor",
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

        self.clean_shutdown = true;
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
        self.server_read_ref
            .handle_online_backup(
                kubidmd_lib::event::OnlineBackupEvent::new(),
                outpath,
                versions,
                compression,
                encryption,
                None,
            )
            .await
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
        let client = S3ClientWrapper::new(s3_config).await.map_err(|err| {
            error!(%err, "Unable to create the S3 client");
            OperationError::InvalidState
        })?;

        self.server_read_ref
            .handle_online_backup(
                kubidmd_lib::event::OnlineBackupEvent::new(),
                Path::new("s3://backup"),
                versions,
                compression,
                encryption,
                Some(client),
            )
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

    // Setup the be for the qs.
    let be = match setup_backend(&config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE -> {:?}", e);
            return Err(());
        }
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
        )
        .await
    };

    let mut server_ctx = CoreHandle {
        clean_shutdown: false,
        tx: broadcast_tx,
        handles,
        server_read_ref,
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
                    let backup_handle = IntervalActor::start_online_backup(
                        server_read_ref,
                        online_backup_config,
                        broadcast_tx.subscribe(),
                    )?;
                    handles.push((TaskName::BackupActor, backup_handle));
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
