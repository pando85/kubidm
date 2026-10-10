//! Verification of backup artifacts beyond the structural check every backup gets after
//! it is written: the levels of `kubidmd database verify-backup`, as steps that do not
//! print, so that a running server can take them as well.
//!
//! The artifact is opened (and decrypted) the way a restore opens it and parsed, then
//! restored into a scratch database in a temporary directory through the production
//! restore path, that database is booted as a server start would boot it and the full
//! consistency verification runs on it. The database of the configuration is never
//! opened, and the temporary directory is removed afterwards.

use std::path::Path;

use kubidm_proto::internal::ConsistencyError;
use kubidmd_lib::be::{verify_backup_structure, BackupStructuralReport};

use super::restore::{backup_encryption_config, restore_database};
use super::{open_backup_file_with_config, run_blocking};
use crate::config::Configuration;
use crate::verify_booted_database;

/// The structural verification of an artifact.
pub(crate) struct StructuralVerification {
    /// The key the artifact is encrypted with, when it is encrypted.
    pub encryption_key: Option<String>,
    /// The report of the checks, or why the artifact could not be checked at all.
    pub report: Result<BackupStructuralReport, String>,
}

/// Open the artifact at `path` with the encryption key of `config` and run the structural
/// checks on it: its format, entry count and server version. Never opens a database.
pub(crate) async fn verify_backup_structure_at(
    config: &Configuration,
    path: &Path,
) -> StructuralVerification {
    let opened = match open_backup_file_with_config(path, backup_encryption_config(config)).await {
        Ok(opened) => opened,
        Err(err) => {
            error!(%err, "Unable to open backup {}", path.display());
            return StructuralVerification {
                encryption_key: None,
                report: Err(format!("unable to open {}: {err}", path.display())),
            };
        }
    };
    let encryption_key = opened.key_identifier().map(str::to_string);

    // Decompressing and parsing the whole backup is blocking work.
    let compression = opened.compression;
    let reader = opened.reader;
    let report = tokio::task::spawn_blocking(move || verify_backup_structure(reader, compression))
        .await
        .map_err(|err| format!("the verification task failed: {err}"));

    StructuralVerification {
        encryption_key,
        report,
    }
}

/// Restore the artifact at `path` into a scratch database in a new temporary directory
/// through the production restore path, boot that database exactly as a server start
/// would and run the full consistency verification on it. Returns the consistency errors
/// found, empty for a restorable backup, or why the restore or the boot failed. The
/// temporary directory is removed when this returns.
///
/// `stop` is asked between the restore and the boot; when it answers true the boot is
/// skipped and an error returned.
pub(crate) async fn verify_backup_restores(
    config: &Configuration,
    path: &Path,
    stop: &(dyn Fn() -> bool + Sync),
) -> Result<Vec<ConsistencyError>, String> {
    let scratch_dir = tempfile::tempdir().map_err(|err| {
        error!(?err, "Unable to create a scratch directory");
        format!("unable to create a scratch directory: {err}")
    })?;

    // The restore touches the database file and ends the process when it can not. The
    // file is created here, so that a verification inside a running server can only
    // fail, never stop the server.
    let db_path = scratch_dir.path().join("verify.db");
    let create_path = db_path.clone();
    run_blocking(move || std::fs::File::create(create_path).map(drop))
        .await
        .map_err(|err| format!("unable to create the scratch database: {err}"))?;

    let mut scratch_config = config.clone();
    scratch_config.db_path = Some(db_path);

    info!(
        "Restoring backup into scratch database in {}",
        scratch_dir.path().display()
    );

    restore_database(&scratch_config, path)
        .await
        .map_err(|err| format!("restore failed: {err:?}"))?;

    if stop() {
        return Err("abandoned before the restored database was booted".to_string());
    }

    // Boot the restored database from scratch exactly as a server start would. The
    // restore above ran in this process, so its backend still carries in-memory state
    // from before the restore (such as the RUV). A fresh boot is what proves the
    // database starts into a consistent state.
    verify_booted_database(&scratch_config)
        .await
        .map_err(|err| format!("restored database could not be opened: {err:?}"))
}
