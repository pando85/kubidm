//! Verification of backup artifacts beyond the structural check every backup gets after
//! it is written: the levels of `kubidmd database verify-backup`, and the scheduled full
//! verification of the newest backup a running server does with
//! `online_backup.verify_schedule`.
//!
//! Both share the same steps, so that a scheduled verification proves exactly what the
//! command proves: the artifact is opened (and decrypted) the way a restore opens it and
//! parsed, then restored into a scratch database through the production restore path,
//! that database is booted as a server start would boot it and the full consistency
//! verification runs on it. The database of the configuration is never opened.
//!
//! Every scratch directory (the copied or downloaded artifact, the scratch database) is
//! named with [`SCRATCH_DIR_PREFIX`]. The scheduled verification creates them in a
//! directory of its server, named after the database file, by default next to the database
//! ([`verify_scratch_parent`]); the server removes the ones an interrupted run left behind
//! when it starts. The command uses `TMPDIR`.

use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use kubidm_proto::backup::S3Config;
use kubidm_proto::internal::{ConsistencyError, OperationError};
use kubidmd_lib::be::{verify_backup_structure, BackupStructuralReport};
use kubidmd_lib::maintenance::maintenance_write_allowed;
use kubidmd_lib::prelude::duration_from_epoch_now;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::cli::fetch_s3_backup_into;
use super::metrics::{BackupDestination, BackupMetrics};
use super::restore::{backup_encryption_config, on_database_thread, restore_and_replay_commit};
use super::{
    compare_backup_names, is_backup_artifact_name, open_backup_file_with_config, run_blocking,
    BackupOpenError, S3BackupError, S3ClientWrapper,
};
use crate::config::Configuration;
use crate::{collect_consistency_errors, open_schema_and_backend, setup_qs};

/// The prefix of the name of every scratch directory a verification creates. The server
/// removes the directories with this prefix in its scratch location when it starts: they
/// can only be left behind by a run that was killed.
pub const SCRATCH_DIR_PREFIX: &str = "kubidm-verify-";

/// The size, in entries, of the entry cache of a scratch database restored by the
/// scheduled verification: the smallest the backend accepts. The scratch database lives
/// inside the running server, whose own cache is sized for the live database.
const SCRATCH_ARC_SIZE: usize = 2048;

/// Why a verification step did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyError {
    /// The step could not run: the artifact could not be read, the encryption key could
    /// not be obtained or the scratch space could not be used. It says nothing about the
    /// artifact.
    Environment(String),
    /// The artifact failed the step: it can not be restored.
    Artifact(String),
    /// The step was not started because the verification was told to stop.
    Abandoned(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Environment(reason)
            | VerifyError::Artifact(reason)
            | VerifyError::Abandoned(reason) => write!(f, "{reason}"),
        }
    }
}

/// The structural verification of an artifact.
pub(crate) struct StructuralVerification {
    /// The key the artifact is encrypted with, when it is encrypted.
    pub encryption_key: Option<String>,
    /// The report of the checks, or why the artifact could not be checked at all.
    pub report: Result<BackupStructuralReport, VerifyError>,
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
            let reason = format!("unable to open {}: {err}", path.display());
            let report = Err(match err {
                // The file could not be read, or the key obtained: nothing is known about
                // the artifact itself.
                BackupOpenError::Io { .. } | BackupOpenError::KeyUnavailable { .. } => {
                    VerifyError::Environment(reason)
                }
                _ => VerifyError::Artifact(reason),
            });
            return StructuralVerification {
                encryption_key: None,
                report,
            };
        }
    };
    let encryption_key = opened.key_identifier().map(str::to_string);

    // Decompressing and parsing the whole backup is blocking work.
    let compression = opened.compression;
    let reader = opened.reader;
    let report = tokio::task::spawn_blocking(move || verify_backup_structure(reader, compression))
        .await
        .map_err(|err| VerifyError::Artifact(format!("the verification task failed: {err}")));

    StructuralVerification {
        encryption_key,
        report,
    }
}

/// A new scratch directory, named with [`SCRATCH_DIR_PREFIX`], in `parent`, which is
/// created when missing, or in the directory of `TMPDIR` without one. Only its owner can
/// read it: it holds a restored, unencrypted database.
pub(crate) fn new_scratch_dir(parent: Option<&Path>) -> io::Result<TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(SCRATCH_DIR_PREFIX);
    match parent {
        Some(parent) => {
            std::fs::create_dir_all(parent)?;
            builder.tempdir_in(parent)
        }
        None => builder.tempdir(),
    }
}

/// Remove the scratch directories, named with [`SCRATCH_DIR_PREFIX`], that a verification
/// killed before it could clean up left in `parent`. Returns how many were removed. A
/// directory that can not be removed is logged and left.
pub(crate) fn remove_stale_scratch_dirs(parent: &Path) -> io::Result<usize> {
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let is_scratch = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(SCRATCH_DIR_PREFIX));
        // A symbolic link is never followed: only real directories are removed.
        if !is_scratch || !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                warn!(
                    "Removed {}, left behind by a backup verification that was interrupted",
                    path.display()
                );
                removed += 1;
            }
            Err(err) => warn!(
                %err,
                "Unable to remove {}, left behind by a backup verification that was \
                 interrupted",
                path.display()
            ),
        }
    }
    Ok(removed)
}

/// The suffix of the directory the scheduled verification of a server creates its scratch
/// directories in: `<database file><suffix>`, see [`verify_scratch_parent`].
pub const SCRATCH_PARENT_SUFFIX: &str = ".verify";

/// Where the scheduled verification of the server described by `config` creates its
/// scratch directories: `<database file>.verify`, in `online_backup.verify_temp_path`, by
/// default in the directory of the database, which is sized for a database and as private
/// as one. Being named after the database file, it is per server even when several servers
/// keep their databases in one directory or share a `verify_temp_path`: the start-up sweep
/// of one never removes the scratch data of another one's run. `verify_temp_path` itself
/// for a server without a database file, and None, for `TMPDIR`, without either.
pub fn verify_scratch_parent(config: &Configuration) -> Option<PathBuf> {
    let configured = config
        .online_backup
        .as_ref()
        .and_then(|online_backup| online_backup.verify_temp_path.clone());
    let Some(db_path) = config.db_path.as_ref() else {
        return configured;
    };
    let Some(db_file) = db_path.file_name() else {
        return configured;
    };
    let base = configured.unwrap_or_else(|| match db_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    });
    let mut name = db_file.to_os_string();
    name.push(SCRATCH_PARENT_SUFFIX);
    Some(base.join(name))
}

/// Restore the artifact at `path` into a scratch database in a new scratch directory in
/// `scratch_parent` (see [`new_scratch_dir`]) through the production restore path, boot
/// that database exactly as a server start would and run the full consistency
/// verification on it. Returns the consistency errors found, empty for a restorable
/// backup, or why a step failed. The scratch directory is removed when this returns.
///
/// `stop` is asked between the steps (the restore, the reindex, the boot and the
/// consistency checks); when it answers true the next step is not started.
pub(crate) async fn verify_backup_restores(
    config: &Configuration,
    path: &Path,
    scratch_parent: Option<&Path>,
    stop: Arc<dyn Fn() -> bool + Send + Sync>,
) -> Result<Vec<ConsistencyError>, VerifyError> {
    let parent = scratch_parent.map(Path::to_path_buf);
    let scratch_dir = run_blocking(move || new_scratch_dir(parent.as_deref()))
        .await
        .map_err(|err| {
            error!(?err, "Unable to create a scratch directory");
            VerifyError::Environment(format!("unable to create a scratch directory: {err}"))
        })?;
    let abandoned = |step: &str| Err(VerifyError::Abandoned(format!("abandoned before {step}")));

    let mut scratch_config = config.clone();
    scratch_config.db_path = Some(scratch_dir.path().join("verify.db"));

    info!(
        "Restoring backup into scratch database in {}",
        scratch_dir.path().display()
    );

    let committed = restore_and_replay_commit(&scratch_config, path, Vec::new())
        .await
        .map_err(|err| match err {
            // The artifact or the scratch database file could not be read or written.
            OperationError::FsError => VerifyError::Environment(format!("restore failed: {err:?}")),
            err => VerifyError::Artifact(format!("restore failed: {err:?}")),
        })?;
    if stop() {
        return abandoned("the restored database was reindexed");
    }
    committed
        .reindex(&scratch_config)
        .await
        .map_err(|err| VerifyError::Artifact(format!("restore failed: {err:?}")))?;
    if stop() {
        return abandoned("the restored database was booted");
    }

    // Boot the restored database from scratch exactly as a server start would. The
    // restore above ran in this process, so its backend still carries in-memory state
    // from before the restore (such as the RUV). A fresh boot is what proves the
    // database starts into a consistent state. Like the restore, the boot and the checks
    // run on the database thread: the outer result says whether that thread ran at all,
    // the inner one whether the database booted.
    let booted = on_database_thread(move || async move {
        let booted = match open_schema_and_backend(&scratch_config) {
            Ok((schema, be)) => setup_qs(be, schema, &scratch_config)
                .await
                .inspect_err(|err| error!(?err, "Failed to start query server")),
            Err(err) => Err(err),
        };
        Ok(match booted {
            Ok(_) if stop() => Ok(None),
            Ok(server) => Ok(Some(collect_consistency_errors(server.verify().await))),
            Err(err) => Err(err),
        })
    })
    .await
    .map_err(|err| VerifyError::Environment(format!("the database thread failed: {err:?}")))?;
    match booted {
        Ok(Some(errors)) => Ok(errors),
        Ok(None) => abandoned("the consistency checks"),
        Err(err) => Err(VerifyError::Artifact(format!(
            "restored database could not be opened: {err:?}"
        ))),
    }
}

/// What a scheduled verification found for one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupVerifyOutcome {
    /// The newest artifact passed the full verification.
    Passed,
    /// The newest artifact failed it, for these reasons: it can not be restored.
    Failed(Vec<String>),
    /// The verification could not run, for this reason: the backups could not be listed,
    /// copied or downloaded, the encryption key could not be obtained or the scratch space
    /// could not be used. It proves nothing about the artifact.
    Error(String),
    /// The destination holds no backup yet.
    NoBackup,
    /// The verification was abandoned, for this reason (the server shuts down, or the
    /// node entered maintenance). It proves nothing either way and is not recorded.
    Abandoned(String),
}

/// The verification of the newest artifact of one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationVerification {
    pub destination: BackupDestination,
    /// The name of the verified artifact, prefix-relative for S3.
    pub artifact: Option<String>,
    /// Whether the outcome is the one of the identical local artifact the same run
    /// verified, so that this artifact was not restored a second time.
    pub reused_local: bool,
    pub outcome: BackupVerifyOutcome,
}

/// One run of the scheduled verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupVerifyRun {
    /// Every configured destination was looked at, in order: local, then S3.
    Completed(Vec<DestinationVerification>),
    /// Nothing was verified, for this reason: another verification is still running, or
    /// the node is in maintenance.
    Skipped(String),
}

/// Sets the flag it holds when dropped: a run of the verification that is dropped (the
/// server shuts down) tells the blocking work it handed off to stop at its next step.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// The outcome of a verification that did not complete because of `error`: abandoned when
/// the run was told to stop or the node entered maintenance meanwhile, which explains it,
/// an error when it could not run, failed when the artifact failed.
fn outcome_of(stop: &AtomicBool, error: VerifyError) -> BackupVerifyOutcome {
    if stop.load(Ordering::Relaxed) {
        BackupVerifyOutcome::Abandoned(format!("the server is shutting down ({error})"))
    } else if !maintenance_write_allowed() {
        BackupVerifyOutcome::Abandoned(format!("the node entered maintenance ({error})"))
    } else {
        match error {
            VerifyError::Environment(reason) => BackupVerifyOutcome::Error(reason),
            VerifyError::Artifact(reason) => BackupVerifyOutcome::Failed(vec![reason]),
            VerifyError::Abandoned(reason) => BackupVerifyOutcome::Abandoned(reason),
        }
    }
}

/// The local artifact a run verified, so that the S3 copy of the same backup is not
/// restored a second time.
struct VerifiedLocal {
    name: String,
    sha256: String,
    outcome: BackupVerifyOutcome,
}

/// The newest local artifact, copied into a scratch directory.
struct CopiedLocal {
    name: String,
    /// Removes the copy when dropped.
    scratch: TempDir,
    copy: PathBuf,
    sha256: String,
}

/// What [`copy_newest_local_backup`] found.
enum LocalPick {
    NoBackup,
    Copied(CopiedLocal),
    /// The newest artifact, when known, could not be copied, for this reason.
    Unreadable(Option<String>, String),
}

/// Copy the newest artifact of `dir` into a new scratch directory in `scratch_parent` and
/// hash the copy. When the artifact disappears before it is copied (retention removed it
/// as a backup completed), the directory is listed once more.
fn copy_newest_local_backup(dir: &Path, scratch_parent: Option<&Path>) -> LocalPick {
    let mut listed_again = false;
    loop {
        let name = match newest_local_backup(dir) {
            Ok(Some(name)) => name,
            Ok(None) => return LocalPick::NoBackup,
            Err(err) => {
                return LocalPick::Unreadable(
                    None,
                    format!("unable to list the backups of {}: {err}", dir.display()),
                )
            }
        };
        let scratch = match new_scratch_dir(scratch_parent) {
            Ok(scratch) => scratch,
            Err(err) => {
                return LocalPick::Unreadable(
                    Some(name),
                    format!("unable to create a scratch directory: {err}"),
                )
            }
        };
        let copy = scratch.path().join(&name);
        match std::fs::copy(dir.join(&name), &copy) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound && !listed_again => {
                info!("Backup {name} was removed before it could be verified; listing again");
                listed_again = true;
                continue;
            }
            Err(err) => {
                let reason = format!("unable to copy {name} from {}: {err}", dir.display());
                return LocalPick::Unreadable(Some(name), reason);
            }
        }
        return match file_sha256(&copy) {
            Ok(sha256) => LocalPick::Copied(CopiedLocal {
                name,
                scratch,
                copy,
                sha256,
            }),
            Err(err) => {
                let reason = format!("unable to read the copy of {name}: {err}");
                LocalPick::Unreadable(Some(name), reason)
            }
        };
    }
}

/// The full verification of the newest backup, scheduled by `online_backup.verify_schedule`.
///
/// A run verifies the newest artifact of the local backup directory, then the newest one
/// of the S3 prefix, each as `kubidmd database verify-backup` does, and records the result
/// in the backup metrics. Two runs never overlap: a run that starts while another is in
/// progress is skipped. A run never overlaps an online backup either: it waits for the
/// backup in progress, and a backup waits for it. Every step that blocks runs off the
/// async workers: file I/O and decryption on the blocking thread pool, the restore,
/// reindex and boot of the scratch database on the offline database thread.
pub struct BackupVerifyJob {
    /// The configuration the scratch databases are restored with.
    config: Configuration,
    /// Where the scratch directories are created; `TMPDIR` without one.
    scratch_parent: Option<PathBuf>,
    metrics: Arc<BackupMetrics>,
    running: tokio::sync::Mutex<()>,
    /// Held by an online backup while it runs, and by a verification.
    backup_lock: Arc<tokio::sync::Mutex<()>>,
}

impl BackupVerifyJob {
    /// The verification of the backups `config` describes. The scratch databases are
    /// restored with the settings of `config` (its domain, its encryption key), never into
    /// its database, and with a small entry cache and a single connection, so that they
    /// cost the running server as little memory as possible. `backup_lock` is the lock the
    /// online backups of the server hold while they run.
    pub fn new(
        config: Configuration,
        metrics: Arc<BackupMetrics>,
        backup_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        let scratch_parent = verify_scratch_parent(&config);
        let mut config = config;
        config.db_arc_size = Some(SCRATCH_ARC_SIZE);
        config.threads = 1;
        Self {
            config,
            scratch_parent,
            metrics,
            running: tokio::sync::Mutex::new(()),
            backup_lock,
        }
    }

    /// Where the scratch directories of this verification are created, if not in
    /// `TMPDIR`.
    pub fn scratch_parent(&self) -> Option<&Path> {
        self.scratch_parent.as_deref()
    }

    /// Verify the newest artifact of every configured destination now.
    pub async fn run(&self) -> BackupVerifyRun {
        let Ok(_running) = self.running.try_lock() else {
            warn!("Scheduled backup verification skipped: the previous one is still running");
            return BackupVerifyRun::Skipped("a verification is already running".to_string());
        };
        // The scratch server commits its migrations like a booting server, which the
        // maintenance fence of this node refuses.
        if !maintenance_write_allowed() {
            warn!("Scheduled backup verification skipped: the node is in maintenance");
            return BackupVerifyRun::Skipped("the node is in maintenance".to_string());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let _stop_on_drop = StopOnDrop(stop.clone());

        let Some(online_backup) = self.config.online_backup.as_ref() else {
            return BackupVerifyRun::Completed(Vec::new());
        };

        // Never at the same time as an online backup: both hold a whole artifact, and the
        // verification a second database, which together could exhaust the host.
        let _no_backup = match self.backup_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                info!("Scheduled backup verification waits for the online backup in progress");
                self.backup_lock.lock().await
            }
        };

        let mut results = Vec::with_capacity(2);
        let mut verified_local = None;
        if let Some(dir) = &online_backup.path {
            let (verification, local) = self.verify_local(dir, &stop).await;
            self.record(&verification);
            results.push(verification);
            verified_local = local;
        }
        if let Some(s3_config) = &online_backup.s3 {
            let verification = self
                .verify_s3(s3_config, verified_local.as_ref(), &stop)
                .await;
            self.record(&verification);
            results.push(verification);
        }
        BackupVerifyRun::Completed(results)
    }

    /// Verify the newest artifact of the local backup directory `dir`. It is copied into a
    /// scratch directory first, so that retention removing it in the meantime can not
    /// fail the verification.
    async fn verify_local(
        &self,
        dir: &Path,
        stop: &Arc<AtomicBool>,
    ) -> (DestinationVerification, Option<VerifiedLocal>) {
        let verification = |artifact: Option<String>, outcome| DestinationVerification {
            destination: BackupDestination::Local,
            artifact,
            reused_local: false,
            outcome,
        };

        let backup_dir = dir.to_path_buf();
        let scratch_parent = self.scratch_parent.clone();
        let picked = run_blocking(move || {
            Ok(copy_newest_local_backup(
                &backup_dir,
                scratch_parent.as_deref(),
            ))
        })
        .await
        .unwrap_or_else(|err| LocalPick::Unreadable(None, format!("the copy task failed: {err}")));

        let copied = match picked {
            LocalPick::Copied(copied) => copied,
            LocalPick::NoBackup => {
                return (verification(None, BackupVerifyOutcome::NoBackup), None);
            }
            LocalPick::Unreadable(name, reason) => {
                let outcome = outcome_of(stop, VerifyError::Environment(reason));
                return (verification(name, outcome), None);
            }
        };
        let CopiedLocal {
            name,
            scratch,
            copy,
            sha256,
        } = copied;

        let outcome = self.verify_in_blocking_pool(copy, scratch, stop).await;
        (
            verification(Some(name.clone()), outcome.clone()),
            Some(VerifiedLocal {
                name,
                sha256,
                outcome,
            }),
        )
    }

    /// Verify the newest complete artifact of the S3 prefix. Its download is checked
    /// against its sidecar checksum; when it holds exactly the bytes of the local artifact
    /// this run just verified, that verification counts for it too. When the download
    /// fails for another reason than the checksum (retention removed the artifact as a
    /// backup completed, a network error), the prefix is listed once more.
    async fn verify_s3(
        &self,
        s3_config: &S3Config,
        local: Option<&VerifiedLocal>,
        stop: &Arc<AtomicBool>,
    ) -> DestinationVerification {
        let verification = |artifact: Option<String>, outcome| DestinationVerification {
            destination: BackupDestination::S3,
            artifact,
            reused_local: false,
            outcome,
        };
        let could_not_run = |artifact: Option<String>, reason: String| {
            verification(artifact, outcome_of(stop, VerifyError::Environment(reason)))
        };

        let client = match S3ClientWrapper::new(s3_config.clone()).await {
            Ok(client) => client,
            Err(err) => {
                return could_not_run(None, format!("unable to create the S3 client: {err}"))
            }
        };

        let mut listed_again = false;
        let (key, fetched) = loop {
            let key = match client.list_backup_artifacts().await {
                Ok(mut keys) => match keys.pop() {
                    Some(key) => key,
                    None => return verification(None, BackupVerifyOutcome::NoBackup),
                },
                Err(err) => {
                    let reason =
                        format!("unable to list the backups in {}: {err}", client.location());
                    return could_not_run(None, reason);
                }
            };
            let scratch_parent = self.scratch_parent.clone();
            let scratch =
                match run_blocking(move || new_scratch_dir(scratch_parent.as_deref())).await {
                    Ok(scratch) => scratch,
                    Err(err) => {
                        let reason = format!("unable to create a scratch directory: {err}");
                        return could_not_run(Some(key), reason);
                    }
                };
            match fetch_s3_backup_into(&client, &key, scratch).await {
                Ok(fetched) => break (key, fetched),
                Err(err @ S3BackupError::InvalidChecksum { .. }) => {
                    let reason = format!("{key} does not match its metadata sidecar: {err}");
                    let outcome = outcome_of(stop, VerifyError::Artifact(reason));
                    return verification(Some(key), outcome);
                }
                Err(err) if !listed_again => {
                    info!("Unable to download {key} ({err}); listing the backups again");
                    listed_again = true;
                }
                Err(err) => {
                    return could_not_run(
                        Some(key.clone()),
                        format!("unable to download {key}: {err}"),
                    )
                }
            }
        };

        let same_as_local = local.filter(|local| {
            key.rsplit('/').next() == Some(local.name.as_str())
                && local.sha256 == fetched.metadata.checksum_sha256
                && matches!(
                    local.outcome,
                    BackupVerifyOutcome::Passed | BackupVerifyOutcome::Failed(_)
                )
        });
        if let Some(local) = same_as_local {
            info!(
                "S3 backup {key} holds exactly the bytes of the local backup verified by this \
                 run: its verification counts for both"
            );
            return DestinationVerification {
                destination: BackupDestination::S3,
                artifact: Some(key),
                reused_local: true,
                outcome: local.outcome.clone(),
            };
        }

        let path = fetched.path.clone();
        let outcome = self.verify_in_blocking_pool(path, fetched, stop).await;
        verification(Some(key), outcome)
    }

    /// Run the full verification of the artifact at `path` on the blocking thread pool: the
    /// restore and the boot are synchronous code that would stall the async runtime.
    /// `scratch` holds the artifact, and is dropped (removing it) there too.
    async fn verify_in_blocking_pool<T: Send + 'static>(
        &self,
        path: PathBuf,
        scratch: T,
        stop: &Arc<AtomicBool>,
    ) -> BackupVerifyOutcome {
        if stop.load(Ordering::Relaxed) {
            let _ = run_blocking(move || {
                drop(scratch);
                Ok(())
            })
            .await;
            return BackupVerifyOutcome::Abandoned("the server is shutting down".to_string());
        }
        let config = self.config.clone();
        let scratch_parent = self.scratch_parent.clone();
        let worker_stop = stop.clone();
        let handle = tokio::runtime::Handle::current();
        run_blocking(move || {
            let outcome = handle.block_on(verify_artifact(
                &config,
                &path,
                scratch_parent.as_deref(),
                &worker_stop,
            ));
            drop(scratch);
            Ok(outcome)
        })
        .await
        .unwrap_or_else(|err| {
            outcome_of(
                stop,
                VerifyError::Artifact(format!("the verification task failed: {err}")),
            )
        })
    }

    /// Log the verification of a destination and record it in the metrics.
    fn record(&self, verification: &DestinationVerification) {
        let destination = &verification.destination;
        let artifact = verification.artifact.as_deref().unwrap_or("none");
        match &verification.outcome {
            BackupVerifyOutcome::Passed => {
                info!(
                    %destination,
                    artifact, "Scheduled full backup verification passed"
                );
                self.metrics
                    .verification_succeeded(destination, duration_from_epoch_now());
            }
            BackupVerifyOutcome::Failed(reasons) => {
                error!(
                    %destination,
                    artifact,
                    ?reasons,
                    "Scheduled full backup verification FAILED: the newest {destination} \
                     backup {artifact} can not be restored. Investigate before you need it"
                );
                self.metrics
                    .verification_failed(destination, duration_from_epoch_now());
            }
            BackupVerifyOutcome::Error(reason) => {
                error!(
                    %destination,
                    artifact,
                    "Scheduled full backup verification could not run: {reason}. This says \
                     nothing about the backup; fix the cause so that the next run can verify it"
                );
                self.metrics
                    .verification_errored(destination, duration_from_epoch_now());
            }
            BackupVerifyOutcome::NoBackup => warn!(
                %destination,
                "Scheduled full backup verification found no {destination} backup to verify"
            ),
            BackupVerifyOutcome::Abandoned(reason) => warn!(
                %destination,
                artifact,
                "Scheduled full backup verification abandoned: {reason}"
            ),
        }
    }
}

/// Run the full verification on the artifact at `path`: the structural checks, then the
/// restore and boot of a scratch database in `scratch_parent`. `stop` is checked between
/// the steps.
async fn verify_artifact(
    config: &Configuration,
    path: &Path,
    scratch_parent: Option<&Path>,
    stop: &Arc<AtomicBool>,
) -> BackupVerifyOutcome {
    match verify_backup_structure_at(config, path).await.report {
        Err(error) => return outcome_of(stop, error),
        Ok(report) if !report.is_valid() => return BackupVerifyOutcome::Failed(report.errors),
        Ok(_) => {}
    }
    if stop.load(Ordering::Relaxed) {
        return BackupVerifyOutcome::Abandoned("the server is shutting down".to_string());
    }

    let flag = Arc::clone(stop);
    let restore_stop = Arc::new(move || flag.load(Ordering::Relaxed));
    match verify_backup_restores(config, path, scratch_parent, restore_stop).await {
        Ok(errors) if errors.is_empty() => BackupVerifyOutcome::Passed,
        Ok(errors) => {
            BackupVerifyOutcome::Failed(errors.iter().map(|err| format!("{err:?}")).collect())
        }
        Err(error) => outcome_of(stop, error),
    }
}

/// The name of the newest automatically generated backup in `dir`, by the time in its
/// name; None when it holds none.
pub(crate) fn newest_local_backup(dir: &Path) -> io::Result<Option<String>> {
    let mut newest: Option<String> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !is_backup_artifact_name(&name) || !entry.path().is_file() {
            continue;
        }
        if newest
            .as_deref()
            .is_none_or(|current| compare_backup_names(&name, current).is_gt())
        {
            newest = Some(name);
        }
    }
    Ok(newest)
}

/// The SHA-256 of the file at `path`, hex encoded as in the S3 metadata sidecars.
fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
            break;
        };
        hasher.update(chunk);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OnlineBackup;

    /// A test configuration whose scratch directories go to `scratch`, backing up to
    /// `backups`.
    fn config(backups: &Path, scratch: &Path) -> Configuration {
        let mut config = Configuration::new_for_test();
        config.online_backup = Some(OnlineBackup {
            path: Some(backups.to_path_buf()),
            verify_schedule: Some("@daily".to_string()),
            verify_temp_path: Some(scratch.to_path_buf()),
            ..Default::default()
        });
        config
    }

    fn job(config: Configuration) -> (BackupVerifyJob, Arc<BackupMetrics>) {
        let metrics = Arc::new(BackupMetrics::new(config.online_backup.as_ref()));
        let job = BackupVerifyJob::new(
            config,
            metrics.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
        );
        (job, metrics)
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn newest_local_backup_orders_by_the_time_in_the_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(newest_local_backup(dir.path()).expect("read"), None);

        for name in [
            // Older servers dropped trailing zeros: as strings, these sort wrongly.
            "backup-2026-01-01T10:00:00.5Z.json.gz",
            "backup-2026-01-01T10:00:00.12Z.json.gz.enc",
            "backup-2025-12-31T23:59:59Z.json",
            // Never a backup: quarantined, partial, manual and sidecar files.
            "backup-2027-01-01T00:00:00Z.json.gz.invalid",
            ".backup-2027-01-01T00:00:00Z.json.gz.partial",
            "manual.json",
            "backup-2027-01-01T00:00:00Z.json.gz.metadata.json",
        ] {
            std::fs::write(dir.path().join(name), b"x").expect("write");
        }
        // A directory named like a backup is not one.
        std::fs::create_dir(dir.path().join("backup-2028-01-01T00:00:00Z.json")).expect("dir");

        assert_eq!(
            newest_local_backup(dir.path()).expect("read").as_deref(),
            Some("backup-2026-01-01T10:00:00.5Z.json.gz")
        );
    }

    #[test]
    fn newest_local_backup_of_a_missing_directory_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(newest_local_backup(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn file_sha256_matches_the_sidecar_encoding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"abc").expect("write");
        assert_eq!(
            file_sha256(&path).expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn errors_are_told_apart_from_failures_and_a_stopped_run_is_abandoned() {
        let stop = AtomicBool::new(false);
        assert_eq!(
            outcome_of(&stop, VerifyError::Artifact("boom".to_string())),
            BackupVerifyOutcome::Failed(vec!["boom".to_string()])
        );
        assert_eq!(
            outcome_of(&stop, VerifyError::Environment("disk full".to_string())),
            BackupVerifyOutcome::Error("disk full".to_string())
        );
        stop.store(true, Ordering::Relaxed);
        for error in [
            VerifyError::Artifact("boom".to_string()),
            VerifyError::Environment("boom".to_string()),
        ] {
            assert!(matches!(
                outcome_of(&stop, error),
                BackupVerifyOutcome::Abandoned(reason) if reason.contains("boom")
            ));
        }
    }

    #[test]
    fn dropping_a_run_stops_its_blocking_work() {
        let stop = Arc::new(AtomicBool::new(false));
        drop(StopOnDrop(stop.clone()));
        assert!(stop.load(Ordering::Relaxed));
    }

    #[test]
    fn scratch_directories_share_one_prefix_and_stale_ones_are_removed() {
        let parent = tempfile::tempdir().expect("tempdir");
        let scratch_parent = parent.path().join("scratch");

        // The parent is created on demand.
        let live = new_scratch_dir(Some(&scratch_parent)).expect("scratch dir");
        let name = live
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("name")
            .to_string();
        assert!(name.starts_with(SCRATCH_DIR_PREFIX), "{name}");

        // What a killed run leaves behind: its directories, with the database inside.
        let stale = scratch_parent.join(format!("{SCRATCH_DIR_PREFIX}stale"));
        std::fs::create_dir_all(stale.join("nested")).expect("dir");
        std::fs::write(stale.join("nested").join("verify.db"), b"x").expect("write");
        let stale = live.keep();
        // Nothing else is touched: other files, and a file with the prefix.
        std::fs::write(scratch_parent.join("kubidm.db"), b"x").expect("write");
        std::fs::write(
            scratch_parent.join(format!("{SCRATCH_DIR_PREFIX}file")),
            b"x",
        )
        .expect("write");

        assert_eq!(
            remove_stale_scratch_dirs(&scratch_parent).expect("sweep"),
            2
        );
        assert!(!stale.exists());
        assert_eq!(
            entries(&scratch_parent),
            vec![format!("{SCRATCH_DIR_PREFIX}file"), "kubidm.db".to_string()]
        );
        // A missing parent has nothing to remove.
        assert_eq!(
            remove_stale_scratch_dirs(&parent.path().join("missing")).expect("sweep"),
            0
        );
    }

    #[test]
    fn scratch_directories_are_named_after_the_database_file() {
        let mut config = Configuration::new_for_test();
        config.db_path = None;
        assert_eq!(verify_scratch_parent(&config), None);
        config.db_path = Some(PathBuf::from("/var/lib/kubidm/kubidm.db"));
        assert_eq!(
            verify_scratch_parent(&config),
            Some(PathBuf::from("/var/lib/kubidm/kubidm.db.verify"))
        );
        config.online_backup = Some(OnlineBackup {
            verify_temp_path: Some(PathBuf::from("/scratch")),
            ..Default::default()
        });
        assert_eq!(
            verify_scratch_parent(&config),
            Some(PathBuf::from("/scratch/kubidm.db.verify"))
        );
        config.db_path = None;
        assert_eq!(
            verify_scratch_parent(&config),
            Some(PathBuf::from("/scratch"))
        );
    }

    /// Two servers whose databases share a directory: the start of one removes what a
    /// killed run of its own left behind, never the scratch data of the other one's run in
    /// progress, which would then fail as if its backup could not be restored.
    #[test]
    fn the_sweep_of_a_server_leaves_the_scratch_data_of_another_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let parent = |db: &str| {
            let mut config = Configuration::new_for_test();
            config.db_path = Some(dir.path().join(db));
            verify_scratch_parent(&config).expect("scratch parent")
        };
        let (a, b) = (parent("a.db"), parent("b.db"));
        assert_ne!(a, b);

        let running = new_scratch_dir(Some(&a)).expect("scratch dir");
        let killed = new_scratch_dir(Some(&b)).expect("scratch dir").keep();
        assert_eq!(remove_stale_scratch_dirs(&b).expect("sweep"), 1);
        assert!(!killed.exists());
        assert!(running.path().is_dir());
    }

    #[tokio::test]
    async fn a_verification_never_overlaps_another() {
        let mut config = Configuration::new_for_test();
        config.online_backup = None;
        let (job, _) = job(config);

        // Nothing configured: nothing to verify.
        assert_eq!(job.run().await, BackupVerifyRun::Completed(Vec::new()));

        let _running = job.running.lock().await;
        assert!(matches!(job.run().await, BackupVerifyRun::Skipped(_)));
    }

    #[tokio::test]
    async fn a_verification_waits_for_the_online_backup_in_progress() {
        let backups = tempfile::tempdir().expect("tempdir");
        let scratch = tempfile::tempdir().expect("tempdir");
        let (job, _) = job(config(backups.path(), scratch.path()));
        let job = Arc::new(job);

        let backup_in_progress = job.backup_lock.clone().lock_owned().await;
        let run = tokio::spawn({
            let job = job.clone();
            async move { job.run().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!run.is_finished(), "the verification ran during a backup");

        drop(backup_in_progress);
        assert!(matches!(
            run.await.expect("run"),
            BackupVerifyRun::Completed(results) if results.len() == 1
        ));
    }

    #[tokio::test]
    async fn an_empty_backup_directory_has_nothing_to_verify() {
        let backups = tempfile::tempdir().expect("tempdir");
        let scratch = tempfile::tempdir().expect("tempdir");
        let (job, metrics) = job(config(backups.path(), scratch.path()));

        assert_eq!(
            job.run().await,
            BackupVerifyRun::Completed(vec![DestinationVerification {
                destination: BackupDestination::Local,
                artifact: None,
                reused_local: false,
                outcome: BackupVerifyOutcome::NoBackup,
            }])
        );
        // Nothing to verify is neither a failure nor an error.
        let text = metrics.render();
        assert!(text.contains("kubidm_backup_verification_failures_total{destination=\"local\"} 0"));
        assert!(text.contains("kubidm_backup_verification_errors_total{destination=\"local\"} 0"));
    }

    #[tokio::test]
    async fn an_unreadable_backup_fails_loudly_and_is_counted() {
        let backups = tempfile::tempdir().expect("tempdir");
        let scratch = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            backups.path().join("backup-2026-01-01T10:00:00Z.json"),
            b"not a backup",
        )
        .expect("write");
        let (job, metrics) = job(config(backups.path(), scratch.path()));

        let BackupVerifyRun::Completed(results) = job.run().await else {
            panic!("the run must complete");
        };
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].artifact.as_deref(),
            Some("backup-2026-01-01T10:00:00Z.json")
        );
        assert!(
            matches!(&results[0].outcome, BackupVerifyOutcome::Failed(reasons) if !reasons.is_empty()),
            "{results:?}"
        );
        let text = metrics.render();
        assert!(text.contains("kubidm_backup_verification_failures_total{destination=\"local\"} 1"));
        assert!(text.contains("kubidm_backup_verification_errors_total{destination=\"local\"} 0"));
        // The scratch copy is gone, the artifact is left as it was.
        assert_eq!(entries(backups.path()).len(), 1);
        assert!(entries(scratch.path()).is_empty());
    }

    #[tokio::test]
    async fn a_verification_that_can_not_run_is_an_error_not_a_failure() {
        let workdir = tempfile::tempdir().expect("tempdir");
        let backups = workdir.path().join("backups");
        std::fs::create_dir(&backups).expect("dir");
        let name = "backup-2026-01-01T10:00:00Z.json";
        std::fs::write(backups.join(name), b"not a backup").expect("write");

        // The scratch space is unusable: a file stands where its directory should be.
        let not_a_directory = workdir.path().join("scratch");
        std::fs::write(&not_a_directory, b"x").expect("write");
        let (job, metrics) = job(config(&backups, &not_a_directory));
        let BackupVerifyRun::Completed(results) = job.run().await else {
            panic!("the run must complete");
        };
        // The artifact is named all the same.
        assert_eq!(results[0].artifact.as_deref(), Some(name));
        assert!(
            matches!(&results[0].outcome, BackupVerifyOutcome::Error(reason) if reason.contains("scratch")),
            "{results:?}"
        );

        // The backup directory is gone.
        let (job, _) = job_with_metrics(
            config(&workdir.path().join("missing"), workdir.path()),
            metrics.clone(),
        );
        let BackupVerifyRun::Completed(results) = job.run().await else {
            panic!("the run must complete");
        };
        assert!(
            matches!(&results[0].outcome, BackupVerifyOutcome::Error(_)),
            "{results:?}"
        );

        let text = metrics.render();
        assert!(text.contains("kubidm_backup_verification_errors_total{destination=\"local\"} 2"));
        assert!(text.contains("kubidm_backup_verification_failures_total{destination=\"local\"} 0"));
        assert!(text.contains(
            "kubidm_backup_verification_last_success_timestamp_seconds{destination=\"local\"} 0\n"
        ));
    }

    fn job_with_metrics(
        config: Configuration,
        metrics: Arc<BackupMetrics>,
    ) -> (BackupVerifyJob, Arc<BackupMetrics>) {
        let job = BackupVerifyJob::new(
            config,
            metrics.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
        );
        (job, metrics)
    }
}
