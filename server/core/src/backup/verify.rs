//! Verification of backup artifacts beyond the structural check every backup gets after
//! it is written: the levels of `kubidmd database verify-backup`, and the scheduled full
//! verification of the newest backup a running server does with
//! `online_backup.verify_schedule`.
//!
//! Both share the same steps, so that a scheduled verification proves exactly what the
//! command proves: the artifact is opened (and decrypted) the way a restore opens it and
//! parsed, then restored into a scratch database in a temporary directory through the
//! production restore path, that database is booted as a server start would boot it and
//! the full consistency verification runs on it. The database of the configuration is
//! never opened, and the temporary directory is removed afterwards.

use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use kubidm_proto::backup::S3Config;
use kubidm_proto::internal::ConsistencyError;
use kubidmd_lib::be::{verify_backup_structure, BackupStructuralReport};
use kubidmd_lib::maintenance::maintenance_write_allowed;
use kubidmd_lib::prelude::duration_from_epoch_now;
use sha2::{Digest, Sha256};

use super::cli::fetch_s3_backup;
use super::metrics::{BackupDestination, BackupMetrics, VerificationLevel};
use super::restore::{backup_encryption_config, restore_database};
use super::{
    compare_backup_names, is_backup_artifact_name, open_backup_file_with_config, run_blocking,
    S3ClientWrapper,
};
use crate::config::Configuration;
use crate::verify_booted_database;

/// The structural verification of an artifact.
pub(crate) struct StructuralVerification {
    /// The key the artifact is encrypted with, when it is encrypted.
    pub encryption_key: Option<String>,
    /// The report of the checks, or why the artifact could not be checked at all.
    pub report: Result<BackupStructuralReport, String>,
}

impl StructuralVerification {
    pub fn passed(&self) -> bool {
        self.report
            .as_ref()
            .is_ok_and(BackupStructuralReport::is_valid)
    }

    /// Why the verification failed; empty when it passed.
    pub fn failures(&self) -> Vec<String> {
        match &self.report {
            Ok(report) => report.errors.clone(),
            Err(reason) => vec![reason.clone()],
        }
    }
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

/// What a scheduled verification found for one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupVerifyOutcome {
    /// The newest artifact passed the full verification.
    Passed,
    /// The newest artifact failed it, for these reasons.
    Failed(Vec<String>),
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

/// The local artifact a run verified, so that the S3 copy of the same backup is not
/// restored a second time.
struct VerifiedLocal {
    name: String,
    sha256: String,
    outcome: BackupVerifyOutcome,
}

/// The full verification of the newest backup, scheduled by `online_backup.verify_schedule`.
///
/// A run verifies the newest artifact of the local backup directory, then the newest one
/// of the S3 prefix, each as `kubidmd database verify-backup` does, and records the result
/// in the backup metrics. Two runs never overlap: a run that starts while another is in
/// progress is skipped. Every step that blocks (file I/O, decryption, the restore and the
/// boot of the scratch database) runs on the blocking thread pool.
pub struct BackupVerifyJob {
    config: Configuration,
    metrics: Arc<BackupMetrics>,
    running: tokio::sync::Mutex<()>,
}

impl BackupVerifyJob {
    /// The verification of the backups `config` describes. The scratch databases are
    /// restored with the settings of `config` (its domain, its encryption key), never into
    /// its database.
    pub fn new(config: Configuration, metrics: Arc<BackupMetrics>) -> Self {
        Self {
            config,
            metrics,
            running: tokio::sync::Mutex::new(()),
        }
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
    /// temporary directory first, so that retention removing it in the meantime can not
    /// fail the verification.
    async fn verify_local(
        &self,
        dir: &Path,
        stop: &Arc<AtomicBool>,
    ) -> (DestinationVerification, Option<VerifiedLocal>) {
        let config = self.config.clone();
        let backup_dir = dir.to_path_buf();
        let worker_stop = stop.clone();
        let handle = tokio::runtime::Handle::current();
        let verified = run_blocking(move || {
            let Some(name) = newest_local_backup(&backup_dir)? else {
                return Ok(None);
            };
            let scratch = tempfile::Builder::new()
                .prefix("kubidm-verify-")
                .tempdir()?;
            let copy = scratch.path().join(&name);
            std::fs::copy(backup_dir.join(&name), &copy)?;
            let sha256 = file_sha256(&copy)?;
            let outcome = handle.block_on(verify_artifact(&config, &copy, &worker_stop));
            drop(scratch);
            Ok(Some(VerifiedLocal {
                name,
                sha256,
                outcome,
            }))
        })
        .await;

        match verified {
            Ok(Some(local)) => (
                DestinationVerification {
                    destination: BackupDestination::Local,
                    artifact: Some(local.name.clone()),
                    outcome: local.outcome.clone(),
                },
                Some(local),
            ),
            Ok(None) => (
                DestinationVerification {
                    destination: BackupDestination::Local,
                    artifact: None,
                    outcome: BackupVerifyOutcome::NoBackup,
                },
                None,
            ),
            Err(err) => (
                DestinationVerification {
                    destination: BackupDestination::Local,
                    artifact: None,
                    outcome: stopped_or_failed(
                        stop,
                        format!(
                            "unable to read the newest backup of {}: {err}",
                            dir.display()
                        ),
                    ),
                },
                None,
            ),
        }
    }

    /// Verify the newest complete artifact of the S3 prefix. Its download is checked
    /// against its sidecar checksum; when it holds exactly the bytes of the local artifact
    /// this run just verified, that verification counts for it too.
    async fn verify_s3(
        &self,
        s3_config: &S3Config,
        local: Option<&VerifiedLocal>,
        stop: &Arc<AtomicBool>,
    ) -> DestinationVerification {
        let failed = |artifact: Option<String>, reason: String| DestinationVerification {
            destination: BackupDestination::S3,
            artifact,
            outcome: stopped_or_failed(stop, reason),
        };

        let client = match S3ClientWrapper::new(s3_config.clone()).await {
            Ok(client) => client,
            Err(err) => return failed(None, format!("unable to create the S3 client: {err}")),
        };
        let newest = match client.list_backup_artifacts().await {
            Ok(mut keys) => keys.pop(),
            Err(err) => {
                return failed(
                    None,
                    format!("unable to list the backups in {}: {err}", client.location()),
                )
            }
        };
        let Some(key) = newest else {
            return DestinationVerification {
                destination: BackupDestination::S3,
                artifact: None,
                outcome: BackupVerifyOutcome::NoBackup,
            };
        };

        let fetched = match fetch_s3_backup(s3_config.clone(), &key).await {
            Ok(fetched) => fetched,
            Err(err) => {
                let reason = format!("unable to download {key}: {err}");
                return failed(Some(key), reason);
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

        let config = self.config.clone();
        let worker_stop = stop.clone();
        let handle = tokio::runtime::Handle::current();
        let local_outcome = same_as_local.map(|local| local.outcome.clone());
        if local_outcome.is_some() {
            info!(
                "S3 backup {key} holds exactly the bytes of the local backup verified by this \
                 run: its verification counts for both"
            );
        }
        let outcome = run_blocking(move || {
            let outcome = match local_outcome {
                Some(outcome) => outcome,
                None => handle.block_on(verify_artifact(&config, &fetched.path, &worker_stop)),
            };
            // Removes the downloaded artifact.
            drop(fetched);
            Ok(outcome)
        })
        .await;

        match outcome {
            Ok(outcome) => DestinationVerification {
                destination: BackupDestination::S3,
                artifact: Some(key),
                outcome,
            },
            Err(err) => failed(Some(key), format!("the verification task failed: {err}")),
        }
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
                self.metrics.verification_succeeded(
                    destination,
                    VerificationLevel::Full,
                    duration_from_epoch_now(),
                );
            }
            BackupVerifyOutcome::Failed(reasons) => {
                error!(
                    %destination,
                    artifact,
                    ?reasons,
                    "Scheduled full backup verification FAILED: the newest {destination} \
                     backup {artifact} can not be restored. Investigate before you need it"
                );
                self.metrics.verification_failed(
                    destination,
                    VerificationLevel::Full,
                    duration_from_epoch_now(),
                );
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

/// The outcome of a verification that could not complete for `reason`: abandoned when the
/// run was told to stop or the node entered maintenance meanwhile, which explains the
/// failure, failed otherwise.
fn stopped_or_failed(stop: &AtomicBool, reason: String) -> BackupVerifyOutcome {
    if stop.load(Ordering::Relaxed) {
        BackupVerifyOutcome::Abandoned(format!("the server is shutting down ({reason})"))
    } else if !maintenance_write_allowed() {
        BackupVerifyOutcome::Abandoned(format!("the node entered maintenance ({reason})"))
    } else {
        BackupVerifyOutcome::Failed(vec![reason])
    }
}

/// Run the full verification on the artifact at `path`: the structural checks, then the
/// restore and boot of a scratch database. `stop` is checked between the steps.
async fn verify_artifact(
    config: &Configuration,
    path: &Path,
    stop: &AtomicBool,
) -> BackupVerifyOutcome {
    let structural = verify_backup_structure_at(config, path).await;
    if !structural.passed() {
        return match structural.report {
            // Opening failed: possibly because the server shuts down.
            Err(reason) => stopped_or_failed(stop, reason),
            Ok(_) => BackupVerifyOutcome::Failed(structural.failures()),
        };
    }
    if stop.load(Ordering::Relaxed) {
        return BackupVerifyOutcome::Abandoned("the server is shutting down".to_string());
    }

    match verify_backup_restores(config, path, &|| stop.load(Ordering::Relaxed)).await {
        Ok(errors) if errors.is_empty() => BackupVerifyOutcome::Passed,
        Ok(errors) => {
            BackupVerifyOutcome::Failed(errors.iter().map(|err| format!("{err:?}")).collect())
        }
        Err(reason) => stopped_or_failed(stop, reason),
    }
}

/// The name of the newest automatically generated backup in `dir`, by the time in its
/// name; None when it holds none.
fn newest_local_backup(dir: &Path) -> io::Result<Option<String>> {
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
    fn a_stopped_run_is_abandoned_rather_than_failed() {
        let stop = AtomicBool::new(false);
        assert_eq!(
            stopped_or_failed(&stop, "boom".to_string()),
            BackupVerifyOutcome::Failed(vec!["boom".to_string()])
        );
        stop.store(true, Ordering::Relaxed);
        assert!(matches!(
            stopped_or_failed(&stop, "boom".to_string()),
            BackupVerifyOutcome::Abandoned(reason) if reason.contains("boom")
        ));
    }

    #[test]
    fn dropping_a_run_stops_its_blocking_work() {
        let stop = Arc::new(AtomicBool::new(false));
        drop(StopOnDrop(stop.clone()));
        assert!(stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn a_verification_never_overlaps_another() {
        let mut config = Configuration::new_for_test();
        config.online_backup = None;
        let job = BackupVerifyJob::new(config, Arc::new(BackupMetrics::new(None)));

        // Nothing configured: nothing to verify.
        assert_eq!(job.run().await, BackupVerifyRun::Completed(Vec::new()));

        let _running = job.running.lock().await;
        assert!(matches!(job.run().await, BackupVerifyRun::Skipped(_)));
    }

    #[tokio::test]
    async fn an_empty_backup_directory_has_nothing_to_verify() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = Configuration::new_for_test();
        config.online_backup = Some(crate::config::OnlineBackup {
            path: Some(dir.path().to_path_buf()),
            ..Default::default()
        });
        let metrics = Arc::new(BackupMetrics::new(config.online_backup.as_ref()));
        let job = BackupVerifyJob::new(config, metrics.clone());

        assert_eq!(
            job.run().await,
            BackupVerifyRun::Completed(vec![DestinationVerification {
                destination: BackupDestination::Local,
                artifact: None,
                outcome: BackupVerifyOutcome::NoBackup,
            }])
        );
        // Nothing to verify is not a failure.
        assert!(!metrics
            .render()
            .contains("kubidm_backup_verification_failures_total"));
    }

    #[tokio::test]
    async fn an_unreadable_backup_fails_loudly_and_is_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("backup-2026-01-01T10:00:00Z.json"),
            b"not a backup",
        )
        .expect("write");
        let mut config = Configuration::new_for_test();
        config.online_backup = Some(crate::config::OnlineBackup {
            path: Some(dir.path().to_path_buf()),
            verify_schedule: Some("@daily".to_string()),
            ..Default::default()
        });
        let metrics = Arc::new(BackupMetrics::new(config.online_backup.as_ref()));
        let job = BackupVerifyJob::new(config, metrics.clone());

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
        assert!(metrics.render().contains(
            "kubidm_backup_verification_failures_total{destination=\"local\",level=\"full\"} 1"
        ));
        // The scratch copy is gone, the artifact is left as it was.
        assert_eq!(std::fs::read_dir(dir.path()).expect("read").count(), 1);
    }
}
