//! End to end tests of the backup metrics served on `/metrics` and of the scheduled full
//! verification of the newest backup (`online_backup.verify_schedule`).
//!
//! Only production code paths are used: backups are taken through the online backup path,
//! the metrics are read over HTTP from the running server, and the scheduled verification
//! runs from its schedule inside the server. The S3 variant needs an S3-compatible service;
//! see `backup_common` for how it is found, when it is skipped and how to run it locally.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kubidm_proto::backup::{
    BackupCompression, BackupEncryptionConfig, EncryptionKeySource, KeyDerivationParams,
    ReplicationConfig, S3Config, WalArchiveConfig,
};
use kubidmd_core::backup::metrics::{BackupDestination, METRICS_STATE_FILE_SUFFIX};
use kubidmd_core::backup::verify::{
    BackupVerifyOutcome, BackupVerifyRun, DestinationVerification, SCRATCH_DIR_PREFIX,
    SCRATCH_PARENT_SUFFIX,
};
use kubidmd_core::backup::MIN_KDF_M_COST;
use kubidmd_core::config::{Configuration, OnlineBackup};
use kubidmd_testkit::AsyncTestEnvironment;
use serde_json::Value;

use super::backup_common::{
    config_with_db, delete_prefix, ensure_bucket, populate, run, sdk_client, start_server,
    test_s3_config, test_s3_region, BACKUP_USER_ALICE,
};

/// How long the scheduled verification may take to pass on a backup. It runs every
/// second; a run restores and boots a small database.
const SCHEDULED_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(180);

const LOCAL: &str = "destination=\"local\"";
const S3: &str = "destination=\"s3\"";

const LAST_SUCCESS: &str = "kubidm_backup_last_success_timestamp_seconds";
const LAST_FAILURE: &str = "kubidm_backup_last_failure_timestamp_seconds";
const FAILURES: &str = "kubidm_backup_failures_total";
const VERIFIED: &str = "kubidm_backup_verification_last_success_timestamp_seconds";
const VERIFICATION_LAST_FAILURE: &str = "kubidm_backup_verification_last_failure_timestamp_seconds";
const VERIFICATION_FAILURES: &str = "kubidm_backup_verification_failures_total";
const VERIFICATION_ERRORS: &str = "kubidm_backup_verification_errors_total";
const PITR_LAST_SUCCESS: &str = "kubidm_backup_pitr_sync_last_success_timestamp_seconds";

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("The clock is before the epoch")
        .as_secs_f64()
}

/// GET `/metrics` of the server of `env`, with `token` as bearer token: its status and
/// body.
async fn get_metrics_with(env: &AsyncTestEnvironment, token: Option<&str>) -> (u16, String) {
    let mut request = env.rsclient.client().get(env.rsclient.make_url("/metrics"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.expect("Failed to request /metrics");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = response.text().await.expect("Failed to read /metrics");
    if status == 200 {
        assert!(
            content_type.starts_with("text/plain; version=0.0.4"),
            "{content_type}"
        );
    }
    (status, body)
}

async fn get_metrics(env: &AsyncTestEnvironment) -> (u16, String) {
    get_metrics_with(env, None).await
}

/// The value of the sample `name{labels}` in a Prometheus text exposition.
fn sample(text: &str, name: &str, labels: &str) -> Option<f64> {
    let series = if labels.is_empty() {
        name.to_string()
    } else {
        format!("{name}{{{labels}}}")
    };
    text.lines()
        .filter_map(|line| line.strip_prefix(&series))
        .find_map(|rest| rest.strip_prefix(' '))
        .map(|value| value.parse().expect("A sample value must be a number"))
}

/// The value of the sample `name{labels}` of the server of `env`, which must exist.
async fn metric(env: &AsyncTestEnvironment, name: &str, labels: &str) -> f64 {
    let (status, text) = get_metrics(env).await;
    assert_eq!(status, 200);
    sample(&text, name, labels).unwrap_or_else(|| panic!("{name}{{{labels}}} missing in\n{text}"))
}

/// Wait until the sample `name{labels}` of the server of `env` is at least `at_least`.
async fn wait_for_metric(env: &AsyncTestEnvironment, name: &str, labels: &str, at_least: f64) {
    let deadline = tokio::time::Instant::now() + SCHEDULED_VERIFICATION_TIMEOUT;
    loop {
        let value = metric(env, name, labels).await;
        if value >= at_least {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name}{{{labels}}} is still {value}, expected at least {at_least}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Run the scheduled verification now, waiting for a scheduled run in progress to end.
async fn verify_now(env: &AsyncTestEnvironment) -> Vec<DestinationVerification> {
    loop {
        match env.core_handle.trigger_backup_verification().await {
            BackupVerifyRun::Completed(results) => return results,
            BackupVerifyRun::Skipped(reason) => {
                assert!(reason.contains("already running"), "{reason}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// The destinations and outcomes of a verification run.
fn outcomes(results: &[DestinationVerification]) -> Vec<(BackupDestination, BackupVerifyOutcome)> {
    results
        .iter()
        .map(|result| (result.destination.clone(), result.outcome.clone()))
        .collect()
}

/// Take an online backup now through the scheduled backup path, to every location of the
/// configuration, and return the newest local artifact.
async fn backup_now(env: &AsyncTestEnvironment, backup_dir: &Path) -> PathBuf {
    env.core_handle
        .trigger_configured_online_backup()
        .await
        .expect("Online backup failed");
    newest_backup(backup_dir)
}

/// The newest backup artifact in `dir`, by name.
fn newest_backup(dir: &Path) -> PathBuf {
    let mut backups: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("Failed to read backup directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("backup-"))
        })
        .collect();
    backups.sort();
    backups.pop().expect("No backup artifact")
}

/// The state file of the metrics of the server whose database is `source.db` in `workdir`.
fn state_file(workdir: &Path) -> PathBuf {
    workdir.join(format!("source.db{METRICS_STATE_FILE_SUFFIX}"))
}

/// Where the scheduled verification of the server whose database is `source.db` in
/// `workdir` creates its scratch directories by default.
fn default_scratch(workdir: &Path) -> PathBuf {
    workdir.join(format!("source.db{SCRATCH_PARENT_SUFFIX}"))
}

/// The scratch directories of a verification in `dir`, none when it does not exist.
fn scratch_dirs(dir: &Path) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(err) => panic!("Failed to read {}: {err}", dir.display()),
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(SCRATCH_DIR_PREFIX))
        })
        .map(|entry| entry.path())
        .collect()
}

/// Client-side encryption with a passphrase file and the cheapest key derivation the
/// server accepts.
fn encryption(workdir: &Path) -> BackupEncryptionConfig {
    let passphrase_file = workdir.join("passphrase");
    std::fs::write(&passphrase_file, "observability e2e passphrase\n")
        .expect("Failed to write the passphrase");
    BackupEncryptionConfig {
        enabled: true,
        key_source: EncryptionKeySource::Passphrase,
        key_derivation: KeyDerivationParams {
            m_cost: MIN_KDF_M_COST,
            t_cost: 1,
            p_cost: 1,
        },
        key_identifier: Some("observability-e2e".to_string()),
        passphrase_file: Some(passphrase_file),
    }
}

fn config_with_online_backup(db_path: &Path, online_backup: OnlineBackup) -> Configuration {
    Configuration {
        online_backup: Some(online_backup),
        ..config_with_db(db_path)
    }
}

/// Assert that the sample `name{labels}` of `text` is a time within `[from, to]`.
fn assert_time_within(text: &str, name: &str, labels: &str, from: f64, to: f64) {
    let value = sample(text, name, labels).unwrap_or_else(|| panic!("{name}{{{labels}}} missing"));
    assert!(
        value >= from.floor() && value <= to.ceil(),
        "{name}{{{labels}}} = {value}, expected within [{from}, {to}] in\n{text}"
    );
}

#[test]
fn test_metrics_endpoint_is_not_served_unless_enabled() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let mut env = start_server(&workdir.path().join("source.db")).await;
        let (status, _) = get_metrics(&env).await;
        assert_eq!(status, 404);
        env.core_handle.shutdown().await;

        // An online backup without the endpoint does not serve it either.
        let config = config_with_online_backup(
            &workdir.path().join("other.db"),
            OnlineBackup {
                path: Some(workdir.path().join("backups")),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        let (status, _) = get_metrics(&env).await;
        assert_eq!(status, 404);
        env.core_handle.shutdown().await;
    });
}

#[test]
fn test_metrics_endpoint_requires_the_configured_bearer_token() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let token_file = workdir.path().join("metrics-token");
        std::fs::write(&token_file, "e2e-metrics-token\n").expect("Failed to write token");
        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(workdir.path().join("backups")),
                metrics_endpoint: true,
                metrics_token_file: Some(token_file),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config).await;

        for token in [None, Some("wrong")] {
            let (status, body) = get_metrics_with(&env, token).await;
            assert_eq!(status, 401, "{token:?}");
            assert!(!body.contains("kubidm_backup"), "{body}");
        }
        let (status, body) = get_metrics_with(&env, Some("e2e-metrics-token")).await;
        assert_eq!(status, 200);
        assert_eq!(sample(&body, LAST_SUCCESS, LOCAL), Some(0.0), "{body}");

        env.core_handle.shutdown().await;
    });
}

#[test]
fn test_metrics_endpoint_reports_backup_and_wal_archive_timestamps() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).expect("Failed to create backup directory");
        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(backup_dir.clone()),
                metrics_endpoint: true,
                wal_archive: Some(WalArchiveConfig {
                    enabled: true,
                    // The test archives on demand; the periodic task must not interfere.
                    segment_interval_seconds: 3600,
                    local_path: Some(workdir.path().join("wal")),
                    ..WalArchiveConfig::default()
                }),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        populate(&env).await;

        // Every configured destination is reported from the start, with no backup yet.
        let (_, text) = get_metrics(&env).await;
        assert_eq!(sample(&text, LAST_SUCCESS, LOCAL), Some(0.0), "{text}");
        assert_eq!(sample(&text, FAILURES, LOCAL), Some(0.0));
        // The full verification is not scheduled, so it is not reported.
        assert_eq!(sample(&text, VERIFIED, LOCAL), None);
        assert!(sample(&text, PITR_LAST_SUCCESS, "").is_some(), "{text}");

        // A backup through the scheduled backup path updates the success of its
        // destination.
        let before = now_secs();
        backup_now(&env, &backup_dir).await;
        let after = now_secs();
        let (_, text) = get_metrics(&env).await;
        assert_time_within(&text, LAST_SUCCESS, LOCAL, before, after);
        assert_eq!(sample(&text, FAILURES, LOCAL), Some(0.0));
        assert_eq!(sample(&text, LAST_FAILURE, LOCAL), Some(0.0));

        // A backup that can not be stored is a failure of its destination, and leaves the
        // last success alone.
        let last_success = sample(&text, LAST_SUCCESS, LOCAL).expect("sample");
        std::fs::rename(&backup_dir, workdir.path().join("moved-backups"))
            .expect("Failed to move the backups");
        std::fs::write(&backup_dir, b"x").expect("Failed to write file");
        env.core_handle
            .trigger_configured_online_backup()
            .await
            .expect_err("A backup into a file must fail");
        let (_, text) = get_metrics(&env).await;
        assert_eq!(sample(&text, FAILURES, LOCAL), Some(1.0));
        assert!(sample(&text, LAST_FAILURE, LOCAL).expect("sample") >= before.floor());
        assert_eq!(sample(&text, LAST_SUCCESS, LOCAL), Some(last_success));

        // A backup to a location the configuration does not name is not counted.
        let elsewhere = workdir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("Failed to create directory");
        env.core_handle
            .trigger_online_backup(
                &elsewhere,
                1,
                BackupCompression::Gzip,
                &BackupEncryptionConfig::default(),
            )
            .await
            .expect("Online backup failed");
        assert_eq!(metric(&env, LAST_SUCCESS, LOCAL).await, last_success);

        // The WAL archive synchronisation is recorded too.
        let before = now_secs();
        env.core_handle
            .sync_wal_archive()
            .await
            .expect("The WAL archive is enabled")
            .expect("WAL archive synchronisation failed");
        assert!(metric(&env, PITR_LAST_SUCCESS, "").await >= before.floor());

        env.core_handle.shutdown().await;
    });
}

#[test]
fn test_metrics_survive_a_restart() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).expect("Failed to create backup directory");
        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(backup_dir.clone()),
                metrics_endpoint: true,
                // Never during the test: the runs are triggered.
                verify_schedule: Some("0 0 0 1 1 * 2099".to_string()),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config.clone()).await;
        populate(&env).await;
        backup_now(&env, &backup_dir).await;
        assert_eq!(
            outcomes(&verify_now(&env).await),
            vec![(BackupDestination::Local, BackupVerifyOutcome::Passed)]
        );
        let (_, before_restart) = get_metrics(&env).await;
        let last_success = sample(&before_restart, LAST_SUCCESS, LOCAL).expect("sample");
        let verified = sample(&before_restart, VERIFIED, LOCAL).expect("sample");
        assert!(last_success > 0.0 && verified > 0.0, "{before_restart}");
        env.core_handle.shutdown().await;
        assert!(state_file(workdir.path()).is_file());

        // The restarted server reports the backup and the verification of the previous
        // run: an alert on their age does not fire because of the restart.
        let mut env = kubidmd_testkit::setup_async_test(config.clone()).await;
        let (_, text) = get_metrics(&env).await;
        assert_eq!(
            sample(&text, LAST_SUCCESS, LOCAL),
            Some(last_success),
            "{text}"
        );
        assert_eq!(sample(&text, VERIFIED, LOCAL), Some(verified), "{text}");
        // The counters restart, as Prometheus expects of a restarted process.
        assert_eq!(sample(&text, FAILURES, LOCAL), Some(0.0));
        env.core_handle.shutdown().await;

        // Without the state file (a first start after an upgrade), the last success comes
        // from the newest backup in the directory, by the time in its name.
        std::fs::remove_file(state_file(workdir.path())).expect("Failed to remove the state file");
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let seeded = loop {
            let value = metric(&env, LAST_SUCCESS, LOCAL).await;
            if value > 0.0 || tokio::time::Instant::now() > deadline {
                break value;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        // The name has the time the backup was taken, to the millisecond or better.
        assert!(
            (seeded - last_success).abs() < 1.0,
            "seeded {seeded}, recorded {last_success}"
        );
        env.core_handle.shutdown().await;
    });
}

#[test]
fn test_scheduled_full_verification_of_an_encrypted_backup_updates_last_verified() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).expect("Failed to create backup directory");
        let encryption = encryption(workdir.path());
        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(backup_dir.clone()),
                metrics_endpoint: true,
                encryption: encryption.clone(),
                // Every second: the schedule itself must pick the new backup up.
                verify_schedule: Some("* * * * * * *".to_string()),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        populate(&env).await;

        // Scheduled, so reported from the start; nothing to verify is not a failure.
        assert_eq!(metric(&env, VERIFIED, LOCAL).await, 0.0);

        let before = now_secs();
        let backup = backup_now(&env, &backup_dir).await;
        let name = backup
            .file_name()
            .and_then(|name| name.to_str())
            .expect("Backup has no file name")
            .to_string();
        assert!(name.ends_with(".enc"), "{name}");

        // The schedule verifies the encrypted backup without any help.
        wait_for_metric(&env, VERIFIED, LOCAL, before.floor()).await;
        assert_eq!(metric(&env, VERIFICATION_FAILURES, LOCAL).await, 0.0);

        // An on demand run takes the same path and reports what it verified.
        let results = verify_now(&env).await;
        assert_eq!(
            outcomes(&results),
            vec![(BackupDestination::Local, BackupVerifyOutcome::Passed)]
        );
        assert_eq!(results[0].artifact.as_deref(), Some(name.as_str()));
        // The scheduled verification never touches the backups, and leaves no scratch
        // directory behind.
        let names: Vec<String> = std::fs::read_dir(&backup_dir)
            .expect("Failed to read backup directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert_eq!(names, vec![name.clone()]);

        // The same artifact, with one byte of its ciphertext changed under its own name:
        // only the authenticated decryption can tell, and the verification fails loudly
        // and is counted, by the schedule as by an on demand run.
        let mut bytes = std::fs::read(&backup).expect("Failed to read backup");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        std::fs::write(&backup, bytes).expect("Failed to write backup");
        let failures = metric(&env, VERIFICATION_FAILURES, LOCAL).await;
        let before = now_secs();
        let outcome = outcomes(&verify_now(&env).await);
        assert!(
            matches!(
                outcome.as_slice(),
                [(BackupDestination::Local, BackupVerifyOutcome::Failed(reasons))]
                    if !reasons.is_empty()
            ),
            "{outcome:?}"
        );
        wait_for_metric(&env, VERIFICATION_FAILURES, LOCAL, failures + 1.0).await;
        assert!(metric(&env, VERIFICATION_LAST_FAILURE, LOCAL).await >= before.floor());
        // An artifact that fails is not an error of the verification.
        assert_eq!(metric(&env, VERIFICATION_ERRORS, LOCAL).await, 0.0);

        env.core_handle.shutdown().await;
        assert!(scratch_dirs(&default_scratch(workdir.path())).is_empty());
    });
}

/// The point of the full verification: an artifact that passes every structural check
/// but can not be restored.
#[test]
fn test_scheduled_full_verification_detects_what_the_structural_check_can_not() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).expect("Failed to create backup directory");
        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(backup_dir.clone()),
                metrics_endpoint: true,
                compression: BackupCompression::NoCompression,
                verify_schedule: Some("0 0 0 1 1 * 2099".to_string()),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        populate(&env).await;
        let backup = backup_now(&env, &backup_dir).await;

        // Strip the uuid from one entry: the artifact still parses as a backup, with the
        // same entry count and version, but the entry can no longer be restored.
        let mut document: Value =
            serde_json::from_slice(&std::fs::read(&backup).expect("Failed to read backup"))
                .expect("Backup is not JSON");
        let alice = document
            .get_mut("entries")
            .and_then(Value::as_array_mut)
            .expect("Backup has no entries")
            .iter_mut()
            .filter_map(|entry| entry.pointer_mut("/ent/V3/attrs"))
            .filter_map(Value::as_object_mut)
            .find(|attrs| {
                attrs
                    .get("name")
                    .is_some_and(|name| name.to_string().contains(BACKUP_USER_ALICE))
            })
            .expect("Alice is not in the backup");
        alice.remove("uuid").expect("Alice has no uuid");
        std::fs::write(
            &backup,
            serde_json::to_vec(&document).expect("Failed to serialise backup"),
        )
        .expect("Failed to write backup");

        let outcome = outcomes(&verify_now(&env).await);
        assert!(
            matches!(
                outcome.as_slice(),
                [(BackupDestination::Local, BackupVerifyOutcome::Failed(reasons))]
                    if reasons.iter().any(|reason| reason.contains("reindex of the restored database failed"))
            ),
            "{outcome:?}"
        );
        assert_eq!(metric(&env, VERIFICATION_FAILURES, LOCAL).await, 1.0);
        assert_eq!(metric(&env, VERIFIED, LOCAL).await, 0.0);

        env.core_handle.shutdown().await;
    });
}

/// A verification that can not run says so, without calling the backup unrestorable.
#[test]
fn test_scheduled_verification_that_can_not_run_is_an_error() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).expect("Failed to create backup directory");
        // The scratch space is unusable: a file stands where its directory should be.
        let scratch = workdir.path().join("scratch");
        std::fs::write(&scratch, b"x").expect("Failed to write file");
        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(backup_dir.clone()),
                metrics_endpoint: true,
                verify_schedule: Some("0 0 0 1 1 * 2099".to_string()),
                verify_temp_path: Some(scratch),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        populate(&env).await;
        let backup = backup_now(&env, &backup_dir).await;

        let results = verify_now(&env).await;
        assert!(
            matches!(
                outcomes(&results).as_slice(),
                [(BackupDestination::Local, BackupVerifyOutcome::Error(_))]
            ),
            "{results:?}"
        );
        assert_eq!(
            results[0].artifact.as_deref(),
            backup.file_name().and_then(|name| name.to_str())
        );
        let (_, text) = get_metrics(&env).await;
        assert_eq!(
            sample(&text, VERIFICATION_ERRORS, LOCAL),
            Some(1.0),
            "{text}"
        );
        assert_eq!(sample(&text, VERIFICATION_FAILURES, LOCAL), Some(0.0));
        assert_eq!(sample(&text, VERIFICATION_LAST_FAILURE, LOCAL), Some(0.0));

        env.core_handle.shutdown().await;
    });
}

/// A shutdown during a verification neither waits for the whole restore nor leaves the
/// restored database behind, and the scratch directories of a run that was killed are
/// removed at the next start.
#[test]
fn test_shutdown_during_a_verification_leaves_no_scratch_data() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).expect("Failed to create backup directory");

        // What a killed run leaves behind, in the default scratch location: next to the
        // database, named after it.
        let stale = default_scratch(workdir.path()).join(format!("{SCRATCH_DIR_PREFIX}killed"));
        std::fs::create_dir_all(&stale).expect("Failed to create directory");
        std::fs::write(stale.join("verify.db"), b"restored data").expect("Failed to write");
        // The run in progress of another server whose database is in the same directory.
        let other = workdir
            .path()
            .join(format!("other.db{SCRATCH_PARENT_SUFFIX}"))
            .join(format!("{SCRATCH_DIR_PREFIX}running"));
        std::fs::create_dir_all(&other).expect("Failed to create directory");

        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(backup_dir.clone()),
                metrics_endpoint: true,
                verify_schedule: Some("* * * * * * *".to_string()),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        assert!(
            !stale.exists(),
            "the start must remove the stale scratch data"
        );
        assert!(
            other.is_dir(),
            "the start must leave the scratch data of another server alone"
        );
        populate(&env).await;
        backup_now(&env, &backup_dir).await;

        // Shut down while a scheduled run has its scratch data on disk.
        let deadline = tokio::time::Instant::now() + SCHEDULED_VERIFICATION_TIMEOUT;
        while scratch_dirs(&default_scratch(workdir.path())).is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "no scheduled verification started"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        env.core_handle.shutdown().await;

        // The abandoned run stops before its next step and removes its scratch data.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while !scratch_dirs(&default_scratch(workdir.path())).is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "scratch data left behind: {:?}",
                scratch_dirs(&default_scratch(workdir.path()))
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // An abandoned run is neither a failure nor an error.
        let state = std::fs::read_to_string(state_file(workdir.path())).unwrap_or_default();
        assert!(!state.contains("verification_last_failure"), "{state}");
        assert!(!state.contains("verification_last_error"), "{state}");
    });
}

#[test]
fn test_s3_metrics_and_scheduled_verification() {
    let Some(primary) = test_s3_config("observability-test") else {
        return;
    };
    let region = test_s3_region(&primary, "eu-west-1", "observability-dr");
    let region_name = region.name().to_string();
    let primary = S3Config {
        replication: Some(ReplicationConfig {
            enabled: true,
            regions: vec![region.clone()],
            sync_interval_seconds: 300,
        }),
        ..primary
    };
    let region_labels = format!("destination=\"s3_region\",region=\"{region_name}\"");

    run(async {
        let sdk = sdk_client(&primary).await;
        ensure_bucket(&sdk, &primary.bucket).await;
        ensure_bucket(&sdk, &region.bucket).await;

        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).expect("Failed to create backup directory");
        let encryption = encryption(workdir.path());
        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(backup_dir.clone()),
                s3: Some(primary.clone()),
                metrics_endpoint: true,
                encryption: encryption.clone(),
                verify_schedule: Some("0 0 0 1 1 * 2099".to_string()),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config.clone()).await;
        populate(&env).await;

        let (_, text) = get_metrics(&env).await;
        for labels in [LOCAL, S3, region_labels.as_str()] {
            assert_eq!(sample(&text, LAST_SUCCESS, labels), Some(0.0), "{text}");
        }

        // The scheduled backup run stores one artifact locally, in S3 and in the region.
        let before = now_secs();
        backup_now(&env, &backup_dir).await;
        let after = now_secs();
        let (_, text) = get_metrics(&env).await;
        for labels in [LOCAL, S3, region_labels.as_str()] {
            assert_time_within(&text, LAST_SUCCESS, labels, before, after);
            assert_eq!(sample(&text, FAILURES, labels), Some(0.0), "{text}");
        }

        // The full verification of the newest local and S3 artifacts, the same backup:
        // the download is checked against its sidecar, and the verification of the local
        // copy counts for it instead of a second restore.
        let before = now_secs();
        let results = verify_now(&env).await;
        assert_eq!(
            outcomes(&results),
            vec![
                (BackupDestination::Local, BackupVerifyOutcome::Passed),
                (BackupDestination::S3, BackupVerifyOutcome::Passed),
            ]
        );
        assert!(!results[0].reused_local);
        assert!(results[1].reused_local, "{results:?}");
        for labels in [LOCAL, S3] {
            assert!(metric(&env, VERIFIED, labels).await >= before.floor());
            assert_eq!(metric(&env, VERIFICATION_FAILURES, labels).await, 0.0);
        }

        // A newer S3 backup that is not the newest local one: each is restored on its own.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        env.core_handle
            .trigger_s3_backup(
                primary.clone(),
                7,
                BackupCompression::NoCompression,
                &BackupEncryptionConfig::default(),
            )
            .await
            .expect("S3 backup failed");
        let results = verify_now(&env).await;
        assert_eq!(
            outcomes(&results),
            vec![
                (BackupDestination::Local, BackupVerifyOutcome::Passed),
                (BackupDestination::S3, BackupVerifyOutcome::Passed),
            ]
        );
        assert!(!results[1].reused_local, "{results:?}");

        // An artifact that can not be produced (the key is gone) fails every destination,
        // the region it never reached included.
        let last_success = metric(&env, LAST_SUCCESS, region_labels.as_str()).await;
        let passphrase_file = encryption
            .passphrase_file
            .clone()
            .expect("A passphrase file");
        std::fs::remove_file(&passphrase_file).expect("Failed to remove the passphrase");
        env.core_handle
            .trigger_configured_online_backup()
            .await
            .expect_err("A backup without its key must fail");
        let (_, text) = get_metrics(&env).await;
        for labels in [LOCAL, S3, region_labels.as_str()] {
            assert_eq!(
                sample(&text, FAILURES, labels),
                Some(1.0),
                "{labels}: {text}"
            );
        }
        assert_eq!(
            sample(&text, LAST_SUCCESS, region_labels.as_str()),
            Some(last_success)
        );
        env.core_handle.shutdown().await;

        // Without a state file, a restarted server takes the last success of S3 and of the
        // region from the newest backup each holds.
        std::fs::remove_file(state_file(workdir.path())).expect("Failed to remove the state file");
        std::fs::write(&passphrase_file, "observability e2e passphrase\n")
            .expect("Failed to write the passphrase");
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let (_, text) = get_metrics(&env).await;
            let seeded = [S3, region_labels.as_str()]
                .iter()
                .all(|labels| sample(&text, LAST_SUCCESS, labels).is_some_and(|v| v > 0.0));
            if seeded {
                // Both hold the newest backup, the one copied to the region on upload.
                assert_eq!(
                    sample(&text, LAST_SUCCESS, S3),
                    sample(&text, LAST_SUCCESS, &region_labels),
                    "{text}"
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "S3 last success never seeded:\n{text}"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        env.core_handle.shutdown().await;

        delete_prefix(&sdk, &primary).await;
        delete_prefix(&sdk, &region.to_s3_config()).await;
    });
}
