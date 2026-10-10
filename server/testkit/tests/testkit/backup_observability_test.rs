//! End to end tests of the backup metrics served on `/metrics` and of the scheduled full
//! verification of the newest backup (`online_backup.verify_schedule`).
//!
//! Only production code paths are used: backups are taken through the online backup path,
//! the metrics are read over HTTP from the running server, and the scheduled verification
//! runs from its schedule inside the server. The S3 variant needs an S3-compatible service;
//! see `backup_common` for how it is found, when it is skipped and how to run it locally.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kubidm_proto::backup::{
    BackupCompression, BackupEncryptionConfig, EncryptionKeySource, KeyDerivationParams,
    ReplicationConfig, S3Config, WalArchiveConfig,
};
use kubidmd_core::backup::metrics::BackupDestination;
use kubidmd_core::backup::verify::{BackupVerifyOutcome, BackupVerifyRun};
use kubidmd_core::backup::MIN_KDF_M_COST;
use kubidmd_core::config::{Configuration, OnlineBackup};
use kubidmd_testkit::AsyncTestEnvironment;

use super::backup_common::{
    backup_via_production_path, config_with_db, delete_prefix, ensure_bucket, populate, run,
    sdk_client, start_server, test_s3_config, test_s3_region,
};

/// How long the scheduled verification may take to pass on a backup. It runs every
/// second; a run restores and boots a small database.
const SCHEDULED_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(180);

const LOCAL: &str = "destination=\"local\"";
const LOCAL_STRUCTURAL: &str = "destination=\"local\",level=\"structural\"";
const LOCAL_FULL: &str = "destination=\"local\",level=\"full\"";
const S3: &str = "destination=\"s3\"";
const S3_STRUCTURAL: &str = "destination=\"s3\",level=\"structural\"";
const S3_FULL: &str = "destination=\"s3\",level=\"full\"";

const LAST_SUCCESS: &str = "kubidm_backup_last_success_timestamp_seconds";
const LAST_FAILURE: &str = "kubidm_backup_last_failure_timestamp_seconds";
const FAILURES: &str = "kubidm_backup_failures_total";
const LAST_VERIFIED: &str = "kubidm_backup_last_verified_timestamp_seconds";
const VERIFICATION_FAILURES: &str = "kubidm_backup_verification_failures_total";
const PITR_LAST_SYNC: &str = "kubidm_backup_pitr_last_sync_timestamp_seconds";

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("The clock is before the epoch")
        .as_secs_f64()
}

/// GET `/metrics` of the server of `env`: its status and body.
async fn get_metrics(env: &AsyncTestEnvironment) -> (u16, String) {
    let response = env
        .rsclient
        .client()
        .get(env.rsclient.make_url("/metrics"))
        .send()
        .await
        .expect("Failed to request /metrics");
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
async fn verify_now(env: &AsyncTestEnvironment) -> Vec<(BackupDestination, BackupVerifyOutcome)> {
    loop {
        match env.core_handle.trigger_backup_verification().await {
            BackupVerifyRun::Completed(results) => {
                return results
                    .into_iter()
                    .map(|result| (result.destination, result.outcome))
                    .collect()
            }
            BackupVerifyRun::Skipped(reason) => {
                assert!(reason.contains("already running"), "{reason}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
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
fn test_metrics_endpoint_reports_backup_and_wal_archive_timestamps() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
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
        assert_eq!(sample(&text, LAST_VERIFIED, LOCAL_STRUCTURAL), Some(0.0));
        // The full verification is not scheduled, so it is not reported.
        assert_eq!(sample(&text, LAST_VERIFIED, LOCAL_FULL), None);
        assert!(sample(&text, PITR_LAST_SYNC, "").is_some(), "{text}");

        // A backup through the online backup path updates the success and the structural
        // verification of its destination.
        let before = now_secs();
        backup_via_production_path(
            &env,
            &backup_dir,
            BackupCompression::Gzip,
            &BackupEncryptionConfig::default(),
        )
        .await;
        let after = now_secs();
        let (_, text) = get_metrics(&env).await;
        for (name, labels) in [(LAST_SUCCESS, LOCAL), (LAST_VERIFIED, LOCAL_STRUCTURAL)] {
            let value = sample(&text, name, labels).expect("sample");
            assert!(
                value >= before.floor() && value <= after.ceil(),
                "{name}{{{labels}}} = {value}, expected within [{before}, {after}]"
            );
        }
        assert_eq!(sample(&text, FAILURES, LOCAL), Some(0.0));
        assert_eq!(sample(&text, LAST_FAILURE, LOCAL), Some(0.0));

        // A backup that can not be stored is a failure of its destination, and leaves the
        // last success alone.
        let last_success = sample(&text, LAST_SUCCESS, LOCAL).expect("sample");
        let not_a_directory = workdir.path().join("not-a-directory");
        std::fs::write(&not_a_directory, b"x").expect("Failed to write file");
        env.core_handle
            .trigger_online_backup(
                &not_a_directory,
                1,
                BackupCompression::Gzip,
                &BackupEncryptionConfig::default(),
            )
            .await
            .expect_err("A backup into a file must fail");
        let (_, text) = get_metrics(&env).await;
        assert_eq!(sample(&text, FAILURES, LOCAL), Some(1.0));
        assert!(sample(&text, LAST_FAILURE, LOCAL).expect("sample") >= before.floor());
        assert_eq!(sample(&text, LAST_SUCCESS, LOCAL), Some(last_success));

        // The WAL archive synchronisation is recorded too.
        let before = now_secs();
        env.core_handle
            .sync_wal_archive()
            .await
            .expect("The WAL archive is enabled")
            .expect("WAL archive synchronisation failed");
        assert!(metric(&env, PITR_LAST_SYNC, "").await >= before.floor());

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
        assert_eq!(metric(&env, LAST_VERIFIED, LOCAL_FULL).await, 0.0);

        let before = now_secs();
        let backup =
            backup_via_production_path(&env, &backup_dir, BackupCompression::Gzip, &encryption)
                .await;
        let name = backup
            .file_name()
            .and_then(|name| name.to_str())
            .expect("Backup has no file name")
            .to_string();
        assert!(name.ends_with(".enc"), "{name}");

        // The schedule verifies the encrypted backup without any help.
        wait_for_metric(&env, LAST_VERIFIED, LOCAL_FULL, before.floor()).await;
        assert_eq!(metric(&env, VERIFICATION_FAILURES, LOCAL_FULL).await, 0.0);

        // An on demand run takes the same path and reports what it verified.
        assert_eq!(
            verify_now(&env).await,
            vec![(BackupDestination::Local, BackupVerifyOutcome::Passed)]
        );
        // The scheduled verification never touches the backups.
        let mut names: Vec<String> = std::fs::read_dir(&backup_dir)
            .expect("Failed to read backup directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        names.sort();
        assert_eq!(names, vec![name.clone()]);

        // A newer artifact that can not be restored fails the verification loudly and is
        // counted, by the schedule as by an on demand run.
        let damaged = "backup-2099-01-01T00:00:00Z.json.gz.enc";
        let mut bytes = std::fs::read(&backup).expect("Failed to read backup");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        std::fs::write(backup_dir.join(damaged), bytes).expect("Failed to write backup");
        let failures = metric(&env, VERIFICATION_FAILURES, LOCAL_FULL).await;
        let outcome = verify_now(&env).await;
        assert!(
            matches!(
                outcome.as_slice(),
                [(BackupDestination::Local, BackupVerifyOutcome::Failed(reasons))]
                    if !reasons.is_empty()
            ),
            "{outcome:?}"
        );
        wait_for_metric(&env, VERIFICATION_FAILURES, LOCAL_FULL, failures + 1.0).await;

        env.core_handle.shutdown().await;
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
        let config = config_with_online_backup(
            &workdir.path().join("source.db"),
            OnlineBackup {
                path: Some(backup_dir.clone()),
                s3: Some(primary.clone()),
                metrics_endpoint: true,
                encryption: encryption(workdir.path()),
                ..OnlineBackup::default()
            },
        );
        let mut env = kubidmd_testkit::setup_async_test(config).await;
        populate(&env).await;

        let (_, text) = get_metrics(&env).await;
        for labels in [LOCAL, S3, region_labels.as_str()] {
            assert_eq!(sample(&text, LAST_SUCCESS, labels), Some(0.0), "{text}");
        }

        // The scheduled backup run stores one artifact locally, in S3 and in the region.
        let before = now_secs();
        env.core_handle
            .trigger_configured_online_backup()
            .await
            .expect("Online backup failed");
        let (_, text) = get_metrics(&env).await;
        for (name, labels) in [
            (LAST_SUCCESS, LOCAL),
            (LAST_SUCCESS, S3),
            (LAST_SUCCESS, region_labels.as_str()),
            (LAST_VERIFIED, LOCAL_STRUCTURAL),
            (LAST_VERIFIED, S3_STRUCTURAL),
        ] {
            assert!(
                sample(&text, name, labels).expect("sample") >= before.floor(),
                "{name}{{{labels}}} in\n{text}"
            );
        }
        for labels in [LOCAL, S3, region_labels.as_str()] {
            assert_eq!(sample(&text, FAILURES, labels), Some(0.0), "{text}");
        }

        // The full verification of the newest local and S3 artifacts, the same backup:
        // the download is checked against its sidecar and counts as verified as well.
        let before = now_secs();
        assert_eq!(
            verify_now(&env).await,
            vec![
                (BackupDestination::Local, BackupVerifyOutcome::Passed),
                (BackupDestination::S3, BackupVerifyOutcome::Passed),
            ]
        );
        for labels in [LOCAL_FULL, S3_FULL] {
            assert!(metric(&env, LAST_VERIFIED, labels).await >= before.floor());
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
        assert_eq!(
            verify_now(&env).await,
            vec![
                (BackupDestination::Local, BackupVerifyOutcome::Passed),
                (BackupDestination::S3, BackupVerifyOutcome::Passed),
            ]
        );

        env.core_handle.shutdown().await;
        delete_prefix(&sdk, &primary).await;
        delete_prefix(&sdk, &region.to_s3_config()).await;
    });
}
