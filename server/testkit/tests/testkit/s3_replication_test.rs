//! End to end test of cross-region S3 backup replication against a real S3 endpoint.
//!
//! Like `s3_recovery_test`, this needs an S3-compatible service and is skipped unless
//! `KUBIDM_TEST_S3_ENDPOINT` is set. CI runs it against [Silo](https://github.com/pgsty/silo),
//! which can be reproduced locally with:
//!
//! ```text
//! docker run -d --name silo -p 9000:9000 \
//!     -e MINIO_ROOT_USER=kubidm-test -e MINIO_ROOT_PASSWORD=kubidm-test-secret \
//!     pgsty/silo:RELEASE.2026-09-16T00-00-00Z server /data
//! KUBIDM_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
//!     cargo test -p kubidmd_testkit --test integration_test s3_replication
//! ```
//!
//! The credentials come from `KUBIDM_TEST_S3_ACCESS_KEY` and `KUBIDM_TEST_S3_SECRET_KEY`
//! (defaults `kubidm-test` / `kubidm-test-secret`). The primary bucket is taken from
//! `KUBIDM_TEST_S3_BUCKET` (default `kubidm-test`) and the replica bucket from
//! `KUBIDM_TEST_S3_REGION_BUCKET` (default `kubidm-test-region`); both live on the same
//! endpoint and are created when missing. Every run uses its own prefixes, so runs never
//! interfere.

use std::time::Duration;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as SdkClient;
use kubidm_proto::backup::{
    BackupCompression, BackupEncryptionConfig, EncryptionKeySource, KeyDerivationParams,
    ReplicationConfig, ReplicationRegionConfig, ReplicationStatus, S3Config, S3Credentials,
};
use kubidmd_core::backup::{is_encrypted_artifact, S3ClientWrapper, MIN_KDF_M_COST};
use kubidmd_core::config::{Configuration, OnlineBackup};
use kubidmd_core::{
    replicate_status_server_core, restore_s3_database, s3_config_for_cli,
    verify_s3_backup_server_core, BackupVerifyLevel,
};
use uuid::Uuid;

use kubidmd_testkit::login_put_admin_idm_admins;

use super::backup_common::{
    assert_directory_state_restored, config_with_db, populate, run, start_server,
};

const ENDPOINT_ENV: &str = "KUBIDM_TEST_S3_ENDPOINT";
const BUCKET_ENV: &str = "KUBIDM_TEST_S3_BUCKET";
const REGION_BUCKET_ENV: &str = "KUBIDM_TEST_S3_REGION_BUCKET";
const ACCESS_KEY_ENV: &str = "KUBIDM_TEST_S3_ACCESS_KEY";
const SECRET_KEY_ENV: &str = "KUBIDM_TEST_S3_SECRET_KEY";
const DEFAULT_BUCKET: &str = "kubidm-test";
const DEFAULT_REGION_BUCKET: &str = "kubidm-test-region";
const DEFAULT_ACCESS_KEY: &str = "kubidm-test";
const DEFAULT_SECRET_KEY: &str = "kubidm-test-secret";
const PRIMARY_REGION: &str = "us-east-1";
/// The name of the replication region. It is also the signing region of its requests;
/// Silo and MinIO accept any signing region unless one is configured on the server.
const REPLICA_REGION: &str = "eu-west-1";
/// A region whose bucket does not exist, to show that a failing region never fails the
/// primary backup.
const BROKEN_REGION: &str = "ap-southeast-1";
const RETAINED_VERSIONS: usize = 2;

struct TestSetup {
    /// The primary configuration with one healthy replication region.
    primary: S3Config,
    /// The primary configuration with the healthy region and a region whose bucket does
    /// not exist.
    primary_with_broken_region: S3Config,
    replica: ReplicationRegionConfig,
    broken: ReplicationRegionConfig,
}

fn credentials() -> S3Credentials {
    S3Credentials {
        access_key_id: std::env::var(ACCESS_KEY_ENV)
            .unwrap_or_else(|_| DEFAULT_ACCESS_KEY.to_string()),
        secret_access_key: std::env::var(SECRET_KEY_ENV)
            .unwrap_or_else(|_| DEFAULT_SECRET_KEY.to_string()),
        session_token: None,
    }
}

/// The S3 configurations for this test run, or None (after printing why) when no endpoint
/// is configured.
fn test_setup() -> Option<TestSetup> {
    let Ok(endpoint) = std::env::var(ENDPOINT_ENV) else {
        eprintln!("skipping: {ENDPOINT_ENV} not set");
        return None;
    };
    let bucket = std::env::var(BUCKET_ENV).unwrap_or_else(|_| DEFAULT_BUCKET.to_string());
    let region_bucket =
        std::env::var(REGION_BUCKET_ENV).unwrap_or_else(|_| DEFAULT_REGION_BUCKET.to_string());
    let run_id = Uuid::new_v4();

    let replica = ReplicationRegionConfig {
        region: REPLICA_REGION.to_string(),
        endpoint: Some(endpoint.clone()),
        bucket: region_bucket,
        // A different prefix from the primary, with a trailing slash, so that the region
        // prefix handling is exercised and not just mirrored.
        path_prefix: Some(format!("dr/{run_id}/")),
        credentials: Some(credentials()),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        kms_key_id: None,
    };
    let broken = ReplicationRegionConfig {
        region: BROKEN_REGION.to_string(),
        endpoint: Some(endpoint.clone()),
        bucket: format!("kubidm-test-missing-{run_id}"),
        path_prefix: None,
        credentials: Some(credentials()),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        kms_key_id: None,
    };

    let replication = |regions: Vec<ReplicationRegionConfig>| ReplicationConfig {
        enabled: true,
        regions,
        sync_interval_seconds: 300,
    };

    let primary = S3Config {
        bucket,
        region: Some(PRIMARY_REGION.to_string()),
        endpoint: Some(endpoint),
        path_prefix: Some(format!("s3-replication-test/{run_id}")),
        credentials: Some(credentials()),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        replication: Some(replication(vec![replica.clone()])),
    };
    let primary_with_broken_region = S3Config {
        replication: Some(replication(vec![replica.clone(), broken.clone()])),
        ..primary.clone()
    };

    Some(TestSetup {
        primary,
        primary_with_broken_region,
        replica,
        broken,
    })
}

/// A server configuration carrying `s3_config` as its `[online_backup.s3]` section, as the
/// `kubidmd database` commands read it.
fn config_with_s3(db_path: &std::path::Path, s3_config: &S3Config) -> Configuration {
    Configuration {
        online_backup: Some(OnlineBackup {
            s3: Some(s3_config.clone()),
            ..OnlineBackup::default()
        }),
        ..config_with_db(db_path)
    }
}

/// A raw SDK client for the endpoint and credentials, used to prepare the buckets, to
/// inspect the objects behind the back of `S3ClientWrapper` and to damage them.
async fn sdk_client(s3_config: &S3Config) -> SdkClient {
    let credentials = s3_config
        .credentials
        .as_ref()
        .expect("Test S3 config has no credentials");
    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .endpoint_url(
            s3_config
                .endpoint
                .clone()
                .expect("Test S3 config has no endpoint"),
        )
        .region(Region::new(PRIMARY_REGION))
        .credentials_provider(Credentials::new(
            credentials.access_key_id.clone(),
            credentials.secret_access_key.clone(),
            None,
            None,
            "kubidm-test",
        ))
        .load()
        .await;
    SdkClient::from_conf(
        aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(true)
            .build(),
    )
}

/// Create `bucket` unless it exists. The S3 tests run concurrently and share the primary
/// bucket, so a creation that loses the race against another test is fine as long as the
/// bucket exists afterwards.
async fn ensure_bucket(sdk: &SdkClient, bucket: &str) {
    if sdk.head_bucket().bucket(bucket).send().await.is_ok() {
        return;
    }
    if let Err(err) = sdk.create_bucket().bucket(bucket).send().await {
        assert!(
            sdk.head_bucket().bucket(bucket).send().await.is_ok(),
            "Failed to create the test bucket {bucket}: {err:?}"
        );
    }
}

/// Every object key below the prefix of `region`, with the prefix stripped, sorted.
async fn raw_region_keys(sdk: &SdkClient, region: &ReplicationRegionConfig) -> Vec<String> {
    let prefix = region
        .path_prefix
        .as_deref()
        .expect("Region config has no prefix")
        .trim_end_matches('/');
    let output = sdk
        .list_objects_v2()
        .bucket(&region.bucket)
        .prefix(format!("{prefix}/"))
        .send()
        .await
        .expect("Failed to list the region objects");
    let mut keys: Vec<String> = output
        .contents()
        .iter()
        .filter_map(|object| object.key())
        .map(|key| {
            key.strip_prefix(&format!("{prefix}/"))
                .unwrap_or(key)
                .to_string()
        })
        .collect();
    keys.sort();
    keys
}

/// `backups` together with their metadata sidecars, sorted: exactly the objects a location
/// holding these backups contains.
fn with_sidecars(backups: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = backups
        .iter()
        .flat_map(|key| [key.clone(), format!("{key}.metadata.json")])
        .collect();
    keys.sort();
    keys
}

fn region_full_key(region: &ReplicationRegionConfig, key: &str) -> String {
    let prefix = region
        .path_prefix
        .as_deref()
        .expect("Region config has no prefix")
        .trim_end_matches('/');
    format!("{prefix}/{key}")
}

#[test]
fn test_s3_backup_replication_retention_status_and_recovery() {
    let Some(setup) = test_setup() else {
        return;
    };

    run(async {
        let sdk = sdk_client(&setup.primary).await;
        ensure_bucket(&sdk, &setup.primary.bucket).await;
        ensure_bucket(&sdk, &setup.replica.bucket).await;

        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let mut env = start_server(&workdir.path().join("source.db")).await;
        populate(&env).await;

        // a. Three backups through the production S3 backup path, replicated to one
        //    region, with a retention of two. Primary and region must end up with exactly
        //    the same two newest backups: replication copies every upload, and retention
        //    runs in the region as well.
        for round in 0..3 {
            if round > 0 {
                // Backup keys carry the timestamp; make sure they differ.
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
            env.core_handle
                .trigger_s3_backup(
                    setup.primary.clone(),
                    RETAINED_VERSIONS,
                    BackupCompression::Gzip,
                    &BackupEncryptionConfig::default(),
                )
                .await
                .expect("S3 backup with replication failed");
        }

        let primary = S3ClientWrapper::new(setup.primary.clone())
            .await
            .expect("Failed to create the primary client");
        let replica = S3ClientWrapper::for_region(&setup.replica)
            .await
            .expect("Failed to create the region client");

        let primary_backups = primary
            .list_backup_artifacts()
            .await
            .expect("Failed to list the primary backups");
        assert_eq!(
            primary_backups.len(),
            RETAINED_VERSIONS,
            "Primary retention must keep {RETAINED_VERSIONS} backups, found {primary_backups:?}"
        );
        let replica_backups = replica
            .list_backup_artifacts()
            .await
            .expect("Failed to list the region backups");
        assert_eq!(
            replica_backups, primary_backups,
            "The region must hold exactly the backups the primary holds"
        );

        // Behind the scenes: the two backups and their two sidecars under the region
        // prefix, nothing else. Retention removed the sidecar of the pruned backup too.
        assert_eq!(
            raw_region_keys(&sdk, &setup.replica).await,
            with_sidecars(&primary_backups),
            "Unexpected objects under the region prefix"
        );

        // b. Every replicated object is byte for byte the primary object and carries the
        //    same sidecar, so checksums, sizes and timestamps agree.
        for key in &primary_backups {
            let (primary_data, primary_metadata) = primary
                .download_backup(key)
                .await
                .expect("Failed to download the primary backup");
            let (replica_data, replica_metadata) = replica
                .download_backup(key)
                .await
                .expect("Failed to download the replicated backup");
            assert_eq!(replica_data, primary_data, "Replica of {key} differs");
            assert_eq!(
                replica_metadata.checksum_sha256, primary_metadata.checksum_sha256,
                "Replica sidecar of {key} records another checksum"
            );
            assert_eq!(replica_metadata, primary_metadata);
        }

        // c. A region that can not be written to (its bucket does not exist) is logged
        //    and skipped: the primary backup and the healthy region are unaffected.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        env.core_handle
            .trigger_s3_backup(
                setup.primary_with_broken_region.clone(),
                RETAINED_VERSIONS,
                BackupCompression::Gzip,
                &BackupEncryptionConfig::default(),
            )
            .await
            .expect("A failing region must not fail the primary backup");

        let primary_backups = primary
            .list_backup_artifacts()
            .await
            .expect("Failed to list the primary backups");
        assert_eq!(primary_backups.len(), RETAINED_VERSIONS);
        assert_eq!(
            replica
                .list_backup_artifacts()
                .await
                .expect("Failed to list the region backups"),
            primary_backups,
            "The healthy region must follow the primary while another region fails"
        );
        let newest = primary_backups.last().expect("No backups").clone();

        env.core_handle.shutdown().await;

        // d. `--region` on the recovery commands targets the replica: verify-s3 at the
        //    full level passes on the replicated copy and never touches the configured
        //    database, and restore-s3 restores from it.
        let untouched_db = workdir.path().join("untouched.db");
        let server_config = config_with_s3(&untouched_db, &setup.primary);
        let replica_s3 = s3_config_for_cli(&server_config, None, Some(REPLICA_REGION), None)
            .expect("--region must resolve the configured replication region");
        assert_eq!(replica_s3.bucket, setup.replica.bucket);
        assert_eq!(replica_s3.path_prefix, setup.replica.path_prefix);
        assert!(
            s3_config_for_cli(&server_config, None, Some("us-west-2"), None).is_err(),
            "--region must reject a region that is not configured"
        );

        assert!(
            verify_s3_backup_server_core(
                &server_config,
                replica_s3.clone(),
                &newest,
                BackupVerifyLevel::Full,
            )
            .await,
            "Full verification of the replicated backup must pass"
        );
        assert!(
            !untouched_db.exists(),
            "Verification must not touch the configured database"
        );

        let restored_db = workdir.path().join("restored-from-region.db");
        restore_s3_database(&config_with_db(&restored_db), replica_s3.clone(), &newest)
            .await
            .expect("Restore from the region failed");
        assert!(restored_db.exists(), "Restore did not create the database");

        // e. replicate-status reports the region healthy, and reports the broken region
        //    as failed with everything pending while the healthy one stays healthy.
        assert!(
            replicate_status_server_core(&server_config, true).await,
            "replicate-status must succeed while the region holds every backup"
        );
        let replication = setup
            .primary
            .replication
            .as_ref()
            .expect("Test config has no replication");
        let health = primary
            .check_replication_health(replication, Some("2024-01-01T00:00:00Z"))
            .await
            .expect("Health check failed");
        assert_eq!(health.overall_status, ReplicationStatus::Completed);
        assert_eq!(health.healthy_regions, 1);
        assert_eq!(health.unhealthy_regions, 0);
        let region = health.regions.first().expect("No region status");
        assert_eq!(region.region, REPLICA_REGION);
        assert_eq!(region.backups_replicated, RETAINED_VERSIONS as u64);
        assert_eq!(region.pending_backups, 0);
        assert_eq!(region.lag_seconds, Some(0));
        assert_eq!(region.last_sync_backup_id.as_deref(), Some(newest.as_str()));
        assert_eq!(health.last_check_timestamp, "2024-01-01T00:00:00Z");

        let two_region_config = config_with_s3(&untouched_db, &setup.primary_with_broken_region);
        assert!(
            !replicate_status_server_core(&two_region_config, true).await,
            "replicate-status must fail while a region is unreachable"
        );
        let health = primary
            .check_replication_health(
                setup
                    .primary_with_broken_region
                    .replication
                    .as_ref()
                    .expect("Test config has no replication"),
                None,
            )
            .await
            .expect("Health check failed");
        assert_eq!(health.healthy_regions, 1);
        assert_eq!(health.unhealthy_regions, 1);
        assert!(matches!(
            health.overall_status,
            ReplicationStatus::Degraded { .. }
        ));
        let broken = health
            .regions
            .iter()
            .find(|region| region.region == BROKEN_REGION)
            .expect("No status for the broken region");
        assert!(
            matches!(broken.status, ReplicationStatus::Failed { .. }),
            "{:?}",
            broken.status
        );
        assert_eq!(broken.bucket, setup.broken.bucket);
        assert_eq!(broken.pending_backups, RETAINED_VERSIONS as u64);
        assert!(broken.last_error.is_some());

        // f. Delete the region's copy of the newest backup, keeping its sidecar: the
        //    region is degraded, one backup is pending and the region lags behind by the
        //    time between the two backups.
        sdk.delete_object()
            .bucket(&setup.replica.bucket)
            .key(region_full_key(&setup.replica, &newest))
            .send()
            .await
            .expect("Failed to delete the replicated object");

        assert!(
            !replicate_status_server_core(&server_config, false).await,
            "replicate-status must fail once a replicated backup is missing"
        );
        let health = primary
            .check_replication_health(replication, None)
            .await
            .expect("Health check failed");
        assert!(matches!(
            health.overall_status,
            ReplicationStatus::Failed { .. }
        ));
        let region = health.regions.first().expect("No region status");
        assert!(
            matches!(region.status, ReplicationStatus::Degraded { .. }),
            "{:?}",
            region.status
        );
        assert_eq!(region.backups_replicated, RETAINED_VERSIONS as u64 - 1);
        assert_eq!(region.pending_backups, 1);
        assert_ne!(region.last_sync_backup_id.as_deref(), Some(newest.as_str()));
        assert!(
            region.lag_seconds.is_some_and(|lag| lag >= 1),
            "The region must lag behind the primary, got {:?}",
            region.lag_seconds
        );
        assert!(
            !verify_s3_backup_server_core(
                &server_config,
                replica_s3.clone(),
                &newest,
                BackupVerifyLevel::Structural,
            )
            .await,
            "verify-s3 --region must fail on the missing copy"
        );

        // g. Truncate the region's copy of the remaining backup while keeping its sidecar:
        //    the size S3 reports no longer matches, nothing is intact any more.
        let oldest = primary_backups.first().expect("No backups").clone();
        sdk.put_object()
            .bucket(&setup.replica.bucket)
            .key(region_full_key(&setup.replica, &oldest))
            .body(ByteStream::from(b"truncated".to_vec()))
            .send()
            .await
            .expect("Failed to overwrite the replicated object");

        let health = primary
            .check_replication_health(replication, None)
            .await
            .expect("Health check failed");
        let region = health.regions.first().expect("No region status");
        assert!(matches!(region.status, ReplicationStatus::Degraded { .. }));
        assert_eq!(region.backups_replicated, 0);
        assert_eq!(region.pending_backups, RETAINED_VERSIONS as u64);
        assert_eq!(region.lag_seconds, None);
        assert_eq!(region.last_sync_backup_id, None);
        assert!(
            !verify_s3_backup_server_core(
                &server_config,
                replica_s3.clone(),
                &oldest,
                BackupVerifyLevel::Structural,
            )
            .await,
            "verify-s3 --region must fail on the truncated copy"
        );

        // h. The sync the replication monitor runs every `sync_interval_seconds` repairs
        //    the region: the missing and the truncated copies are copied again from the
        //    primary, after which the region is healthy and its copies verify.
        let results = primary
            .sync_replication(replication)
            .await
            .expect("Replication sync failed");
        assert_eq!(results.len(), 1);
        let (region_name, outcome) = results.into_iter().next().expect("No sync result");
        assert_eq!(region_name, REPLICA_REGION);
        let outcome = outcome.expect("The region must be synced");
        assert_eq!(
            outcome.copied, primary_backups,
            "Both damaged copies must be copied"
        );
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);

        let health = primary
            .check_replication_health(replication, None)
            .await
            .expect("Health check failed");
        assert_eq!(health.overall_status, ReplicationStatus::Completed);
        let region = health.regions.first().expect("No region status");
        assert_eq!(region.backups_replicated, RETAINED_VERSIONS as u64);
        assert_eq!(region.pending_backups, 0);
        assert_eq!(region.lag_seconds, Some(0));
        assert_eq!(
            raw_region_keys(&sdk, &setup.replica).await,
            with_sidecars(&primary_backups),
            "The sync must restore exactly the backups and sidecars of the primary"
        );
        for key in [&newest, &oldest] {
            assert!(
                verify_s3_backup_server_core(
                    &server_config,
                    replica_s3.clone(),
                    key,
                    BackupVerifyLevel::Structural,
                )
                .await,
                "verify-s3 --region must pass on the repaired copy of {key}"
            );
        }

        // A second sync has nothing left to do.
        let results = primary
            .sync_replication(replication)
            .await
            .expect("Replication sync failed");
        let outcome = results
            .into_iter()
            .next()
            .and_then(|(_, outcome)| outcome.ok())
            .expect("The region must be synced");
        assert!(outcome.copied.is_empty(), "{:?}", outcome.copied);
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);

        // i. A region added after the backups were taken receives them on the next sync,
        //    while a region that can not be reached is reported without failing the sync
        //    of the others.
        let late = ReplicationRegionConfig {
            region: "eu-central-1".to_string(),
            path_prefix: Some(format!(
                "late/{}",
                setup
                    .replica
                    .path_prefix
                    .as_deref()
                    .expect("Region config has no prefix")
            )),
            ..setup.replica.clone()
        };
        let late_replication = ReplicationConfig {
            regions: vec![late.clone(), setup.broken.clone()],
            ..replication.clone()
        };
        let health = primary
            .check_replication_health(&late_replication, None)
            .await
            .expect("Health check failed");
        assert_eq!(health.regions[0].backups_replicated, 0);
        assert_eq!(health.regions[0].pending_backups, RETAINED_VERSIONS as u64);

        let results = primary
            .sync_replication(&late_replication)
            .await
            .expect("Replication sync failed");
        assert_eq!(results.len(), 2);
        let late_outcome = results[0]
            .1
            .as_ref()
            .expect("The late region must be synced");
        assert_eq!(late_outcome.copied, primary_backups);
        assert!(late_outcome.failed.is_empty(), "{:?}", late_outcome.failed);
        assert_eq!(results[1].0, BROKEN_REGION);
        assert!(
            results[1].1.is_err(),
            "A region whose bucket does not exist can not be synced"
        );

        let health = primary
            .check_replication_health(&late_replication, None)
            .await
            .expect("Health check failed");
        assert_eq!(health.healthy_regions, 1);
        assert_eq!(health.regions[0].status, ReplicationStatus::Completed);
        assert_eq!(
            raw_region_keys(&sdk, &late).await,
            with_sidecars(&primary_backups),
            "The late region must hold exactly the backups and sidecars of the primary"
        );
    });
}

/// A server configuration with `s3_config` as its `[online_backup.s3]` section and
/// `encryption` as its `[online_backup.encryption]` section, as the `kubidmd database`
/// commands of a host that recovers encrypted backups read it.
fn config_with_s3_and_encryption(
    db_path: &std::path::Path,
    s3_config: &S3Config,
    encryption: &BackupEncryptionConfig,
) -> Configuration {
    let mut config = config_with_s3(db_path, s3_config);
    if let Some(online_backup) = config.online_backup.as_mut() {
        online_backup.enabled = false;
        online_backup.encryption = encryption.clone();
    }
    config
}

#[test]
fn test_s3_replication_of_encrypted_backups() {
    let Some(setup) = test_setup() else {
        return;
    };

    run(async {
        let sdk = sdk_client(&setup.primary).await;
        ensure_bucket(&sdk, &setup.primary.bucket).await;
        ensure_bucket(&sdk, &setup.replica.bucket).await;

        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let passphrase_file = workdir.path().join("passphrase");
        std::fs::write(&passphrase_file, "replicated backup passphrase\n")
            .expect("Failed to write the passphrase");
        let encryption = BackupEncryptionConfig {
            enabled: true,
            key_source: EncryptionKeySource::Passphrase,
            // The cheapest derivation the server accepts; this test is about replication.
            key_derivation: KeyDerivationParams {
                m_cost: MIN_KDF_M_COST,
                t_cost: 1,
                p_cost: 1,
            },
            key_identifier: Some("replicated-key".to_string()),
            passphrase_file: Some(passphrase_file),
        };

        // a. One encrypted backup through the production S3 backup path, replicated.
        let mut env = start_server(&workdir.path().join("source.db")).await;
        populate(&env).await;
        env.core_handle
            .trigger_s3_backup(
                setup.primary.clone(),
                RETAINED_VERSIONS,
                BackupCompression::Gzip,
                &encryption,
            )
            .await
            .expect("Encrypted S3 backup with replication failed");
        env.core_handle.shutdown().await;

        let primary = S3ClientWrapper::new(setup.primary.clone())
            .await
            .expect("Failed to create the primary client");
        let replica = S3ClientWrapper::for_region(&setup.replica)
            .await
            .expect("Failed to create the region client");
        let primary_backups = primary
            .list_backup_artifacts()
            .await
            .expect("Failed to list the primary backups");
        assert_eq!(primary_backups.len(), 1, "{primary_backups:?}");
        let key = primary_backups[0].clone();
        assert!(
            key.ends_with(".json.gz.enc"),
            "An encrypted backup must carry the .enc suffix: {key}"
        );

        // b. The region holds the same encrypted object and the same sidecar, which says
        //    encrypted and names the key.
        assert_eq!(
            raw_region_keys(&sdk, &setup.replica).await,
            with_sidecars(&primary_backups),
            "The region must hold the .enc object and its sidecar, nothing else"
        );
        let (primary_data, primary_metadata) = primary
            .download_backup(&key)
            .await
            .expect("Failed to download the primary backup");
        let (replica_data, replica_metadata) = replica
            .download_backup(&key)
            .await
            .expect("Failed to download the replicated backup");
        assert_eq!(
            replica_data, primary_data,
            "The replica must be byte identical"
        );
        assert!(is_encrypted_artifact(&replica_data));
        assert_eq!(replica_metadata, primary_metadata);
        assert!(replica_metadata.encrypted);
        assert_eq!(
            replica_metadata.key_identifier.as_deref(),
            Some("replicated-key")
        );

        // c. A damaged .enc copy is detected and repaired by the sync without the key.
        sdk.put_object()
            .bucket(&setup.replica.bucket)
            .key(region_full_key(&setup.replica, &key))
            .body(ByteStream::from(b"truncated".to_vec()))
            .send()
            .await
            .expect("Failed to overwrite the replicated object");
        let replication = setup
            .primary
            .replication
            .as_ref()
            .expect("Test config has no replication");
        let health = primary
            .check_replication_health(replication, None)
            .await
            .expect("Health check failed");
        assert_eq!(health.regions[0].pending_backups, 1);
        let results = primary
            .sync_replication(replication)
            .await
            .expect("Replication sync failed");
        let outcome = results
            .into_iter()
            .next()
            .and_then(|(_, outcome)| outcome.ok())
            .expect("The region must be synced");
        assert_eq!(outcome.copied, primary_backups);
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        let health = primary
            .check_replication_health(replication, None)
            .await
            .expect("Health check failed");
        assert_eq!(health.overall_status, ReplicationStatus::Completed);

        // d. The replica verifies and restores with the key, through --region, and is
        //    refused without it.
        let untouched_db = workdir.path().join("untouched.db");
        let server_config =
            config_with_s3_and_encryption(&untouched_db, &setup.primary, &encryption);
        let replica_s3 = s3_config_for_cli(&server_config, None, Some(REPLICA_REGION), None)
            .expect("--region must resolve the configured replication region");
        assert!(
            verify_s3_backup_server_core(
                &server_config,
                replica_s3.clone(),
                &key,
                BackupVerifyLevel::Full,
            )
            .await,
            "Full verification of the replicated encrypted backup must pass with the key"
        );
        assert!(!untouched_db.exists());

        let no_key_db = workdir.path().join("no-key.db");
        assert!(
            !verify_s3_backup_server_core(
                &config_with_s3(&no_key_db, &setup.primary),
                replica_s3.clone(),
                &key,
                BackupVerifyLevel::Structural,
            )
            .await,
            "verify-s3 --region must fail without the key"
        );
        assert!(
            restore_s3_database(&config_with_db(&no_key_db), replica_s3.clone(), &key)
                .await
                .is_err(),
            "restore-s3 --region must fail without the key"
        );
        assert!(!no_key_db.exists());

        let restored_db = workdir.path().join("restored-from-region.db");
        restore_s3_database(
            &config_with_s3_and_encryption(&restored_db, &setup.primary, &encryption),
            replica_s3,
            &key,
        )
        .await
        .expect("Restore of the encrypted backup from the region failed");

        let mut env = start_server(&restored_db).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        assert_directory_state_restored(&env.rsclient).await;
        env.core_handle.shutdown().await;
    });
}
