//! End to end test of cross-region S3 backup replication against a real S3 endpoint.
//!
//! Like `s3_recovery_test`, this needs an S3-compatible service; see `backup_common` for how
//! it is found, when it is skipped and how to run it locally. The replicas live in the
//! region test bucket on the same endpoint.

use std::time::Duration;

use aws_sdk_s3::primitives::ByteStream;
use kubidm_proto::backup::{
    BackupCompression, BackupEncryptionConfig, EncryptionKeySource, KeyDerivationParams,
    ReplicationConfig, ReplicationRegionConfig, ReplicationStatus, S3Config,
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
    assert_directory_state_restored, config_with_db, delete_prefix, ensure_bucket, full_key,
    object_keys, populate, run, sdk_client, start_server, test_s3_config, test_s3_region,
    with_sidecars,
};

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

impl TestSetup {
    /// The replica as an S3 location, to inspect and clean up its objects.
    fn replica_s3(&self) -> S3Config {
        self.replica.to_s3_config()
    }
}

/// The S3 configurations for this test run, or None when S3 tests are skipped.
fn test_setup() -> Option<TestSetup> {
    let primary = test_s3_config("s3-replication-test")?;
    let replica = test_s3_region(&primary, REPLICA_REGION, "dr");
    let replica = ReplicationRegionConfig {
        // A different prefix from the primary, with a trailing slash, so that the region
        // prefix handling is exercised and not just mirrored.
        path_prefix: replica.path_prefix.map(|prefix| format!("{prefix}/")),
        ..replica
    };
    let broken = ReplicationRegionConfig {
        bucket: format!("kubidm-test-missing-{}", Uuid::new_v4()),
        path_prefix: None,
        ..test_s3_region(&primary, BROKEN_REGION, "broken")
    };

    let replication = |regions: Vec<ReplicationRegionConfig>| ReplicationConfig {
        enabled: true,
        regions,
        sync_interval_seconds: 300,
    };

    let primary = S3Config {
        replication: Some(replication(vec![replica.clone()])),
        ..primary
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
            object_keys(&sdk, &setup.replica_s3()).await,
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
        let mut restored_env = start_server(&restored_db).await;
        login_put_admin_idm_admins(&restored_env.rsclient).await;
        assert_directory_state_restored(&restored_env.rsclient).await;
        restored_env.core_handle.shutdown().await;

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
            .key(full_key(&setup.replica_s3(), &newest))
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
            .key(full_key(&setup.replica_s3(), &oldest))
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
            object_keys(&sdk, &setup.replica_s3()).await,
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
            name: None,
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
            object_keys(&sdk, &late.to_s3_config()).await,
            with_sidecars(&primary_backups),
            "The late region must hold exactly the backups and sidecars of the primary"
        );

        for location in [
            setup.primary.clone(),
            setup.replica_s3(),
            late.to_s3_config(),
        ] {
            delete_prefix(&sdk, &location).await;
        }
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
            object_keys(&sdk, &setup.replica_s3()).await,
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
            .key(full_key(&setup.replica_s3(), &key))
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

        delete_prefix(&sdk, &setup.primary).await;
        delete_prefix(&sdk, &setup.replica_s3()).await;
    });
}
