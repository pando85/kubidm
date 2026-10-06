//! End to end test of the S3 backup and recovery path against a real S3 endpoint.
//!
//! The test needs an S3-compatible service and is skipped unless `KUBIDM_TEST_S3_ENDPOINT`
//! is set, so that a plain `cargo test` stays green without Docker. CI runs it against
//! `adobe/s3mock`:
//!
//! ```text
//! docker run -d --rm --name kubidm-s3mock -p 9090:9090 adobe/s3mock:latest
//! KUBIDM_TEST_S3_ENDPOINT=http://127.0.0.1:9090 cargo test -p kubidmd_testkit --test integration_test s3_recovery
//! ```
//!
//! The bucket is taken from `KUBIDM_TEST_S3_BUCKET` (default `kubidm-test`) and created when
//! it does not exist. Every run uses its own `path_prefix`, so runs never interfere.

use std::time::Duration;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as SdkClient;
use kubidm_proto::backup::{BackupCompression, S3Config, S3Credentials};
use kubidmd_core::backup::{S3BackupError, S3ClientWrapper};
use kubidmd_core::{restore_s3_database, verify_s3_backup_server_core, BackupVerifyLevel};
use kubidmd_testkit::login_put_admin_idm_admins;
use uuid::Uuid;

use super::backup_common::{
    assert_directory_state_restored, config_with_db, populate, run, start_server,
};

const ENDPOINT_ENV: &str = "KUBIDM_TEST_S3_ENDPOINT";
const BUCKET_ENV: &str = "KUBIDM_TEST_S3_BUCKET";
const DEFAULT_BUCKET: &str = "kubidm-test";
const REGION: &str = "us-east-1";
const RETAINED_VERSIONS: usize = 2;

/// The S3 configuration for this test run, or None (after printing why) when no endpoint is
/// configured.
fn test_s3_config() -> Option<S3Config> {
    let Ok(endpoint) = std::env::var(ENDPOINT_ENV) else {
        eprintln!("skipping: {ENDPOINT_ENV} not set");
        return None;
    };
    let bucket = std::env::var(BUCKET_ENV).unwrap_or_else(|_| DEFAULT_BUCKET.to_string());

    Some(S3Config {
        bucket,
        region: Some(REGION.to_string()),
        endpoint: Some(endpoint),
        path_prefix: Some(format!("s3-recovery-test/{}", Uuid::new_v4())),
        credentials: Some(S3Credentials {
            access_key_id: "test".to_string(),
            secret_access_key: "test".to_string(),
            session_token: None,
        }),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        replication: None,
    })
}

/// A raw SDK client for the same endpoint, used to prepare the bucket, to inspect the
/// objects behind the back of `S3ClientWrapper` and to corrupt them.
async fn sdk_client(s3_config: &S3Config) -> SdkClient {
    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .endpoint_url(
            s3_config
                .endpoint
                .clone()
                .expect("Test S3 config has no endpoint"),
        )
        .region(Region::new(REGION))
        .credentials_provider(Credentials::new("test", "test", None, None, "kubidm-test"))
        .load()
        .await;
    SdkClient::from_conf(
        aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(true)
            .build(),
    )
}

async fn ensure_bucket(sdk: &SdkClient, bucket: &str) {
    if sdk.head_bucket().bucket(bucket).send().await.is_ok() {
        return;
    }
    sdk.create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("Failed to create the test bucket");
}

/// Every object key below `prefix`, with the prefix stripped, sorted.
async fn raw_object_keys(sdk: &SdkClient, s3_config: &S3Config) -> Vec<String> {
    let prefix = s3_config
        .path_prefix
        .clone()
        .expect("Test S3 config has no prefix");
    let output = sdk
        .list_objects_v2()
        .bucket(&s3_config.bucket)
        .prefix(format!("{prefix}/"))
        .send()
        .await
        .expect("Failed to list objects");
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

fn full_key(s3_config: &S3Config, key: &str) -> String {
    let prefix = s3_config
        .path_prefix
        .as_deref()
        .expect("Test S3 config has no prefix");
    format!("{prefix}/{key}")
}

#[test]
fn test_s3_backup_retention_verify_and_restore() {
    let Some(s3_config) = test_s3_config() else {
        return;
    };

    run(async {
        let sdk = sdk_client(&s3_config).await;
        ensure_bucket(&sdk, &s3_config.bucket).await;

        let workdir = tempfile::tempdir().expect("Failed to create workdir");

        // a. Three backups through the production S3 backup path with a retention of two
        //    must leave exactly the two newest backups and their metadata sidecars.
        let mut env = start_server(&workdir.path().join("source.db")).await;
        populate(&env).await;

        for round in 0..3 {
            if round > 0 {
                // Backup keys carry the timestamp; make sure they differ.
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
            env.core_handle
                .trigger_s3_backup(
                    s3_config.clone(),
                    RETAINED_VERSIONS,
                    BackupCompression::Gzip,
                )
                .await
                .expect("S3 backup failed");
        }

        let client = S3ClientWrapper::new(s3_config.clone())
            .await
            .expect("Failed to create the S3 client");
        let mut backups = client.list_backups().await.expect("Failed to list backups");
        backups.sort();
        assert_eq!(
            backups.len(),
            RETAINED_VERSIONS,
            "Retention must keep exactly {RETAINED_VERSIONS} backups, found {backups:?}"
        );
        for key in &backups {
            assert!(
                key.starts_with("backup-") && key.ends_with(".json.gz"),
                "Unexpected backup key {key}"
            );
            assert!(
                !key.ends_with(".metadata.json"),
                "Listing must not contain metadata sidecars, found {key}"
            );
        }

        // Behind the scenes: the two backups, their two sidecars and nothing else. The
        // sidecar of the pruned backup must have been removed with it.
        let raw_keys = raw_object_keys(&sdk, &s3_config).await;
        let expected_raw: Vec<String> = {
            let mut keys: Vec<String> = backups
                .iter()
                .flat_map(|key| [key.clone(), format!("{key}.metadata.json")])
                .collect();
            keys.sort();
            keys
        };
        assert_eq!(
            raw_keys, expected_raw,
            "Unexpected objects under the prefix"
        );

        let newest = backups.last().expect("No backups").clone();

        // b. The stored object matches its recorded size and checksum.
        assert!(
            client
                .verify_backup(&newest)
                .await
                .expect("verify_backup failed"),
            "A freshly uploaded backup must verify"
        );

        env.core_handle.shutdown().await;

        // c. verify-s3 at the full level passes and never touches the configured database.
        let untouched_db = workdir.path().join("untouched.db");
        assert!(
            verify_s3_backup_server_core(
                &config_with_db(&untouched_db),
                s3_config.clone(),
                &newest,
                BackupVerifyLevel::Full,
            )
            .await,
            "Full verification of the newest S3 backup must pass"
        );
        assert!(
            !untouched_db.exists(),
            "Verification must not touch the configured database"
        );

        // d. restore-s3 into an empty database yields a functional server with the state.
        let restored_db = workdir.path().join("restored.db");
        restore_s3_database(&config_with_db(&restored_db), s3_config.clone(), &newest)
            .await
            .expect("Restore from S3 failed");
        assert!(restored_db.exists(), "Restore did not create the database");

        let mut env = start_server(&restored_db).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        assert_directory_state_restored(&env.rsclient).await;
        env.core_handle.shutdown().await;

        // e. Corrupt the newest object while keeping its size and its sidecar. The size
        //    pre-check then passes and only the checksum can reveal the corruption.
        let metadata = client
            .get_backup_metadata(&newest)
            .await
            .expect("Failed to read the backup metadata");
        let corrupted = vec![b'x'; metadata.size_bytes as usize];
        sdk.put_object()
            .bucket(&s3_config.bucket)
            .key(full_key(&s3_config, &newest))
            .body(ByteStream::from(corrupted))
            .send()
            .await
            .expect("Failed to overwrite the backup object");

        assert!(
            !client
                .verify_backup(&newest)
                .await
                .expect("verify_backup failed on the corrupted object"),
            "verify_backup must report the corrupted object"
        );
        assert!(
            matches!(
                client.download_backup(&newest).await,
                Err(S3BackupError::InvalidChecksum { .. })
            ),
            "download_backup must reject the corrupted object"
        );

        let corrupt_target_db = workdir.path().join("corrupt-target.db");
        assert!(
            restore_s3_database(
                &config_with_db(&corrupt_target_db),
                s3_config.clone(),
                &newest
            )
            .await
            .is_err(),
            "Restoring a corrupted object must fail"
        );
        assert!(
            !corrupt_target_db.exists(),
            "A failed restore must not create the target database"
        );
        assert!(
            !verify_s3_backup_server_core(
                &config_with_db(&corrupt_target_db),
                s3_config.clone(),
                &newest,
                BackupVerifyLevel::Structural,
            )
            .await,
            "verify-s3 must fail on the corrupted object"
        );
        assert!(!corrupt_target_db.exists());
    });
}
