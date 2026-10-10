//! End to end test of the S3 backup and recovery path against a real S3 endpoint.
//!
//! The test needs an S3-compatible service; see `backup_common` for how it is found, when it
//! is skipped and how to run it locally.

use std::time::Duration;

use aws_sdk_s3::primitives::ByteStream;
use kubidm_proto::backup::{BackupCompression, BackupEncryptionConfig};
use kubidmd_core::backup::{S3BackupError, S3ClientWrapper};
use kubidmd_core::{restore_s3_database, verify_s3_backup_server_core, BackupVerifyLevel};
use kubidmd_testkit::login_put_admin_idm_admins;

use super::backup_common::{
    assert_directory_state_restored, config_with_db, delete_prefix, ensure_bucket, full_key,
    object_keys, populate, run, sdk_client, start_server, test_s3_config, with_sidecars,
};

const RETAINED_VERSIONS: usize = 2;

#[test]
fn test_s3_backup_retention_verify_and_restore() {
    let Some(s3_config) = test_s3_config("s3-recovery-test") else {
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
                    &BackupEncryptionConfig::default(),
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
        assert_eq!(
            object_keys(&sdk, &s3_config).await,
            with_sidecars(&backups),
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

        delete_prefix(&sdk, &s3_config).await;
    });
}
