//! End to end tests of client-side backup encryption.
//!
//! Only production code paths are used: a server configured with `[online_backup.encryption]`
//! takes an online backup, the artifact is checked to be really encrypted, verified with the
//! `kubidmd database verify-backup` logic, restored with the `kubidmd database restore`
//! logic into an empty database, and that database is booted as a server again. Restores
//! without the key, with a wrong key and with a mismatching key identifier must fail
//! cleanly and leave the target database untouched.
//!
//! The S3 variant needs an S3-compatible service; see `backup_common` for how it is found,
//! when it is skipped and how to run it locally.

use std::io::Read;
use std::path::{Path, PathBuf};

use kubidm_proto::backup::{
    is_encrypted_backup_name, BackupCompression, BackupEncryptionConfig, EncryptionKeySource,
    KeyDerivationParams,
};
use kubidmd_core::backup::{
    backup_identity, is_backup_artifact_name, is_encrypted_artifact, open_backup_file_with_config,
    read_encryption_header, BackupEncryptionError, BackupEncryptor, BackupOpenError,
    S3ClientWrapper, MIN_KDF_M_COST,
};
use kubidmd_core::config::{Configuration, OnlineBackup};
use kubidmd_core::{
    restore_database, restore_s3_database, verify_backup_server_core, verify_booted_database,
    verify_s3_backup_server_core, BackupVerifyLevel,
};
use kubidmd_testkit::{
    login_put_admin_idm_admins, NOT_ADMIN_TEST_PASSWORD, NOT_ADMIN_TEST_USERNAME,
};
use serde_json::Value;

use super::backup_common::{
    anonymous_client, assert_directory_state_restored, backup_via_production_path, config_with_db,
    delete_prefix, ensure_bucket, object_keys, populate, run, sdk_client, start_server,
    test_s3_config, BACKUP_USER_ALICE,
};

const PASSPHRASE: &str = "e2e backup passphrase, long enough to matter";
const WRONG_PASSPHRASE: &str = "not the passphrase the backup was made with";
const KEY_ID: &str = "e2e-backup-key";

/// The cheapest key derivation the server accepts, so that the tests spend their time on
/// the backup paths rather than on Argon2.
fn fast_kdf() -> KeyDerivationParams {
    KeyDerivationParams {
        m_cost: MIN_KDF_M_COST,
        t_cost: 1,
        p_cost: 1,
    }
}

/// Encryption with the passphrase read from a file.
fn file_passphrase_encryption(
    passphrase_file: &Path,
    key_identifier: Option<&str>,
) -> BackupEncryptionConfig {
    BackupEncryptionConfig {
        enabled: true,
        key_source: EncryptionKeySource::Passphrase,
        key_derivation: fast_kdf(),
        key_identifier: key_identifier.map(str::to_string),
        passphrase_file: Some(passphrase_file.to_path_buf()),
    }
}

fn write_passphrase(workdir: &Path, name: &str, passphrase: &str) -> PathBuf {
    let path = workdir.join(name);
    std::fs::write(&path, format!("{passphrase}\n")).expect("Failed to write the passphrase");
    path
}

/// The configuration a restore or verification host runs with: the database to restore
/// into and the `[online_backup.encryption]` section that names the key. The online backup
/// task itself is disabled, as it is on a host that only restores.
fn config_with_encryption(db_path: &Path, encryption: BackupEncryptionConfig) -> Configuration {
    let mut config = config_with_db(db_path);
    config.online_backup = Some(OnlineBackup {
        enabled: false,
        encryption,
        ..OnlineBackup::default()
    });
    config
}

/// The artifact is named as an encrypted backup, is recognised by retention, and its bytes
/// are an encrypted container that is neither JSON nor gzip and leaks no directory content.
fn assert_really_encrypted(artifact: &Path, compression: BackupCompression, key_id: &str) {
    let file_name = artifact
        .file_name()
        .and_then(|name| name.to_str())
        .expect("Backup has no file name");
    assert!(
        is_encrypted_backup_name(file_name),
        "An encrypted backup must carry the .enc suffix: {file_name}"
    );
    assert!(
        file_name.ends_with(&format!(".json{}.enc", compression.suffix())),
        "The compression suffix must precede the encryption suffix: {file_name}"
    );
    assert!(
        is_backup_artifact_name(file_name),
        "An encrypted backup must be retained by retention: {file_name}"
    );
    assert_eq!(BackupCompression::identify_file(artifact), compression);

    let raw = std::fs::read(artifact).expect("Failed to read backup");
    assert!(
        is_encrypted_artifact(&raw),
        "The artifact must start with the container magic"
    );
    let (header, _) = read_encryption_header(&raw).expect("The header must parse");
    assert_eq!(header.key_identifier, key_id);
    assert_eq!(header.compressed, compression == BackupCompression::Gzip);

    assert!(
        serde_json::from_slice::<Value>(&raw).is_err(),
        "An encrypted artifact must not be valid JSON"
    );
    let mut inflated = Vec::new();
    assert!(
        flate2::read::GzDecoder::new(&raw[..])
            .read_to_end(&mut inflated)
            .is_err(),
        "An encrypted artifact must not be valid gzip"
    );
    for needle in ["\"entries\"", BACKUP_USER_ALICE, NOT_ADMIN_TEST_USERNAME] {
        assert!(
            !raw.windows(needle.len())
                .any(|window| window == needle.as_bytes()),
            "The artifact leaks plaintext: {needle}"
        );
    }
}

/// Start a server, populate it, take an encrypted backup with the given settings and shut
/// the server down. Returns the artifact and the session token of the test user.
async fn populated_encrypted_backup(
    workdir: &Path,
    compression: BackupCompression,
    encryption: &BackupEncryptionConfig,
) -> (PathBuf, String) {
    let mut env = start_server(&workdir.join("source.db")).await;
    let user_token = populate(&env).await;
    let backup =
        backup_via_production_path(&env, &workdir.join("backups"), compression, encryption).await;
    env.core_handle.shutdown().await;
    (backup, user_token)
}

#[test]
fn test_encrypted_online_backup_verifies_and_restores_a_functional_server() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let passphrase = write_passphrase(workdir.path(), "passphrase", PASSPHRASE);
        let encryption = file_passphrase_encryption(&passphrase, Some(KEY_ID));

        // Both compressions produce a correctly named, really encrypted artifact.
        {
            let mut env = start_server(&workdir.path().join("compressions.db")).await;
            populate(&env).await;
            for compression in [BackupCompression::NoCompression, BackupCompression::Gzip] {
                let backup = backup_via_production_path(
                    &env,
                    &workdir
                        .path()
                        .join(format!("compressions{}", compression.suffix())),
                    compression,
                    &encryption,
                )
                .await;
                assert_really_encrypted(&backup, compression, KEY_ID);
            }
            env.core_handle.shutdown().await;
        }

        let (backup, user_token) =
            populated_encrypted_backup(workdir.path(), BackupCompression::Gzip, &encryption).await;
        assert_really_encrypted(&backup, BackupCompression::Gzip, KEY_ID);

        // verify-backup decrypts transparently with the configured key and never touches
        // the configured database.
        let untouched_db = workdir.path().join("untouched.db");
        let verify_config = config_with_encryption(&untouched_db, encryption.clone());
        assert!(
            verify_backup_server_core(&verify_config, &backup, BackupVerifyLevel::Structural).await,
            "Structural verification of an encrypted backup must pass with the key"
        );
        assert!(
            verify_backup_server_core(&verify_config, &backup, BackupVerifyLevel::Full).await,
            "Full verification of an encrypted backup must pass with the key"
        );
        assert!(
            !untouched_db.exists(),
            "Verification must not touch the configured database"
        );

        // restore decrypts transparently into an empty database.
        let restored_db = workdir.path().join("restored.db");
        restore_database(
            &config_with_encryption(&restored_db, encryption.clone()),
            &backup,
        )
        .await
        .expect("Restore of an encrypted backup failed");
        assert!(restored_db.exists(), "Restore did not create the database");

        // The restored database boots a functional server with the backed up state.
        let mut env = start_server(&restored_db).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        assert_directory_state_restored(&env.rsclient).await;

        let user_client = anonymous_client(&env);
        user_client
            .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
            .await
            .expect("Backed up credential was rejected by the restored server");
        assert!(user_client
            .whoami()
            .await
            .expect("whoami failed on the restored server")
            .is_some());

        let session_client = anonymous_client(&env);
        session_client.set_token(user_token).await;
        assert!(session_client
            .whoami()
            .await
            .expect("Pre-backup session was rejected by the restored server")
            .is_some());

        env.core_handle.shutdown().await;

        let errors = verify_booted_database(&config_with_db(&restored_db))
            .await
            .expect("Restored database could not be opened");
        assert!(
            errors.is_empty(),
            "Restored database has consistency errors: {errors:?}"
        );
    });
}

#[test]
fn test_encrypted_backup_is_refused_without_the_right_key() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let right = write_passphrase(workdir.path(), "passphrase", PASSPHRASE);
        let wrong = write_passphrase(workdir.path(), "wrong-passphrase", WRONG_PASSPHRASE);
        let encryption = file_passphrase_encryption(&right, Some(KEY_ID));

        let (backup, _) =
            populated_encrypted_backup(workdir.path(), BackupCompression::Gzip, &encryption).await;
        assert_really_encrypted(&backup, BackupCompression::Gzip, KEY_ID);

        // The right key works: this is the control for the failures below.
        let control_db = workdir.path().join("control.db");
        restore_database(&config_with_encryption(&control_db, encryption), &backup)
            .await
            .expect("Restore with the right passphrase failed");
        assert!(control_db.exists());

        // Without encryption configured at all.
        let plain_config = config_with_db(&workdir.path().join("no-encryption.db"));
        match open_backup_file_with_config(&backup, None).await {
            Err(BackupOpenError::EncryptedWithoutKey { key_identifier }) => {
                assert_eq!(key_identifier, KEY_ID, "The error must name the key")
            }
            other => panic!("Expected EncryptedWithoutKey, got {other:?}"),
        }
        assert!(
            restore_database(&plain_config, &backup).await.is_err(),
            "Restore without encryption configured must fail"
        );
        assert!(
            !verify_backup_server_core(&plain_config, &backup, BackupVerifyLevel::Structural).await,
            "Verification without encryption configured must fail"
        );
        assert!(
            !verify_backup_server_core(&plain_config, &backup, BackupVerifyLevel::Full).await,
            "Full verification without encryption configured must fail"
        );
        assert!(
            !workdir.path().join("no-encryption.db").exists(),
            "A failed restore must not create the target database"
        );

        // With encryption explicitly disabled.
        let disabled_config = config_with_encryption(
            &workdir.path().join("disabled.db"),
            BackupEncryptionConfig::default(),
        );
        assert!(matches!(
            open_backup_file_with_config(&backup, Some(&BackupEncryptionConfig::default())).await,
            Err(BackupOpenError::EncryptedWithoutKey { .. })
        ));
        assert!(restore_database(&disabled_config, &backup).await.is_err());
        assert!(!workdir.path().join("disabled.db").exists());

        // With a wrong passphrase.
        let wrong_encryption = file_passphrase_encryption(&wrong, Some(KEY_ID));
        match open_backup_file_with_config(&backup, Some(&wrong_encryption)).await {
            Err(BackupOpenError::Decrypt(BackupEncryptionError::DecryptionFailed {
                artifact_key,
                configured_key,
            })) => {
                assert_eq!(artifact_key, KEY_ID);
                assert_eq!(configured_key, KEY_ID);
            }
            other => panic!("Expected DecryptionFailed, got {other:?}"),
        }
        let wrong_db = workdir.path().join("wrong-passphrase.db");
        let wrong_config = config_with_encryption(&wrong_db, wrong_encryption);
        assert!(
            restore_database(&wrong_config, &backup).await.is_err(),
            "Restore with a wrong passphrase must fail"
        );
        assert!(
            !verify_backup_server_core(&wrong_config, &backup, BackupVerifyLevel::Full).await,
            "Verification with a wrong passphrase must fail"
        );
        assert!(!wrong_db.exists());

        // With the right passphrase but a key identifier that does not match the artifact.
        let other_id = file_passphrase_encryption(&right, Some("rotated-key"));
        match open_backup_file_with_config(&backup, Some(&other_id)).await {
            Err(BackupOpenError::Decrypt(BackupEncryptionError::KeyIdentifierMismatch {
                artifact_key,
                configured_key,
            })) => {
                assert_eq!(artifact_key, KEY_ID);
                assert_eq!(configured_key, "rotated-key");
            }
            other => panic!("Expected KeyIdentifierMismatch, got {other:?}"),
        }
        let mismatch_db = workdir.path().join("mismatch.db");
        assert!(
            restore_database(&config_with_encryption(&mismatch_db, other_id), &backup)
                .await
                .is_err()
        );
        assert!(!mismatch_db.exists());

        // With the right passphrase and no key identifier configured: the key is simply
        // tried, and the artifact keeps the identifier it was written with.
        let unnamed = file_passphrase_encryption(&right, None);
        let opened = open_backup_file_with_config(&backup, Some(&unnamed))
            .await
            .expect("The right passphrase must open the artifact without a key_identifier");
        assert_eq!(opened.key_identifier(), Some(KEY_ID));

        // With the right key, but the valid backup copied over the name of a newer one: it
        // is not the backup that name claims, so restoring it would silently roll back.
        let replayed = backup.with_file_name("backup-2099-06-01T00:00:00Z.json.gz.enc");
        std::fs::copy(&backup, &replayed).expect("Failed to copy the backup");
        match open_backup_file_with_config(&replayed, Some(&unnamed)).await {
            Err(BackupOpenError::Decrypt(BackupEncryptionError::ArtifactMismatch {
                expected,
                recorded,
            })) => {
                assert_eq!(expected, backup_identity(&replayed));
                assert_eq!(recorded, backup_identity(&backup));
            }
            other => panic!("Expected ArtifactMismatch, got {other:?}"),
        }
        let replayed_db = workdir.path().join("replayed.db");
        let replayed_config = config_with_encryption(&replayed_db, unnamed);
        assert!(
            restore_database(&replayed_config, &replayed).await.is_err(),
            "Restore of an older backup under a newer name must fail"
        );
        assert!(
            !verify_backup_server_core(&replayed_config, &replayed, BackupVerifyLevel::Full).await,
            "Verification of an older backup under a newer name must fail"
        );
        assert!(!replayed_db.exists());
    });
}

#[test]
fn test_encrypted_s3_backup_verify_and_restore() {
    let Some(s3_config) = test_s3_config("s3-encryption-test") else {
        return;
    };

    run(async {
        let sdk = sdk_client(&s3_config).await;
        ensure_bucket(&sdk, &s3_config.bucket).await;

        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let right = write_passphrase(workdir.path(), "passphrase", PASSPHRASE);
        let wrong = write_passphrase(workdir.path(), "wrong-passphrase", WRONG_PASSPHRASE);
        let encryption = file_passphrase_encryption(&right, Some(KEY_ID));

        // An encrypted backup through the production S3 backup path.
        let mut env = start_server(&workdir.path().join("source.db")).await;
        populate(&env).await;
        env.core_handle
            .trigger_s3_backup(s3_config.clone(), 2, BackupCompression::Gzip, &encryption)
            .await
            .expect("Encrypted S3 backup failed");
        env.core_handle.shutdown().await;

        let client = S3ClientWrapper::new(s3_config.clone())
            .await
            .expect("Failed to create the S3 client");
        let backups = client.list_backups().await.expect("Failed to list backups");
        assert_eq!(
            backups.len(),
            1,
            "Expected exactly one backup, found {backups:?}"
        );
        let key = backups[0].clone();
        assert!(
            key.starts_with("backup-") && key.ends_with(".json.gz.enc"),
            "An encrypted S3 backup must carry the .enc suffix: {key}"
        );
        assert!(is_backup_artifact_name(&key));
        assert_eq!(
            object_keys(&sdk, &s3_config).await,
            vec![key.clone(), format!("{key}.metadata.json")],
            "The artifact and its sidecar, nothing else"
        );

        // The sidecar says encrypted and names the key; the object is really encrypted.
        let metadata = client
            .get_backup_metadata(&key)
            .await
            .expect("Failed to read the backup metadata");
        assert!(metadata.encrypted, "The sidecar must record the encryption");
        assert_eq!(metadata.key_identifier.as_deref(), Some(KEY_ID));
        assert_eq!(metadata.compression, BackupCompression::Gzip);

        let (raw, _) = client
            .download_backup(&key)
            .await
            .expect("Failed to download the backup");
        assert_eq!(raw.len() as u64, metadata.size_bytes);
        assert!(is_encrypted_artifact(&raw));
        let (header, _) = read_encryption_header(&raw).expect("The header must parse");
        assert_eq!(header.key_identifier, KEY_ID);
        assert!(header.compressed);
        assert!(serde_json::from_slice::<Value>(&raw).is_err());

        // verify-s3 and restore-s3 succeed with the key.
        let untouched_db = workdir.path().join("untouched.db");
        assert!(
            verify_s3_backup_server_core(
                &config_with_encryption(&untouched_db, encryption.clone()),
                s3_config.clone(),
                &key,
                BackupVerifyLevel::Full,
            )
            .await,
            "Full verification of the encrypted S3 backup must pass with the key"
        );
        assert!(!untouched_db.exists());

        let restored_db = workdir.path().join("restored.db");
        restore_s3_database(
            &config_with_encryption(&restored_db, encryption.clone()),
            s3_config.clone(),
            &key,
        )
        .await
        .expect("Restore of the encrypted S3 backup failed");
        assert!(restored_db.exists());

        let mut env = start_server(&restored_db).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        assert_directory_state_restored(&env.rsclient).await;
        env.core_handle.shutdown().await;

        // Without the key, and with a wrong key, they fail and leave the database alone.
        let no_key_db = workdir.path().join("no-key.db");
        assert!(
            !verify_s3_backup_server_core(
                &config_with_db(&no_key_db),
                s3_config.clone(),
                &key,
                BackupVerifyLevel::Structural,
            )
            .await,
            "verify-s3 must fail without the key"
        );
        assert!(
            restore_s3_database(&config_with_db(&no_key_db), s3_config.clone(), &key)
                .await
                .is_err(),
            "restore-s3 must fail without the key"
        );
        assert!(!no_key_db.exists());

        let wrong_db = workdir.path().join("wrong-key.db");
        let wrong_config =
            config_with_encryption(&wrong_db, file_passphrase_encryption(&wrong, Some(KEY_ID)));
        assert!(
            !verify_s3_backup_server_core(
                &wrong_config,
                s3_config.clone(),
                &key,
                BackupVerifyLevel::Full,
            )
            .await,
            "verify-s3 must fail with a wrong passphrase"
        );
        assert!(
            restore_s3_database(&wrong_config, s3_config.clone(), &key)
                .await
                .is_err(),
            "restore-s3 must fail with a wrong passphrase"
        );
        assert!(!wrong_db.exists());

        // Someone with write access to the bucket swaps the encrypted backup for a plain
        // one under an encrypted name, with a consistent sidecar that says "not
        // encrypted". The plain backup is a perfectly valid backup, so only the name
        // check stands between it and the restore.
        let opener = BackupEncryptor::from_config(&encryption)
            .await
            .expect("Failed to resolve the key")
            .expect("Encryption is enabled");
        let (plaintext, _) = opener
            .decrypt(&raw, &backup_identity(Path::new(&key)))
            .expect("Failed to decrypt the backup");
        let swapped_key = "backup-2099-01-01T00:00:00Z.json.gz.enc";
        client
            .upload_backup(
                &plaintext,
                swapped_key,
                "2099-01-01T00:00:00Z",
                BackupCompression::Gzip,
                None,
            )
            .await
            .expect("Failed to upload the swapped backup");
        assert!(
            !client
                .get_backup_metadata(swapped_key)
                .await
                .expect("Failed to read the swapped metadata")
                .encrypted
        );
        let swapped_db = workdir.path().join("swapped.db");
        let swapped_config = config_with_encryption(&swapped_db, encryption.clone());
        assert!(
            !verify_s3_backup_server_core(
                &swapped_config,
                s3_config.clone(),
                swapped_key,
                BackupVerifyLevel::Structural,
            )
            .await,
            "verify-s3 must refuse a plain artifact under an encrypted name"
        );
        assert!(
            restore_s3_database(&swapped_config, s3_config.clone(), swapped_key)
                .await
                .is_err(),
            "restore-s3 must refuse a plain artifact under an encrypted name"
        );
        assert!(!swapped_db.exists());

        // The same person stores the valid encrypted backup again under a newer key, with
        // a consistent sidecar. It decrypts with the key, but it is not the backup the key
        // claims, so it must not silently roll a restore back to the older state.
        let replayed_key = "backup-2099-06-01T00:00:00Z.json.gz.enc";
        client
            .upload_backup(
                &raw,
                replayed_key,
                "2099-06-01T00:00:00Z",
                BackupCompression::Gzip,
                Some(KEY_ID),
            )
            .await
            .expect("Failed to upload the replayed backup");
        let replayed_db = workdir.path().join("replayed.db");
        let replayed_config = config_with_encryption(&replayed_db, encryption.clone());
        assert!(
            !verify_s3_backup_server_core(
                &replayed_config,
                s3_config.clone(),
                replayed_key,
                BackupVerifyLevel::Structural,
            )
            .await,
            "verify-s3 must refuse an older backup stored under a newer key"
        );
        assert!(
            restore_s3_database(&replayed_config, s3_config.clone(), replayed_key)
                .await
                .is_err(),
            "restore-s3 must refuse an older backup stored under a newer key"
        );
        assert!(!replayed_db.exists());

        delete_prefix(&sdk, &s3_config).await;
    });
}
