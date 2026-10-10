//! End to end tests for backup verification and restore.
//!
//! These tests only use production code paths. An online backup is taken from a running
//! server, checked with the `kubidmd database verify-backup` logic, restored with the
//! `kubidmd database restore` logic into an empty database, and that database is then
//! booted as a server again and exercised.

use std::path::{Path, PathBuf};

use kubidm_proto::backup::{BackupCompression, BackupEncryptionConfig};
use kubidmd_core::backup::{is_backup_artifact_name, INVALID_BACKUP_SUFFIX};
use kubidmd_core::config::Configuration;
use kubidmd_core::{
    restore_database, verify_backup_server_core, verify_booted_database, BackupVerifyLevel,
};
use kubidmd_lib::be::verify_backup_structure;
use kubidmd_testkit::{
    login_put_admin_idm_admins, AsyncTestEnvironment, NOT_ADMIN_TEST_PASSWORD,
    NOT_ADMIN_TEST_USERNAME, TEST_INTEGRATION_RS_ID,
};
use serde_json::Value;

use super::backup_common::{
    anonymous_client, assert_directory_state_restored, config_with_db, populate, run, start_server,
    BACKUP_RECYCLED_GROUP, BACKUP_USER_ALICE,
};

/// Take an online backup through the production online backup path and return it.
async fn backup_via_production_path(env: &AsyncTestEnvironment, backup_dir: &Path) -> PathBuf {
    env.core_handle
        .trigger_online_backup(
            backup_dir,
            1,
            BackupCompression::NoCompression,
            &BackupEncryptionConfig::default(),
        )
        .await
        .expect("Online backup failed");

    let mut backups: Vec<PathBuf> = std::fs::read_dir(backup_dir)
        .expect("Failed to read backup directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    assert_eq!(backups.len(), 1, "Expected exactly one backup artifact");
    backups.pop().expect("Backup artifact is missing")
}

/// Start a server, populate it, back it up through the production path and shut it down.
/// Returns the backup and the session token of the test user.
async fn populated_backup(workdir: &Path) -> (PathBuf, String) {
    let backup_dir = workdir.join("backups");
    std::fs::create_dir(&backup_dir).expect("Failed to create backup directory");

    let mut env = start_server(&workdir.join("source.db")).await;
    let user_token = populate(&env).await;
    let backup = backup_via_production_path(&env, &backup_dir).await;
    env.core_handle.shutdown().await;

    (backup, user_token)
}

/// The online backup verifies every artifact right after writing it. A backup that passed
/// keeps its name (a rejected one is renamed with `.invalid`) and reads back with the same
/// structural checks as `verify-backup --level structural`.
fn assert_backup_verified_after_write(backup: &Path, compression: BackupCompression) {
    let file_name = backup
        .file_name()
        .and_then(|name| name.to_str())
        .expect("Backup has no file name");
    assert!(
        !file_name.ends_with(INVALID_BACKUP_SUFFIX),
        "A backup that passed verification must keep its name: {file_name}"
    );
    assert!(
        is_backup_artifact_name(file_name),
        "A verified backup must be retained by retention: {file_name}"
    );
    assert!(
        file_name.ends_with(&format!(".json{}", compression.suffix())),
        "Backup name must carry the compression suffix: {file_name}"
    );

    let report = verify_backup_structure(
        std::fs::File::open(backup).expect("Failed to open backup"),
        compression,
    )
    .expect("A verified backup must parse");
    assert!(
        report.is_valid(),
        "A verified backup must pass structural checks: {:?}",
        report.errors
    );
    assert_eq!(report.version.as_deref(), Some(env!("KUBIDM_PKG_SERIES")));

    // The entry count reported by verification is the number of entries in the artifact.
    let raw = std::fs::read(backup).expect("Failed to read backup");
    let document: Value = match compression {
        BackupCompression::NoCompression => serde_json::from_slice(&raw),
        BackupCompression::Gzip => serde_json::from_reader(flate2::read::GzDecoder::new(&raw[..])),
    }
    .expect("Backup is not JSON");
    let entries = document
        .get("entries")
        .and_then(Value::as_array)
        .expect("Backup has no entries");
    assert_eq!(report.entry_count, entries.len());
    assert!(report.entry_count > 0);
}

/// Happy path of the post-write verification of online backups: a production backup, plain
/// and gzip, keeps its retention-matching name and reads back structurally valid with the
/// entry count it carries. Fault injection (garbage, compression mismatch, unrestorable
/// content, quarantine naming) is covered by the `kubidmd_core::backup::finalize` unit
/// tests, since the backend can not be made to emit a broken artifact from here.
#[test]
fn test_online_backup_keeps_verified_artifact_name_and_structure() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let mut env = start_server(&workdir.path().join("source.db")).await;
        populate(&env).await;

        for compression in [BackupCompression::NoCompression, BackupCompression::Gzip] {
            let backup_dir = workdir
                .path()
                .join(format!("backups{}", compression.suffix()));
            std::fs::create_dir(&backup_dir).expect("Failed to create backup directory");

            env.core_handle
                .trigger_online_backup(
                    &backup_dir,
                    1,
                    compression,
                    &BackupEncryptionConfig::default(),
                )
                .await
                .expect("Online backup failed");

            let artifacts: Vec<PathBuf> = std::fs::read_dir(&backup_dir)
                .expect("Failed to read backup directory")
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect();
            assert_eq!(artifacts.len(), 1, "Expected exactly one backup artifact");
            assert_backup_verified_after_write(&artifacts[0], compression);
        }

        env.core_handle.shutdown().await;
    });
}

#[test]
fn test_backup_verify_passes_for_production_backup() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let (backup, _) = populated_backup(workdir.path()).await;

        // Verification is handed the server's configuration. The database that
        // configuration points at must never be created or modified by it.
        let untouched_db = workdir.path().join("untouched.db");
        let config = config_with_db(&untouched_db);

        assert!(
            verify_backup_server_core(&config, &backup, BackupVerifyLevel::Structural).await,
            "Structural verification must pass for a production backup"
        );
        assert!(
            verify_backup_server_core(&config, &backup, BackupVerifyLevel::Full).await,
            "Full verification must pass for a production backup"
        );
        assert!(
            !untouched_db.exists(),
            "Verification must not touch the configured database"
        );
    });
}

#[test]
fn test_backup_verify_detects_unrestorable_backup() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let (backup, _) = populated_backup(workdir.path()).await;

        // Strip the uuid from one entry. The artifact still parses as a backup, so it is
        // structurally valid, but the entry can no longer be loaded by a restore.
        let mut document: Value =
            serde_json::from_slice(&std::fs::read(&backup).expect("Failed to read backup"))
                .expect("Backup is not JSON");
        let entries = document
            .get_mut("entries")
            .and_then(Value::as_array_mut)
            .expect("Backup has no entries");
        let alice = entries
            .iter_mut()
            .filter_map(|entry| entry.pointer_mut("/ent/V3/attrs"))
            .filter_map(Value::as_object_mut)
            .find(|attrs| {
                attrs
                    .get("name")
                    .map(|name| name.to_string().contains(BACKUP_USER_ALICE))
                    .unwrap_or(false)
            })
            .expect("Alice is not in the backup");
        alice.remove("uuid").expect("Alice has no uuid");

        let corrupted = workdir.path().join("corrupted.json");
        std::fs::write(
            &corrupted,
            serde_json::to_vec(&document).expect("Failed to serialise backup"),
        )
        .expect("Failed to write corrupted backup");

        let config = Configuration::new_for_test();
        assert!(
            verify_backup_server_core(&config, &corrupted, BackupVerifyLevel::Structural).await,
            "Structural verification can not see entry level corruption"
        );
        assert!(
            !verify_backup_server_core(&config, &corrupted, BackupVerifyLevel::Full).await,
            "Full verification must detect the unrestorable entry"
        );
    });
}

#[test]
fn test_backup_verify_rejects_invalid_artifacts() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let config = Configuration::new_for_test();

        let missing = workdir.path().join("missing.json");
        assert!(
            !verify_backup_server_core(&config, &missing, BackupVerifyLevel::Structural).await,
            "A missing artifact must fail verification"
        );

        let garbage = workdir.path().join("garbage.json");
        std::fs::write(&garbage, b"this is not a backup").expect("Failed to write garbage");
        assert!(
            !verify_backup_server_core(&config, &garbage, BackupVerifyLevel::Structural).await,
            "Unparseable data must fail structural verification"
        );
        assert!(
            !verify_backup_server_core(&config, &garbage, BackupVerifyLevel::Full).await,
            "Unparseable data must fail full verification"
        );

        // A V1 backup carries neither a version marker nor, here, any entries. It parses
        // but can never be restored by this server.
        let empty = workdir.path().join("empty.json");
        std::fs::write(&empty, b"[]").expect("Failed to write empty backup");
        assert!(
            !verify_backup_server_core(&config, &empty, BackupVerifyLevel::Structural).await,
            "An empty, versionless backup must fail structural verification"
        );
    });
}

#[test]
fn test_backup_restore_boots_functional_server() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let (backup, user_token) = populated_backup(workdir.path()).await;

        // Restore through the production restore path into an empty database.
        let restored_db = workdir.path().join("restored.db");
        restore_database(&config_with_db(&restored_db), &backup)
            .await
            .expect("Restore failed");
        assert!(restored_db.exists(), "Restore did not create the database");

        // Boot the restored database as a server and exercise it.
        let mut env = start_server(&restored_db).await;
        let rsclient = &env.rsclient;
        login_put_admin_idm_admins(rsclient).await;

        assert_directory_state_restored(rsclient).await;

        // OAuth2 client state.
        let oauth2 = rsclient
            .idm_oauth2_rs_get(TEST_INTEGRATION_RS_ID)
            .await
            .expect("Failed to get oauth2 client")
            .expect("OAuth2 client did not survive the restore");
        assert!(
            oauth2.attrs.contains_key("oauth2_rs_origin"),
            "OAuth2 client lost its origin"
        );

        // Recycled state.
        let recycled = rsclient
            .recycle_bin_list()
            .await
            .expect("Failed to list the recycle bin");
        assert!(
            recycled.iter().any(|entry| {
                entry
                    .attrs
                    .get("name")
                    .map(|names| names.iter().any(|name| name == BACKUP_RECYCLED_GROUP))
                    .unwrap_or(false)
            }),
            "Recycled group did not survive the restore"
        );

        // The backed up credential must authenticate against the restored server.
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

        // The session established before the backup is part of the backed up state, so
        // its token must still be accepted by the restored server.
        let session_client = anonymous_client(&env);
        session_client.set_token(user_token).await;
        assert!(session_client
            .whoami()
            .await
            .expect("Pre-backup session was rejected by the restored server")
            .is_some());

        env.core_handle.shutdown().await;

        // Finally the restored database, now that a server has booted from it, must pass
        // the full consistency verification.
        let errors = verify_booted_database(&config_with_db(&restored_db))
            .await
            .expect("Restored database could not be opened");
        assert!(
            errors.is_empty(),
            "Restored database has consistency errors: {errors:?}"
        );
    });
}
