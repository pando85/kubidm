//! End to end tests for backup verification and restore.
//!
//! These tests only use production code paths. An online backup is taken from a running
//! server, checked with the `kubidmd database verify-backup` logic, restored with the
//! `kubidmd database restore` logic into an empty database, and that database is then
//! booted as a server again and exercised.

use std::future::Future;
use std::path::{Path, PathBuf};

use kubidm_client::{KubidmClient, KubidmClientBuilder};
use kubidm_proto::backup::BackupCompression;
use kubidmd_core::config::Configuration;
use kubidmd_core::{
    restore_database, verify_backup_server_core, verify_booted_database, BackupVerifyLevel,
};
use kubidmd_testkit::{
    login_put_admin_idm_admins, setup_async_test, AsyncTestEnvironment, NOT_ADMIN_TEST_PASSWORD,
    NOT_ADMIN_TEST_USERNAME, TEST_INTEGRATION_RS_DISPLAY, TEST_INTEGRATION_RS_ID,
    TEST_INTEGRATION_RS_REDIRECT_URL, TEST_INTEGRATION_RS_URL,
};
use serde_json::Value;
use url::Url;

const BACKUP_TEST_GROUP: &str = "backup_test_group";
const BACKUP_ENGINEERS_GROUP: &str = "backup_engineers";
const BACKUP_RECYCLED_GROUP: &str = "backup_recycled_group";
const BACKUP_USER_ALICE: &str = "backup_user_alice";
const BACKUP_USER_BOB: &str = "backup_user_bob";

fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build the tokio runtime")
        .block_on(future)
}

/// A configuration for the test domain. Domain and origin must match the ones the backed up
/// server ran with, exactly as a production restore uses the server's own configuration.
fn config_with_db(db_path: &Path) -> Configuration {
    Configuration {
        db_path: Some(db_path.to_path_buf()),
        domain: "localhost".to_string(),
        origin: Url::parse("http://localhost").expect("Invalid origin"),
        ..Configuration::new_for_test()
    }
}

async fn start_server(db_path: &Path) -> AsyncTestEnvironment {
    setup_async_test(config_with_db(db_path)).await
}

/// A second, unauthenticated client for the server of `env`.
fn anonymous_client(env: &AsyncTestEnvironment) -> KubidmClient {
    KubidmClientBuilder::new()
        .address(format!("http://localhost:{}", env.http_sock_addr.port()))
        .enable_native_ca_roots(false)
        .no_proxy()
        .build()
        .expect("Failed to build client")
}

/// Group members are returned as SPNs such as `name@domain`.
fn has_member(members: &[String], name: &str) -> bool {
    members
        .iter()
        .any(|member| member == name || member.starts_with(&format!("{name}@")))
}

/// Populate the server with the state a realistic deployment carries: people with
/// credentials, static groups, an OAuth2 client, a recycled entry and a live user session.
/// Returns the session token of the test user.
async fn populate(env: &AsyncTestEnvironment) -> String {
    let rsclient = &env.rsclient;
    login_put_admin_idm_admins(rsclient).await;

    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("Failed to create test user");
    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("Failed to set test user password");
    rsclient
        .idm_person_account_create(BACKUP_USER_ALICE, "Alice")
        .await
        .expect("Failed to create alice");
    rsclient
        .idm_person_account_create(BACKUP_USER_BOB, "Bob")
        .await
        .expect("Failed to create bob");

    rsclient
        .idm_group_create(BACKUP_TEST_GROUP, None)
        .await
        .expect("Failed to create test group");
    rsclient
        .idm_group_add_members(BACKUP_TEST_GROUP, &[NOT_ADMIN_TEST_USERNAME])
        .await
        .expect("Failed to add member to test group");
    rsclient
        .idm_group_create(BACKUP_ENGINEERS_GROUP, None)
        .await
        .expect("Failed to create engineers group");
    rsclient
        .idm_group_add_members(
            BACKUP_ENGINEERS_GROUP,
            &[BACKUP_USER_ALICE, BACKUP_USER_BOB],
        )
        .await
        .expect("Failed to add members to engineers group");

    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("Failed to create oauth2 client");
    rsclient
        .idm_oauth2_client_add_origin(
            TEST_INTEGRATION_RS_ID,
            &Url::parse(TEST_INTEGRATION_RS_REDIRECT_URL).expect("Invalid redirect URL"),
        )
        .await
        .expect("Failed to add oauth2 origin");

    rsclient
        .idm_group_create(BACKUP_RECYCLED_GROUP, None)
        .await
        .expect("Failed to create recycled group");
    rsclient
        .idm_group_delete(BACKUP_RECYCLED_GROUP)
        .await
        .expect("Failed to delete recycled group");

    // Establish a session for the test user so that session state is part of the backup.
    let user_client = anonymous_client(env);
    user_client
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as the test user");
    user_client
        .get_token()
        .await
        .expect("Authenticated client has no token")
}

/// Take an online backup through the production online backup path and return it.
async fn backup_via_production_path(env: &AsyncTestEnvironment, backup_dir: &Path) -> PathBuf {
    env.core_handle
        .trigger_online_backup(backup_dir, 1, BackupCompression::NoCompression)
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

        for name in [NOT_ADMIN_TEST_USERNAME, BACKUP_USER_ALICE, BACKUP_USER_BOB] {
            let person = rsclient
                .idm_person_account_get(name)
                .await
                .expect("Failed to get person");
            assert!(
                person.is_some(),
                "Person {name} did not survive the restore"
            );
        }

        let members = rsclient
            .idm_group_get_members(BACKUP_TEST_GROUP)
            .await
            .expect("Failed to get test group members")
            .expect("Test group did not survive the restore");
        assert!(has_member(&members, NOT_ADMIN_TEST_USERNAME));

        let engineers = rsclient
            .idm_group_get_members(BACKUP_ENGINEERS_GROUP)
            .await
            .expect("Failed to get engineers members")
            .expect("Engineers group did not survive the restore");
        assert!(has_member(&engineers, BACKUP_USER_ALICE));
        assert!(has_member(&engineers, BACKUP_USER_BOB));

        // Dynamic group membership must be intact on the restored server. Dynamic
        // members are held in the dynmember attribute.
        let all_persons = rsclient
            .idm_group_get("idm_all_persons")
            .await
            .expect("Failed to get idm_all_persons")
            .expect("idm_all_persons did not survive the restore")
            .attrs
            .remove("dynmember")
            .expect("idm_all_persons has no dynamic members");
        for name in [NOT_ADMIN_TEST_USERNAME, BACKUP_USER_ALICE, BACKUP_USER_BOB] {
            assert!(
                has_member(&all_persons, name),
                "Dynamic group idm_all_persons is missing {name}"
            );
        }

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
