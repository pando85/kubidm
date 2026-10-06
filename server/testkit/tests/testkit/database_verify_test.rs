//! End to end test for `kubidmd database verify` on a cold database.
//!
//! A server is started on a fresh database, populated, and shut down. The database is
//! then opened the way the `kubidmd database verify` command does, without booting a
//! server and without running the startup migrations, and must verify clean. The same
//! is checked for a database produced by restoring a backup of such a server.

use std::future::Future;
use std::path::{Path, PathBuf};

use kubidm_proto::backup::BackupCompression;
use kubidmd_core::config::Configuration;
use kubidmd_core::{restore_database, verify_database};
use kubidmd_testkit::{login_put_admin_idm_admins, setup_async_test, AsyncTestEnvironment};
use url::Url;

const VERIFY_TEST_USER: &str = "verify_test_user";
const VERIFY_TEST_GROUP: &str = "verify_test_group";

fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build the tokio runtime")
        .block_on(future)
}

/// A configuration for the test domain, pointing at `db_path`.
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

/// Create a person and a group that holds it, so the database carries references between
/// user created entries as well as the system entries.
async fn populate(env: &AsyncTestEnvironment) {
    let rsclient = &env.rsclient;
    login_put_admin_idm_admins(rsclient).await;

    rsclient
        .idm_person_account_create(VERIFY_TEST_USER, VERIFY_TEST_USER)
        .await
        .expect("Failed to create test user");
    rsclient
        .idm_group_create(VERIFY_TEST_GROUP, None)
        .await
        .expect("Failed to create test group");
    rsclient
        .idm_group_add_members(VERIFY_TEST_GROUP, &[VERIFY_TEST_USER])
        .await
        .expect("Failed to add member to test group");
}

#[test]
fn test_database_verify_passes_on_cold_database() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let db_path = workdir.path().join("verify.db");

        let mut env = start_server(&db_path).await;
        populate(&env).await;
        env.core_handle.shutdown().await;

        // The database is now cold: no server holds it. Verification must open it as the
        // `kubidmd database verify` command does and find it consistent.
        let config = config_with_db(&db_path);
        let errors = verify_database(&config)
            .await
            .expect("Database verification could not open the database");
        assert!(
            errors.is_empty(),
            "A healthy cold database must pass verification, got: {errors:?}"
        );
    });
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

#[test]
fn test_database_verify_passes_on_cold_restored_database() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        std::fs::create_dir(&backup_dir).expect("Failed to create backup directory");

        let mut env = start_server(&workdir.path().join("source.db")).await;
        populate(&env).await;
        let backup = backup_via_production_path(&env, &backup_dir).await;
        env.core_handle.shutdown().await;

        // Restore through the production restore path (restore + reindex) into a new,
        // empty database. No server has ever booted from it.
        let restored_db = workdir.path().join("restored.db");
        let config = config_with_db(&restored_db);
        restore_database(&config, &backup)
            .await
            .expect("Restore failed");

        // The restored database must verify clean when opened cold, as the
        // `kubidmd database verify` command does after a restore.
        let errors = verify_database(&config)
            .await
            .expect("Database verification could not open the restored database");
        assert!(
            errors.is_empty(),
            "A restored database must pass cold verification, got: {errors:?}"
        );
    });
}
