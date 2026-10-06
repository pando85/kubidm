//! End to end test for `kubidmd database verify` on a cold database.
//!
//! A server is started on a fresh database, populated, and shut down. The database is
//! then opened the way the `kubidmd database verify` command does, without booting a
//! server and without running the startup migrations, and must verify clean.

use std::future::Future;
use std::path::Path;

use kubidmd_core::config::Configuration;
use kubidmd_core::verify_database;
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
