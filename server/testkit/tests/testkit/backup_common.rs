//! Helpers shared by the backup, verification and recovery end to end tests.
//!
//! The tests only drive production code paths: a server is started, populated with the
//! state a realistic deployment carries, backed up through the online backup, and the
//! backup is verified and restored with the `kubidmd database` logic.

use std::future::Future;
use std::path::Path;

use kubidm_client::{KubidmClient, KubidmClientBuilder};
use kubidmd_core::config::Configuration;
use kubidmd_testkit::{
    login_put_admin_idm_admins, setup_async_test, AsyncTestEnvironment, NOT_ADMIN_TEST_PASSWORD,
    NOT_ADMIN_TEST_USERNAME, TEST_INTEGRATION_RS_DISPLAY, TEST_INTEGRATION_RS_ID,
    TEST_INTEGRATION_RS_REDIRECT_URL, TEST_INTEGRATION_RS_URL,
};
use url::Url;

pub const BACKUP_TEST_GROUP: &str = "backup_test_group";
pub const BACKUP_ENGINEERS_GROUP: &str = "backup_engineers";
pub const BACKUP_RECYCLED_GROUP: &str = "backup_recycled_group";
pub const BACKUP_USER_ALICE: &str = "backup_user_alice";
pub const BACKUP_USER_BOB: &str = "backup_user_bob";

pub fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build the tokio runtime")
        .block_on(future)
}

/// A configuration for the test domain. Domain and origin must match the ones the backed up
/// server ran with, exactly as a production restore uses the server's own configuration.
pub fn config_with_db(db_path: &Path) -> Configuration {
    Configuration {
        db_path: Some(db_path.to_path_buf()),
        domain: "localhost".to_string(),
        origin: Url::parse("http://localhost").expect("Invalid origin"),
        ..Configuration::new_for_test()
    }
}

pub async fn start_server(db_path: &Path) -> AsyncTestEnvironment {
    setup_async_test(config_with_db(db_path)).await
}

/// A second, unauthenticated client for the server of `env`.
pub fn anonymous_client(env: &AsyncTestEnvironment) -> KubidmClient {
    KubidmClientBuilder::new()
        .address(format!("http://localhost:{}", env.http_sock_addr.port()))
        .enable_native_ca_roots(false)
        .no_proxy()
        .build()
        .expect("Failed to build client")
}

/// Group members are returned as SPNs such as `name@domain`.
pub fn has_member(members: &[String], name: &str) -> bool {
    members
        .iter()
        .any(|member| member == name || member.starts_with(&format!("{name}@")))
}

/// Populate the server with the state a realistic deployment carries: people with
/// credentials, static groups, an OAuth2 client, a recycled entry and a live user session.
/// Returns the session token of the test user.
pub async fn populate(env: &AsyncTestEnvironment) -> String {
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

/// Assert, on a server booted from a restored database, that the people, static groups
/// and memberships created by `populate` survived the restore and that dynamic group
/// membership was rebuilt.
pub async fn assert_directory_state_restored(rsclient: &KubidmClient) {
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

    // Dynamic group membership must be intact on the restored server. Dynamic members are
    // held in the dynmember attribute.
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
}
