//! Helpers shared by the backup, verification and recovery end to end tests.
//!
//! The tests only drive production code paths: a server is started, populated with the
//! state a realistic deployment carries, backed up through the online backup, and the
//! backup is verified and restored with the `kubidmd database` logic.
//!
//! # S3
//!
//! The S3 tests need an S3-compatible service, found through `KUBIDM_TEST_S3_ENDPOINT`.
//! [`test_s3_config`] is their single gate: without an endpoint they are skipped, so that a
//! plain `cargo test` stays green without Docker, unless S3 tests are required, in which case
//! they fail. They are required when `KUBIDM_TEST_S3_REQUIRED` is set to anything but `0` or
//! `false`, or, when that variable is not set at all, when `CI` is set, so that a CI job that
//! loses its S3 service can not pass by skipping them.
//!
//! CI runs them against [Silo](https://github.com/pgsty/silo), a MinIO fork; the image is
//! pinned in `.github/workflows/rust_build.yml`. Locally:
//!
//! ```text
//! docker run -d --rm --name silo -p 9000:9000 \
//!     -e MINIO_ROOT_USER=kubidm-test -e MINIO_ROOT_PASSWORD=kubidm-test-secret \
//!     <the image of rust_build.yml> server /data
//! KUBIDM_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
//!     cargo test -p kubidmd_testkit --test integration_test -- s3_ pitr encryption
//! ```
//!
//! The credentials come from `KUBIDM_TEST_S3_ACCESS_KEY` and `KUBIDM_TEST_S3_SECRET_KEY`
//! (defaults `kubidm-test` / `kubidm-test-secret`; MinIO and Silo require a secret of at
//! least eight characters). The primary bucket is taken from `KUBIDM_TEST_S3_BUCKET` (default
//! `kubidm-test`) and the bucket of the replication regions from
//! `KUBIDM_TEST_S3_REGION_BUCKET` (default `kubidm-test-region`); both live on the same
//! endpoint and are created when missing. Every test uses its own prefixes, so runs never
//! interfere, and removes them when it passes.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::Client as SdkClient;
use kubidm_client::{KubidmClient, KubidmClientBuilder};
use kubidm_proto::backup::{
    BackupCompression, BackupEncryptionConfig, ReplicationRegionConfig, S3Config, S3Credentials,
};
use kubidmd_core::config::Configuration;
use kubidmd_testkit::{
    login_put_admin_idm_admins, setup_async_test, AsyncTestEnvironment, NOT_ADMIN_TEST_PASSWORD,
    NOT_ADMIN_TEST_USERNAME, TEST_INTEGRATION_RS_DISPLAY, TEST_INTEGRATION_RS_ID,
    TEST_INTEGRATION_RS_REDIRECT_URL, TEST_INTEGRATION_RS_URL,
};
use url::Url;
use uuid::Uuid;

pub const BACKUP_TEST_GROUP: &str = "backup_test_group";
pub const BACKUP_ENGINEERS_GROUP: &str = "backup_engineers";
pub const BACKUP_RECYCLED_GROUP: &str = "backup_recycled_group";
pub const BACKUP_USER_ALICE: &str = "backup_user_alice";
pub const BACKUP_USER_BOB: &str = "backup_user_bob";

/// Drive `work`, an offline database command, on the current thread runtime of the test
/// while a task ticks on the same runtime, and check that the runtime stayed free: the
/// longest stretch without a tick must be short against the whole command. A command that
/// ran its database work on the runtime would hold the only thread of the runtime for
/// most of it.
pub async fn assert_runtime_stays_free<F: Future>(work: F) -> F::Output {
    const TICK: Duration = Duration::from_millis(10);
    let ticks = Arc::new(Mutex::new(Vec::new()));
    let ticker = {
        let ticks = Arc::clone(&ticks);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TICK).await;
                ticks.lock().expect("ticks").push(Instant::now());
            }
        })
    };
    let start = Instant::now();
    let output = work.await;
    let end = Instant::now();
    ticker.abort();

    let elapsed = end - start;
    let mut times = vec![start];
    times.extend(ticks.lock().expect("ticks").iter().copied());
    times.push(end);
    let longest_stall = times
        .windows(2)
        .map(|pair| pair[1].saturating_duration_since(pair[0]))
        .max()
        .unwrap_or_default();
    assert!(
        longest_stall <= (elapsed / 2).max(Duration::from_millis(250)),
        "The runtime was blocked for {longest_stall:?} of the {elapsed:?} the command took"
    );
    output
}

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

/// Take an online backup through the production online backup path into `backup_dir`,
/// which is created when missing, keeping a single version, and return the artifact.
pub async fn backup_via_production_path(
    env: &AsyncTestEnvironment,
    backup_dir: &Path,
    compression: BackupCompression,
    encryption: &BackupEncryptionConfig,
) -> PathBuf {
    std::fs::create_dir_all(backup_dir).expect("Failed to create backup directory");
    env.core_handle
        .trigger_online_backup(backup_dir, 1, compression, encryption)
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

// === S3 ===

const S3_ENDPOINT_ENV: &str = "KUBIDM_TEST_S3_ENDPOINT";
const S3_REQUIRED_ENV: &str = "KUBIDM_TEST_S3_REQUIRED";
const S3_BUCKET_ENV: &str = "KUBIDM_TEST_S3_BUCKET";
const S3_REGION_BUCKET_ENV: &str = "KUBIDM_TEST_S3_REGION_BUCKET";
const S3_ACCESS_KEY_ENV: &str = "KUBIDM_TEST_S3_ACCESS_KEY";
const S3_SECRET_KEY_ENV: &str = "KUBIDM_TEST_S3_SECRET_KEY";
/// The signing region of the primary test location. Silo and MinIO accept any signing
/// region unless one is configured on the server.
pub const S3_TEST_REGION: &str = "us-east-1";

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// Whether an environment variable is set to a value that means yes.
fn env_flag(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .map(|value| !matches!(value.trim(), "" | "0" | "false"))
}

/// Whether the S3 tests must run rather than be skipped, see the module documentation.
fn s3_tests_required() -> bool {
    env_flag(S3_REQUIRED_ENV)
        .or_else(|| env_flag("CI"))
        .unwrap_or(false)
}

/// The S3 configuration of a test, below the primary test bucket under
/// `<prefix>/<fresh uuid>`, or None (after printing why) when no S3 endpoint is configured
/// and S3 tests are not required. Every S3 end to end test starts with this gate.
///
/// # Panics
///
/// When no endpoint is configured while S3 tests are required, so that losing the S3
/// service fails the run instead of silently skipping the tests.
pub fn test_s3_config(prefix: &str) -> Option<S3Config> {
    let Ok(endpoint) = std::env::var(S3_ENDPOINT_ENV) else {
        assert!(
            !s3_tests_required(),
            "{S3_ENDPOINT_ENV} is not set, but the S3 tests are required here ({S3_REQUIRED_ENV} \
             or CI is set): start an S3 service and set {S3_ENDPOINT_ENV}, or set \
             {S3_REQUIRED_ENV}=0 to skip them"
        );
        eprintln!("skipping: {S3_ENDPOINT_ENV} not set");
        return None;
    };

    Some(S3Config {
        bucket: env_or(S3_BUCKET_ENV, "kubidm-test"),
        region: Some(S3_TEST_REGION.to_string()),
        endpoint: Some(endpoint),
        path_prefix: Some(format!("{prefix}/{}", Uuid::new_v4())),
        credentials: Some(S3Credentials {
            access_key_id: env_or(S3_ACCESS_KEY_ENV, "kubidm-test"),
            secret_access_key: env_or(S3_SECRET_KEY_ENV, "kubidm-test-secret"),
            session_token: None,
        }),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        replication: None,
    })
}

/// A replication region `region` of the test location `primary`: the same endpoint and
/// credentials, in the region test bucket under `<prefix>/<fresh uuid>`.
pub fn test_s3_region(primary: &S3Config, region: &str, prefix: &str) -> ReplicationRegionConfig {
    ReplicationRegionConfig {
        name: None,
        region: region.to_string(),
        endpoint: primary.endpoint.clone(),
        bucket: env_or(S3_REGION_BUCKET_ENV, "kubidm-test-region"),
        path_prefix: Some(format!("{prefix}/{}", Uuid::new_v4())),
        credentials: primary.credentials.clone(),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        kms_key_id: None,
    }
}

/// A raw SDK client for the endpoint and credentials of `s3_config`, used to prepare the
/// buckets, to inspect the objects behind the back of the code under test and to damage
/// them.
pub async fn sdk_client(s3_config: &S3Config) -> SdkClient {
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
        .region(Region::new(S3_TEST_REGION))
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

/// Create `bucket` unless it exists. The S3 tests run concurrently and share the buckets,
/// so a creation that loses the race against another test is fine as long as the bucket
/// exists afterwards.
pub async fn ensure_bucket(sdk: &SdkClient, bucket: &str) {
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

fn prefix_of(s3_config: &S3Config) -> &str {
    s3_config
        .path_prefix
        .as_deref()
        .expect("Test S3 config has no prefix")
        .trim_end_matches('/')
}

/// The full object key of `key`, which is relative to the prefix of `s3_config`.
pub fn full_key(s3_config: &S3Config, key: &str) -> String {
    format!("{}/{key}", prefix_of(s3_config))
}

/// Every object key below the prefix of `s3_config`, with the prefix stripped, sorted.
pub async fn object_keys(sdk: &SdkClient, s3_config: &S3Config) -> Vec<String> {
    let prefix = format!("{}/", prefix_of(s3_config));
    let mut keys = Vec::new();
    let mut pages = sdk
        .list_objects_v2()
        .bucket(&s3_config.bucket)
        .prefix(&prefix)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        let page = page.expect("Failed to list objects");
        keys.extend(
            page.contents()
                .iter()
                .filter_map(|object| object.key())
                .filter_map(|key| key.strip_prefix(&prefix))
                .map(str::to_string),
        );
    }
    keys.sort();
    keys
}

/// `backups` together with their metadata sidecars, sorted: exactly the objects a location
/// holding these backups contains.
pub fn with_sidecars(backups: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = backups
        .iter()
        .flat_map(|key| [key.clone(), format!("{key}.metadata.json")])
        .collect();
    keys.sort();
    keys
}

/// The content of the object `key`, relative to the prefix of `s3_config`.
pub async fn s3_object(sdk: &SdkClient, s3_config: &S3Config, key: &str) -> Vec<u8> {
    sdk.get_object()
        .bucket(&s3_config.bucket)
        .key(full_key(s3_config, key))
        .send()
        .await
        .expect("Failed to get the object")
        .body
        .collect()
        .await
        .expect("Failed to read the object")
        .into_bytes()
        .to_vec()
}

/// Delete every object below the prefix of `s3_config`.
pub async fn delete_prefix(sdk: &SdkClient, s3_config: &S3Config) {
    for key in object_keys(sdk, s3_config).await {
        sdk.delete_object()
            .bucket(&s3_config.bucket)
            .key(full_key(s3_config, &key))
            .send()
            .await
            .expect("Failed to delete an object");
    }
}
