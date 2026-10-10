//! End to end tests of WAL archiving and point-in-time recovery (PITR).
//!
//! A server runs with `[online_backup.wal_archive]` enabled, so every committed write is
//! archived. An online backup through the production path becomes the base, more writes
//! follow, and `kubidmd database recover` logic rebuilds the database at a point in time
//! between them and at the latest point. The recovered databases are booted as servers and
//! inspected through the client API.
//!
//! The S3 variant needs an S3-compatible service and is skipped unless
//! `KUBIDM_TEST_S3_ENDPOINT` is set, exactly like `s3_recovery_test`; see there for running
//! it against a local Silo container.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::Client as SdkClient;
use kubidm_client::KubidmClient;
use kubidm_proto::backup::{
    is_encrypted_backup_name, BackupCompression, BackupEncryptionConfig, EncryptionKeySource,
    KeyDerivationParams, PitrManifest, ReplicationConfig, ReplicationRegionConfig, S3Config,
    S3Credentials, WalArchiveConfig, PITR_MANIFEST_KEY,
};
use kubidmd_core::backup::pitr::{
    pitr_list_server_core, pitr_recover_server_core, PitrArchive, PitrError, PitrSettings,
    RecoveryTargetSpec,
};
use kubidmd_core::backup::{is_encrypted_artifact, MIN_KDF_M_COST};
use kubidmd_core::config::{Configuration, OnlineBackup};
use kubidmd_lib::be::SharedWalArchiver;
use kubidmd_lib::repl::wal::{format_ts_rfc3339, list_segments, WalArchiver};
use kubidmd_testkit::{login_put_admin_idm_admins, setup_async_test, AsyncTestEnvironment};
use uuid::Uuid;

use super::backup_common::{
    assert_directory_state_restored, config_with_db, populate, run, BACKUP_ENGINEERS_GROUP,
};
use super::s3_recovery_test::ensure_bucket;

/// Created after the base backup and before the recovery target.
const PITR_USER_BEFORE: &str = "pitr_user_before";
/// Created after the recovery target.
const PITR_USER_AFTER: &str = "pitr_user_after";
/// Created by the server started on the recovered database.
const PITR_USER_NEW_HISTORY: &str = "pitr_user_new_history";

/// The configuration of a server whose WAL is archived. Segments are written to `wal_dir`
/// and local base backups to `backup_dir`; with `s3`, base backups and the archive are in
/// S3 instead.
fn pitr_config(
    db_path: &Path,
    backup_dir: &Path,
    wal_dir: &Path,
    s3: Option<S3Config>,
) -> Configuration {
    let mut config = config_with_db(db_path);
    config.online_backup = Some(OnlineBackup {
        path: Some(backup_dir.to_path_buf()),
        enabled: true,
        s3,
        wal_archive: Some(WalArchiveConfig {
            enabled: true,
            // The tests archive on demand; the periodic task must not interfere.
            segment_interval_seconds: 3600,
            local_path: Some(wal_dir.to_path_buf()),
            ..WalArchiveConfig::default()
        }),
        ..OnlineBackup::default()
    });
    config
}

fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("The clock is before the epoch");
    format_ts_rfc3339(now)
}

async fn person_exists(rsclient: &KubidmClient, name: &str) -> bool {
    rsclient
        .idm_person_account_get(name)
        .await
        .expect("Failed to get person")
        .is_some()
}

async fn group_exists(rsclient: &KubidmClient, name: &str) -> bool {
    rsclient
        .idm_group_get(name)
        .await
        .expect("Failed to get group")
        .is_some()
}

async fn archive_now(env: &AsyncTestEnvironment) {
    env.core_handle
        .sync_wal_archive()
        .await
        .expect("WAL archiving must be enabled")
        .expect("WAL archive synchronisation failed");
}

/// Write the history the tests recover from on a populated server that archives its WAL
/// and has just taken a base backup: a person (archived in its own segment), then the
/// returned target time, then a second person and the deletion of a group. The server is
/// shut down, which archives the open segment.
async fn write_history(mut env: AsyncTestEnvironment) -> String {
    env.rsclient
        .idm_person_account_create(PITR_USER_BEFORE, "Before")
        .await
        .expect("Failed to create the person before the target");
    archive_now(&env).await;

    // CIDs are taken from the same clock; keep the target clearly between the writes.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let target = now_rfc3339();
    tokio::time::sleep(Duration::from_millis(200)).await;

    env.rsclient
        .idm_person_account_create(PITR_USER_AFTER, "After")
        .await
        .expect("Failed to create the person after the target");
    env.rsclient
        .idm_group_delete(BACKUP_ENGINEERS_GROUP)
        .await
        .expect("Failed to delete the engineers group");

    // A clean shutdown closes and archives the open segment.
    env.core_handle.shutdown().await;
    target
}

/// Boot `config`'s database as a server and check it holds the state as of the target:
/// everything from before it, nothing from after it.
async fn assert_state_at_target(config: Configuration) -> AsyncTestEnvironment {
    let env = setup_async_test(config).await;
    login_put_admin_idm_admins(&env.rsclient).await;
    assert_directory_state_restored(&env.rsclient).await;
    assert!(
        person_exists(&env.rsclient, PITR_USER_BEFORE).await,
        "A write before the target must be recovered"
    );
    assert!(
        !person_exists(&env.rsclient, PITR_USER_AFTER).await,
        "A write after the target must not be recovered"
    );
    assert!(
        group_exists(&env.rsclient, BACKUP_ENGINEERS_GROUP).await,
        "A deletion after the target must not be recovered"
    );
    env
}

#[test]
fn test_pitr_local_recover_to_time_and_latest() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        let wal_dir = workdir.path().join("wal");
        std::fs::create_dir(&backup_dir).expect("Failed to create backup directory");
        let source_config = pitr_config(
            &workdir.path().join("source.db"),
            &backup_dir,
            &wal_dir,
            None,
        );

        let env = setup_async_test(source_config.clone()).await;
        populate(&env).await;
        env.core_handle
            .trigger_online_backup(&backup_dir, 7, BackupCompression::Gzip, &Default::default())
            .await
            .expect("Online backup failed");
        let target = write_history(env).await;

        // The local archive: segments and the manifest stay in the WAL directory.
        assert!(wal_dir.join(PITR_MANIFEST_KEY).is_file());
        let segments = list_segments(&wal_dir).expect("Failed to list the WAL segments");
        assert!(
            segments.len() >= 2,
            "Expected at least two archived segments, found {segments:?}"
        );
        assert!(pitr_list_server_core(&source_config, None).await);

        // A target before the base backup is refused and touches nothing.
        let early_db = workdir.path().join("early.db");
        let early = pitr_recover_server_core(
            &pitr_config(&early_db, &backup_dir, &wal_dir, None),
            &RecoveryTargetSpec::Time("2000-01-01T00:00:00Z".to_string()),
            false,
            None,
        )
        .await;
        assert!(
            matches!(early, Err(PitrError::NotRecoverable(_))),
            "{early:?}"
        );
        assert!(!early_db.exists());

        // The dry run reports the plan and creates nothing.
        let recovered_db = workdir.path().join("recovered.db");
        let recovered_config = pitr_config(&recovered_db, &backup_dir, &wal_dir, None);
        let dry = pitr_recover_server_core(
            &recovered_config,
            &RecoveryTargetSpec::Time(target.clone()),
            true,
            None,
        )
        .await
        .expect("Dry run failed");
        assert!(dry.dry_run);
        assert!(
            dry.records > 0,
            "The person before the target must be replayed"
        );
        assert!(
            !recovered_db.exists(),
            "A dry run must not create the database"
        );

        // Recover to the target time.
        let outcome = pitr_recover_server_core(
            &recovered_config,
            &RecoveryTargetSpec::Time(target),
            false,
            None,
        )
        .await
        .expect("Recovery to the target time failed");
        assert_eq!(outcome.records, dry.records);
        let apply = outcome.apply.expect("Records must have been applied");
        assert!(apply.created >= 1);

        // The recovered server sees the state as of the target. It archives into the same
        // archive (the recovered database keeps the server identity) and starts new history.
        let mut env = assert_state_at_target(recovered_config.clone()).await;
        env.rsclient
            .idm_person_account_create(PITR_USER_NEW_HISTORY, "New history")
            .await
            .expect("Failed to create the person on the recovered server");
        env.core_handle.shutdown().await;

        // Latest: the recovered point plus the new history. What the recovery abandoned
        // (the person and the deletion after the target) never comes back.
        let latest_db = workdir.path().join("latest.db");
        let latest_config = pitr_config(&latest_db, &backup_dir, &wal_dir, None);
        pitr_recover_server_core(&latest_config, &RecoveryTargetSpec::Latest, false, None)
            .await
            .expect("Recovery to the latest point failed");
        let mut env = assert_state_at_target(latest_config).await;
        assert!(
            person_exists(&env.rsclient, PITR_USER_NEW_HISTORY).await,
            "The history written after the recovery must be recovered"
        );
        env.core_handle.shutdown().await;
    });
}

/// Created after the last archived segment, right before an unclean stop.
const PITR_USER_LOST: &str = "pitr_user_lost";

#[test]
fn test_pitr_unclean_stop_leaves_a_gap_recovery_does_not_cross() {
    let workdir = tempfile::tempdir().expect("Failed to create workdir");
    let backup_dir = workdir.path().join("backups");
    let wal_dir = workdir.path().join("wal");
    std::fs::create_dir(&backup_dir).expect("Failed to create backup directory");
    let config = pitr_config(
        &workdir.path().join("source.db"),
        &backup_dir,
        &wal_dir,
        None,
    );

    // A server takes a base backup, archives one write and then stops without shutting
    // down, with a second write only in its open segment.
    run(async {
        let env = setup_async_test(config.clone()).await;
        populate(&env).await;
        env.core_handle
            .trigger_online_backup(&backup_dir, 7, BackupCompression::Gzip, &Default::default())
            .await
            .expect("Online backup failed");
        env.rsclient
            .idm_person_account_create(PITR_USER_BEFORE, "Before")
            .await
            .expect("Failed to create the archived person");
        archive_now(&env).await;
        env.rsclient
            .idm_person_account_create(PITR_USER_LOST, "Lost")
            .await
            .expect("Failed to create the unarchived person");
        // No shutdown: the runtime goes away under the server, as in a crash.
        std::mem::forget(env);
    });

    // The restarted server notices the unclosed segment and records the gap.
    run(async {
        let mut env = setup_async_test(config.clone()).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        assert!(person_exists(&env.rsclient, PITR_USER_LOST).await);
        env.rsclient
            .idm_person_account_create(PITR_USER_AFTER, "After")
            .await
            .expect("Failed to create the person after the restart");
        env.core_handle.shutdown().await;

        // The gap is in the manifest, and a target past it is refused without touching
        // the database: replaying across it would silently miss the lost write.
        let manifest: kubidm_proto::backup::PitrManifest = serde_json::from_slice(
            &std::fs::read(wal_dir.join(PITR_MANIFEST_KEY)).expect("Failed to read the manifest"),
        )
        .expect("Failed to parse the manifest");
        assert_eq!(manifest.gaps.len(), 1, "{:?}", manifest.gaps);
        let refused_db = workdir.path().join("refused.db");
        let refused = pitr_recover_server_core(
            &pitr_config(&refused_db, &backup_dir, &wal_dir, None),
            &RecoveryTargetSpec::Time(now_rfc3339()),
            false,
            None,
        )
        .await;
        assert!(
            matches!(&refused, Err(PitrError::NotRecoverable(msg)) if msg.contains("missing")),
            "{refused:?}"
        );
        assert!(!refused_db.exists());

        // The latest recoverable point stops before the gap.
        let latest_db = workdir.path().join("latest.db");
        let latest_config = pitr_config(&latest_db, &backup_dir, &wal_dir, None);
        pitr_recover_server_core(&latest_config, &RecoveryTargetSpec::Latest, false, None)
            .await
            .expect("Recovery to the latest point before the gap failed");
        let mut env = setup_async_test(latest_config).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        assert!(person_exists(&env.rsclient, PITR_USER_BEFORE).await);
        assert!(!person_exists(&env.rsclient, PITR_USER_LOST).await);
        assert!(!person_exists(&env.rsclient, PITR_USER_AFTER).await);
        env.core_handle.shutdown().await;
    });
}

// === S3 ===

const ENDPOINT_ENV: &str = "KUBIDM_TEST_S3_ENDPOINT";
const BUCKET_ENV: &str = "KUBIDM_TEST_S3_BUCKET";
const ACCESS_KEY_ENV: &str = "KUBIDM_TEST_S3_ACCESS_KEY";
const SECRET_KEY_ENV: &str = "KUBIDM_TEST_S3_SECRET_KEY";
const REGION: &str = "us-east-1";

/// The S3 configuration for this test run, or None (after printing why) when no endpoint
/// is configured. Every run uses its own prefix.
fn test_s3_config() -> Option<S3Config> {
    let Ok(endpoint) = std::env::var(ENDPOINT_ENV) else {
        eprintln!("skipping: {ENDPOINT_ENV} not set");
        return None;
    };
    let env_or =
        |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.to_string());
    Some(S3Config {
        bucket: env_or(BUCKET_ENV, "kubidm-test"),
        region: Some(REGION.to_string()),
        endpoint: Some(endpoint),
        path_prefix: Some(format!("pitr-test/{}", Uuid::new_v4())),
        credentials: Some(S3Credentials {
            access_key_id: env_or(ACCESS_KEY_ENV, "kubidm-test"),
            secret_access_key: env_or(SECRET_KEY_ENV, "kubidm-test-secret"),
            session_token: None,
        }),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        replication: None,
    })
}

async fn sdk_client(s3_config: &S3Config) -> SdkClient {
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
        .region(Region::new(REGION))
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

/// Every object key below the prefix of `s3_config`, with the prefix stripped, sorted.
async fn object_keys(sdk: &SdkClient, s3_config: &S3Config) -> Vec<String> {
    // Several S3 tests of this binary may race to create the shared bucket.
    ensure_bucket(sdk, &s3_config.bucket).await;
    let prefix = format!(
        "{}/",
        s3_config
            .path_prefix
            .as_deref()
            .expect("Test S3 config has no prefix")
    );
    let output = sdk
        .list_objects_v2()
        .bucket(&s3_config.bucket)
        .prefix(&prefix)
        .send()
        .await
        .expect("Failed to list objects");
    let mut keys: Vec<String> = output
        .contents()
        .iter()
        .filter_map(|object| object.key())
        .filter_map(|key| key.strip_prefix(&prefix))
        .map(str::to_string)
        .collect();
    keys.sort();
    keys
}

#[test]
fn test_pitr_s3_recover_on_a_new_host() {
    let Some(s3_config) = test_s3_config() else {
        return;
    };

    run(async {
        let sdk = sdk_client(&s3_config).await;
        // Creates the bucket when needed; the prefix is fresh.
        assert!(object_keys(&sdk, &s3_config).await.is_empty());

        let source_host = tempfile::tempdir().expect("Failed to create workdir");
        let source_wal: PathBuf = source_host.path().join("wal");
        let source_config = pitr_config(
            &source_host.path().join("source.db"),
            &source_host.path().join("backups"),
            &source_wal,
            Some(s3_config.clone()),
        );

        let env = setup_async_test(source_config).await;
        populate(&env).await;
        env.core_handle
            .trigger_s3_backup(
                s3_config.clone(),
                7,
                BackupCompression::Gzip,
                &Default::default(),
            )
            .await
            .expect("S3 backup failed");
        let target = write_history(env).await;

        // Everything was shipped: the local WAL directory holds no segment any more, and
        // the prefix holds the base backup, the segments and the manifest, each with its
        // metadata sidecar. Backup retention left the archive alone.
        assert!(
            list_segments(&source_wal)
                .expect("Failed to list the local WAL directory")
                .is_empty(),
            "Uploaded segments must be removed locally"
        );
        let keys = object_keys(&sdk, &s3_config).await;
        assert!(keys.iter().any(|key| key == PITR_MANIFEST_KEY), "{keys:?}");
        assert_eq!(
            keys.iter()
                .filter(|key| key.starts_with("backup-") && key.ends_with(".json.gz"))
                .count(),
            1,
            "{keys:?}"
        );
        let segment_count = keys
            .iter()
            .filter(|key| key.starts_with("wal/wal-") && key.ends_with(".json.gz"))
            .count();
        assert!(segment_count >= 2, "{keys:?}");
        assert!(keys
            .iter()
            .filter(|key| !key.ends_with(".metadata.json"))
            .all(|key| keys.contains(&format!("{key}.metadata.json"))));

        // A new host: an empty WAL directory and no local backups. Everything comes from
        // S3.
        let new_host = tempfile::tempdir().expect("Failed to create workdir");
        let recovered_config = pitr_config(
            &new_host.path().join("recovered.db"),
            &new_host.path().join("backups"),
            &new_host.path().join("wal"),
            Some(s3_config.clone()),
        );
        assert!(pitr_list_server_core(&recovered_config, None).await);
        let outcome = pitr_recover_server_core(
            &recovered_config,
            &RecoveryTargetSpec::Time(target),
            false,
            None,
        )
        .await
        .expect("Recovery from S3 to the target time failed");
        assert!(outcome.records > 0);

        let mut env = assert_state_at_target(recovered_config.clone()).await;
        env.core_handle.shutdown().await;

        // Latest from S3: the abandoned history after the target stays abandoned.
        let latest_config = pitr_config(
            &new_host.path().join("latest.db"),
            &new_host.path().join("backups"),
            &new_host.path().join("wal"),
            Some(s3_config.clone()),
        );
        pitr_recover_server_core(&latest_config, &RecoveryTargetSpec::Latest, false, None)
            .await
            .expect("Recovery from S3 to the latest point failed");
        let mut env = assert_state_at_target(latest_config).await;
        env.core_handle.shutdown().await;
    });
}

// === Interplay with client-side encryption and cross-region replication ===

const PITR_PASSPHRASE: &str = "pitr e2e passphrase, long enough to matter";
const PITR_KEY_ID: &str = "pitr-e2e-key";
const PITR_REGION: &str = "eu-west-1";
const REGION_BUCKET_ENV: &str = "KUBIDM_TEST_S3_REGION_BUCKET";

/// Backup encryption with the passphrase in a file under `dir` and the cheapest key
/// derivation the server accepts.
fn pitr_encryption(dir: &Path) -> BackupEncryptionConfig {
    let passphrase_file = dir.join("backup-passphrase");
    std::fs::write(&passphrase_file, format!("{PITR_PASSPHRASE}\n"))
        .expect("Failed to write the passphrase");
    BackupEncryptionConfig {
        enabled: true,
        key_source: EncryptionKeySource::Passphrase,
        key_derivation: KeyDerivationParams {
            m_cost: MIN_KDF_M_COST,
            t_cost: 1,
            p_cost: 1,
        },
        key_identifier: Some(PITR_KEY_ID.to_string()),
        passphrase_file: Some(passphrase_file),
    }
}

fn with_encryption(
    mut config: Configuration,
    encryption: &BackupEncryptionConfig,
) -> Configuration {
    if let Some(online_backup) = config.online_backup.as_mut() {
        online_backup.encryption = encryption.clone();
    }
    config
}

fn read_manifest(path: &Path) -> PitrManifest {
    serde_json::from_slice(&std::fs::read(path).expect("Failed to read the manifest"))
        .expect("Failed to parse the manifest")
}

#[test]
fn test_pitr_local_encrypted_base_and_wal_recover() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        let wal_dir = workdir.path().join("wal");
        std::fs::create_dir(&backup_dir).expect("Failed to create backup directory");
        let encryption = pitr_encryption(workdir.path());
        let encrypted = |db: &str| {
            with_encryption(
                pitr_config(&workdir.path().join(db), &backup_dir, &wal_dir, None),
                &encryption,
            )
        };
        let source_config = encrypted("source.db");

        let env = setup_async_test(source_config.clone()).await;
        populate(&env).await;
        env.core_handle
            .trigger_online_backup(&backup_dir, 7, BackupCompression::Gzip, &encryption)
            .await
            .expect("Encrypted online backup failed");
        let target = write_history(env).await;

        // The base is an encrypted artifact, and so is every archived segment: no plaintext
        // segment is left in the WAL directory, each one is `<segment>.enc`, and the
        // manifest records the key it needs.
        let bases: Vec<String> = std::fs::read_dir(&backup_dir)
            .expect("Failed to read the backup directory")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .collect();
        assert_eq!(bases.len(), 1, "{bases:?}");
        assert!(is_encrypted_backup_name(&bases[0]), "{bases:?}");
        assert!(
            list_segments(&wal_dir)
                .expect("Failed to list the WAL directory")
                .is_empty(),
            "No plaintext segment may stay in the WAL directory"
        );
        let manifest = read_manifest(&wal_dir.join(PITR_MANIFEST_KEY));
        assert!(manifest.segments.len() >= 2, "{:?}", manifest.segments);
        for segment in &manifest.segments {
            assert_eq!(segment.encryption_key.as_deref(), Some(PITR_KEY_ID));
            let stored = std::fs::read(wal_dir.join(segment.stored_name()))
                .expect("The encrypted segment is missing");
            assert!(is_encrypted_artifact(&stored));
            assert!(!wal_dir.join(&segment.segment_id).exists());
        }
        assert!(pitr_list_server_core(&source_config, None).await);

        // Without the key nothing can be recovered, and nothing is touched.
        let keyless_db = workdir.path().join("keyless.db");
        let keyless = pitr_recover_server_core(
            &pitr_config(&keyless_db, &backup_dir, &wal_dir, None),
            &RecoveryTargetSpec::Time(target.clone()),
            false,
            None,
        )
        .await;
        assert!(
            matches!(&keyless, Err(PitrError::Encryption(msg)) if msg.contains(PITR_KEY_ID)),
            "{keyless:?}"
        );
        assert!(!keyless_db.exists());

        // With the key: the encrypted base is restored and the encrypted segments replayed.
        let recovered_config = encrypted("recovered.db");
        let outcome = pitr_recover_server_core(
            &recovered_config,
            &RecoveryTargetSpec::Time(target),
            false,
            None,
        )
        .await
        .expect("Recovery of the encrypted archive failed");
        assert!(outcome.records > 0);
        let mut env = assert_state_at_target(recovered_config).await;
        env.core_handle.shutdown().await;
    });
}

/// The region of the PITR replication test, in its own bucket and prefix.
fn pitr_region(primary: &S3Config) -> ReplicationRegionConfig {
    ReplicationRegionConfig {
        region: PITR_REGION.to_string(),
        endpoint: primary.endpoint.clone(),
        bucket: std::env::var(REGION_BUCKET_ENV)
            .unwrap_or_else(|_| "kubidm-test-region".to_string()),
        path_prefix: Some(format!("pitr-dr/{}", Uuid::new_v4())),
        credentials: primary.credentials.clone(),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        kms_key_id: None,
    }
}

/// The keys of the WAL segments among `keys`.
fn segment_keys(keys: &[String]) -> Vec<String> {
    keys.iter()
        .filter(|key| key.starts_with("wal/wal-") && !key.ends_with(".metadata.json"))
        .cloned()
        .collect()
}

async fn s3_manifest(sdk: &SdkClient, s3_config: &S3Config) -> PitrManifest {
    let prefix = s3_config.path_prefix.as_deref().expect("No prefix");
    let object = sdk
        .get_object()
        .bucket(&s3_config.bucket)
        .key(format!("{prefix}/{PITR_MANIFEST_KEY}"))
        .send()
        .await
        .expect("Failed to get the manifest");
    let data = object
        .body
        .collect()
        .await
        .expect("Failed to read the manifest")
        .into_bytes();
    serde_json::from_slice(&data).expect("Failed to parse the manifest")
}

async fn s3_object(sdk: &SdkClient, s3_config: &S3Config, key: &str) -> Vec<u8> {
    let prefix = s3_config.path_prefix.as_deref().expect("No prefix");
    sdk.get_object()
        .bucket(&s3_config.bucket)
        .key(format!("{prefix}/{key}"))
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

async fn delete_all(sdk: &SdkClient, s3_config: &S3Config) {
    let prefix = s3_config.path_prefix.as_deref().expect("No prefix");
    for key in object_keys(sdk, s3_config).await {
        sdk.delete_object()
            .bucket(&s3_config.bucket)
            .key(format!("{prefix}/{key}"))
            .send()
            .await
            .expect("Failed to delete an object");
    }
}

/// Encryption, replication and PITR together, against S3: the base backups and the WAL
/// segments are encrypted before they leave the host, both are replicated to a region, and
/// the region alone is enough to recover once the primary archive is gone. The region keeps
/// its copy when the primary starts over, applies retention to it on its own, and hands the
/// history its recovery abandoned back to the primary.
#[test]
fn test_pitr_s3_encrypted_replicated_recover_from_region() {
    let Some(mut s3_config) = test_s3_config() else {
        return;
    };
    let region = pitr_region(&s3_config);
    s3_config.replication = Some(ReplicationConfig {
        enabled: true,
        regions: vec![region.clone()],
        sync_interval_seconds: 3600,
        max_retries: 0,
        retry_delay_seconds: 0,
    });
    let region_s3 = region.to_s3_config();

    // The scenario is long enough for its future to overflow the stack of the test thread
    // in a debug build; keep it on the heap.
    run(Box::pin(async {
        let sdk = sdk_client(&s3_config).await;
        assert!(object_keys(&sdk, &s3_config).await.is_empty());
        assert!(object_keys(&sdk, &region_s3).await.is_empty());

        let source_host = tempfile::tempdir().expect("Failed to create workdir");
        let encryption = pitr_encryption(source_host.path());
        let host_config = |host: &Path, db: &str| {
            with_encryption(
                pitr_config(
                    &host.join(db),
                    &host.join("backups"),
                    &host.join("wal"),
                    Some(s3_config.clone()),
                ),
                &encryption,
            )
        };

        let env = setup_async_test(host_config(source_host.path(), "source.db")).await;
        populate(&env).await;
        env.core_handle
            .trigger_s3_backup(s3_config.clone(), 7, BackupCompression::Gzip, &encryption)
            .await
            .expect("Encrypted, replicated S3 backup failed");
        let target = write_history(env).await;

        // The primary and the region hold the same encrypted base, the same encrypted
        // segments and an equivalent manifest.
        let primary_keys = object_keys(&sdk, &s3_config).await;
        let region_keys = object_keys(&sdk, &region_s3).await;
        let primary_segments = segment_keys(&primary_keys);
        assert!(primary_segments.len() >= 2, "{primary_keys:?}");
        assert_eq!(primary_segments, segment_keys(&region_keys));
        for key in &primary_segments {
            assert!(key.ends_with(".json.gz.enc"), "{key}");
            assert!(is_encrypted_artifact(
                &s3_object(&sdk, &s3_config, key).await
            ));
            assert!(is_encrypted_artifact(
                &s3_object(&sdk, &region_s3, key).await
            ));
        }
        for keys in [&primary_keys, &region_keys] {
            assert!(keys.iter().any(|key| key == PITR_MANIFEST_KEY), "{keys:?}");
            assert_eq!(
                keys.iter()
                    .filter(|key| key.starts_with("backup-") && key.ends_with(".json.gz.enc"))
                    .count(),
                1,
                "{keys:?}"
            );
        }
        let primary_manifest = s3_manifest(&sdk, &s3_config).await;
        let region_manifest = s3_manifest(&sdk, &region_s3).await;
        assert_eq!(primary_manifest.segments, region_manifest.segments);
        assert_eq!(primary_manifest.base_backups, region_manifest.base_backups);

        let new_host = tempfile::tempdir().expect("Failed to create workdir");
        std::fs::copy(
            source_host.path().join("backup-passphrase"),
            new_host.path().join("backup-passphrase"),
        )
        .expect("Failed to copy the passphrase");
        let unknown = pitr_recover_server_core(
            &host_config(new_host.path(), "unknown.db"),
            &RecoveryTargetSpec::Latest,
            true,
            Some("nowhere"),
        )
        .await;
        assert!(matches!(unknown, Err(PitrError::Config(_))), "{unknown:?}");

        // The primary is unreachable (its bucket does not exist for this host): the region
        // alone recovers the state as of the target, decrypting base and segments with the
        // key, and records the abandoned history in its own manifest.
        let mut unreachable_primary = host_config(new_host.path(), "recovered.db");
        if let Some(s3) = unreachable_primary
            .online_backup
            .as_mut()
            .and_then(|backup| backup.s3.as_mut())
        {
            s3.bucket = format!("kubidm-test-missing-{}", Uuid::new_v4());
        }
        assert!(!pitr_list_server_core(&unreachable_primary, None).await);
        assert!(pitr_list_server_core(&unreachable_primary, Some(PITR_REGION)).await);
        let outcome = pitr_recover_server_core(
            &unreachable_primary,
            &RecoveryTargetSpec::Time(target),
            false,
            Some(PITR_REGION),
        )
        .await
        .expect("Recovery from the region failed");
        assert!(outcome.records > 0);
        let region_manifest = s3_manifest(&sdk, &region_s3).await;
        assert_eq!(region_manifest.timeline_breaks.len(), 1);
        assert!(s3_manifest(&sdk, &s3_config)
            .await
            .timeline_breaks
            .is_empty());

        // The recovered server reaches the primary again. Its first synchronisation takes
        // the abandoned history from the region into the primary, so that a recovery from
        // the primary never replays it either.
        let recovered_config = host_config(new_host.path(), "recovered.db");
        let mut env = assert_state_at_target(recovered_config.clone()).await;
        env.rsclient
            .idm_person_account_create(PITR_USER_NEW_HISTORY, "New history")
            .await
            .expect("Failed to create the person on the recovered server");
        env.core_handle.shutdown().await;
        assert_eq!(
            s3_manifest(&sdk, &s3_config).await.timeline_breaks,
            region_manifest.timeline_breaks
        );
        let latest_config = host_config(new_host.path(), "latest.db");
        pitr_recover_server_core(&latest_config, &RecoveryTargetSpec::Latest, false, None)
            .await
            .expect("Recovery from the primary failed");
        let mut env = assert_state_at_target(latest_config).await;
        assert!(person_exists(&env.rsclient, PITR_USER_NEW_HISTORY).await);
        env.core_handle.shutdown().await;

        // The primary archive is lost. The region still holds everything, including the
        // history written after the recovery, which was replicated at shutdown.
        let primary_segments = s3_manifest(&sdk, &s3_config).await.segments;
        delete_all(&sdk, &s3_config).await;
        let last_host = tempfile::tempdir().expect("Failed to create workdir");
        std::fs::copy(
            source_host.path().join("backup-passphrase"),
            last_host.path().join("backup-passphrase"),
        )
        .expect("Failed to copy the passphrase");
        let from_region = host_config(last_host.path(), "from-region.db");
        pitr_recover_server_core(
            &from_region,
            &RecoveryTargetSpec::Latest,
            false,
            Some(PITR_REGION),
        )
        .await
        .expect("Recovery from the region after the loss of the primary failed");
        let mut env = assert_state_at_target(from_region.clone()).await;
        assert!(person_exists(&env.rsclient, PITR_USER_NEW_HISTORY).await);
        env.core_handle.shutdown().await;

        // The server now archives into an empty primary; the region keeps the segments the
        // primary no longer has.
        let region_manifest = s3_manifest(&sdk, &region_s3).await;
        let primary_manifest = s3_manifest(&sdk, &s3_config).await;
        for segment in primary_segments.iter().chain(&primary_manifest.segments) {
            assert!(
                region_manifest.segments.contains(segment),
                "{segment:?} missing in the region"
            );
        }
        assert!(region_manifest.segments.len() > primary_manifest.segments.len());

        // Retention in the region: once the base backup is gone from the region and the
        // segments are older than the retention period, the region deletes them on its own.
        let region_base = region_manifest
            .base_backups
            .first()
            .expect("The region indexes the base backup")
            .key
            .clone();
        let region_prefix = region_s3.path_prefix.as_deref().expect("No prefix");
        for key in [region_base.clone(), format!("{region_base}.metadata.json")] {
            sdk.delete_object()
                .bucket(&region_s3.bucket)
                .key(format!("{region_prefix}/{key}"))
                .send()
                .await
                .expect("Failed to delete the region base");
        }
        let settings = PitrSettings::from_config(&from_region)
            .expect("Invalid PITR settings")
            .expect("PITR is enabled");
        let wal_dir = last_host.path().join("retention-wal");
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::new(
                settings.backend_wal_config(),
                region_manifest.server_uuid,
                wal_dir.clone(),
            )
            .expect("Failed to open a WAL archiver"),
        ));
        let archive = PitrArchive::new(
            PitrSettings {
                local_dir: wal_dir,
                ..settings
            },
            archiver,
        );
        let far_future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("The clock is before the epoch")
            + Duration::from_secs(60 * 86400);
        let report = archive
            .sync(far_future, false)
            .await
            .expect("Synchronisation failed");
        assert_eq!(report.region_errors, 0);
        let region_manifest = s3_manifest(&sdk, &region_s3).await;
        assert!(region_manifest.base_backups.is_empty());
        assert!(
            region_manifest.segments.is_empty(),
            "{:?}",
            region_manifest.segments
        );
        assert!(segment_keys(&object_keys(&sdk, &region_s3).await).is_empty());
    }));
}
