//! End to end tests of WAL archiving and point-in-time recovery (PITR).
//!
//! A server runs with `[online_backup.wal_archive]` enabled, so every committed write is
//! archived. An online backup through the production path becomes the base, more writes
//! follow, and `kubidmd database recover` logic rebuilds the database at a point in time
//! between them and at the latest point. The recovered databases are booted as servers and
//! inspected through the client API.
//!
//! The S3 variants need an S3-compatible service; see `backup_common` for how it is found,
//! when they are skipped and how to run them locally.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as SdkClient;
use kubidm_client::KubidmClient;
use kubidm_proto::backup::{
    is_encrypted_backup_name, BackupCompression, BackupEncryptionConfig, EncryptionKeySource,
    KeyDerivationParams, PitrManifest, ReplicationConfig, ReplicationRegionConfig, S3Config,
    WalArchiveConfig, PITR_MANIFEST_KEY,
};
use kubidmd_core::backup::pitr::{
    check_wal_replication, pitr_list_server_core, pitr_recover_server_core, PitrArchive, PitrError,
    PitrSettings, RecoveryTargetSpec, RegionManifestState, HANDED_OVER_BASES_DIR,
};
use kubidmd_core::backup::{is_encrypted_artifact, MIN_KDF_M_COST};
use kubidmd_core::config::{Configuration, OnlineBackup};
use kubidmd_core::{
    backup_server_core, dbscan_quarantine_id2entry_core, dbscan_restore_quarantined_core,
    replicate_status_server_core, restore_s3_database, restore_server_core, RestoreStatus,
};
use kubidmd_lib::be::SharedWalArchiver;
use kubidmd_lib::repl::wal::{format_ts_rfc3339, list_segments, read_pending_events, WalArchiver};
use kubidmd_testkit::{login_put_admin_idm_admins, setup_async_test, AsyncTestEnvironment};
use uuid::Uuid;

use super::backup_common::{
    assert_directory_state_restored, assert_runtime_stays_free, backup_via_production_path,
    config_with_db, delete_prefix, ensure_bucket, full_key, object_keys, populate, run, s3_object,
    sdk_client, test_s3_config, test_s3_region, BACKUP_ENGINEERS_GROUP,
};

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

        // Recover to the target time. The restore, replay, reindex and verification run on
        // a thread of their own: the single thread of the test runtime stays free.
        let outcome = assert_runtime_stays_free(pitr_recover_server_core(
            &recovered_config,
            &RecoveryTargetSpec::Time(target),
            false,
            None,
        ))
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

/// The `db-scan` repair commands change the database outside any transaction the archive
/// could record. Each records a gap: recovery stops right before the change, and an online
/// backup taken after it makes later points recoverable again.
#[test]
fn test_pitr_dbscan_repairs_are_gaps_recovery_does_not_cross() {
    run(async {
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

        let mut env = setup_async_test(config.clone()).await;
        populate(&env).await;
        env.core_handle
            .trigger_online_backup(&backup_dir, 7, BackupCompression::Gzip, &Default::default())
            .await
            .expect("Online backup failed");
        env.rsclient
            .idm_person_account_create(PITR_USER_BEFORE, "Before")
            .await
            .expect("Failed to create the person before the repair");
        env.core_handle.shutdown().await;
        assert!(read_manifest(&wal_dir.join(PITR_MANIFEST_KEY))
            .gaps
            .is_empty());

        // The server is stopped: quarantine an entry and put it back.
        dbscan_quarantine_id2entry_core(&config, 1).await;
        dbscan_restore_quarantined_core(&config, 1).await;
        let manifest = read_manifest(&wal_dir.join(PITR_MANIFEST_KEY));
        assert_eq!(manifest.gaps.len(), 2, "{:?}", manifest.gaps);
        assert!(manifest
            .gaps
            .iter()
            .all(|gap| gap.reason.contains("db-scan")));

        // A target past the repairs is refused; the latest point stops before them and
        // holds everything committed until then.
        let refused_db = workdir.path().join("refused.db");
        let refused = pitr_recover_server_core(
            &pitr_config(&refused_db, &backup_dir, &wal_dir, None),
            &RecoveryTargetSpec::Time(now_rfc3339()),
            false,
            None,
        )
        .await;
        assert!(
            matches!(&refused, Err(PitrError::NotRecoverable(msg)) if msg.contains("db-scan")),
            "{refused:?}"
        );
        assert!(!refused_db.exists());
        let before_db = workdir.path().join("before.db");
        let before_config = pitr_config(&before_db, &backup_dir, &wal_dir, None);
        pitr_recover_server_core(&before_config, &RecoveryTargetSpec::Latest, false, None)
            .await
            .expect("Recovery to the latest point before the repairs failed");
        let mut recovered = setup_async_test(before_config).await;
        login_put_admin_idm_admins(&recovered.rsclient).await;
        assert!(person_exists(&recovered.rsclient, PITR_USER_BEFORE).await);
        recovered.core_handle.shutdown().await;

        // An online backup taken after the repairs is a base past them.
        let mut env = setup_async_test(config.clone()).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        env.core_handle
            .trigger_online_backup(&backup_dir, 7, BackupCompression::Gzip, &Default::default())
            .await
            .expect("Online backup failed");
        env.rsclient
            .idm_person_account_create(PITR_USER_AFTER, "After")
            .await
            .expect("Failed to create the person after the repair");
        env.core_handle.shutdown().await;
        let after_db = workdir.path().join("after.db");
        let after_config = pitr_config(&after_db, &backup_dir, &wal_dir, None);
        pitr_recover_server_core(&after_config, &RecoveryTargetSpec::Latest, false, None)
            .await
            .expect("Recovery from the base taken after the repairs failed");
        let mut recovered = setup_async_test(after_config).await;
        login_put_admin_idm_admins(&recovered.rsclient).await;
        assert!(person_exists(&recovered.rsclient, PITR_USER_BEFORE).await);
        assert!(person_exists(&recovered.rsclient, PITR_USER_AFTER).await);
        recovered.core_handle.shutdown().await;
    });
}

/// A manual `kubidmd database backup` written into the base backup directory under a backup
/// name is a recovery base like an online backup: recovery can use it right away, and the
/// server indexes it at its next archive run.
#[test]
fn test_pitr_manual_backup_in_the_base_directory_is_a_base() {
    run(async {
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

        // No online backup is ever taken.
        let mut env = setup_async_test(config.clone()).await;
        populate(&env).await;
        env.core_handle.shutdown().await;
        assert!(!pitr_list_server_core(&config, None).await);

        // A manual backup elsewhere is not a base; one in the base directory is.
        let key = format!("backup-{}.json.gz", now_rfc3339());
        let elsewhere = workdir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("Failed to create a directory");
        assert!(backup_server_core(&config, Some(&elsewhere.join(&key)), None).await);
        assert!(!pitr_list_server_core(&config, None).await);
        assert!(backup_server_core(&config, Some(&backup_dir.join(&key)), None).await);
        assert!(
            pitr_list_server_core(&config, None).await,
            "Recovery can start from the manual backup before the server indexed it"
        );

        // The server indexes it, and archives what follows.
        let mut env = setup_async_test(config.clone()).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        env.rsclient
            .idm_person_account_create(PITR_USER_AFTER, "After")
            .await
            .expect("Failed to create the person after the manual backup");
        env.core_handle.shutdown().await;
        let manifest = read_manifest(&wal_dir.join(PITR_MANIFEST_KEY));
        assert_eq!(
            manifest
                .base_backups
                .iter()
                .map(|base| base.key.as_str())
                .collect::<Vec<_>>(),
            vec![key.as_str()]
        );
        assert!(
            std::fs::read_dir(wal_dir.join(HANDED_OVER_BASES_DIR))
                .expect("Failed to read the hand-over directory")
                .next()
                .is_none(),
            "The hand-over file goes once the manifest records the base"
        );

        let recovered_db = workdir.path().join("recovered.db");
        let recovered_config = pitr_config(&recovered_db, &backup_dir, &wal_dir, None);
        let outcome =
            pitr_recover_server_core(&recovered_config, &RecoveryTargetSpec::Latest, false, None)
                .await
                .expect("Recovery from the manual backup failed");
        assert_eq!(outcome.plan.base.key, key);
        let mut recovered = setup_async_test(recovered_config).await;
        login_put_admin_idm_admins(&recovered.rsclient).await;
        assert_directory_state_restored(&recovered.rsclient).await;
        assert!(person_exists(&recovered.rsclient, PITR_USER_AFTER).await);
        recovered.core_handle.shutdown().await;
    });
}

// === S3 ===

/// An object under the prefix that is neither a backup nor part of the archive.
const FOREIGN_OBJECT: &str = "notes/readme.txt";

#[test]
fn test_pitr_s3_recover_on_a_new_host() {
    let Some(s3_config) = test_s3_config("pitr-test") else {
        return;
    };

    run(async {
        let sdk = sdk_client(&s3_config).await;
        ensure_bucket(&sdk, &s3_config.bucket).await;
        assert!(object_keys(&sdk, &s3_config).await.is_empty());

        // An object of someone else under the prefix, which no retention may touch.
        sdk.put_object()
            .bucket(&s3_config.bucket)
            .key(full_key(&s3_config, FOREIGN_OBJECT))
            .body(ByteStream::from_static(b"not a backup"))
            .send()
            .await
            .expect("Failed to upload the foreign object");

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
        // Two backups with a retention of one: retention deletes the first one, and must
        // leave the archive and the foreign object alone.
        for round in 0..2 {
            if round > 0 {
                // Backup keys carry the timestamp; make sure they differ.
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
            env.core_handle
                .trigger_s3_backup(
                    s3_config.clone(),
                    1,
                    BackupCompression::Gzip,
                    &Default::default(),
                )
                .await
                .expect("S3 backup failed");
        }
        let target = write_history(env).await;

        // Everything was shipped: the local WAL directory holds no segment any more, and
        // the prefix holds the base backup and the segments, each with its metadata
        // sidecar, and the manifest, a single object. Backup retention deleted the older
        // backup only.
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
        assert!(keys.iter().any(|key| key == FOREIGN_OBJECT), "{keys:?}");
        assert!(keys
            .iter()
            .filter(|key| {
                !key.ends_with(".metadata.json")
                    && key.as_str() != FOREIGN_OBJECT
                    && key.as_str() != PITR_MANIFEST_KEY
            })
            .all(|key| keys.contains(&format!("{key}.metadata.json"))));
        assert!(!keys.contains(&format!("{PITR_MANIFEST_KEY}.metadata.json")));

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

        delete_prefix(&sdk, &s3_config).await;
    });
}

// === Interplay with client-side encryption and cross-region replication ===

const PITR_PASSPHRASE: &str = "pitr e2e passphrase, long enough to matter";
const PITR_KEY_ID: &str = "pitr-e2e-key";
const PITR_REGION: &str = "eu-west-1";

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

/// The keys of the WAL segments among `keys`.
fn segment_keys(keys: &[String]) -> Vec<String> {
    keys.iter()
        .filter(|key| key.starts_with("wal/wal-") && !key.ends_with(".metadata.json"))
        .cloned()
        .collect()
}

async fn s3_manifest(sdk: &SdkClient, s3_config: &S3Config) -> PitrManifest {
    serde_json::from_slice(&s3_object(sdk, s3_config, PITR_MANIFEST_KEY).await)
        .expect("Failed to parse the manifest")
}

/// Encryption, replication and PITR together, against S3: the base backups and the WAL
/// segments are encrypted before they leave the host, both are replicated to a region, and
/// the region alone is enough to recover once the primary archive is gone. The region keeps
/// its copy when the primary starts over, applies retention to it on its own, and hands the
/// history its recovery abandoned back to the primary.
#[test]
fn test_pitr_s3_encrypted_replicated_recover_from_region() {
    let Some(mut s3_config) = test_s3_config("pitr-test") else {
        return;
    };
    let region = test_s3_region(&s3_config, PITR_REGION, "pitr-dr");
    s3_config.replication = Some(ReplicationConfig {
        enabled: true,
        regions: vec![region.clone()],
        sync_interval_seconds: 3600,
    });
    let region_s3 = region.to_s3_config();

    // The scenario is long enough for its future to overflow the stack of the test thread
    // in a debug build; keep it on the heap.
    run(Box::pin(async {
        let sdk = sdk_client(&s3_config).await;
        ensure_bucket(&sdk, &s3_config.bucket).await;
        ensure_bucket(&sdk, &region_s3.bucket).await;
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
        delete_prefix(&sdk, &s3_config).await;
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
            WalArchiver::open(
                settings.backend_wal_config(),
                region_manifest.server_uuid,
                wal_dir.clone(),
                None,
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

        delete_prefix(&sdk, &s3_config).await;
        delete_prefix(&sdk, &region_s3).await;
    }));
}

/// `replicate-status` reports the replicated WAL archive per region (manifest and every
/// segment copy), and the archive runs of the server repair what a region lost or holds
/// damaged, so that a recovery from the region works again.
#[test]
fn test_pitr_s3_replicate_status_reports_and_the_archive_repairs_region_copies() {
    let Some(mut s3_config) = test_s3_config("pitr-status") else {
        return;
    };
    let region = test_s3_region(&s3_config, PITR_REGION, "pitr-status-dr");
    s3_config.replication = Some(ReplicationConfig {
        enabled: true,
        regions: vec![region.clone()],
        sync_interval_seconds: 3600,
    });
    let region_s3 = region.to_s3_config();

    run(Box::pin(async {
        let sdk = sdk_client(&s3_config).await;
        ensure_bucket(&sdk, &s3_config.bucket).await;
        ensure_bucket(&sdk, &region_s3.bucket).await;
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let config = pitr_config(
            &workdir.path().join("source.db"),
            &workdir.path().join("backups"),
            &workdir.path().join("wal"),
            Some(s3_config.clone()),
        );
        let settings = PitrSettings::from_config(&config)
            .expect("Invalid PITR settings")
            .expect("PITR is enabled");

        let mut env = setup_async_test(config.clone()).await;
        populate(&env).await;
        env.core_handle
            .trigger_s3_backup(
                s3_config.clone(),
                7,
                BackupCompression::Gzip,
                &Default::default(),
            )
            .await
            .expect("Replicated S3 backup failed");
        env.rsclient
            .idm_person_account_create(PITR_USER_BEFORE, "Before")
            .await
            .expect("Failed to create a person");
        archive_now(&env).await;
        env.rsclient
            .idm_person_account_create(PITR_USER_AFTER, "After")
            .await
            .expect("Failed to create a person");
        env.core_handle.shutdown().await;

        // Everything is replicated: backups and archive.
        let health = check_wal_replication(&settings)
            .await
            .expect("Unable to check the WAL archive replication")
            .expect("The archive is replicated");
        assert!(health.is_healthy(), "{health:#?}");
        assert!(health.segments >= 2, "{health:#?}");
        assert!(replicate_status_server_core(&config, true).await);

        // The region loses one segment, holds a truncated copy of another, and its
        // manifest is overwritten with something unreadable.
        let segments = segment_keys(&object_keys(&sdk, &region_s3).await);
        let region_prefix = region_s3.path_prefix.as_deref().expect("No prefix");
        sdk.delete_object()
            .bucket(&region_s3.bucket)
            .key(format!("{region_prefix}/{}", segments[0]))
            .send()
            .await
            .expect("Failed to delete a region segment");
        for (key, body) in [
            (segments[1].as_str(), b"truncated".as_slice()),
            (PITR_MANIFEST_KEY, b"{ not a manifest".as_slice()),
        ] {
            sdk.put_object()
                .bucket(&region_s3.bucket)
                .key(format!("{region_prefix}/{key}"))
                .body(ByteStream::from(body.to_vec()))
                .send()
                .await
                .expect("Failed to damage a region object");
        }
        let health = check_wal_replication(&settings)
            .await
            .expect("Unable to check the WAL archive replication")
            .expect("The archive is replicated");
        let region_health = &health.regions[0];
        assert!(!health.is_healthy());
        assert!(
            matches!(region_health.manifest, RegionManifestState::Damaged(_)),
            "{region_health:#?}"
        );
        assert_eq!(
            region_health.segments.missing.len(),
            1,
            "{region_health:#?}"
        );
        assert_eq!(
            region_health.segments.damaged.len(),
            1,
            "{region_health:#?}"
        );
        assert!(!replicate_status_server_core(&config, true).await);
        let unreadable = pitr_recover_server_core(
            &pitr_config(
                &workdir.path().join("unused.db"),
                &workdir.path().join("backups"),
                &workdir.path().join("wal"),
                Some(s3_config.clone()),
            ),
            &RecoveryTargetSpec::Latest,
            true,
            Some(PITR_REGION),
        )
        .await;
        assert!(unreadable.is_err(), "{unreadable:?}");

        // The archive run of the next start repairs the region.
        let mut env = setup_async_test(config.clone()).await;
        archive_now(&env).await;
        env.core_handle.shutdown().await;
        let health = check_wal_replication(&settings)
            .await
            .expect("Unable to check the WAL archive replication")
            .expect("The archive is replicated");
        assert!(health.is_healthy(), "{health:#?}");
        assert!(replicate_status_server_core(&config, false).await);

        // And the region recovers the latest state again.
        let recovered_config = pitr_config(
            &workdir.path().join("recovered.db"),
            &workdir.path().join("backups"),
            &workdir.path().join("wal"),
            Some(s3_config.clone()),
        );
        pitr_recover_server_core(
            &recovered_config,
            &RecoveryTargetSpec::Latest,
            false,
            Some(PITR_REGION),
        )
        .await
        .expect("Recovery from the repaired region failed");
        let mut env = setup_async_test(recovered_config).await;
        login_put_admin_idm_admins(&env.rsclient).await;
        assert!(person_exists(&env.rsclient, PITR_USER_BEFORE).await);
        assert!(person_exists(&env.rsclient, PITR_USER_AFTER).await);
        env.core_handle.shutdown().await;

        delete_prefix(&sdk, &s3_config).await;
        delete_prefix(&sdk, &region_s3).await;
    }));
}

// === Restores abandon history ===

/// An endpoint nothing listens on.
const UNREACHABLE_ENDPOINT: &str = "http://127.0.0.1:1";

/// Created on the source after its base backup, and abandoned by a restore of that backup.
const PITR_USER_ABANDONED: &str = "pitr_user_abandoned";

/// Boot the database a restore produced from the base backup of `write_abandoned_history`:
/// the abandoned write is not there. Write new history on it and shut it down.
async fn write_new_history_after_restore(config: Configuration) {
    let mut env = setup_async_test(config).await;
    login_put_admin_idm_admins(&env.rsclient).await;
    assert_directory_state_restored(&env.rsclient).await;
    assert!(!person_exists(&env.rsclient, PITR_USER_ABANDONED).await);
    env.rsclient
        .idm_person_account_create(PITR_USER_NEW_HISTORY, "New history")
        .await
        .expect("Failed to create the person on the restored server");
    env.core_handle.shutdown().await;
}

/// Write a person after the base backup on `env`, archive it, and shut the server down.
async fn write_abandoned_history(mut env: AsyncTestEnvironment) {
    env.rsclient
        .idm_person_account_create(PITR_USER_ABANDONED, "Abandoned")
        .await
        .expect("Failed to create the person after the base backup");
    archive_now(&env).await;
    env.core_handle.shutdown().await;
}

/// Recover `config` to the latest point and check that it holds the history written after
/// the restore, and not the history the restore abandoned.
async fn assert_latest_skips_abandoned_history(config: Configuration) {
    pitr_recover_server_core(&config, &RecoveryTargetSpec::Latest, false, None)
        .await
        .expect("Recovery to the latest point failed");
    let mut env = setup_async_test(config).await;
    login_put_admin_idm_admins(&env.rsclient).await;
    assert_directory_state_restored(&env.rsclient).await;
    assert!(
        person_exists(&env.rsclient, PITR_USER_NEW_HISTORY).await,
        "The history written after the restore must be recovered"
    );
    assert!(
        !person_exists(&env.rsclient, PITR_USER_ABANDONED).await,
        "The history the restore abandoned must never be replayed"
    );
    env.core_handle.shutdown().await;
}

/// `kubidmd database restore` of a base backup, with WAL archiving configured, records in
/// the archive that the history after the backup was abandoned, so a later `recover` never
/// replays it.
#[test]
fn test_pitr_restore_abandons_the_history_after_the_backup() {
    run(async {
        let workdir = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = workdir.path().join("backups");
        let wal_dir = workdir.path().join("wal");
        let config = pitr_config(
            &workdir.path().join("source.db"),
            &backup_dir,
            &wal_dir,
            None,
        );

        let env = setup_async_test(config.clone()).await;
        populate(&env).await;
        let base = backup_via_production_path(
            &env,
            &backup_dir,
            BackupCompression::Gzip,
            &Default::default(),
        )
        .await;
        write_abandoned_history(env).await;
        assert!(read_manifest(&wal_dir.join(PITR_MANIFEST_KEY))
            .timeline_breaks
            .is_empty());

        // Restore the base into the configured database, as after a bad change.
        let status = restore_server_core(&config, &base)
            .await
            .expect("Restore failed");
        assert_eq!(status, RestoreStatus::Complete);
        let breaks = read_manifest(&wal_dir.join(PITR_MANIFEST_KEY)).timeline_breaks;
        assert_eq!(breaks.len(), 1, "{breaks:?}");

        write_new_history_after_restore(config).await;
        assert_latest_skips_abandoned_history(pitr_config(
            &workdir.path().join("latest.db"),
            &backup_dir,
            &wal_dir,
            None,
        ))
        .await;
    });
}

/// `restore-s3` records the abandoned history in the S3 archive like `restore`, and
/// reports, without failing, a restore whose archive could not be reached.
#[test]
fn test_pitr_s3_restore_abandons_history_and_reports_an_archive_it_can_not_update() {
    let Some(s3_config) = test_s3_config("pitr-restore-test") else {
        return;
    };

    run(async {
        let sdk = sdk_client(&s3_config).await;
        ensure_bucket(&sdk, &s3_config.bucket).await;

        let host = tempfile::tempdir().expect("Failed to create workdir");
        let host_config = |db: &str| {
            pitr_config(
                &host.path().join(db),
                &host.path().join("backups"),
                &host.path().join("wal"),
                Some(s3_config.clone()),
            )
        };
        let config = host_config("source.db");

        let env = setup_async_test(config.clone()).await;
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
        write_abandoned_history(env).await;
        let base = s3_manifest(&sdk, &s3_config)
            .await
            .base_backups
            .first()
            .expect("The base backup is indexed")
            .key
            .clone();

        // The archive can not be updated: its endpoint is unreachable, as during an
        // outage, or its bucket does not exist. The database is restored, the status says
        // the archive was not updated (exit code 2), and the restore is handed to the
        // server's first synchronisation through its WAL directory. Each of these hosts has
        // its own WAL directory, so that what they hand over stays out of the restore below.
        fn unreachable_endpoint(s3: &mut S3Config) {
            s3.endpoint = Some(UNREACHABLE_ENDPOINT.to_string());
        }
        fn missing_bucket(s3: &mut S3Config) {
            s3.bucket = format!("kubidm-test-missing-{}", Uuid::new_v4());
        }
        let failures = [
            ("unreachable", unreachable_endpoint as fn(&mut S3Config)),
            ("missing-bucket", missing_bucket),
        ];
        for (name, break_archive) in failures {
            let db = host.path().join(format!("{name}.db"));
            let wal_dir = host.path().join(format!("{name}-wal"));
            let mut failing = pitr_config(
                &db,
                &host.path().join("backups"),
                &wal_dir,
                Some(s3_config.clone()),
            );
            if let Some(s3) = failing
                .online_backup
                .as_mut()
                .and_then(|backup| backup.s3.as_mut())
            {
                break_archive(s3);
            }
            let status = restore_s3_database(&failing, s3_config.clone(), &base)
                .await
                .expect("The restore itself must succeed");
            assert_eq!(status, RestoreStatus::WalArchiveNotUpdated, "{name}");
            assert_eq!(status.exit_code(), 2, "{name}");
            assert!(db.exists(), "{name}");
            assert_eq!(read_pending_events(&wal_dir).restores.len(), 1, "{name}");
        }
        assert!(s3_manifest(&sdk, &s3_config)
            .await
            .timeline_breaks
            .is_empty());

        // The archive is reachable: the abandoned history is recorded.
        let status = restore_s3_database(&config, s3_config.clone(), &base)
            .await
            .expect("Restore from S3 failed");
        assert_eq!(status, RestoreStatus::Complete);
        let breaks = s3_manifest(&sdk, &s3_config).await.timeline_breaks;
        assert_eq!(breaks.len(), 1, "{breaks:?}");

        write_new_history_after_restore(config).await;
        let new_host = tempfile::tempdir().expect("Failed to create workdir");
        assert_latest_skips_abandoned_history(pitr_config(
            &new_host.path().join("latest.db"),
            &new_host.path().join("backups"),
            &new_host.path().join("wal"),
            Some(s3_config.clone()),
        ))
        .await;

        delete_prefix(&sdk, &s3_config).await;
    });
}

// === A WAL archive in its own S3 location ===

/// `config` with the WAL archive in `wal_s3`, `[online_backup.wal_archive.s3]`, instead of
/// the location of the base backups.
fn with_wal_s3(mut config: Configuration, wal_s3: &S3Config) -> Configuration {
    if let Some(wal) = config
        .online_backup
        .as_mut()
        .and_then(|backup| backup.wal_archive.as_mut())
    {
        wal.s3 = Some(wal_s3.clone());
    }
    config
}

fn replicated_to(s3_config: S3Config, region: &ReplicationRegionConfig) -> S3Config {
    S3Config {
        replication: Some(ReplicationConfig {
            enabled: true,
            regions: vec![region.clone()],
            sync_interval_seconds: 3600,
        }),
        ..s3_config
    }
}

/// The WAL archive in `[online_backup.wal_archive.s3]`, the base backups in
/// `[online_backup.s3]`, each replicating to a region of the same name: recovery reads the
/// segments from one location and the bases from the other, from the primaries and from
/// the region.
#[test]
fn test_pitr_s3_separate_wal_location_recovers_from_primary_and_region() {
    let Some(base_s3) = test_s3_config("pitr-bases") else {
        return;
    };
    let Some(wal_s3) = test_s3_config("pitr-wal") else {
        return;
    };
    let base_region = test_s3_region(&base_s3, PITR_REGION, "pitr-bases-dr");
    let wal_region = test_s3_region(&wal_s3, PITR_REGION, "pitr-wal-dr");
    let base_s3 = replicated_to(base_s3, &base_region);
    let wal_s3 = replicated_to(wal_s3, &wal_region);
    let base_region_s3 = base_region.to_s3_config();
    let wal_region_s3 = wal_region.to_s3_config();

    run(Box::pin(async {
        let sdk = sdk_client(&base_s3).await;
        ensure_bucket(&sdk, &base_s3.bucket).await;
        ensure_bucket(&sdk, &base_region_s3.bucket).await;

        let host_config = |host: &Path, db: &str, base_s3: &S3Config, wal_s3: &S3Config| {
            with_wal_s3(
                pitr_config(
                    &host.join(db),
                    &host.join("backups"),
                    &host.join("wal"),
                    Some(base_s3.clone()),
                ),
                wal_s3,
            )
        };

        let source_host = tempfile::tempdir().expect("Failed to create workdir");
        let env = setup_async_test(host_config(
            source_host.path(),
            "source.db",
            &base_s3,
            &wal_s3,
        ))
        .await;
        populate(&env).await;
        env.core_handle
            .trigger_s3_backup(
                base_s3.clone(),
                7,
                BackupCompression::Gzip,
                &Default::default(),
            )
            .await
            .expect("S3 backup failed");
        let target = write_history(env).await;

        // The bases are in the backup location and its region, the archive in the WAL
        // location and its region, and nothing of either in the other.
        let base_keys = object_keys(&sdk, &base_s3).await;
        let backups: Vec<String> = base_keys
            .iter()
            .filter(|key| !key.ends_with(".metadata.json"))
            .cloned()
            .collect();
        assert_eq!(backups.len(), 1, "{base_keys:?}");
        assert!(backups[0].starts_with("backup-"), "{base_keys:?}");
        assert_eq!(object_keys(&sdk, &base_region_s3).await, base_keys);
        for location in [&wal_s3, &wal_region_s3] {
            let keys = object_keys(&sdk, location).await;
            assert!(keys.iter().any(|key| key == PITR_MANIFEST_KEY), "{keys:?}");
            assert!(segment_keys(&keys).len() >= 2, "{keys:?}");
            assert!(
                !keys.iter().any(|key| key.starts_with("backup-")),
                "{keys:?}"
            );
        }
        let manifest = s3_manifest(&sdk, &wal_s3).await;
        assert_eq!(
            manifest.base_backups.len(),
            1,
            "{:?}",
            manifest.base_backups
        );
        assert_eq!(manifest.base_backups[0].key, backups[0]);
        assert_eq!(
            s3_manifest(&sdk, &wal_region_s3).await.base_backups,
            manifest.base_backups
        );

        // A new host recovers from the primaries: segments from the WAL location, the base
        // from the backup location.
        let new_host = tempfile::tempdir().expect("Failed to create workdir");
        let recovered_config = host_config(new_host.path(), "recovered.db", &base_s3, &wal_s3);
        assert!(pitr_list_server_core(&recovered_config, None).await);
        pitr_recover_server_core(
            &recovered_config,
            &RecoveryTargetSpec::Time(target.clone()),
            false,
            None,
        )
        .await
        .expect("Recovery from the primaries failed");
        let mut env = assert_state_at_target(recovered_config).await;
        env.core_handle.shutdown().await;

        // Both primaries are unreachable: `--region` finds the archive in the region of the
        // WAL location and the base in the region of the same name of the backup location.
        let missing = |s3: &S3Config| S3Config {
            bucket: format!("kubidm-test-missing-{}", Uuid::new_v4()),
            ..s3.clone()
        };
        let region_host = tempfile::tempdir().expect("Failed to create workdir");
        let from_region = host_config(
            region_host.path(),
            "from-region.db",
            &missing(&base_s3),
            &missing(&wal_s3),
        );
        assert!(!pitr_list_server_core(&from_region, None).await);
        assert!(pitr_list_server_core(&from_region, Some(PITR_REGION)).await);
        pitr_recover_server_core(
            &from_region,
            &RecoveryTargetSpec::Time(target),
            false,
            Some(PITR_REGION),
        )
        .await
        .expect("Recovery from the region failed");
        let mut env = assert_state_at_target(from_region).await;
        env.core_handle.shutdown().await;

        // Without a region of that name in the backup location, the bases can not be found
        // in a region, and `--region` is refused.
        let unreplicated_bases = S3Config {
            replication: None,
            ..base_s3.clone()
        };
        let refused_db = region_host.path().join("refused.db");
        let refused = pitr_recover_server_core(
            &host_config(
                region_host.path(),
                "refused.db",
                &unreplicated_bases,
                &wal_s3,
            ),
            &RecoveryTargetSpec::Latest,
            true,
            Some(PITR_REGION),
        )
        .await;
        assert!(
            matches!(&refused, Err(PitrError::Config(msg)) if msg.contains("[online_backup.s3]")),
            "{refused:?}"
        );
        assert!(!refused_db.exists());

        for location in [&base_s3, &wal_s3, &base_region_s3, &wal_region_s3] {
            delete_prefix(&sdk, location).await;
        }
    }));
}

/// The WAL archive in `[online_backup.wal_archive.s3]` and the base backups in the local
/// backup directory: a new host recovers with that directory and the S3 archive.
#[test]
fn test_pitr_s3_wal_location_with_local_bases() {
    let Some(wal_s3) = test_s3_config("pitr-wal-local-bases") else {
        return;
    };

    run(async {
        let sdk = sdk_client(&wal_s3).await;
        ensure_bucket(&sdk, &wal_s3.bucket).await;

        let host_config = |host: &Path, db: &str, backup_dir: &Path| {
            with_wal_s3(
                pitr_config(&host.join(db), backup_dir, &host.join("wal"), None),
                &wal_s3,
            )
        };
        let source_host = tempfile::tempdir().expect("Failed to create workdir");
        let backup_dir = source_host.path().join("backups");
        let env = setup_async_test(host_config(source_host.path(), "source.db", &backup_dir)).await;
        populate(&env).await;
        let base = backup_via_production_path(
            &env,
            &backup_dir,
            BackupCompression::Gzip,
            &Default::default(),
        )
        .await;
        let target = write_history(env).await;

        // Segments and the manifest went to S3; the base stayed local.
        let keys = object_keys(&sdk, &wal_s3).await;
        assert!(keys.iter().any(|key| key == PITR_MANIFEST_KEY), "{keys:?}");
        assert!(segment_keys(&keys).len() >= 2, "{keys:?}");
        assert!(
            !keys.iter().any(|key| key.starts_with("backup-")),
            "{keys:?}"
        );

        // A new host without the backup directory can not recover.
        let new_host = tempfile::tempdir().expect("Failed to create workdir");
        let new_backup_dir = new_host.path().join("backups");
        std::fs::create_dir(&new_backup_dir).expect("Failed to create backup directory");
        let without_bases = host_config(new_host.path(), "without-bases.db", &new_backup_dir);
        assert!(
            pitr_recover_server_core(
                &without_bases,
                &RecoveryTargetSpec::Time(target.clone()),
                false,
                None,
            )
            .await
            .is_err(),
            "Recovery must fail without the local base backup"
        );
        assert!(!new_host.path().join("without-bases.db").exists());

        // With a copy of the backup directory it recovers.
        let file_name = base.file_name().expect("The base has no file name");
        std::fs::copy(&base, new_backup_dir.join(file_name)).expect("Failed to copy the base");
        let recovered_config = host_config(new_host.path(), "recovered.db", &new_backup_dir);
        pitr_recover_server_core(
            &recovered_config,
            &RecoveryTargetSpec::Time(target),
            false,
            None,
        )
        .await
        .expect("Recovery with the local base and the S3 archive failed");
        let mut env = assert_state_at_target(recovered_config).await;
        env.core_handle.shutdown().await;

        delete_prefix(&sdk, &wal_s3).await;
    });
}
