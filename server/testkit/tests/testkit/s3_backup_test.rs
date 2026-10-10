use kubidm_proto::backup::{
    BackupCompression, ReplicationConfig, ReplicationRegionConfig, ReplicationStatus,
    S3BackupMetadata, S3Config, S3Credentials, S3EncryptionAlgorithm, S3ServerSideEncryption,
};
use kubidmd_core::backup::{
    create_empty_backup_data, create_large_backup_data, create_medium_backup_data,
    create_small_backup_data, create_test_backup_data, MockS3Error, MockS3TestBuilder,
    MockS3TestContext,
};

fn create_test_context() -> MockS3TestContext {
    MockS3TestBuilder::new()
        .with_bucket("kubidm-backups")
        .build()
}

fn create_test_context_with_prefix(prefix: &str) -> MockS3TestContext {
    MockS3TestBuilder::new()
        .with_bucket("kubidm-backups")
        .with_prefix(prefix)
        .build()
}

fn create_test_s3_config() -> S3Config {
    S3Config {
        bucket: "kubidm-backups".to_string(),
        region: Some("us-east-1".to_string()),
        endpoint: Some("https://s3.us-east-1.amazonaws.com".to_string()),
        path_prefix: Some("kubidm/backups".to_string()),
        credentials: Some(S3Credentials {
            access_key_id: "test-access-key".to_string(),
            secret_access_key: "test-secret-key".to_string(),
            session_token: None,
        }),
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        replication: None,
    }
}

fn create_test_s3_config_with_encryption() -> S3Config {
    S3Config {
        bucket: "kubidm-backups".to_string(),
        region: Some("us-east-1".to_string()),
        endpoint: None,
        path_prefix: None,
        credentials: None,
        server_side_encryption: Some(S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::AwsKms),
            kms_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/test-key".to_string()),
        }),
        storage_class: "STANDARD".to_string(),
        replication: None,
    }
}

fn create_test_replication_config() -> ReplicationConfig {
    ReplicationConfig {
        enabled: true,
        regions: vec![
            ReplicationRegionConfig {
                name: None,
                region: "eu-west-1".to_string(),
                bucket: "kubidm-backups-eu".to_string(),
                endpoint: Some("https://s3.eu-west-1.amazonaws.com".to_string()),
                path_prefix: Some("kubidm/backups".to_string()),
                credentials: None,
                server_side_encryption: None,
                storage_class: "STANDARD".to_string(),
                kms_key_id: None,
            },
            ReplicationRegionConfig {
                name: None,
                region: "ap-southeast-1".to_string(),
                bucket: "kubidm-backups-ap".to_string(),
                endpoint: None,
                path_prefix: None,
                credentials: None,
                server_side_encryption: None,
                storage_class: "STANDARD".to_string(),
                kms_key_id: None,
            },
        ],
        sync_interval_seconds: 300,
    }
}

#[test]
fn test_s3_backup_upload_basic() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    let metadata = ctx
        .upload_backup(
            "backup-2024-01-15.tar.gz",
            &data,
            "2024-01-15T10:00:00Z",
            BackupCompression::Gzip,
        )
        .expect("Failed to upload backup");

    assert_eq!(metadata.size_bytes, data.len() as u64);
    assert_eq!(metadata.compression, BackupCompression::Gzip);
    assert!(!metadata.encrypted);
}

#[test]
fn test_s3_backup_download_basic() {
    let ctx = create_test_context();
    let data = create_medium_backup_data();

    ctx.upload_backup(
        "backup-2024-01-15.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("Failed to upload backup");

    let (downloaded_data, metadata) = ctx
        .download_backup("backup-2024-01-15.tar.gz")
        .expect("Failed to download backup");

    assert_eq!(downloaded_data, data);
    assert_eq!(metadata.size_bytes, data.len() as u64);
}

#[test]
fn test_s3_backup_roundtrip_consistency() {
    let ctx = create_test_context();

    for size in [100, 1024, 10 * 1024, 100 * 1024] {
        let data = create_test_backup_data(size);

        let metadata = ctx
            .upload_backup(
                &format!("backup-{}.tar.gz", size),
                &data,
                "2024-01-15T10:00:00Z",
                BackupCompression::Gzip,
            )
            .expect("Failed to upload backup");

        let (downloaded, downloaded_meta) = ctx
            .download_backup(&format!("backup-{}.tar.gz", size))
            .expect("Failed to download backup");

        assert_eq!(downloaded, data);
        assert_eq!(downloaded_meta.checksum_sha256, metadata.checksum_sha256);
    }
}

#[test]
fn test_s3_backup_list() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    ctx.upload_backup(
        "backup-1.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");
    ctx.upload_backup(
        "backup-2.tar.gz",
        &data,
        "2024-01-16T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");
    ctx.upload_backup(
        "backup-3.tar.gz",
        &data,
        "2024-01-17T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    let backups = ctx.list_backups().expect("Failed to list backups");

    assert_eq!(backups.len(), 3);
    assert!(backups.contains(&"backup-1.tar.gz".to_string()));
    assert!(backups.contains(&"backup-2.tar.gz".to_string()));
    assert!(backups.contains(&"backup-3.tar.gz".to_string()));
}

#[test]
fn test_s3_backup_delete() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    ctx.upload_backup(
        "backup-to-delete.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    assert!(ctx.object_exists("backup-to-delete.tar.gz"));

    ctx.delete_backup("backup-to-delete.tar.gz")
        .expect("delete failed");

    assert!(!ctx.object_exists("backup-to-delete.tar.gz"));

    let result = ctx.download_backup("backup-to-delete.tar.gz");
    assert!(result.is_err());
}

#[test]
fn test_s3_backup_verify_integrity() {
    let ctx = create_test_context();
    let data = create_medium_backup_data();

    ctx.upload_backup(
        "backup-verify.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    assert!(ctx
        .verify_backup("backup-verify.tar.gz")
        .expect("verify failed"));
}

#[test]
fn test_s3_backup_empty() {
    let ctx = create_test_context();
    let data = create_empty_backup_data();

    let metadata = ctx
        .upload_backup(
            "empty-backup.tar.gz",
            &data,
            "2024-01-15T10:00:00Z",
            BackupCompression::NoCompression,
        )
        .expect("Failed to upload empty backup");

    assert_eq!(metadata.size_bytes, 0);

    let (downloaded, _) = ctx
        .download_backup("empty-backup.tar.gz")
        .expect("Failed to download empty backup");

    assert_eq!(downloaded.len(), 0);
}

#[test]
fn test_s3_backup_with_prefix() {
    let ctx = create_test_context_with_prefix("kubidm/backups/2024");
    let data = create_small_backup_data();

    ctx.upload_backup(
        "jan-backup.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");
    ctx.upload_backup(
        "feb-backup.tar.gz",
        &data,
        "2024-02-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    let backups = ctx.list_backups().expect("list failed");
    assert_eq!(backups.len(), 2);
    assert!(backups.contains(&"jan-backup.tar.gz".to_string()));
    assert!(backups.contains(&"feb-backup.tar.gz".to_string()));
}

#[test]
fn test_s3_backup_overwrite() {
    let ctx = create_test_context();
    let data1 = create_test_backup_data(100);
    let data2 = create_test_backup_data(200);

    ctx.upload_backup(
        "overwrite-backup.tar.gz",
        &data1,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    ctx.upload_backup(
        "overwrite-backup.tar.gz",
        &data2,
        "2024-01-16T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    let (downloaded, metadata) = ctx
        .download_backup("overwrite-backup.tar.gz")
        .expect("download failed");

    assert_eq!(downloaded, data2);
    assert_eq!(metadata.size_bytes, data2.len() as u64);
}

#[test]
fn test_s3_backup_corrupted_detection() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    ctx.upload_backup(
        "corrupt-backup.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    ctx.corrupt_backup("corrupt-backup.tar.gz")
        .expect("corrupt failed");

    let result = ctx.download_backup("corrupt-backup.tar.gz");
    assert!(result.is_err());
    assert!(matches!(result, Err(MockS3Error::InvalidChecksum)));
}

#[test]
fn test_s3_backup_size_mismatch() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    ctx.upload_backup(
        "size-mismatch.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    ctx.set_backup_size("size-mismatch.tar.gz", 5000)
        .expect("size change failed");

    let verified = ctx
        .verify_backup("size-mismatch.tar.gz")
        .expect("verify failed");
    assert!(!verified);
}

#[test]
fn test_s3_backup_nonexistent() {
    let ctx = create_test_context();

    let result = ctx.download_backup("nonexistent-backup.tar.gz");
    assert!(result.is_err());
    assert!(matches!(result, Err(MockS3Error::MetadataNotFound)));

    let result = ctx.delete_backup("nonexistent-backup.tar.gz");
    assert!(result.is_ok());

    let result = ctx.verify_backup("nonexistent-backup.tar.gz");
    assert!(result.is_err());
}

#[test]
fn test_s3_backup_error_simulation() {
    let ctx = MockS3TestBuilder::new()
        .with_bucket("kubidm-backups")
        .simulate_errors(true)
        .build();
    let data = create_small_backup_data();

    let upload_result = ctx.upload_backup(
        "backup.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    );
    assert!(upload_result.is_err());
    assert!(matches!(upload_result, Err(MockS3Error::ConnectionTimeout)));

    let download_result = ctx.download_backup("backup.tar.gz");
    assert!(download_result.is_err());
    assert!(matches!(download_result, Err(MockS3Error::NetworkError)));
}

#[test]
fn test_s3_config_bucket_validation() {
    let config = create_test_s3_config();

    assert!(!config.bucket.is_empty());
    assert!(config.region.is_some());
    assert!(config.endpoint.is_some());
    assert!(config.path_prefix.is_some());
    assert!(config.credentials.is_some());
}

#[test]
fn test_s3_config_minimal() {
    let config = S3Config {
        bucket: "minimal-bucket".to_string(),
        region: None,
        endpoint: None,
        path_prefix: None,
        credentials: None,
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        replication: None,
    };

    assert_eq!(config.bucket, "minimal-bucket");
    assert!(config.region.is_none());
    assert!(config.endpoint.is_none());
}

#[test]
fn test_s3_config_with_encryption() {
    let config = create_test_s3_config_with_encryption();

    assert!(config.server_side_encryption.is_some());
    let sse = config.server_side_encryption.unwrap();
    assert_eq!(sse.algorithm, Some(S3EncryptionAlgorithm::AwsKms));
    assert!(sse.kms_key_id.is_some());
}

#[test]
fn test_s3_config_with_replication() {
    let config = S3Config {
        bucket: "primary-bucket".to_string(),
        region: Some("us-east-1".to_string()),
        endpoint: None,
        path_prefix: None,
        credentials: None,
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        replication: Some(create_test_replication_config()),
    };

    assert!(config.replication.is_some());
    let replication = config.replication.unwrap();
    assert!(replication.enabled);
    assert_eq!(replication.regions.len(), 2);
}

#[test]
fn test_s3_credentials_with_session_token() {
    let creds = S3Credentials {
        access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        session_token: Some("temporary-session-token".to_string()),
    };

    assert!(!creds.access_key_id.is_empty());
    assert!(!creds.secret_access_key.is_empty());
    assert!(creds.session_token.is_some());
}

#[test]
fn test_s3_credentials_without_session_token() {
    let creds = S3Credentials {
        access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        session_token: None,
    };

    assert!(creds.session_token.is_none());
}

#[test]
fn test_replication_config_regions() {
    let config = create_test_replication_config();

    assert!(config.enabled);
    assert_eq!(config.regions.len(), 2);

    let eu_region = &config.regions[0];
    assert_eq!(eu_region.region, "eu-west-1");
    assert_eq!(eu_region.bucket, "kubidm-backups-eu");

    let ap_region = &config.regions[1];
    assert_eq!(ap_region.region, "ap-southeast-1");
    assert_eq!(ap_region.bucket, "kubidm-backups-ap");
}

#[test]
fn test_replication_config_defaults() {
    let config = ReplicationConfig::default();

    assert!(!config.enabled);
    assert_eq!(config.regions.len(), 0);
    assert_eq!(config.sync_interval_seconds, 300);
}

#[test]
fn test_replication_status_display() {
    assert_eq!(
        ReplicationStatus::NotConfigured.to_string(),
        "Not Configured"
    );
    assert_eq!(ReplicationStatus::InProgress.to_string(), "In Progress");
    assert_eq!(ReplicationStatus::Completed.to_string(), "Completed");

    let failed = ReplicationStatus::Failed {
        error: "connection timeout".to_string(),
    };
    assert!(failed.to_string().contains("Failed"));
    assert!(failed.to_string().contains("connection timeout"));

    let degraded = ReplicationStatus::Degraded {
        message: "missing backups".to_string(),
    };
    assert!(degraded.to_string().contains("Degraded"));
    assert!(degraded.to_string().contains("missing backups"));
}

#[test]
fn test_backup_metadata_creation() {
    let metadata = S3BackupMetadata::new(
        "sha256-checksum-value".to_string(),
        "2024-01-15T10:30:00Z".to_string(),
        BackupCompression::Gzip,
        102400,
    );

    assert_eq!(metadata.checksum_sha256, "sha256-checksum-value");
    assert_eq!(metadata.timestamp, "2024-01-15T10:30:00Z");
    assert_eq!(metadata.compression, BackupCompression::Gzip);
    assert_eq!(metadata.size_bytes, 102400);
    assert!(!metadata.encrypted);
    assert!(metadata.key_identifier.is_none());
}

#[test]
fn test_backup_metadata_encrypted() {
    let metadata = S3BackupMetadata::new_encrypted(
        "sha256-checksum".to_string(),
        "2024-01-15T10:30:00Z".to_string(),
        BackupCompression::Gzip,
        2048,
        "encryption-key-id-12345".to_string(),
    );

    assert!(metadata.encrypted);
    assert_eq!(
        metadata.key_identifier,
        Some("encryption-key-id-12345".to_string())
    );
}

#[test]
fn test_backup_compression_variants() {
    assert_eq!(BackupCompression::Gzip.suffix(), ".gz");
    assert_eq!(BackupCompression::NoCompression.suffix(), "");
}

#[test]
fn test_multiple_backups_concurrent_operations() {
    let ctx = create_test_context();

    let mut backup_names = Vec::new();
    for i in 0..20 {
        let name = format!("concurrent-backup-{}.tar.gz", i);
        backup_names.push(name.clone());
        let data = create_test_backup_data(500 + i * 10);
        ctx.upload_backup(
            &name,
            &data,
            "2024-01-15T10:00:00Z",
            BackupCompression::Gzip,
        )
        .expect("upload failed");
    }

    let backups = ctx.list_backups().expect("list failed");
    assert_eq!(backups.len(), 20);

    for name in &backup_names {
        assert!(ctx.object_exists(name));
    }

    for name in &backup_names {
        ctx.delete_backup(name).expect("delete failed");
    }

    assert_eq!(ctx.list_backups().expect("list failed").len(), 0);
}

#[test]
fn test_backup_unicode_names() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    let unicode_names = [
        "backup-日本語.tar.gz",
        "backup-émojis-😀.tar.gz",
        "backup-スペイン語.tar.gz",
        "backup-中文.tar.gz",
        "backup-한국어.tar.gz",
    ];

    for name in &unicode_names {
        ctx.upload_backup(name, &data, "2024-01-15T10:00:00Z", BackupCompression::Gzip)
            .expect("upload failed");
        assert!(ctx.object_exists(name));
    }

    let backups = ctx.list_backups().expect("list failed");
    assert_eq!(backups.len(), unicode_names.len());

    for name in &unicode_names {
        let (downloaded, _) = ctx.download_backup(name).expect("download failed");
        assert_eq!(downloaded, data);
    }
}

#[test]
fn test_backup_special_chars_names() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    let special_names = [
        "backup-with-dashes.tar.gz",
        "backup_with_underscores.tar.gz",
        "backup.with.dots.tar.gz",
        "backup-2024-01-15_10-30.tar.gz",
    ];

    for name in &special_names {
        ctx.upload_backup(name, &data, "2024-01-15T10:00:00Z", BackupCompression::Gzip)
            .expect("upload failed");
        assert!(ctx.object_exists(name));
    }

    let backups = ctx.list_backups().expect("list failed");
    assert_eq!(backups.len(), special_names.len());
}

#[test]
fn test_backup_large_data() {
    let ctx = create_test_context();
    let large_data = create_test_backup_data(1024 * 1024);

    let metadata = ctx
        .upload_backup(
            "large-backup.tar.gz",
            &large_data,
            "2024-01-15T10:00:00Z",
            BackupCompression::Gzip,
        )
        .expect("upload failed");

    assert_eq!(metadata.size_bytes, large_data.len() as u64);

    let (downloaded, _) = ctx
        .download_backup("large-backup.tar.gz")
        .expect("download failed");
    assert_eq!(downloaded.len(), large_data.len());
}

#[test]
fn test_backup_timestamps() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    let timestamps = [
        "2024-01-15T00:00:00Z",
        "2024-01-15T12:30:45Z",
        "2024-12-31T23:59:59Z",
        "2023-06-15T08:15:30+05:00",
    ];

    for (i, ts) in timestamps.iter().enumerate() {
        let metadata = ctx
            .upload_backup(
                &format!("backup-ts-{}.tar.gz", i),
                &data,
                ts,
                BackupCompression::Gzip,
            )
            .expect("upload failed");

        assert_eq!(metadata.timestamp, *ts);
    }
}

#[test]
fn test_backup_compression_types() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    let metadata_gzip = ctx
        .upload_backup(
            "backup-gzip.tar.gz",
            &data,
            "2024-01-15T10:00:00Z",
            BackupCompression::Gzip,
        )
        .expect("upload failed");
    assert_eq!(metadata_gzip.compression, BackupCompression::Gzip);

    let metadata_none = ctx
        .upload_backup(
            "backup-none.tar",
            &data,
            "2024-01-15T10:00:00Z",
            BackupCompression::NoCompression,
        )
        .expect("upload failed");
    assert_eq!(metadata_none.compression, BackupCompression::NoCompression);
}

#[test]
fn test_backup_verification_after_operations() {
    let ctx = create_test_context();
    let data = create_medium_backup_data();

    ctx.upload_backup(
        "test-backup.tar.gz",
        &data,
        "2024-01-15T10:00:00Z",
        BackupCompression::Gzip,
    )
    .expect("upload failed");

    assert!(ctx
        .verify_backup("test-backup.tar.gz")
        .expect("verify failed"));

    let (downloaded, _) = ctx
        .download_backup("test-backup.tar.gz")
        .expect("download failed");
    assert_eq!(downloaded.len(), data.len());

    assert!(ctx
        .verify_backup("test-backup.tar.gz")
        .expect("verify failed"));

    ctx.delete_backup("test-backup.tar.gz")
        .expect("delete failed");
    assert!(!ctx.object_exists("test-backup.tar.gz"));
}

#[test]
fn test_backup_context_clear() {
    let ctx = create_test_context();
    let data = create_small_backup_data();

    for i in 0..10 {
        ctx.upload_backup(
            &format!("backup-{}.tar.gz", i),
            &data,
            "2024-01-15T10:00:00Z",
            BackupCompression::Gzip,
        )
        .expect("upload failed");
    }

    assert_eq!(ctx.backup_count(), 10);

    ctx.clear();

    assert_eq!(ctx.backup_count(), 0);
    assert_eq!(ctx.list_backups().expect("list failed").len(), 0);
}

#[test]
fn test_storage_class_variants() {
    let storage_classes = [
        "STANDARD",
        "REDUCED_REDUNDANCY",
        "STANDARD_IA",
        "ONEZONE_IA",
        "INTELLIGENT_TIERING",
        "GLACIER",
        "DEEP_ARCHIVE",
        "GLACIER_IR",
    ];

    for class in &storage_classes {
        let config = S3Config {
            bucket: "test-bucket".to_string(),
            region: None,
            endpoint: None,
            path_prefix: None,
            credentials: None,
            server_side_encryption: None,
            storage_class: class.to_string(),
            replication: None,
        };

        assert_eq!(config.storage_class, *class);
    }
}

#[test]
fn test_encryption_algorithm_variants() {
    let aes_config = S3ServerSideEncryption {
        algorithm: Some(S3EncryptionAlgorithm::Aes256),
        kms_key_id: None,
    };
    assert_eq!(aes_config.algorithm, Some(S3EncryptionAlgorithm::Aes256));
    assert!(aes_config.kms_key_id.is_none());

    let kms_config = S3ServerSideEncryption {
        algorithm: Some(S3EncryptionAlgorithm::AwsKms),
        kms_key_id: Some("kms-key-arn".to_string()),
    };
    assert_eq!(kms_config.algorithm, Some(S3EncryptionAlgorithm::AwsKms));
    assert!(kms_config.kms_key_id.is_some());
}

#[test]
fn test_replication_region_config_endpoint_handling() {
    let with_endpoint = ReplicationRegionConfig {
        name: None,
        region: "us-west-2".to_string(),
        bucket: "west-bucket".to_string(),
        endpoint: Some("https://s3.us-west-2.amazonaws.com".to_string()),
        path_prefix: None,
        credentials: None,
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        kms_key_id: None,
    };
    assert!(with_endpoint.endpoint.is_some());

    let without_endpoint = ReplicationRegionConfig {
        name: None,
        region: "us-east-1".to_string(),
        bucket: "east-bucket".to_string(),
        endpoint: None,
        path_prefix: None,
        credentials: None,
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        kms_key_id: None,
    };
    assert!(without_endpoint.endpoint.is_none());
}

#[test]
fn test_backup_data_generators() {
    let small = create_small_backup_data();
    assert_eq!(small.len(), 1024);

    let medium = create_medium_backup_data();
    assert_eq!(medium.len(), 10 * 1024);

    let large = create_large_backup_data();
    assert_eq!(large.len(), 1024 * 1024);

    let empty = create_empty_backup_data();
    assert_eq!(empty.len(), 0);

    let custom = create_test_backup_data(500);
    assert_eq!(custom.len(), 500);
}
