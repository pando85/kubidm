//! Relates to backup functionality in the Server
use std::{fmt::Display, path::Path, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};
use serde_with::DeserializeFromStr;
use sketching::tracing::warn;
use uuid::Uuid;

pub const BACKUP_ENCRYPTION_MAGIC: &[u8] = b"KANIDM_ENC_BACKUP_V1";
pub const BACKUP_ENCRYPTION_KEY_LEN: usize = 32;
pub const BACKUP_ENCRYPTION_NONCE_LEN: usize = 12;
pub const BACKUP_ENCRYPTION_SALT_LEN: usize = 16;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, DeserializeFromStr, Serialize)]
pub enum BackupCompression {
    NoCompression,
    #[default]
    Gzip,
}

impl BackupCompression {
    pub fn suffix(&self) -> &'static str {
        match self {
            BackupCompression::NoCompression => "",
            BackupCompression::Gzip => ".gz",
        }
    }

    pub fn identify_file(filepath: &Path) -> Self {
        let filename = filepath.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if filename.ends_with(".gz") {
            BackupCompression::Gzip
        } else {
            BackupCompression::NoCompression
        }
    }
}

impl Display for BackupCompression {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BackupCompression::NoCompression => write!(f, "No Compression"),
            BackupCompression::Gzip => write!(f, "Gzip"),
        }
    }
}

impl From<Option<String>> for BackupCompression {
    fn from(opt: Option<String>) -> Self {
        match opt {
            Some(s) => BackupCompression::from(s),
            None => BackupCompression::default(),
        }
    }
}

impl From<String> for BackupCompression {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "gzip" => BackupCompression::Gzip,
            "none" | "nocompression" => BackupCompression::NoCompression,
            _ => {
                warn!(
                    "Unknown compression type '{}', should be one of nocompression, gzip - defaulting to {}",
                    s,
                    BackupCompression::default()
                );
                BackupCompression::default()
            }
        }
    }
}

impl FromStr for BackupCompression {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.to_string().into())
    }
}

#[test]
fn test_backup_compression_identify() {
    let gzip_path = Path::new("/var/lib/kubidm/backups/backup-2024-01-01.tar.gz");
    let no_comp_path = Path::new("/var/lib/kubidm/backups/backup-2024-01-01.tar");

    assert_eq!(
        BackupCompression::identify_file(gzip_path),
        BackupCompression::Gzip
    );
    assert_eq!(
        BackupCompression::identify_file(no_comp_path),
        BackupCompression::NoCompression
    );

    for (input, expected) in [
        (vec!["gzip", "Gzip", "GzIp"], BackupCompression::Gzip),
        (
            vec!["none", "NoNe", "nocompression", "NoCompression"],
            BackupCompression::NoCompression,
        ),
    ] {
        for i in input {
            assert_eq!(
                BackupCompression::from_str(i).expect("Threw an error?"),
                expected
            );
        }
    }
}

#[test]
fn test_key_derivation_params_default() {
    let params = KeyDerivationParams::default();
    assert_eq!(params.m_cost, 19 * 1024);
    assert_eq!(params.t_cost, 2);
    assert_eq!(params.p_cost, 1);
}

#[test]
fn test_encryption_key_source_display() {
    assert_eq!(EncryptionKeySource::Passphrase.to_string(), "passphrase");
    assert_eq!(
        EncryptionKeySource::File {
            path: "/path/to/key".to_string()
        }
        .to_string(),
        "file:/path/to/key"
    );
    assert_eq!(
        EncryptionKeySource::HttpEndpoint {
            url: "https://vault.example.com/key".to_string()
        }
        .to_string(),
        "http:https://vault.example.com/key"
    );
}

#[test]
fn test_encryption_key_source_serialization() {
    let source_passphrase = EncryptionKeySource::Passphrase;
    let json = serde_json::to_string(&source_passphrase).unwrap();
    assert_eq!(json, "\"Passphrase\"");

    let source_file = EncryptionKeySource::File {
        path: "/path/to/key".to_string(),
    };
    let json = serde_json::to_string(&source_file).unwrap();
    let deserialized: EncryptionKeySource = serde_json::from_str(&json).unwrap();
    assert_eq!(source_file, deserialized);

    let source_http = EncryptionKeySource::HttpEndpoint {
        url: "https://vault.example.com/key".to_string(),
    };
    let json = serde_json::to_string(&source_http).unwrap();
    let deserialized: EncryptionKeySource = serde_json::from_str(&json).unwrap();
    assert_eq!(source_http, deserialized);
}

#[test]
fn test_backup_encryption_config_default() {
    let config = BackupEncryptionConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.key_source, EncryptionKeySource::Passphrase);
    assert!(config.key_identifier.is_none());
}

#[test]
fn test_backup_encryption_config_serialization() {
    let config = BackupEncryptionConfig {
        enabled: true,
        key_source: EncryptionKeySource::File {
            path: "/path/to/key".to_string(),
        },
        key_derivation: KeyDerivationParams::default(),
        key_identifier: Some("key-123".to_string()),
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: BackupEncryptionConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config.enabled, deserialized.enabled);
    assert_eq!(config.key_source, deserialized.key_source);
    assert_eq!(config.key_identifier, deserialized.key_identifier);
}

#[test]
fn test_backup_encryption_config_display() {
    let config = BackupEncryptionConfig {
        enabled: true,
        key_source: EncryptionKeySource::Passphrase,
        key_derivation: KeyDerivationParams::default(),
        key_identifier: None,
    };
    assert!(config.to_string().contains("enabled: true"));
    assert!(config.to_string().contains("key_source: passphrase"));
}

#[test]
fn test_key_derivation_params_custom_values() {
    let params = KeyDerivationParams {
        m_cost: 32 * 1024,
        t_cost: 4,
        p_cost: 2,
    };
    assert_eq!(params.m_cost, 32 * 1024);
    assert_eq!(params.t_cost, 4);
    assert_eq!(params.p_cost, 2);
}

#[test]
fn test_key_derivation_params_serialization() {
    let params = KeyDerivationParams {
        m_cost: 16384,
        t_cost: 3,
        p_cost: 1,
    };

    let json = serde_json::to_string(&params).unwrap();
    let deserialized: KeyDerivationParams = serde_json::from_str(&json).unwrap();

    assert_eq!(params.m_cost, deserialized.m_cost);
    assert_eq!(params.t_cost, deserialized.t_cost);
    assert_eq!(params.p_cost, deserialized.p_cost);
}

#[test]
fn test_key_derivation_params_from_json_partial() {
    let json = "{}";
    let params: KeyDerivationParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.m_cost, 19 * 1024);
    assert_eq!(params.t_cost, 2);
    assert_eq!(params.p_cost, 1);
}

#[test]
fn test_backup_encryption_header_display() {
    let header = BackupEncryptionHeader::new(
        "test-key-id".to_string(),
        vec![0u8; BACKUP_ENCRYPTION_SALT_LEN],
        vec![0u8; BACKUP_ENCRYPTION_NONCE_LEN],
        KeyDerivationParams::default(),
        true,
    );

    let display = header.to_string();
    assert!(display.contains("test-key-id"));
    assert!(display.contains("compressed: true"));
}

#[test]
fn test_backup_encryption_magic_constant() {
    assert_eq!(BACKUP_ENCRYPTION_MAGIC.len(), 20);
    assert_eq!(BACKUP_ENCRYPTION_MAGIC, b"KANIDM_ENC_BACKUP_V1");
}

#[test]
fn test_backup_encryption_key_len_constant() {
    assert_eq!(BACKUP_ENCRYPTION_KEY_LEN, 32);
}

#[test]
fn test_backup_encryption_nonce_len_constant() {
    assert_eq!(BACKUP_ENCRYPTION_NONCE_LEN, 12);
}

#[test]
fn test_backup_encryption_salt_len_constant() {
    assert_eq!(BACKUP_ENCRYPTION_SALT_LEN, 16);
}

#[test]
fn test_s3_backup_metadata_not_encrypted() {
    let meta = S3BackupMetadata::new(
        "sha256".to_string(),
        "2024-01-01".to_string(),
        BackupCompression::Gzip,
        1024,
    );
    assert!(!meta.encrypted);
    assert!(meta.key_identifier.is_none());
}

#[test]
fn test_backup_encryption_header_validate_magic() {
    let header = BackupEncryptionHeader::new(
        "test-key".to_string(),
        vec![0u8; 16],
        vec![0u8; 12],
        KeyDerivationParams::default(),
        false,
    );
    assert!(header.validate_magic());
}

#[test]
fn test_s3_backup_metadata_encrypted() {
    let meta = S3BackupMetadata::new_encrypted(
        "sha256".to_string(),
        "2024-01-01".to_string(),
        BackupCompression::Gzip,
        1024,
        "key-123".to_string(),
    );
    assert!(meta.encrypted);
    assert_eq!(meta.key_identifier, Some("key-123".to_string()));
}

#[test]
fn test_replication_config_default() {
    let config = ReplicationConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.regions.len(), 0);
    assert_eq!(config.sync_interval_seconds, 300);
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.retry_delay_seconds, 30);
}

#[test]
fn test_replication_status_display() {
    assert_eq!(
        ReplicationStatus::NotConfigured.to_string(),
        "Not Configured"
    );
    assert_eq!(ReplicationStatus::InProgress.to_string(), "In Progress");
    assert_eq!(
        ReplicationStatus::Failed {
            error: "network error".to_string()
        }
        .to_string(),
        "Failed: network error"
    );
}

#[test]
fn test_replication_region_status() {
    let status = ReplicationRegionStatus {
        region: "us-west-2".to_string(),
        bucket: "backup-bucket".to_string(),
        status: ReplicationStatus::Completed,
        last_sync_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        last_sync_backup_id: Some("backup-123".to_string()),
        lag_seconds: Some(60),
        bytes_replicated: 1024,
        backups_replicated: 5,
        pending_backups: 0,
        last_error: None,
    };
    assert!(status.last_error.is_none());
    assert_eq!(status.lag_seconds, Some(60));
    assert!(status.to_string().contains("pending: 0"));
}

#[test]
fn test_replication_region_config_to_s3_config() {
    let region = ReplicationRegionConfig {
        region: "eu-west-1".to_string(),
        endpoint: Some("https://s3.eu-west-1.example.com".to_string()),
        bucket: "kubidm-backups-eu".to_string(),
        path_prefix: Some("dr".to_string()),
        credentials: Some(S3Credentials {
            access_key_id: "eu-key".to_string(),
            secret_access_key: "eu-secret".to_string(),
            session_token: None,
        }),
        server_side_encryption: None,
        storage_class: "STANDARD_IA".to_string(),
        kms_key_id: None,
    };

    let s3 = region.to_s3_config();
    assert_eq!(s3.bucket, "kubidm-backups-eu");
    assert_eq!(s3.region.as_deref(), Some("eu-west-1"));
    assert_eq!(
        s3.endpoint.as_deref(),
        Some("https://s3.eu-west-1.example.com")
    );
    assert_eq!(s3.path_prefix.as_deref(), Some("dr"));
    assert_eq!(s3.credentials, region.credentials);
    assert_eq!(s3.server_side_encryption, None);
    assert_eq!(s3.storage_class, "STANDARD_IA");
    assert!(
        s3.replication.is_none(),
        "a replica never replicates further"
    );
}

#[test]
fn test_replication_region_config_to_s3_config_kms_shorthand() {
    let mut region = ReplicationRegionConfig {
        region: "eu-west-1".to_string(),
        endpoint: None,
        bucket: "kubidm-backups-eu".to_string(),
        path_prefix: None,
        credentials: None,
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        kms_key_id: Some("arn:aws:kms:eu-west-1:1:key/eu".to_string()),
    };

    // The shorthand alone selects aws:kms with that key.
    assert_eq!(
        region.to_s3_config().server_side_encryption,
        Some(S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::AwsKms),
            kms_key_id: Some("arn:aws:kms:eu-west-1:1:key/eu".to_string()),
        })
    );

    // An explicit block without a key borrows the shorthand key.
    region.server_side_encryption = Some(S3ServerSideEncryption {
        algorithm: Some(S3EncryptionAlgorithm::AwsKms),
        kms_key_id: None,
    });
    assert_eq!(
        region
            .to_s3_config()
            .server_side_encryption
            .and_then(|sse| sse.kms_key_id)
            .as_deref(),
        Some("arn:aws:kms:eu-west-1:1:key/eu")
    );

    // An explicit block with its own key wins.
    region.server_side_encryption = Some(S3ServerSideEncryption {
        algorithm: Some(S3EncryptionAlgorithm::Aes256),
        kms_key_id: Some("explicit".to_string()),
    });
    assert_eq!(
        region.to_s3_config().server_side_encryption,
        Some(S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::Aes256),
            kms_key_id: Some("explicit".to_string()),
        })
    );
}

#[test]
fn test_replication_health_check() {
    let check = ReplicationHealthCheck {
        overall_status: ReplicationStatus::Completed,
        regions: vec![],
        total_lag_seconds: 120,
        max_lag_seconds: 120,
        healthy_regions: 1,
        unhealthy_regions: 0,
        last_check_timestamp: "2024-01-01T00:00:00Z".to_string(),
    };
    assert_eq!(check.healthy_regions, 1);
    assert_eq!(check.unhealthy_regions, 0);
}

#[test]
fn test_replication_lag_metrics() {
    let metrics = ReplicationLagMetrics {
        region: "eu-west-1".to_string(),
        lag_seconds: 300,
        pending_backups: 2,
        last_backup_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        replication_delay_seconds: 60,
    };
    assert_eq!(metrics.lag_seconds, 300);
    assert_eq!(metrics.pending_backups, 2);
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct S3Config {
    pub bucket: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub credentials: Option<S3Credentials>,
    #[serde(default)]
    pub server_side_encryption: Option<S3ServerSideEncryption>,
    #[serde(default = "default_s3_storage_class")]
    pub storage_class: String,
    #[serde(default)]
    pub replication: Option<ReplicationConfig>,
}

fn default_s3_storage_class() -> String {
    "STANDARD".to_string()
}

impl S3Config {
    /// A minimal configuration for `bucket` with every optional setting unset and the
    /// default storage class. Credentials and region then come from the SDK's default
    /// provider chain (environment, profile, instance role).
    pub fn with_bucket(bucket: String) -> Self {
        Self {
            bucket,
            region: None,
            endpoint: None,
            path_prefix: None,
            credentials: None,
            server_side_encryption: None,
            storage_class: default_s3_storage_class(),
            replication: None,
        }
    }
}

impl Display for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "S3Config {{ bucket: {}, region: {:?}, endpoint: {:?}, replication_enabled: {} }}",
            self.bucket,
            self.region,
            self.endpoint,
            self.replication
                .as_ref()
                .map(|r| r.enabled)
                .unwrap_or(false)
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct S3ServerSideEncryption {
    #[serde(default)]
    pub algorithm: Option<S3EncryptionAlgorithm>,
    #[serde(default)]
    pub kms_key_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub enum S3EncryptionAlgorithm {
    #[serde(rename = "AES256")]
    Aes256,
    #[default]
    #[serde(rename = "aws:kms")]
    AwsKms,
}

impl Display for S3EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S3EncryptionAlgorithm::Aes256 => write!(f, "AES256"),
            S3EncryptionAlgorithm::AwsKms => write!(f, "aws:kms"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReplicationRegionConfig {
    pub region: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    pub bucket: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub credentials: Option<S3Credentials>,
    #[serde(default)]
    pub server_side_encryption: Option<S3ServerSideEncryption>,
    #[serde(default = "default_s3_storage_class")]
    pub storage_class: String,
    #[serde(default)]
    pub kms_key_id: Option<String>,
}

impl ReplicationRegionConfig {
    /// The S3 configuration of this replica: the region's bucket, endpoint, prefix,
    /// credentials, encryption and storage class, with `region` as the signing region.
    /// Everything the server does against the primary bucket (upload, listing, retention,
    /// download, verification) works against the replica through this configuration.
    ///
    /// A region level `kms_key_id` is a shorthand for `aws:kms` server-side encryption
    /// with that key. An explicit `server_side_encryption` block wins when both are set
    /// and only fills its missing `kms_key_id` from the shorthand.
    pub fn to_s3_config(&self) -> S3Config {
        let server_side_encryption = match (&self.server_side_encryption, &self.kms_key_id) {
            (Some(sse), kms_key_id) => Some(S3ServerSideEncryption {
                algorithm: sse.algorithm.clone(),
                kms_key_id: sse.kms_key_id.clone().or_else(|| kms_key_id.clone()),
            }),
            (None, Some(kms_key_id)) => Some(S3ServerSideEncryption {
                algorithm: Some(S3EncryptionAlgorithm::AwsKms),
                kms_key_id: Some(kms_key_id.clone()),
            }),
            (None, None) => None,
        };

        S3Config {
            bucket: self.bucket.clone(),
            region: Some(self.region.clone()),
            endpoint: self.endpoint.clone(),
            path_prefix: self.path_prefix.clone(),
            credentials: self.credentials.clone(),
            server_side_encryption,
            storage_class: self.storage_class.clone(),
            replication: None,
        }
    }
}

impl Display for ReplicationRegionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReplicationRegionConfig {{ region: {}, bucket: {}, endpoint: {:?} }}",
            self.region, self.bucket, self.endpoint
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReplicationConfig {
    #[serde(default = "default_replication_enabled")]
    pub enabled: bool,
    pub regions: Vec<ReplicationRegionConfig>,
    #[serde(default = "default_replication_sync_interval")]
    pub sync_interval_seconds: u64,
    #[serde(default = "default_replication_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_replication_retry_delay")]
    pub retry_delay_seconds: u64,
}

fn default_replication_enabled() -> bool {
    false
}

fn default_replication_sync_interval() -> u64 {
    300
}

fn default_replication_max_retries() -> u32 {
    3
}

fn default_replication_retry_delay() -> u64 {
    30
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            enabled: default_replication_enabled(),
            regions: Vec::new(),
            sync_interval_seconds: default_replication_sync_interval(),
            max_retries: default_replication_max_retries(),
            retry_delay_seconds: default_replication_retry_delay(),
        }
    }
}

impl Display for ReplicationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReplicationConfig {{ enabled: {}, regions: {}, sync_interval: {}s }}",
            self.enabled,
            self.regions.len(),
            self.sync_interval_seconds
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum ReplicationStatus {
    NotConfigured,
    Pending,
    InProgress,
    Completed,
    Failed { error: String },
    Degraded { message: String },
}

impl Display for ReplicationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplicationStatus::NotConfigured => write!(f, "Not Configured"),
            ReplicationStatus::Pending => write!(f, "Pending"),
            ReplicationStatus::InProgress => write!(f, "In Progress"),
            ReplicationStatus::Completed => write!(f, "Completed"),
            ReplicationStatus::Failed { error } => write!(f, "Failed: {}", error),
            ReplicationStatus::Degraded { message } => write!(f, "Degraded: {}", message),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReplicationRegionStatus {
    pub region: String,
    pub bucket: String,
    pub status: ReplicationStatus,
    /// Timestamp recorded in the metadata of the newest backup present in the region.
    pub last_sync_timestamp: Option<String>,
    /// Key of the newest backup present in the region.
    pub last_sync_backup_id: Option<String>,
    /// Age of the region relative to the primary: the seconds between the newest primary
    /// backup and the newest backup present in the region. Zero when the region holds the
    /// newest primary backup, None when the region holds none of the primary backups.
    pub lag_seconds: Option<u64>,
    pub bytes_replicated: u64,
    /// Primary backups found intact in the region.
    pub backups_replicated: u64,
    /// Primary backups missing from the region or differing from the primary copy.
    pub pending_backups: u64,
    pub last_error: Option<String>,
}

impl Display for ReplicationRegionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Region {} (bucket: {}): {} - lag: {}s, backups: {}, pending: {}, bytes: {}",
            self.region,
            self.bucket,
            self.status,
            self.lag_seconds.unwrap_or(0),
            self.backups_replicated,
            self.pending_backups,
            self.bytes_replicated
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReplicationHealthCheck {
    pub overall_status: ReplicationStatus,
    pub regions: Vec<ReplicationRegionStatus>,
    pub total_lag_seconds: u64,
    pub max_lag_seconds: u64,
    pub healthy_regions: usize,
    pub unhealthy_regions: usize,
    pub last_check_timestamp: String,
}

impl Display for ReplicationHealthCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReplicationHealth {{ overall: {}, healthy: {}, unhealthy: {}, max_lag: {}s }}",
            self.overall_status, self.healthy_regions, self.unhealthy_regions, self.max_lag_seconds
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReplicationLagMetrics {
    pub region: String,
    pub lag_seconds: u64,
    pub pending_backups: usize,
    pub last_backup_timestamp: Option<String>,
    pub replication_delay_seconds: u64,
}

impl Display for ReplicationLagMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReplicationLag {{ region: {}, lag: {}s, pending: {} }}",
            self.region, self.lag_seconds, self.pending_backups
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct KeyDerivationParams {
    #[serde(default = "default_argon2_m_cost")]
    pub m_cost: u32,
    #[serde(default = "default_argon2_t_cost")]
    pub t_cost: u32,
    #[serde(default = "default_argon2_p_cost")]
    pub p_cost: u32,
}

fn default_argon2_m_cost() -> u32 {
    19 * 1024
}

fn default_argon2_t_cost() -> u32 {
    2
}

fn default_argon2_p_cost() -> u32 {
    1
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            m_cost: default_argon2_m_cost(),
            t_cost: default_argon2_t_cost(),
            p_cost: default_argon2_p_cost(),
        }
    }
}

impl Display for KeyDerivationParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeyDerivationParams {{ m_cost: {}, t_cost: {}, p_cost: {} }}",
            self.m_cost, self.t_cost, self.p_cost
        )
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum EncryptionKeySource {
    #[default]
    Passphrase,
    File {
        path: String,
    },
    HttpEndpoint {
        url: String,
    },
}

impl Display for EncryptionKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionKeySource::Passphrase => write!(f, "passphrase"),
            EncryptionKeySource::File { path } => write!(f, "file:{}", path),
            EncryptionKeySource::HttpEndpoint { url } => write!(f, "http:{}", url),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BackupEncryptionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub key_source: EncryptionKeySource,
    #[serde(default)]
    pub key_derivation: KeyDerivationParams,
    #[serde(default)]
    pub key_identifier: Option<String>,
}

impl Default for BackupEncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_source: EncryptionKeySource::Passphrase,
            key_derivation: KeyDerivationParams::default(),
            key_identifier: None,
        }
    }
}

impl Display for BackupEncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BackupEncryptionConfig {{ enabled: {}, key_source: {}, key_derivation: {} }}",
            self.enabled, self.key_source, self.key_derivation
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupEncryptionHeader {
    pub magic: String,
    pub key_identifier: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_derivation: KeyDerivationParams,
    pub compressed: bool,
}

impl BackupEncryptionHeader {
    pub fn new(
        key_identifier: String,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        key_derivation: KeyDerivationParams,
        compressed: bool,
    ) -> Self {
        Self {
            magic: String::from_utf8_lossy(BACKUP_ENCRYPTION_MAGIC).to_string(),
            key_identifier,
            salt,
            nonce,
            key_derivation,
            compressed,
        }
    }

    pub fn validate_magic(&self) -> bool {
        self.magic.as_bytes() == BACKUP_ENCRYPTION_MAGIC
    }
}

impl Display for BackupEncryptionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BackupEncryptionHeader {{ key_identifier: {}, compressed: {} }}",
            self.key_identifier, self.compressed
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct S3BackupMetadata {
    pub checksum_sha256: String,
    pub timestamp: String,
    pub compression: BackupCompression,
    pub size_bytes: u64,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub key_identifier: Option<String>,
}

impl S3BackupMetadata {
    pub fn new(
        checksum_sha256: String,
        timestamp: String,
        compression: BackupCompression,
        size_bytes: u64,
    ) -> Self {
        Self {
            checksum_sha256,
            timestamp,
            compression,
            size_bytes,
            encrypted: false,
            key_identifier: None,
        }
    }

    pub fn new_encrypted(
        checksum_sha256: String,
        timestamp: String,
        compression: BackupCompression,
        size_bytes: u64,
        key_identifier: String,
    ) -> Self {
        Self {
            checksum_sha256,
            timestamp,
            compression,
            size_bytes,
            encrypted: true,
            key_identifier: Some(key_identifier),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WalArchiveConfig {
    #[serde(default = "default_wal_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub s3: Option<S3Config>,
    #[serde(default = "default_wal_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_wal_segment_size")]
    pub segment_size_bytes: u64,
}

fn default_wal_enabled() -> bool {
    false
}

fn default_wal_retention_days() -> u32 {
    7
}

fn default_wal_segment_size() -> u64 {
    16 * 1024 * 1024
}

impl Default for WalArchiveConfig {
    fn default() -> Self {
        Self {
            enabled: default_wal_enabled(),
            s3: None,
            retention_days: default_wal_retention_days(),
            segment_size_bytes: default_wal_segment_size(),
        }
    }
}

impl Display for WalArchiveConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WalArchiveConfig {{ enabled: {}, retention_days: {}, segment_size: {} }}",
            self.enabled, self.retention_days, self.segment_size_bytes
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WalSegment {
    pub segment_id: String,
    pub server_uuid: Uuid,
    pub start_ts: Duration,
    pub end_ts: Duration,
    pub checksum_sha256: String,
    pub size_bytes: u64,
    pub compression: BackupCompression,
    pub created_at: String,
}

impl WalSegment {
    pub fn new(
        segment_id: String,
        server_uuid: Uuid,
        start_ts: Duration,
        end_ts: Duration,
        checksum_sha256: String,
        size_bytes: u64,
        compression: BackupCompression,
    ) -> Self {
        Self {
            segment_id,
            server_uuid,
            start_ts,
            end_ts,
            checksum_sha256,
            size_bytes,
            compression,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Display for WalSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WalSegment {{ id: {}, server: {}, range: {:?}-{:?}, size: {} }}",
            self.segment_id, self.server_uuid, self.start_ts, self.end_ts, self.size_bytes
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WalSegmentMetadata {
    pub segment: WalSegment,
    pub entry_count: u64,
    pub first_cid: String,
    pub last_cid: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WalEntry {
    pub cid_ts: Duration,
    pub cid_server: Uuid,
    pub entry_id: u64,
    pub operation: WalOperation,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum WalOperation {
    Create { entry_data: Vec<u8> },
    Modify { entry_data: Vec<u8> },
    Delete,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RecoveryTarget {
    pub target_type: RecoveryTargetType,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum RecoveryTargetType {
    Time { timestamp: String },
    Transaction { cid: String },
    Latest,
}

impl RecoveryTarget {
    pub fn to_time(target_time: &str) -> Result<Self, String> {
        let _ = chrono::DateTime::parse_from_rfc3339(target_time)
            .map_err(|e| format!("Invalid timestamp format: {}", e))?;
        Ok(Self {
            target_type: RecoveryTargetType::Time {
                timestamp: target_time.to_string(),
            },
        })
    }

    pub fn to_transaction(cid: &str) -> Result<Self, String> {
        if cid.is_empty() {
            return Err("Transaction CID cannot be empty".to_string());
        }
        Ok(Self {
            target_type: RecoveryTargetType::Transaction {
                cid: cid.to_string(),
            },
        })
    }

    pub fn latest() -> Self {
        Self {
            target_type: RecoveryTargetType::Latest,
        }
    }
}

impl Display for RecoveryTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.target_type {
            RecoveryTargetType::Time { timestamp } => write!(f, "time:{}", timestamp),
            RecoveryTargetType::Transaction { cid } => write!(f, "transaction:{}", cid),
            RecoveryTargetType::Latest => write!(f, "latest"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PitrManifest {
    pub server_uuid: Uuid,
    pub segments: Vec<WalSegment>,
    pub base_backup_id: String,
    pub base_backup_timestamp: String,
    pub earliest_recoverable_time: String,
    pub latest_recoverable_time: String,
}

impl PitrManifest {
    pub fn new(server_uuid: Uuid, base_backup_id: String, base_backup_timestamp: String) -> Self {
        let timestamp = base_backup_timestamp.clone();
        Self {
            server_uuid,
            segments: Vec::new(),
            base_backup_id,
            base_backup_timestamp,
            earliest_recoverable_time: timestamp.clone(),
            latest_recoverable_time: timestamp,
        }
    }

    pub fn add_segment(&mut self, segment: WalSegment) {
        if self.segments.is_empty() {
            self.earliest_recoverable_time = segment.created_at.clone();
        }
        self.latest_recoverable_time = segment.created_at.clone();
        self.segments.push(segment);
    }
}

#[test]
fn test_wal_archive_config_default() {
    let config = WalArchiveConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.retention_days, 7);
    assert_eq!(config.segment_size_bytes, 16 * 1024 * 1024);
    assert!(config.s3.is_none());
}

#[test]
fn test_wal_archive_config_display() {
    let config = WalArchiveConfig {
        enabled: true,
        s3: None,
        retention_days: 30,
        segment_size_bytes: 1024,
    };
    let display = config.to_string();
    assert!(display.contains("enabled: true"));
    assert!(display.contains("retention_days: 30"));
}

#[test]
fn test_wal_segment_creation() {
    let server_uuid = uuid::Uuid::new_v4();
    let segment = WalSegment::new(
        "test-segment-id".to_string(),
        server_uuid,
        Duration::from_secs(0),
        Duration::from_secs(100),
        "sha256-checksum".to_string(),
        1024,
        BackupCompression::Gzip,
    );

    assert_eq!(segment.segment_id, "test-segment-id");
    assert_eq!(segment.server_uuid, server_uuid);
    assert_eq!(segment.start_ts, Duration::from_secs(0));
    assert_eq!(segment.end_ts, Duration::from_secs(100));
    assert_eq!(segment.checksum_sha256, "sha256-checksum");
    assert_eq!(segment.size_bytes, 1024);
    assert_eq!(segment.compression, BackupCompression::Gzip);
    assert!(!segment.created_at.is_empty());
}

#[test]
fn test_wal_segment_display() {
    let server_uuid = uuid::Uuid::new_v4();
    let segment = WalSegment::new(
        "test-segment".to_string(),
        server_uuid,
        Duration::from_secs(0),
        Duration::from_secs(100),
        "checksum".to_string(),
        1024,
        BackupCompression::NoCompression,
    );

    let display = segment.to_string();
    assert!(display.contains("WalSegment"));
    assert!(display.contains("test-segment"));
    assert!(display.contains(server_uuid.to_string().as_str()));
}

#[test]
fn test_wal_segment_serialization() {
    let server_uuid = uuid::Uuid::new_v4();
    let segment = WalSegment::new(
        "test-segment".to_string(),
        server_uuid,
        Duration::from_secs(0),
        Duration::from_secs(100),
        "checksum".to_string(),
        1024,
        BackupCompression::Gzip,
    );

    let json = serde_json::to_string(&segment).expect("Failed to serialize");
    assert!(json.contains("test-segment"));
    assert!(json.contains(server_uuid.to_string().as_str()));

    let deserialized: WalSegment = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(segment.segment_id, deserialized.segment_id);
    assert_eq!(segment.server_uuid, deserialized.server_uuid);
}

#[test]
fn test_wal_entry_creation() {
    let server_uuid = uuid::Uuid::new_v4();
    let entry = WalEntry {
        cid_ts: Duration::from_secs(1000),
        cid_server: server_uuid,
        entry_id: 1,
        operation: WalOperation::Create {
            entry_data: vec![1, 2, 3],
        },
    };

    assert_eq!(entry.cid_ts, Duration::from_secs(1000));
    assert_eq!(entry.cid_server, server_uuid);
    assert_eq!(entry.entry_id, 1);
    assert!(matches!(entry.operation, WalOperation::Create { .. }));
}

#[test]
fn test_wal_operation_types() {
    let create_op = WalOperation::Create {
        entry_data: vec![1, 2, 3],
    };
    let modify_op = WalOperation::Modify {
        entry_data: vec![4, 5, 6],
    };
    let delete_op = WalOperation::Delete;

    assert!(matches!(create_op, WalOperation::Create { .. }));
    assert!(matches!(modify_op, WalOperation::Modify { .. }));
    assert!(matches!(delete_op, WalOperation::Delete));
}

#[test]
fn test_wal_entry_serialization() {
    let server_uuid = uuid::Uuid::new_v4();
    let entry = WalEntry {
        cid_ts: Duration::from_secs(1000),
        cid_server: server_uuid,
        entry_id: 1,
        operation: WalOperation::Create {
            entry_data: vec![1, 2, 3],
        },
    };

    let json = serde_json::to_string(&entry).expect("Failed to serialize");
    let deserialized: WalEntry = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(entry.entry_id, deserialized.entry_id);
}

#[test]
fn test_recovery_target_to_time_valid() {
    let target = RecoveryTarget::to_time("2024-01-15T10:30:00Z");
    assert!(target.is_ok());
    let target = target.unwrap();
    assert!(matches!(
        target.target_type,
        RecoveryTargetType::Time { .. }
    ));
}

#[test]
fn test_recovery_target_to_time_invalid() {
    let target = RecoveryTarget::to_time("invalid-timestamp");
    assert!(target.is_err());
}

#[test]
fn test_recovery_target_to_time_with_timezone() {
    let target = RecoveryTarget::to_time("2024-01-15T10:30:00+05:00");
    assert!(target.is_ok());
}

#[test]
fn test_recovery_target_to_time_microseconds() {
    let target = RecoveryTarget::to_time("2024-01-15T10:30:00.123456Z");
    assert!(target.is_ok());
}

#[test]
fn test_recovery_target_to_transaction_valid() {
    let target = RecoveryTarget::to_transaction("123456789-uuid");
    assert!(target.is_ok());
    let target = target.unwrap();
    assert!(matches!(
        target.target_type,
        RecoveryTargetType::Transaction { .. }
    ));
}

#[test]
fn test_recovery_target_to_transaction_empty() {
    let target = RecoveryTarget::to_transaction("");
    assert!(target.is_err());
}

#[test]
fn test_recovery_target_latest() {
    let target = RecoveryTarget::latest();
    assert!(matches!(target.target_type, RecoveryTargetType::Latest));
}

#[test]
fn test_recovery_target_display_time() {
    let target = RecoveryTarget::to_time("2024-01-15T10:30:00Z").unwrap();
    let display = target.to_string();
    assert_eq!(display, "time:2024-01-15T10:30:00Z");
}

#[test]
fn test_recovery_target_display_transaction() {
    let target = RecoveryTarget::to_transaction("test-cid").unwrap();
    let display = target.to_string();
    assert_eq!(display, "transaction:test-cid");
}

#[test]
fn test_recovery_target_display_latest() {
    let target = RecoveryTarget::latest();
    let display = target.to_string();
    assert_eq!(display, "latest");
}

#[test]
fn test_recovery_target_serialization() {
    let target = RecoveryTarget::to_time("2024-01-15T10:30:00Z").unwrap();
    let json = serde_json::to_string(&target).expect("Failed to serialize");
    assert!(json.contains("2024-01-15T10:30:00Z"));

    let deserialized: RecoveryTarget = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(target.to_string(), deserialized.to_string());
}

#[test]
fn test_recovery_target_type_serialization() {
    let time_type = RecoveryTargetType::Time {
        timestamp: "2024-01-15T10:30:00Z".to_string(),
    };
    let json = serde_json::to_string(&time_type).expect("Failed to serialize");
    assert!(json.contains("Time"));

    let transaction_type = RecoveryTargetType::Transaction {
        cid: "test-cid".to_string(),
    };
    let json = serde_json::to_string(&transaction_type).expect("Failed to serialize");
    assert!(json.contains("Transaction"));

    let latest_type = RecoveryTargetType::Latest;
    let json = serde_json::to_string(&latest_type).expect("Failed to serialize");
    assert!(json.contains("Latest"));
}

#[test]
fn test_pitr_manifest_creation() {
    let server_uuid = uuid::Uuid::new_v4();
    let manifest = PitrManifest::new(
        server_uuid,
        "backup-001".to_string(),
        "2024-01-01T00:00:00Z".to_string(),
    );

    assert_eq!(manifest.server_uuid, server_uuid);
    assert_eq!(manifest.base_backup_id, "backup-001");
    assert_eq!(manifest.base_backup_timestamp, "2024-01-01T00:00:00Z");
    assert!(manifest.segments.is_empty());
    assert_eq!(manifest.earliest_recoverable_time, "2024-01-01T00:00:00Z");
    assert_eq!(manifest.latest_recoverable_time, "2024-01-01T00:00:00Z");
}

#[test]
fn test_pitr_manifest_add_segment() {
    let server_uuid = uuid::Uuid::new_v4();
    let mut manifest = PitrManifest::new(
        server_uuid,
        "backup-001".to_string(),
        "2024-01-01T00:00:00Z".to_string(),
    );

    let segment1 = WalSegment::new(
        "segment-1".to_string(),
        server_uuid,
        Duration::from_secs(0),
        Duration::from_secs(100),
        "checksum1".to_string(),
        1024,
        BackupCompression::Gzip,
    );

    let segment2 = WalSegment::new(
        "segment-2".to_string(),
        server_uuid,
        Duration::from_secs(100),
        Duration::from_secs(200),
        "checksum2".to_string(),
        2048,
        BackupCompression::Gzip,
    );

    manifest.add_segment(segment1.clone());
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.earliest_recoverable_time, segment1.created_at);
    assert_eq!(manifest.latest_recoverable_time, segment1.created_at);

    manifest.add_segment(segment2.clone());
    assert_eq!(manifest.segments.len(), 2);
    assert_eq!(manifest.earliest_recoverable_time, segment1.created_at);
    assert_eq!(manifest.latest_recoverable_time, segment2.created_at);
}

#[test]
fn test_pitr_manifest_serialization() {
    let server_uuid = uuid::Uuid::new_v4();
    let manifest = PitrManifest::new(
        server_uuid,
        "backup-001".to_string(),
        "2024-01-01T00:00:00Z".to_string(),
    );

    let json = serde_json::to_string(&manifest).expect("Failed to serialize");
    assert!(json.contains("backup-001"));
    assert!(json.contains(server_uuid.to_string().as_str()));

    let deserialized: PitrManifest = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(manifest.server_uuid, deserialized.server_uuid);
    assert_eq!(manifest.base_backup_id, deserialized.base_backup_id);
}

#[test]
fn test_pitr_manifest_empty_segments() {
    let server_uuid = uuid::Uuid::new_v4();
    let manifest = PitrManifest::new(
        server_uuid,
        "backup-001".to_string(),
        "2024-01-01T00:00:00Z".to_string(),
    );

    assert_eq!(manifest.segments.len(), 0);
    assert_eq!(
        manifest.earliest_recoverable_time,
        manifest.latest_recoverable_time
    );
}

#[test]
fn test_pitr_manifest_multiple_segments() {
    let server_uuid = uuid::Uuid::new_v4();
    let mut manifest = PitrManifest::new(
        server_uuid,
        "backup-001".to_string(),
        "2024-01-01T00:00:00Z".to_string(),
    );

    for i in 0..10 {
        let segment = WalSegment::new(
            format!("segment-{}", i),
            server_uuid,
            Duration::from_secs(i * 100),
            Duration::from_secs((i + 1) * 100),
            format!("checksum-{}", i),
            1024,
            BackupCompression::Gzip,
        );
        manifest.add_segment(segment);
    }

    assert_eq!(manifest.segments.len(), 10);
}

#[test]
fn test_wal_segment_metadata_creation() {
    let server_uuid = uuid::Uuid::new_v4();
    let segment = WalSegment::new(
        "segment-1".to_string(),
        server_uuid,
        Duration::from_secs(0),
        Duration::from_secs(100),
        "checksum".to_string(),
        1024,
        BackupCompression::Gzip,
    );

    let metadata = WalSegmentMetadata {
        segment,
        entry_count: 100,
        first_cid: "cid-1".to_string(),
        last_cid: "cid-100".to_string(),
    };

    assert_eq!(metadata.entry_count, 100);
    assert_eq!(metadata.first_cid, "cid-1");
    assert_eq!(metadata.last_cid, "cid-100");
}

#[test]
fn test_wal_segment_metadata_serialization() {
    let server_uuid = uuid::Uuid::new_v4();
    let segment = WalSegment::new(
        "segment-1".to_string(),
        server_uuid,
        Duration::from_secs(0),
        Duration::from_secs(100),
        "checksum".to_string(),
        1024,
        BackupCompression::Gzip,
    );

    let metadata = WalSegmentMetadata {
        segment,
        entry_count: 100,
        first_cid: "cid-1".to_string(),
        last_cid: "cid-100".to_string(),
    };

    let json = serde_json::to_string(&metadata).expect("Failed to serialize");
    assert!(json.contains("entry_count"));

    let deserialized: WalSegmentMetadata =
        serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(metadata.entry_count, deserialized.entry_count);
}

#[test]
fn test_wal_segment_equality() {
    let server_uuid = uuid::Uuid::new_v4();
    let segment1 = WalSegment::new(
        "segment-1".to_string(),
        server_uuid,
        Duration::from_secs(0),
        Duration::from_secs(100),
        "checksum".to_string(),
        1024,
        BackupCompression::Gzip,
    );

    let segment2 = WalSegment::new(
        "segment-1".to_string(),
        server_uuid,
        Duration::from_secs(0),
        Duration::from_secs(100),
        "checksum".to_string(),
        1024,
        BackupCompression::Gzip,
    );

    assert_eq!(segment1.segment_id, segment2.segment_id);
    assert_eq!(segment1.server_uuid, segment2.server_uuid);
}

#[test]
fn test_wal_entry_equality() {
    let server_uuid = uuid::Uuid::new_v4();
    let entry1 = WalEntry {
        cid_ts: Duration::from_secs(1000),
        cid_server: server_uuid,
        entry_id: 1,
        operation: WalOperation::Create {
            entry_data: vec![1, 2, 3],
        },
    };

    let entry2 = WalEntry {
        cid_ts: Duration::from_secs(1000),
        cid_server: server_uuid,
        entry_id: 1,
        operation: WalOperation::Create {
            entry_data: vec![1, 2, 3],
        },
    };

    assert_eq!(entry1, entry2);
}

#[test]
fn test_recovery_target_equality() {
    let target1 = RecoveryTarget::to_time("2024-01-15T10:30:00Z").unwrap();
    let target2 = RecoveryTarget::to_time("2024-01-15T10:30:00Z").unwrap();
    assert_eq!(target1, target2);

    let target3 = RecoveryTarget::latest();
    let target4 = RecoveryTarget::latest();
    assert_eq!(target3, target4);
}

#[test]
fn test_pitr_manifest_equality() {
    let server_uuid = uuid::Uuid::new_v4();
    let manifest1 = PitrManifest::new(
        server_uuid,
        "backup-001".to_string(),
        "2024-01-01T00:00:00Z".to_string(),
    );

    let manifest2 = PitrManifest::new(
        server_uuid,
        "backup-001".to_string(),
        "2024-01-01T00:00:00Z".to_string(),
    );

    assert_eq!(manifest1, manifest2);
}

#[test]
fn test_wal_archive_config_with_s3() {
    let s3_config = S3Config {
        bucket: "test-bucket".to_string(),
        region: Some("us-west-2".to_string()),
        endpoint: None,
        path_prefix: None,
        credentials: None,
        server_side_encryption: None,
        storage_class: "STANDARD".to_string(),
        replication: None,
    };

    let config = WalArchiveConfig {
        enabled: true,
        s3: Some(s3_config),
        retention_days: 30,
        segment_size_bytes: 32 * 1024 * 1024,
    };

    assert!(config.enabled);
    assert!(config.s3.is_some());
    assert_eq!(config.retention_days, 30);
    assert_eq!(config.segment_size_bytes, 32 * 1024 * 1024);
}
