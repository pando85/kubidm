//! Relates to backup functionality in the Server
use std::{
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_with::DeserializeFromStr;
use sketching::tracing::warn;
use uuid::Uuid;

pub const BACKUP_ENCRYPTION_MAGIC: &[u8] = b"KANIDM_ENC_BACKUP_V1";
pub const BACKUP_ENCRYPTION_KEY_LEN: usize = 32;
pub const BACKUP_ENCRYPTION_NONCE_LEN: usize = 12;
pub const BACKUP_ENCRYPTION_SALT_LEN: usize = 16;
/// File name suffix of a client-side encrypted backup artifact, appended after the
/// compression suffix: `backup-<ts>.json.enc`, `backup-<ts>.json.gz.enc`.
pub const BACKUP_ENCRYPTED_SUFFIX: &str = ".enc";

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

    /// The compression a backup file name announces. An encrypted artifact carries the
    /// compression suffix of its plaintext before [`BACKUP_ENCRYPTED_SUFFIX`], so
    /// `backup.json.gz.enc` identifies as gzip.
    pub fn identify_file(filepath: &Path) -> Self {
        let filename = filepath.file_name().and_then(|s| s.to_str()).unwrap_or("");
        Self::identify_name(filename)
    }

    /// [`Self::identify_file`] for a bare file name or object key.
    pub fn identify_name(name: &str) -> Self {
        let name = name.strip_suffix(BACKUP_ENCRYPTED_SUFFIX).unwrap_or(name);
        if name.ends_with(".gz") {
            BackupCompression::Gzip
        } else {
            BackupCompression::NoCompression
        }
    }
}

/// Whether a backup file name or object key announces a client-side encrypted artifact.
pub fn is_encrypted_backup_name(name: &str) -> bool {
    name.ends_with(BACKUP_ENCRYPTED_SUFFIX)
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

    // The encrypted suffix wraps the compression suffix.
    assert_eq!(
        BackupCompression::identify_file(Path::new(
            "/backups/backup-2024-01-01T22:00:00Z.json.gz.enc"
        )),
        BackupCompression::Gzip
    );
    assert_eq!(
        BackupCompression::identify_file(Path::new(
            "/backups/backup-2024-01-01T22:00:00Z.json.enc"
        )),
        BackupCompression::NoCompression
    );
    assert_eq!(
        BackupCompression::identify_name("backup.json.gz.enc"),
        BackupCompression::Gzip
    );
    assert_eq!(
        BackupCompression::identify_name("backup.json.enc"),
        BackupCompression::NoCompression
    );
    assert!(is_encrypted_backup_name(
        "backup-2024-01-01T22:00:00Z.json.gz.enc"
    ));
    assert!(is_encrypted_backup_name(
        "backup-2024-01-01T22:00:00Z.json.enc"
    ));
    assert!(!is_encrypted_backup_name(
        "backup-2024-01-01T22:00:00Z.json.gz"
    ));
    assert!(!is_encrypted_backup_name(
        "backup-2024-01-01T22:00:00Z.json.gz.enc.metadata.json"
    ));

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
    assert!(config.passphrase_file.is_none());
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
        passphrase_file: None,
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: BackupEncryptionConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config.enabled, deserialized.enabled);
    assert_eq!(config.key_source, deserialized.key_source);
    assert_eq!(config.key_identifier, deserialized.key_identifier);
    assert_eq!(config, deserialized);
}

#[test]
fn test_backup_encryption_config_display() {
    let config = BackupEncryptionConfig {
        enabled: true,
        key_source: EncryptionKeySource::Passphrase,
        key_derivation: KeyDerivationParams::default(),
        key_identifier: None,
        passphrase_file: None,
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
    /// Name written into every artifact and into the S3 metadata sidecar to tell which key
    /// an artifact needs. Defaults to a fingerprint of the key material for a key file or
    /// key endpoint, and to `passphrase` for a passphrase, which is never fingerprinted.
    #[serde(default)]
    pub key_identifier: Option<String>,
    /// With `key_source = "Passphrase"`: read the passphrase from this file instead of the
    /// `KUBIDM_BACKUP_PASSPHRASE` environment variable. Trailing whitespace is ignored.
    #[serde(default)]
    pub passphrase_file: Option<PathBuf>,
}

impl Default for BackupEncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_source: EncryptionKeySource::Passphrase,
            key_derivation: KeyDerivationParams::default(),
            key_identifier: None,
            passphrase_file: None,
        }
    }
}

impl Display for BackupEncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BackupEncryptionConfig {{ enabled: {}, key_source: {}, passphrase_file: {:?}, key_identifier: {:?}, key_derivation: {} }}",
            self.enabled, self.key_source, self.passphrase_file, self.key_identifier, self.key_derivation
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

/// Configuration of write-ahead log (WAL) archiving for point-in-time recovery.
///
/// When enabled, every committed write transaction appends the full serialised state of
/// each entry it changed to a local WAL segment. Closed segments are uploaded to S3 when
/// an S3 configuration is present (this section's, or otherwise the one of
/// `[online_backup.s3]`) and are otherwise kept in `local_path`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WalArchiveConfig {
    #[serde(default = "default_wal_enabled")]
    pub enabled: bool,
    /// S3 location of the archived segments. Defaults to the `[online_backup.s3]` section.
    #[serde(default)]
    pub s3: Option<S3Config>,
    /// How long archived segments are kept. A segment is never deleted while it is newer
    /// than the oldest base backup that is still available, whatever this value.
    #[serde(default = "default_wal_retention_days")]
    pub retention_days: u32,
    /// A segment is closed once the records it holds reach this size.
    #[serde(default = "default_wal_segment_size")]
    pub segment_size_bytes: u64,
    /// A segment is also closed once it is this old, so that a quiet server still archives
    /// its changes regularly. This is also the period of the upload task.
    #[serde(default = "default_wal_segment_interval_seconds")]
    pub segment_interval_seconds: u64,
    /// Directory the server writes segments to before they are uploaded, and where they
    /// stay when no S3 location is configured. Defaults to `wal` next to the database.
    #[serde(default)]
    pub local_path: Option<PathBuf>,
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

fn default_wal_segment_interval_seconds() -> u64 {
    300
}

impl Default for WalArchiveConfig {
    fn default() -> Self {
        Self {
            enabled: default_wal_enabled(),
            s3: None,
            retention_days: default_wal_retention_days(),
            segment_size_bytes: default_wal_segment_size(),
            segment_interval_seconds: default_wal_segment_interval_seconds(),
            local_path: None,
        }
    }
}

impl WalArchiveConfig {
    /// Check the numeric settings. Returns the offending key and the reason.
    pub fn validate(&self) -> Result<(), String> {
        if self.segment_size_bytes == 0 {
            return Err("segment_size_bytes must be greater than zero".to_string());
        }
        if self.retention_days == 0 {
            return Err("retention_days must be greater than zero".to_string());
        }
        if self.segment_interval_seconds == 0 {
            return Err("segment_interval_seconds must be greater than zero".to_string());
        }
        Ok(())
    }

    pub fn segment_interval(&self) -> Duration {
        Duration::from_secs(self.segment_interval_seconds)
    }

    pub fn retention(&self) -> Duration {
        Duration::from_secs(u64::from(self.retention_days) * 24 * 60 * 60)
    }
}

impl Display for WalArchiveConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WalArchiveConfig {{ enabled: {}, retention_days: {}, segment_size: {}, segment_interval_seconds: {}, local_path: {:?} }}",
            self.enabled,
            self.retention_days,
            self.segment_size_bytes,
            self.segment_interval_seconds,
            self.local_path
        )
    }
}

/// The name of the PITR manifest, in the WAL directory or under the S3 prefix.
pub const PITR_MANIFEST_KEY: &str = "pitr-manifest.json";
/// The S3 key prefix, below the configured `path_prefix`, under which segments are stored.
pub const WAL_SEGMENT_KEY_PREFIX: &str = "wal/";
/// Current version of the manifest format.
pub const PITR_MANIFEST_VERSION: u32 = 1;

/// A closed, archived WAL segment as the manifest describes it.
///
/// `start_ts` and `end_ts` are the CID timestamps of the first and last record. All CIDs
/// of a segment belong to one server (`server_uuid`), and records are ordered by CID.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WalSegment {
    /// The file name of the segment. Lexical order is CID order.
    pub segment_id: String,
    pub server_uuid: Uuid,
    pub start_ts: Duration,
    pub end_ts: Duration,
    pub first_cid: String,
    pub last_cid: String,
    pub entry_count: u64,
    pub checksum_sha256: String,
    pub size_bytes: u64,
    pub compression: BackupCompression,
    /// Server version that wrote the segment. Segments can only be replayed by the same
    /// version, like backups.
    pub server_version: String,
    /// RFC3339 rendering of `end_ts`, for display.
    pub created_at: String,
}

impl WalSegment {
    /// The S3 key of this segment relative to the configured `path_prefix`.
    pub fn object_key(&self) -> String {
        format!("{WAL_SEGMENT_KEY_PREFIX}{}", self.segment_id)
    }
}

impl Display for WalSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WalSegment {{ id: {}, server: {}, range: {:?}-{:?}, entries: {}, size: {} }}",
            self.segment_id,
            self.server_uuid,
            self.start_ts,
            self.end_ts,
            self.entry_count,
            self.size_bytes
        )
    }
}

/// A base backup the manifest knows about.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PitrBaseBackup {
    /// File name (local) or object key relative to `path_prefix` (S3) of the backup.
    pub key: String,
    /// RFC3339 time the backup was taken.
    pub timestamp: String,
    /// The CID timestamp watermark of the backup: the timestamp of the last transaction
    /// the backup contains. WAL records with a CID timestamp above it are not in the
    /// backup and must be replayed on top of it.
    pub watermark_ts: Duration,
    /// Server version that wrote the backup.
    pub server_version: String,
}

/// A range of history abandoned by a restore or a point-in-time recovery.
///
/// Restoring or recovering the database to the CID timestamp `after_ts` discards everything
/// the server committed after it. Those transactions are still in the WAL archive, and base
/// backups may have been taken while they were live, but they no longer describe the
/// database: replaying them on a later recovery would resurrect state the operator chose to
/// discard. Every WAL record and base backup watermark in `(after_ts, until_ts]` is
/// therefore ignored. `until_ts` is at least the time of the restore or recovery, so the
/// transactions of the server started on the recovered database lie after it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PitrTimelineBreak {
    /// The CID timestamp the database was restored or recovered to.
    pub after_ts: Duration,
    /// The end of the abandoned range.
    pub until_ts: Duration,
    /// RFC3339 time of the restore or recovery, for display.
    pub at: String,
    /// The command that caused it, for display.
    pub reason: String,
}

impl PitrTimelineBreak {
    /// Whether the CID timestamp `ts` lies in the abandoned range.
    pub fn contains(&self, ts: Duration) -> bool {
        ts > self.after_ts && ts <= self.until_ts
    }
}

/// CID timestamps whose WAL records are missing from the archive, because a committed
/// transaction could not be recorded or the server stopped without archiving its open
/// segment. Replaying from a base backup across a gap would silently skip changes, so a
/// recovery whose replay range overlaps `[from_ts, until_ts]` is refused; a base backup
/// taken after `until_ts` closes the gap.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PitrWalGap {
    pub from_ts: Duration,
    pub until_ts: Duration,
    /// Why the records are missing, for display.
    pub reason: String,
}

/// Index of the base backups and WAL segments a server has archived.
///
/// The manifest is the source of truth for recovery: it pairs every base backup with its
/// CID watermark so that the segments that follow it can be selected, and records the
/// ranges of history that a restore or recovery abandoned.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PitrManifest {
    pub version: u32,
    pub server_uuid: Uuid,
    /// Ordered by `watermark_ts`.
    pub base_backups: Vec<PitrBaseBackup>,
    /// Ordered by `start_ts`.
    pub segments: Vec<WalSegment>,
    /// Ordered by `until_ts`.
    #[serde(default)]
    pub timeline_breaks: Vec<PitrTimelineBreak>,
    /// Ordered by `from_ts`.
    #[serde(default)]
    pub gaps: Vec<PitrWalGap>,
    /// RFC3339 time of the last update, for display.
    pub updated_at: String,
}

impl PitrManifest {
    pub fn new(server_uuid: Uuid) -> Self {
        Self {
            version: PITR_MANIFEST_VERSION,
            server_uuid,
            base_backups: Vec::new(),
            segments: Vec::new(),
            timeline_breaks: Vec::new(),
            gaps: Vec::new(),
            updated_at: String::new(),
        }
    }

    /// Record a base backup, replacing any earlier record of the same key.
    pub fn add_base_backup(&mut self, base: PitrBaseBackup) {
        self.base_backups
            .retain(|existing| existing.key != base.key);
        self.base_backups.push(base);
        self.base_backups
            .sort_by(|a, b| a.watermark_ts.cmp(&b.watermark_ts).then(a.key.cmp(&b.key)));
    }

    /// Record a segment, replacing any earlier record of the same id.
    pub fn add_segment(&mut self, segment: WalSegment) {
        self.segments
            .retain(|existing| existing.segment_id != segment.segment_id);
        self.segments.push(segment);
        self.segments.sort_by(|a, b| {
            a.start_ts
                .cmp(&b.start_ts)
                .then(a.segment_id.cmp(&b.segment_id))
        });
    }

    /// Record that a restore or recovery abandoned the history in `(after_ts, until_ts]`.
    /// The base backups taken during that history are dropped from the index, since they
    /// hold state that no longer exists; their artifacts are left to backup retention.
    pub fn add_timeline_break(&mut self, timeline_break: PitrTimelineBreak) {
        self.base_backups
            .retain(|base| !timeline_break.contains(base.watermark_ts));
        self.timeline_breaks.push(timeline_break);
        self.timeline_breaks.sort_by(|a, b| {
            a.until_ts
                .cmp(&b.until_ts)
                .then(a.after_ts.cmp(&b.after_ts))
        });
    }

    /// Record a gap in the archive, ignoring one already recorded.
    pub fn add_gap(&mut self, gap: PitrWalGap) {
        if self
            .gaps
            .iter()
            .any(|known| known.from_ts == gap.from_ts && known.until_ts == gap.until_ts)
        {
            return;
        }
        self.gaps.push(gap);
        self.gaps
            .sort_by(|a, b| a.from_ts.cmp(&b.from_ts).then(a.until_ts.cmp(&b.until_ts)));
    }

    /// The first gap that makes replaying from a base with watermark `watermark_ts` up to
    /// `target_ts` incomplete: one that overlaps `(watermark_ts, target_ts]`. A gap that
    /// lies entirely in abandoned history is ignored, since that history is never
    /// replayed.
    pub fn gap_blocking(&self, watermark_ts: Duration, target_ts: Duration) -> Option<&PitrWalGap> {
        self.gaps.iter().find(|gap| {
            target_ts > watermark_ts
                && gap.from_ts <= target_ts
                && gap.until_ts > watermark_ts
                && !self
                    .timeline_breaks
                    .iter()
                    .any(|b| gap.from_ts > b.after_ts && gap.until_ts <= b.until_ts)
        })
    }

    /// Whether the CID timestamp `ts` belongs to history a restore or recovery abandoned.
    pub fn is_abandoned(&self, ts: Duration) -> bool {
        self.timeline_breaks.iter().any(|b| b.contains(ts))
    }

    /// Drop the base backups whose key is not in `existing` any more, for example because
    /// backup retention deleted them.
    pub fn retain_base_backups(&mut self, existing: &[String]) {
        self.base_backups
            .retain(|base| existing.iter().any(|key| key == &base.key));
    }

    pub fn remove_segment(&mut self, segment_id: &str) {
        self.segments.retain(|s| s.segment_id != segment_id);
    }

    /// Drop the timeline breaks that no retained base backup or segment precedes: once all
    /// archived history is newer than a break, it can not affect any recovery.
    pub fn prune_timeline_breaks(&mut self) {
        let oldest_base = self.base_backups.iter().map(|b| b.watermark_ts).min();
        let oldest_segment = self.segments.iter().map(|s| s.start_ts).min();
        let oldest = match (oldest_base, oldest_segment) {
            (Some(b), Some(s)) => Some(b.min(s)),
            (b, s) => b.or(s),
        };
        match oldest {
            Some(oldest) => self.timeline_breaks.retain(|b| oldest <= b.until_ts),
            None => self.timeline_breaks.clear(),
        }
    }

    /// Drop the gaps no retained base backup or segment precedes: a recovery can only start
    /// from a base taken after them, and replays nothing from before that base.
    pub fn prune_gaps(&mut self) {
        let oldest_base = self.base_backups.iter().map(|b| b.watermark_ts).min();
        let oldest_segment = self.segments.iter().map(|s| s.start_ts).min();
        let oldest = match (oldest_base, oldest_segment) {
            (Some(b), Some(s)) => Some(b.min(s)),
            (b, s) => b.or(s),
        };
        match oldest {
            Some(oldest) => self.gaps.retain(|gap| oldest < gap.until_ts),
            None => self.gaps.clear(),
        }
    }

    pub fn oldest_base_backup(&self) -> Option<&PitrBaseBackup> {
        self.base_backups.first()
    }

    /// The newest base backup whose watermark is at or before `target_ts` and does not
    /// belong to abandoned history.
    pub fn base_backup_for(&self, target_ts: Duration) -> Option<&PitrBaseBackup> {
        self.base_backups
            .iter()
            .rfind(|base| base.watermark_ts <= target_ts && !self.is_abandoned(base.watermark_ts))
    }

    /// The segments that hold records after `watermark_ts` and up to `target_ts`, in CID
    /// order. A segment that straddles either bound is included; the records themselves
    /// are filtered at replay time.
    pub fn segments_between(
        &self,
        watermark_ts: Duration,
        target_ts: Duration,
    ) -> Vec<&WalSegment> {
        self.segments
            .iter()
            .filter(|segment| segment.end_ts > watermark_ts && segment.start_ts <= target_ts)
            .collect()
    }

    /// The latest CID timestamp recovery can reach: the end of the last segment, the
    /// watermark of the newest base backup, or the point an earlier recovery restored to,
    /// whichever is newest and does not belong to abandoned history, moved back to just
    /// before any gap the replay from the base backup in use would cross.
    pub fn latest_recoverable_ts(&self) -> Option<Duration> {
        let mut latest = self
            .segments
            .iter()
            .map(|s| s.end_ts)
            .chain(self.base_backups.iter().map(|b| b.watermark_ts))
            .chain(self.timeline_breaks.iter().map(|b| b.after_ts))
            .filter(|ts| !self.is_abandoned(*ts))
            .max()?;
        // Each step moves `latest` strictly back past one gap, so this ends.
        while let Some(base) = self.base_backup_for(latest) {
            let Some(gap) = self.gap_blocking(base.watermark_ts, latest) else {
                break;
            };
            latest = gap
                .from_ts
                .checked_sub(Duration::from_nanos(1))
                .map_or(base.watermark_ts, |before| before.max(base.watermark_ts));
        }
        Some(latest)
    }

    /// The recoverable window `(earliest, latest)` in CID timestamps: from the watermark of
    /// the oldest usable base backup to [`Self::latest_recoverable_ts`]. None without a
    /// base backup, since segments alone can not be recovered.
    pub fn recoverable_window(&self) -> Option<(Duration, Duration)> {
        let earliest = self
            .base_backups
            .iter()
            .map(|b| b.watermark_ts)
            .find(|ts| !self.is_abandoned(*ts))?;
        let latest = self.latest_recoverable_ts()?;
        Some((earliest, latest.max(earliest)))
    }
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

#[cfg(test)]
mod wal_tests {
    use super::*;

    fn segment(id: &str, start: u64, end: u64) -> WalSegment {
        WalSegment {
            segment_id: id.to_string(),
            server_uuid: Uuid::nil(),
            start_ts: Duration::from_secs(start),
            end_ts: Duration::from_secs(end),
            first_cid: String::new(),
            last_cid: String::new(),
            entry_count: 1,
            checksum_sha256: String::new(),
            size_bytes: 1,
            compression: BackupCompression::Gzip,
            server_version: "test".to_string(),
            created_at: String::new(),
        }
    }

    fn base(key: &str, watermark: u64) -> PitrBaseBackup {
        PitrBaseBackup {
            key: key.to_string(),
            timestamp: String::new(),
            watermark_ts: Duration::from_secs(watermark),
            server_version: "test".to_string(),
        }
    }

    #[test]
    fn test_wal_archive_config_default() {
        let config = WalArchiveConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.retention_days, 7);
        assert_eq!(config.segment_size_bytes, 16 * 1024 * 1024);
        assert_eq!(config.segment_interval_seconds, 300);
        assert!(config.s3.is_none());
        assert!(config.local_path.is_none());
        assert!(config.validate().is_ok());
        assert_eq!(config.retention(), Duration::from_secs(7 * 86400));
        assert_eq!(config.segment_interval(), Duration::from_secs(300));
    }

    #[test]
    fn test_wal_archive_config_validate() {
        let zero_size = WalArchiveConfig {
            segment_size_bytes: 0,
            ..WalArchiveConfig::default()
        };
        assert!(zero_size
            .validate()
            .unwrap_err()
            .contains("segment_size_bytes"));

        let zero_retention = WalArchiveConfig {
            retention_days: 0,
            ..WalArchiveConfig::default()
        };
        assert!(zero_retention
            .validate()
            .unwrap_err()
            .contains("retention_days"));

        let zero_interval = WalArchiveConfig {
            segment_interval_seconds: 0,
            ..WalArchiveConfig::default()
        };
        assert!(zero_interval
            .validate()
            .unwrap_err()
            .contains("segment_interval_seconds"));
    }

    #[test]
    fn test_wal_archive_config_deserialize_defaults() {
        let config: WalArchiveConfig = serde_json::from_str(r#"{"enabled": true}"#).unwrap();
        assert!(config.enabled);
        assert_eq!(config.segment_interval_seconds, 300);
        assert_eq!(config.retention_days, 7);

        let config: WalArchiveConfig = serde_json::from_str(
            r#"{"enabled": true, "segment_interval_seconds": 5, "local_path": "/tmp/wal"}"#,
        )
        .unwrap();
        assert_eq!(config.segment_interval_seconds, 5);
        assert_eq!(config.local_path, Some(PathBuf::from("/tmp/wal")));
        assert!(config.to_string().contains("segment_interval_seconds: 5"));
    }

    #[test]
    fn test_wal_segment_object_key_and_display() {
        let s = segment("wal-x.json.gz", 1, 2);
        assert_eq!(s.object_key(), "wal/wal-x.json.gz");
        assert!(s.to_string().contains("wal-x.json.gz"));
        let json = serde_json::to_string(&s).unwrap();
        let back: WalSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn test_pitr_manifest_add_sorts_and_dedups() {
        let mut manifest = PitrManifest::new(Uuid::nil());
        manifest.add_segment(segment("b", 20, 30));
        manifest.add_segment(segment("a", 10, 20));
        manifest.add_segment(segment("a", 10, 25));
        assert_eq!(manifest.segments.len(), 2);
        assert_eq!(manifest.segments[0].segment_id, "a");
        assert_eq!(manifest.segments[0].end_ts, Duration::from_secs(25));

        manifest.add_base_backup(base("backup-2", 50));
        manifest.add_base_backup(base("backup-1", 5));
        manifest.add_base_backup(base("backup-2", 40));
        assert_eq!(manifest.base_backups.len(), 2);
        assert_eq!(manifest.oldest_base_backup().unwrap().key, "backup-1");
        assert_eq!(
            manifest.base_backups[1].watermark_ts,
            Duration::from_secs(40)
        );

        manifest.retain_base_backups(&["backup-2".to_string()]);
        assert_eq!(manifest.base_backups.len(), 1);
        manifest.remove_segment("a");
        assert_eq!(manifest.segments.len(), 1);
    }

    #[test]
    fn test_pitr_manifest_base_selection_and_window() {
        let mut manifest = PitrManifest::new(Uuid::nil());
        assert!(manifest.recoverable_window().is_none());
        assert!(manifest.latest_recoverable_ts().is_none());

        manifest.add_base_backup(base("backup-1", 10));
        manifest.add_base_backup(base("backup-2", 40));
        manifest.add_segment(segment("s1", 11, 20));
        manifest.add_segment(segment("s2", 21, 45));
        manifest.add_segment(segment("s3", 46, 60));

        assert!(manifest.base_backup_for(Duration::from_secs(9)).is_none());
        assert_eq!(
            manifest
                .base_backup_for(Duration::from_secs(10))
                .unwrap()
                .key,
            "backup-1"
        );
        assert_eq!(
            manifest
                .base_backup_for(Duration::from_secs(39))
                .unwrap()
                .key,
            "backup-1"
        );
        assert_eq!(
            manifest
                .base_backup_for(Duration::from_secs(40))
                .unwrap()
                .key,
            "backup-2"
        );
        assert_eq!(
            manifest
                .base_backup_for(Duration::from_secs(1000))
                .unwrap()
                .key,
            "backup-2"
        );

        // From backup-2 (watermark 40) to 50: s2 straddles the watermark, s3 the target.
        let ids: Vec<&str> = manifest
            .segments_between(Duration::from_secs(40), Duration::from_secs(50))
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s2", "s3"]);

        // A segment ending exactly on the watermark holds nothing new.
        let ids: Vec<&str> = manifest
            .segments_between(Duration::from_secs(20), Duration::from_secs(20))
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert!(ids.is_empty());

        assert_eq!(
            manifest.recoverable_window(),
            Some((Duration::from_secs(10), Duration::from_secs(60)))
        );

        // A base newer than every segment extends the window.
        manifest.add_base_backup(base("backup-3", 70));
        assert_eq!(
            manifest.latest_recoverable_ts(),
            Some(Duration::from_secs(70))
        );
    }

    #[test]
    fn test_pitr_manifest_timeline_breaks() {
        let mut manifest = PitrManifest::new(Uuid::nil());
        manifest.add_base_backup(base("backup-1", 10));
        manifest.add_base_backup(base("backup-2", 40));
        manifest.add_segment(segment("s1", 11, 50));
        manifest.add_segment(segment("s2", 51, 60));

        // Recovered to 30 at 70: everything in (30, 70] is abandoned, including the base
        // backup taken at 40.
        manifest.add_timeline_break(PitrTimelineBreak {
            after_ts: Duration::from_secs(30),
            until_ts: Duration::from_secs(70),
            at: String::new(),
            reason: "recover".to_string(),
        });
        assert_eq!(manifest.base_backups.len(), 1);
        assert!(!manifest.is_abandoned(Duration::from_secs(30)));
        assert!(manifest.is_abandoned(Duration::from_secs(31)));
        assert!(manifest.is_abandoned(Duration::from_secs(70)));
        assert!(!manifest.is_abandoned(Duration::from_secs(71)));
        assert_eq!(
            manifest
                .base_backup_for(Duration::from_secs(1000))
                .unwrap()
                .key,
            "backup-1"
        );
        // The segments end in abandoned history; the latest point is the recovered one.
        assert_eq!(
            manifest.latest_recoverable_ts(),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            manifest.recoverable_window(),
            Some((Duration::from_secs(10), Duration::from_secs(30)))
        );

        // The new history after the recovery extends the window again.
        manifest.add_segment(segment("s3", 80, 90));
        assert_eq!(
            manifest.latest_recoverable_ts(),
            Some(Duration::from_secs(90))
        );

        // A second recovery to an earlier point abandons the first recovered point too.
        manifest.add_timeline_break(PitrTimelineBreak {
            after_ts: Duration::from_secs(20),
            until_ts: Duration::from_secs(100),
            at: String::new(),
            reason: "recover".to_string(),
        });
        assert_eq!(
            manifest.latest_recoverable_ts(),
            Some(Duration::from_secs(20))
        );

        // Breaks stay while archived history precedes them, and go once it does not.
        manifest.prune_timeline_breaks();
        assert_eq!(manifest.timeline_breaks.len(), 2);
        manifest.retain_base_backups(&[]);
        manifest.remove_segment("s1");
        manifest.remove_segment("s2");
        manifest.remove_segment("s3");
        manifest.add_segment(segment("s4", 85, 95));
        manifest.prune_timeline_breaks();
        assert_eq!(manifest.timeline_breaks.len(), 1);
        assert_eq!(
            manifest.timeline_breaks[0].until_ts,
            Duration::from_secs(100)
        );
        manifest.remove_segment("s4");
        manifest.prune_timeline_breaks();
        assert!(manifest.timeline_breaks.is_empty());

        // Manifests written before timeline breaks existed still load.
        let mut json: serde_json::Value = serde_json::to_value(&manifest).unwrap();
        json.as_object_mut().unwrap().remove("timeline_breaks");
        let back: PitrManifest = serde_json::from_value(json).unwrap();
        assert!(back.timeline_breaks.is_empty());
    }

    #[test]
    fn test_pitr_manifest_gaps() {
        let gap = |from: u64, until: u64| PitrWalGap {
            from_ts: Duration::from_secs(from),
            until_ts: Duration::from_secs(until),
            reason: "test".to_string(),
        };
        let mut manifest = PitrManifest::new(Uuid::nil());
        manifest.add_base_backup(base("backup-1", 10));
        manifest.add_segment(segment("s1", 11, 100));

        // Records from 40 to 50 are missing.
        manifest.add_gap(gap(40, 50));
        manifest.add_gap(gap(40, 50));
        assert_eq!(manifest.gaps.len(), 1);

        let w = Duration::from_secs(10);
        assert!(manifest.gap_blocking(w, Duration::from_secs(39)).is_none());
        assert!(manifest.gap_blocking(w, Duration::from_secs(40)).is_some());
        assert!(manifest.gap_blocking(w, Duration::from_secs(90)).is_some());
        // A base that already holds the gap's history is not blocked; nor is a replay of
        // nothing.
        assert!(manifest
            .gap_blocking(Duration::from_secs(50), Duration::from_secs(90))
            .is_none());
        assert!(manifest
            .gap_blocking(Duration::from_secs(45), Duration::from_secs(45))
            .is_none());

        // The latest point stops just before the gap.
        assert_eq!(
            manifest.latest_recoverable_ts(),
            Some(Duration::from_secs(40) - Duration::from_nanos(1))
        );

        // A base taken after the gap closes it.
        manifest.add_base_backup(base("backup-2", 60));
        assert_eq!(
            manifest.latest_recoverable_ts(),
            Some(Duration::from_secs(100))
        );
        // A gap starting before the base it follows limits the latest point to that base.
        manifest.add_gap(gap(55, 70));
        assert_eq!(
            manifest.latest_recoverable_ts(),
            Some(Duration::from_secs(60))
        );

        // A gap inside abandoned history does not matter.
        manifest.add_timeline_break(PitrTimelineBreak {
            after_ts: Duration::from_secs(62),
            until_ts: Duration::from_secs(80),
            at: String::new(),
            reason: "recover".to_string(),
        });
        manifest.add_segment(segment("s2", 81, 120));
        assert!(manifest
            .gap_blocking(Duration::from_secs(60), Duration::from_secs(120))
            .is_some());
        manifest
            .gaps
            .retain(|g| g.from_ts != Duration::from_secs(55));
        manifest.add_gap(gap(65, 70));
        assert!(manifest
            .gap_blocking(Duration::from_secs(60), Duration::from_secs(120))
            .is_none());

        // Gaps go once no retained history precedes them.
        manifest.prune_gaps();
        assert_eq!(manifest.gaps.len(), 2);
        manifest.retain_base_backups(&["backup-2".to_string()]);
        manifest.remove_segment("s1");
        manifest.prune_gaps();
        assert_eq!(manifest.gaps.len(), 1);
        assert_eq!(manifest.gaps[0].from_ts, Duration::from_secs(65));
    }

    #[test]
    fn test_pitr_manifest_serialization() {
        let mut manifest = PitrManifest::new(Uuid::nil());
        manifest.add_base_backup(base("backup-1", 10));
        manifest.add_segment(segment("s1", 11, 20));
        let json = serde_json::to_string(&manifest).unwrap();
        let back: PitrManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
        assert_eq!(back.version, PITR_MANIFEST_VERSION);
    }

    #[test]
    fn test_recovery_target() {
        assert!(RecoveryTarget::to_time("2024-01-15T10:30:00Z").is_ok());
        assert!(RecoveryTarget::to_time("2024-01-15T10:30:00+05:00").is_ok());
        assert!(RecoveryTarget::to_time("2024-01-15T10:30:00.123456Z").is_ok());
        assert!(RecoveryTarget::to_time("invalid-timestamp").is_err());
        assert!(RecoveryTarget::to_transaction("").is_err());

        let time = RecoveryTarget::to_time("2024-01-15T10:30:00Z").unwrap();
        assert!(matches!(time.target_type, RecoveryTargetType::Time { .. }));
        assert_eq!(time.to_string(), "time:2024-01-15T10:30:00Z");

        let txn = RecoveryTarget::to_transaction("123-uuid").unwrap();
        assert!(matches!(
            txn.target_type,
            RecoveryTargetType::Transaction { .. }
        ));
        assert_eq!(txn.to_string(), "transaction:123-uuid");

        let latest = RecoveryTarget::latest();
        assert!(matches!(latest.target_type, RecoveryTargetType::Latest));
        assert_eq!(latest.to_string(), "latest");

        let json = serde_json::to_string(&time).unwrap();
        let back: RecoveryTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(time, back);
    }
}
