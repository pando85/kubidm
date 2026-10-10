//! The server configuration as processed from the startup wrapper. This controls a number of
//! variables that determine how our backends, query server, and frontends are configured.
//!
//! These components should be "per server". Any "per domain" config should be in the system
//! or domain entries that are able to be replicated.

use cidr::IpCidr;
use kubidm_proto::backup::{
    BackupCompression, BackupEncryptionConfig, ReplicationConfig, S3Config, S3EncryptionAlgorithm,
    WalArchiveConfig,
};
pub use kubidm_proto::config::ServerRole;
use kubidm_proto::constants::DEFAULT_SERVER_ADDRESS;
use kubidm_proto::internal::FsType;
use serde::Deserialize;
use serde_with::{formats::PreferOne, serde_as, OneOrMany};
use sketching::LogLevel;
use std::{
    collections::BTreeSet,
    fmt::{self, Display},
    fs::File,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};
use url::Url;

use crate::backup::{same_s3_location, validate_encryption_config, validate_s3_location};
use crate::interval::parse_backup_schedule;
use crate::repl::config::ReplicationConfiguration;

#[derive(Debug, Deserialize)]
struct VersionDetection {
    #[serde(default)]
    version: Version,
}

#[derive(Debug, Deserialize, Default)]
// #[serde(tag = "version")]
pub enum Version {
    #[serde(rename = "2")]
    V2,

    #[default]
    Legacy,
}

// Allowed as the large enum is only short lived at startup to the true config
#[allow(clippy::large_enum_variant)]
pub enum ServerConfigUntagged {
    Version(ServerConfigVersion),
    Legacy(ServerConfig),
}

pub enum ServerConfigVersion {
    V2 { values: ServerConfigV2 },
}

#[derive(Deserialize, Debug, Clone)]
pub struct OnlineBackup {
    /// The destination folder for your backups, defaults to the db_path dir if not set
    pub path: Option<PathBuf>,
    /// The schedule to run online backups (see <https://crontab.guru/>), defaults to @daily
    ///
    /// Examples:
    ///
    /// - every day at 22:00 UTC (default): `"00 22 * * *"`
    /// - every 6th hours (four times a day) at 3 minutes past the hour, :
    ///   `"03 */6 * * *"`
    ///
    /// We also support non standard cron syntax, with the following format:
    ///
    /// `<sec>  <min>   <hour>   <day of month>   <month>   <day of week>   <year>`
    ///
    /// eg:
    /// - `1 2 3 5 12 * 2023` would only back up once on the 5th of December 2023 at 03:02:01am.
    /// - `3 2 1 * * Mon *` backs up every Monday at 03:02:01am.
    ///
    /// (it's very similar to the standard cron syntax, it just allows to specify the seconds at the beginning and the year at the end)
    pub schedule: String,
    #[serde(default = "default_online_backup_versions")]
    /// How many past backup versions to keep in every backup location, defaults to 7.
    /// Must be at least 1.
    pub versions: usize,
    /// Enabled by default
    #[serde(default = "default_online_backup_enabled")]
    pub enabled: bool,

    #[serde(default)]
    pub compression: BackupCompression,

    /// S3 configuration for cloud backup storage. If provided, backups will also be stored in S3.
    #[serde(default)]
    pub s3: Option<S3Config>,

    /// Client-side backup encryption. When enabled, every backup made from this
    /// configuration (online, S3 and `kubidmd database backup`) is encrypted with
    /// AES-256-GCM under a key derived from the configured key source, and encrypted
    /// artifacts are decrypted on restore and verification with the same key.
    #[serde(default)]
    pub encryption: BackupEncryptionConfig,

    /// WAL archive configuration for Point-in-Time Recovery (PITR).
    #[serde(default)]
    pub wal_archive: Option<WalArchiveConfig>,

    /// An optional schedule, in the syntax of `schedule`, for the full verification of the
    /// newest backup: the newest artifact of the local directory, and of the S3 prefix when
    /// S3 is configured, is restored into a temporary database, booted and checked as
    /// `kubidmd database verify-backup` does. Off by default. Requires `enabled = true`.
    #[serde(default)]
    pub verify_schedule: Option<String>,

    /// Where the scheduled verification creates its scratch directories (the copied or
    /// downloaded artifact and the restored, unencrypted scratch database), each named
    /// `kubidm-verify-*`. Defaults to the directory of the database. The server removes the
    /// `kubidm-verify-*` directories it finds there when it starts, so it must not be
    /// shared with another server.
    #[serde(default)]
    pub verify_temp_path: Option<PathBuf>,

    /// Serve the backup metrics in the Prometheus text format on `GET /metrics`. Off by
    /// default.
    #[serde(default)]
    pub metrics_endpoint: bool,

    /// A file holding the token a scraper must send as `Authorization: Bearer <token>` to
    /// read `/metrics`. Without it the endpoint needs no authentication. Requires
    /// `metrics_endpoint = true`.
    #[serde(default)]
    pub metrics_token_file: Option<PathBuf>,
}

impl Default for OnlineBackup {
    fn default() -> Self {
        OnlineBackup {
            path: None,
            schedule: default_online_backup_schedule(),
            versions: default_online_backup_versions(),
            enabled: default_online_backup_enabled(),
            compression: BackupCompression::default(),
            s3: None,
            encryption: BackupEncryptionConfig::default(),
            wal_archive: None,
            verify_schedule: None,
            verify_temp_path: None,
            metrics_endpoint: false,
            metrics_token_file: None,
        }
    }
}

impl OnlineBackup {
    /// Check the settings that can be checked without a database: the backup encryption
    /// key must be obtainable now, so that the first scheduled backup does not discover a
    /// missing key, the replication section must be coherent, and the WAL archive must be
    /// able to work. Accepting a setting that has no effect silently would let an operator
    /// believe a feature is active when it is not.
    ///
    /// The WAL directory itself is checked for writability when the server starts (the
    /// backend creates and probes it), not here, since `configtest` must not create it.
    pub fn validate(&self) -> Result<(), String> {
        if self.versions == 0 {
            // Retention keeps the newest `versions` backups, so zero would delete every
            // backup, in every location and region, right after it was taken.
            return Err(
                "online_backup.versions must be at least 1: it is the number of backups kept \
                 in every backup location, and 0 would delete every backup right after it was \
                 taken"
                    .to_string(),
            );
        }

        validate_encryption_config(&self.encryption)
            .map_err(|reason| format!("online_backup.encryption: {reason}"))?;

        if let Some(wal_archive) = self.wal_archive.as_ref().filter(|w| w.enabled) {
            if !self.enabled {
                return Err(
                    "online_backup.wal_archive: WAL archiving requires online_backup.enabled = true, \
                     since point-in-time recovery replays the archive on top of a base backup"
                        .to_string(),
                );
            }
            wal_archive
                .validate()
                .map_err(|reason| format!("online_backup.wal_archive: {reason}"))?;
            // A separate S3 location of the archive may replicate it to regions of its own.
            if let Some(wal_s3) = &wal_archive.s3 {
                validate_s3_location(wal_s3)
                    .map_err(|reason| format!("online_backup.wal_archive.s3: {reason}"))?;
                if let Some(replication) = &wal_s3.replication {
                    validate_replication(wal_s3, replication).map_err(|reason| {
                        reason.replacen("online_backup.s3", "online_backup.wal_archive.s3", 1)
                    })?;
                }
            }
        }

        if let Some(s3) = &self.s3 {
            validate_s3_location(s3).map_err(|reason| format!("online_backup.s3: {reason}"))?;
            if let Some(replication) = &s3.replication {
                validate_replication(s3, replication)?;
            }
        }

        if self.enabled {
            parse_backup_schedule(&self.schedule)
                .map_err(|reason| format!("online_backup.schedule: {reason}"))?;
        }

        if let Some(verify_schedule) = &self.verify_schedule {
            if !self.enabled {
                return Err(
                    "online_backup.verify_schedule: the scheduled verification requires \
                     online_backup.enabled = true; verify the backups of a host that does not \
                     take them with `kubidmd database verify-backup`"
                        .to_string(),
                );
            }
            parse_backup_schedule(verify_schedule)
                .map_err(|reason| format!("online_backup.verify_schedule: {reason}"))?;
        }

        // The token file itself is only read by the server that serves the endpoint, when
        // it starts (and that start fails when it can not be read): the offline commands
        // share this configuration and never need the token, so a token mounted for the
        // server alone must not stop them.
        if self.metrics_token_file.is_some() && !self.metrics_endpoint {
            return Err(
                "online_backup.metrics_token_file: it protects the metrics endpoint, which \
                 requires online_backup.metrics_endpoint = true"
                    .to_string(),
            );
        }

        Ok(())
    }
}

/// The token of `online_backup.metrics_token_file`: the content of the file without its
/// surrounding whitespace. Fails when it can not be read or holds no token.
pub fn read_metrics_token(path: &Path) -> Result<String, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("unable to read {}: {err}", path.display()))?;
    let token = content.trim();
    if token.is_empty() {
        return Err(format!("{} holds no token", path.display()));
    }
    Ok(token.to_string())
}

/// Check an enabled `[online_backup.s3.replication]` section of `s3`: it needs at least one
/// region, every region needs a name and a bucket, region names must be unique (they
/// identify the region in `replicate-status` and in `--region`), the sync interval must be
/// positive, and every region must be a location of its own: neither the primary location
/// nor that of another region (same endpoint, bucket and path prefix), since such a copy
/// adds no redundancy while being reported as healthy. A disabled section is accepted as is.
fn validate_replication(s3: &S3Config, replication: &ReplicationConfig) -> Result<(), String> {
    if !replication.enabled {
        return Ok(());
    }

    if replication.regions.is_empty() {
        return Err(
            "online_backup.s3.replication: enabled = true requires at least one \
             [[online_backup.s3.replication.regions]] entry"
                .to_string(),
        );
    }

    if replication.sync_interval_seconds == 0 {
        return Err(
            "online_backup.s3.replication: sync_interval_seconds must be greater than 0"
                .to_string(),
        );
    }

    let mut names = BTreeSet::new();
    for (index, region) in replication.regions.iter().enumerate() {
        if region.region.trim().is_empty() {
            return Err(format!(
                "online_backup.s3.replication.regions[{index}]: region must not be empty"
            ));
        }
        if region
            .name
            .as_ref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(format!(
                "online_backup.s3.replication.regions[{index}]: name must not be empty; omit it \
                 to name the region after its signing region"
            ));
        }
        if region.bucket.trim().is_empty() {
            return Err(format!(
                "online_backup.s3.replication.regions[{index}] ({}): bucket must not be empty",
                region.name()
            ));
        }
        if !names.insert(region.name()) {
            return Err(format!(
                "online_backup.s3.replication.regions[{index}]: region name {:?} is used by \
                 more than one entry; region names must be unique. Set `name` to tell apart \
                 replicas that share a signing region",
                region.name()
            ));
        }
        if region.kms_key_id.is_some()
            && region
                .server_side_encryption
                .as_ref()
                .is_some_and(|sse| sse.algorithm == Some(S3EncryptionAlgorithm::Aes256))
        {
            return Err(format!(
                "online_backup.s3.replication.regions[{index}] ({}): kms_key_id is a shorthand \
                 for aws:kms server-side encryption and can not be combined with \
                 server_side_encryption.algorithm = \"AES256\"",
                region.name()
            ));
        }
        let location = region.to_s3_config();
        validate_s3_location(&location).map_err(|reason| {
            format!(
                "online_backup.s3.replication.regions[{index}] ({}): {reason}",
                region.name()
            )
        })?;
        if same_s3_location(&location, s3) {
            return Err(format!(
                "online_backup.s3.replication.regions[{index}] ({}): bucket {:?} with this \
                 endpoint and path_prefix is the primary backup location itself; a replica \
                 must be stored elsewhere",
                region.name(),
                region.bucket
            ));
        }
        if let Some(other) = replication
            .regions
            .iter()
            .take(index)
            .find(|other| same_s3_location(&other.to_s3_config(), &location))
        {
            return Err(format!(
                "online_backup.s3.replication.regions[{index}] ({}): bucket {:?} with this \
                 endpoint and path_prefix is already the location of region {:?}",
                region.name(),
                region.bucket,
                other.name()
            ));
        }
    }

    Ok(())
}

fn default_online_backup_enabled() -> bool {
    true
}

fn default_online_backup_schedule() -> String {
    "@daily".to_string()
}

fn default_online_backup_versions() -> usize {
    7
}

#[derive(Deserialize, Debug, Clone)]
pub struct TlsConfiguration {
    pub chain: PathBuf,
    pub key: PathBuf,
    pub client_ca: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub enum TcpAddressInfo {
    #[default]
    None,
    ProxyV2(Vec<IpCidr>),
    ProxyV1(Vec<IpCidr>),
}

#[derive(Deserialize, Debug, Clone, Default)]
pub enum LdapAddressInfo {
    #[default]
    None,
    #[serde(rename = "proxy-v2")]
    ProxyV2(Vec<IpCidr>),
    #[serde(rename = "proxy-v1")]
    ProxyV1(Vec<IpCidr>),
}

impl LdapAddressInfo {
    pub fn trusted_tcp_info(&self) -> TcpAddressInfo {
        match self {
            LdapAddressInfo::None => TcpAddressInfo::None,
            LdapAddressInfo::ProxyV2(trusted) => TcpAddressInfo::ProxyV2(trusted.clone()),
            LdapAddressInfo::ProxyV1(trusted) => TcpAddressInfo::ProxyV1(trusted.clone()),
        }
    }
}

impl Display for LdapAddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::ProxyV2(trusted) => {
                f.write_str("proxy-v2 [ ")?;
                for ip in trusted {
                    write!(f, "{ip} ")?;
                }
                f.write_str("]")
            }
            Self::ProxyV1(trusted) => {
                f.write_str("proxy-v1 [ ")?;
                for ip in trusted {
                    write!(f, "{ip} ")?;
                }
                f.write_str("]")
            }
        }
    }
}

pub(crate) enum AddressSet {
    NonContiguousIpSet(Vec<IpCidr>),
    All,
}

impl AddressSet {
    pub(crate) fn contains(&self, ip_addr: &IpAddr) -> bool {
        match self {
            Self::All => true,
            Self::NonContiguousIpSet(range) => {
                range.iter().any(|ip_cidr| ip_cidr.contains(ip_addr))
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
pub enum HttpAddressInfo {
    #[default]
    None,
    #[serde(rename = "x-forward-for")]
    XForwardFor(Vec<IpCidr>),
    // IMPORTANT: This is undocumented, and only exists for backwards compat
    // with config v1 which has a boolean toggle for this option.
    #[serde(rename = "x-forward-for-all-source-trusted")]
    XForwardForAllSourcesTrusted,
    #[serde(rename = "proxy-v2")]
    ProxyV2(Vec<IpCidr>),
    #[serde(rename = "proxy-v1")]
    ProxyV1(Vec<IpCidr>),
}

impl HttpAddressInfo {
    pub(crate) fn trusted_x_forward_for(&self) -> Option<AddressSet> {
        match self {
            Self::XForwardForAllSourcesTrusted => Some(AddressSet::All),
            Self::XForwardFor(trusted) => Some(AddressSet::NonContiguousIpSet(trusted.clone())),
            _ => None,
        }
    }

    pub fn trusted_tcp_info(&self) -> TcpAddressInfo {
        match self {
            Self::ProxyV2(trusted) => TcpAddressInfo::ProxyV2(trusted.clone()),
            Self::ProxyV1(trusted) => TcpAddressInfo::ProxyV1(trusted.clone()),
            Self::None | Self::XForwardFor(_) | Self::XForwardForAllSourcesTrusted => {
                TcpAddressInfo::None
            }
        }
    }
}

impl Display for HttpAddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),

            Self::XForwardFor(trusted) => {
                f.write_str("x-forward-for [ ")?;
                for ip in trusted {
                    write!(f, "{ip} ")?;
                }
                f.write_str("]")
            }
            Self::XForwardForAllSourcesTrusted => {
                f.write_str("x-forward-for [ ALL SOURCES TRUSTED ]")
            }
            Self::ProxyV2(trusted) => {
                f.write_str("proxy-v2 [ ")?;
                for ip in trusted {
                    write!(f, "{ip} ")?;
                }
                f.write_str("]")
            }
            Self::ProxyV1(trusted) => {
                f.write_str("proxy-v1 [ ")?;
                for ip in trusted {
                    write!(f, "{ip} ")?;
                }
                f.write_str("]")
            }
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
pub enum HttpVersions {
    #[serde(rename = "all")]
    #[default]
    All,
    #[serde(rename = "2")]
    V2_0,
    #[serde(rename = "1")]
    V1_1,
}

impl Display for HttpVersions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("http/2 + http/1"),
            Self::V2_0 => f.write_str("http/2"),
            Self::V1_1 => f.write_str("http/1"),
        }
    }
}

/// This is the Server Configuration as read from `server.toml` or environment variables.
///
/// Fields noted as "REQUIRED" are required for the server to start, even if they show as optional due to how file parsing works.
///
/// If you want to set these as environment variables, prefix them with `KUBIDM_` and they will be picked up. This does not include replication peer config.
///
/// NOTE: not all flags or values from the internal [Configuration] object are exposed via this structure
/// to prevent certain settings being set (e.g. integration test modes)
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// *REQUIRED* - Kubidm Domain, eg `kubidm.example.com`.
    domain: Option<String>,
    /// *REQUIRED* - The user-facing HTTPS URL for this server, eg <https://idm.example.com>
    origin: Option<Url>,
    /// File path of the database file
    db_path: Option<PathBuf>,
    /// The filesystem type, either "zfs" or "generic". Defaults to "generic" if unset. I you change this, run a database vacuum.
    db_fs_type: Option<kubidm_proto::internal::FsType>,

    ///  *REQUIRED* - The file path to the TLS Certificate Chain
    tls_chain: Option<PathBuf>,
    ///  *REQUIRED* - The file path to the TLS Private Key
    tls_key: Option<PathBuf>,

    /// The directory path of the client ca and crl dir.
    tls_client_ca: Option<PathBuf>,

    /// The listener address for the HTTPS server.
    ///
    /// eg. `[::]:8443` or `127.0.0.1:8443`. Defaults to [kubidm_proto::constants::DEFAULT_SERVER_ADDRESS]
    bindaddress: Option<String>,
    /// The listener address for the LDAP server.
    ///
    /// eg. `[::]:3636` or `127.0.0.1:3636`.
    ///
    /// If unset, the LDAP server will be disabled.
    ldapbindaddress: Option<String>,
    /// The role of this server, one of write_replica, write_replica_no_ui, read_only_replica, defaults to [ServerRole::WriteReplica]
    role: Option<ServerRole>,
    /// The log level, one of info, debug, trace. Defaults to "info" if not set.
    log_level: Option<LogLevel>,

    /// Backup Configuration, see [OnlineBackup] for details on sub-keys.
    online_backup: Option<OnlineBackup>,

    /// Trust the X-Forwarded-For header for client IP address. Defaults to false if unset.
    trust_x_forward_for: Option<bool>,

    /// The path to the "admin" socket, used for local communication when performing certain server control tasks. Default is set on build, based on the system target.
    adminbindpath: Option<String>,

    /// The maximum amount of threads the server will use for the async worker pool. Defaults
    /// to std::threads::available_parallelism.
    thread_count: Option<usize>,

    /// Maximum Request Size in bytes
    maximum_request_size_bytes: Option<usize>,

    /// Don't touch this unless you know what you're doing!
    #[allow(dead_code)]
    db_arc_size: Option<usize>,
    #[serde(default)]
    #[serde(rename = "replication")]
    /// Replication configuration, this is a development feature and not yet ready for production use.
    repl_config: Option<ReplicationConfiguration>,
    /// An optional OpenTelemetry collector (GRPC) url to send trace and log data to, eg `localhost:4317`. If not set, disables the feature.
    otel_grpc_endpoint: Option<String>,
    /// Policy Information Point (PIP) configuration for external attribute retrieval.
    /// See [kubidmd_lib::idm::pip::config::PipConfig] for details.
    #[serde(default)]
    pip_config: Option<kubidmd_lib::idm::pip::config::PipConfig>,
}

impl ServerConfigUntagged {
    /// loads the configuration file from the path specified, then overlays fields from environment variables starting with `KUBIDM_``
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, std::io::Error> {
        // see if we can load it from the config file you asked for
        let mut f: File = File::open(config_path.as_ref()).inspect_err(|e| {
            eprintln!("Unable to open config file [{e:?}] 🥺");
            let diag = kubidm_lib_file_permissions::diagnose_path(config_path.as_ref());
            eprintln!("{diag}");
        })?;

        let mut contents = String::new();

        f.read_to_string(&mut contents).inspect_err(|e| {
            eprintln!("unable to read contents {e:?}");
            let diag = kubidm_lib_file_permissions::diagnose_path(config_path.as_ref());
            eprintln!("{diag}");
        })?;

        // First, can we detect the config version?
        let config_version = toml::from_str::<VersionDetection>(contents.as_str())
            .map(|vd| vd.version)
            .map_err(|err| {
                eprintln!(
                    "Unable to parse config version from '{:?}': {:?}",
                    config_path.as_ref(),
                    err
                );
                std::io::Error::new(std::io::ErrorKind::InvalidData, err)
            })?;

        match config_version {
            Version::V2 => toml::from_str::<ServerConfigV2>(contents.as_str())
                .map(|values| ServerConfigUntagged::Version(ServerConfigVersion::V2 { values })),
            Version::Legacy => {
                toml::from_str::<ServerConfig>(contents.as_str()).map(ServerConfigUntagged::Legacy)
            }
        }
        .map_err(|err| {
            eprintln!(
                "Unable to parse config from '{:?}': {:?}",
                config_path.as_ref(),
                err
            );
            std::io::Error::new(std::io::ErrorKind::InvalidData, err)
        })
    }
}

#[serde_as]
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerConfigV2 {
    #[allow(dead_code)]
    version: String,
    domain: Option<String>,
    origin: Option<Url>,
    db_path: Option<PathBuf>,
    db_fs_type: Option<kubidm_proto::internal::FsType>,
    tls_chain: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,

    migration_path: Option<PathBuf>,

    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    bindaddress: Option<Vec<String>>,
    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    ldapbindaddress: Option<Vec<String>>,

    role: Option<ServerRole>,
    log_level: Option<LogLevel>,
    online_backup: Option<OnlineBackup>,

    http_server_versions: Option<HttpVersions>,
    http_client_address_info: Option<HttpAddressInfo>,
    ldap_client_address_info: Option<LdapAddressInfo>,

    adminbindpath: Option<String>,
    thread_count: Option<usize>,
    maximum_request_size_bytes: Option<usize>,
    #[allow(dead_code)]
    db_arc_size: Option<usize>,
    #[serde(default)]
    #[serde(rename = "replication")]
    repl_config: Option<ReplicationConfiguration>,
    otel_grpc_endpoint: Option<String>,
    /// Policy Information Point (PIP) configuration for external attribute retrieval.
    #[serde(default)]
    pip_config: Option<kubidmd_lib::idm::pip::config::PipConfig>,
}

#[derive(Debug, Clone)]
pub struct IntegrationTestConfig {
    pub admin_user: String,
    pub admin_password: String,
    pub idm_admin_user: String,
    pub idm_admin_password: String,
}

#[derive(Debug, Clone)]
pub struct IntegrationReplConfig {
    // We can bake in a private key for mTLS here.
    // pub private_key: PKey

    // We might need some condition variables / timers to force replication
    // events? Or a channel to submit with oneshot responses.
}

/// The internal configuration of the server. User-facing configuration is in [ServerConfig], as the configuration file is parsed by that object.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub address: Vec<String>,
    pub ldapbindaddress: Option<Vec<String>>,
    pub adminbindpath: String,
    pub threads: usize,
    // db type later
    pub db_path: Option<PathBuf>,
    pub db_fs_type: Option<FsType>,
    pub db_arc_size: Option<usize>,
    pub maximum_request: usize,

    pub migration_path: Option<PathBuf>,

    pub http_server_versions: HttpVersions,
    pub http_client_address_info: HttpAddressInfo,
    pub ldap_client_address_info: LdapAddressInfo,

    pub tls_config: Option<TlsConfiguration>,
    pub integration_test_config: Option<Box<IntegrationTestConfig>>,
    pub online_backup: Option<OnlineBackup>,
    pub domain: String,
    pub origin: Url,
    pub role: ServerRole,
    pub log_level: LogLevel,
    /// Replication settings.
    pub repl_config: Option<ReplicationConfiguration>,
    /// This allows internally setting some unsafe options for replication.
    pub integration_repl_config: Option<Box<IntegrationReplConfig>>,
    pub otel_grpc_endpoint: Option<String>,
    /// Policy Information Point (PIP) configuration for external attribute retrieval.
    pub pip_config: Option<kubidmd_lib::idm::pip::config::PipConfig>,
}

impl Configuration {
    pub fn build() -> ConfigurationBuilder {
        ConfigurationBuilder {
            bindaddress: None,
            ldapbindaddress: None,
            adminbindpath: env!("KUBIDM_SERVER_ADMIN_BIND_PATH").to_string(),
            threads: std::thread::available_parallelism()
                .map(|t| t.get())
                .unwrap_or_else(|_e| {
                    eprintln!("WARNING: Unable to read number of available CPUs, defaulting to 4");
                    4
                }),
            db_path: None,
            db_fs_type: None,
            db_arc_size: None,
            migration_path: None,
            maximum_request: 256 * 1024, // 256k
            http_server_versions: HttpVersions::default(),
            http_client_address_info: HttpAddressInfo::default(),
            ldap_client_address_info: LdapAddressInfo::default(),
            tls_key: None,
            tls_chain: None,
            tls_client_ca: None,
            online_backup: None,
            domain: None,
            origin: None,
            log_level: None,
            role: None,
            repl_config: None,
            otel_grpc_endpoint: None,
            pip_config: None,
        }
    }

    pub fn new_for_test() -> Self {
        #[allow(clippy::expect_used)]
        Configuration {
            address: vec![DEFAULT_SERVER_ADDRESS.to_string()],
            ldapbindaddress: None,
            adminbindpath: env!("KUBIDM_SERVER_ADMIN_BIND_PATH").to_string(),
            threads: 1,
            db_path: None,
            db_fs_type: None,
            db_arc_size: None,
            migration_path: None,
            maximum_request: 256 * 1024, // 256k
            http_server_versions: HttpVersions::default(),
            http_client_address_info: HttpAddressInfo::default(),
            ldap_client_address_info: LdapAddressInfo::default(),
            tls_config: None,
            integration_test_config: None,
            online_backup: None,
            domain: "idm.example.com".to_string(),
            origin: Url::from_str("https://idm.example.com")
                .expect("Failed to parse built-in string as URL"),
            log_level: LogLevel::default(),
            role: ServerRole::WriteReplicaNoUI,
            repl_config: None,
            integration_repl_config: None,
            otel_grpc_endpoint: None,
            pip_config: None,
        }
    }
}

impl fmt::Display for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for a in &self.address {
            write!(f, "address: {a}, ")?;
        }
        write!(f, "domain: {}, ", self.domain)?;
        match &self.ldapbindaddress {
            Some(las) => {
                for la in las {
                    write!(f, "ldap address: {la}, ")?;
                }
            }
            None => write!(f, "ldap address: disabled, ")?,
        };
        write!(f, "origin: {} ", self.origin)?;
        write!(f, "admin bind path: {}, ", self.adminbindpath)?;
        write!(f, "thread count: {}, ", self.threads)?;
        write!(
            f,
            "dbpath: {}, ",
            self.db_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or("MEMORY".to_string())
        )?;
        match self.db_arc_size {
            Some(v) => write!(f, "arcsize: {v}, "),
            None => write!(f, "arcsize: AUTO, "),
        }?;
        write!(f, "max request size: {}b, ", self.maximum_request)?;
        write!(f, "http server versions: {}, ", self.http_server_versions)?;
        write!(
            f,
            "http client address info: {}, ",
            self.http_client_address_info
        )?;
        write!(
            f,
            "ldap client address info: {}, ",
            self.ldap_client_address_info
        )?;

        write!(f, "with TLS: {}, ", self.tls_config.is_some())?;
        match &self.online_backup {
            Some(bck) => {
                write!(
                    f,
                    "online_backup: enabled: {} - schedule: {} versions: {} path: {}, ",
                    bck.enabled,
                    bck.schedule,
                    bck.versions,
                    bck.path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or("<unset>".to_string())
                )?;
                if let Some(s3) = &bck.s3 {
                    write!(f, "s3: {}, ", s3)?;
                }
                if let Some(wal) = bck.wal_archive.as_ref().filter(|wal| wal.enabled) {
                    write!(f, "wal_archive: {}, ", wal)?;
                }
                if let Some(verify_schedule) = &bck.verify_schedule {
                    write!(f, "verify_schedule: {}, ", verify_schedule)?;
                }
                if let Some(verify_temp_path) = &bck.verify_temp_path {
                    write!(f, "verify_temp_path: {}, ", verify_temp_path.display())?;
                }
                if bck.metrics_endpoint {
                    write!(
                        f,
                        "metrics_endpoint: enabled ({}), ",
                        if bck.metrics_token_file.is_some() {
                            "bearer token"
                        } else {
                            "no authentication"
                        }
                    )?;
                }
                write!(f, "")
            }
            None => write!(f, "online_backup: disabled, "),
        }?;
        write!(
            f,
            "integration mode: {}, ",
            self.integration_test_config.is_some()
        )?;
        write!(f, "log_level: {}", self.log_level)?;
        write!(f, "role: {}, ", self.role)?;
        match &self.repl_config {
            Some(repl) => {
                write!(f, "replication: enabled")?;
                write!(f, "repl_origin: {} ", repl.origin)?;
                write!(f, "repl_address: {} ", repl.bindaddress)?;
                write!(
                    f,
                    "integration repl config mode: {}, ",
                    self.integration_repl_config.is_some()
                )?;
            }
            None => {
                write!(f, "replication: disabled, ")?;
            }
        }
        write!(f, "otel_grpc_endpoint: {:?}", self.otel_grpc_endpoint)?;
        Ok(())
    }
}

/// The internal configuration of the server. User-facing configuration is in [ServerConfig], as the configuration file is parsed by that object.
#[derive(Debug, Clone)]
pub struct ConfigurationBuilder {
    bindaddress: Option<Vec<String>>,
    ldapbindaddress: Option<Vec<String>>,
    adminbindpath: String,
    threads: usize,
    db_path: Option<PathBuf>,
    db_fs_type: Option<FsType>,
    db_arc_size: Option<usize>,
    migration_path: Option<PathBuf>,
    maximum_request: usize,
    http_server_versions: HttpVersions,
    http_client_address_info: HttpAddressInfo,
    ldap_client_address_info: LdapAddressInfo,
    tls_key: Option<PathBuf>,
    tls_chain: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    online_backup: Option<OnlineBackup>,
    domain: Option<String>,
    origin: Option<Url>,
    role: Option<ServerRole>,
    log_level: Option<LogLevel>,
    repl_config: Option<ReplicationConfiguration>,
    otel_grpc_endpoint: Option<String>,
    pip_config: Option<kubidmd_lib::idm::pip::config::PipConfig>,
}

impl ConfigurationBuilder {
    #![allow(clippy::needless_pass_by_value)]
    pub fn add_cli_config(mut self, cli_config: &kubidm_proto::cli::KubidmdCli) -> Self {
        // logging
        if let Some(log_level) = &cli_config.log_level {
            self.log_level = Some(*log_level);
        }

        if let Some(otel_grpc_endpoint) = &cli_config.otel_grpc_endpoint {
            self.otel_grpc_endpoint = Some(otel_grpc_endpoint.clone());
        }

        // core domainy things
        if let Some(domain) = &cli_config.domain {
            self.domain = Some(domain.clone());
        }

        if let Some(origin) = &cli_config.origin {
            self.origin = Some(origin.clone());
        }

        if let Some(role) = &cli_config.role {
            self.role = Some(*role);
        }

        // networking

        if cli_config.bindaddress.is_some() {
            self.bindaddress = cli_config
                .bindaddress
                .clone()
                .map(|s| s.split(',').map(|s| s.to_string()).collect())
        }

        if cli_config.ldapbindaddress.is_some() {
            self.ldapbindaddress = cli_config
                .ldapbindaddress
                .clone()
                .map(|s| s.split(',').map(|s| s.to_string()).collect())
        }

        // replication

        if let Some(repl_origin) = cli_config.replication_origin.clone() {
            if let Some(repl) = &mut self.repl_config {
                repl.origin = repl_origin
            } else {
                self.repl_config = Some(ReplicationConfiguration {
                    origin: repl_origin,
                    ..Default::default()
                });
            }
        }

        if let Some(replication_bindaddress) = &cli_config.replication_bindaddress {
            if let Some(repl_config) = &mut self.repl_config {
                repl_config.bindaddress = *replication_bindaddress;
            } else {
                self.repl_config = Some(ReplicationConfiguration {
                    bindaddress: *replication_bindaddress,
                    ..Default::default()
                });
            }
        }

        if let Some(task_poll_interval) = cli_config.replication_task_poll_interval {
            if let Some(repl) = &mut self.repl_config {
                repl.task_poll_interval = Some(task_poll_interval);
            } else {
                self.repl_config = Some(ReplicationConfiguration {
                    task_poll_interval: Some(task_poll_interval),
                    ..Default::default()
                });
            }
        }

        // tls

        if let Some(tls_key) = &cli_config.tls_key {
            self.tls_key = Some(tls_key.clone());
        }

        if let Some(tls_chain) = &cli_config.tls_chain {
            self.tls_chain = Some(tls_chain.clone());
        }

        if let Some(tls_client_ca) = &cli_config.tls_client_ca {
            self.tls_client_ca = Some(tls_client_ca.clone());
        }

        // filesystem things
        if let Some(adminbindpath) = &cli_config.admin_bind_path {
            self.adminbindpath = adminbindpath.clone();
        }

        if let Some(db_path) = &cli_config.db_path {
            self.db_path = Some(db_path.clone());
        }

        if let Some(db_fs_type) = &cli_config.db_fs_type {
            self.db_fs_type = Some(*db_fs_type);
        }

        if cli_config.db_arc_size.is_some() {
            self.db_arc_size = cli_config.db_arc_size;
        }

        // backup things
        if let Some(online_backup_path) = &cli_config.online_backup_path {
            if let Some(backup) = &mut self.online_backup {
                backup.path = Some(online_backup_path.clone());
            } else {
                self.online_backup = Some(OnlineBackup {
                    path: Some(online_backup_path.clone()),
                    ..Default::default()
                });
            }
        }

        if let Some(online_backup_schedule) = &cli_config.online_backup_schedule {
            if let Some(backup) = &mut self.online_backup {
                backup.schedule = online_backup_schedule.clone();
            } else {
                self.online_backup = Some(OnlineBackup {
                    schedule: online_backup_schedule.clone(),
                    ..Default::default()
                });
            }
        }

        if let Some(online_backup_versions) = &cli_config.online_backup_versions {
            if let Some(backup) = &mut self.online_backup {
                backup.versions = *online_backup_versions;
            } else {
                self.online_backup = Some(OnlineBackup {
                    versions: *online_backup_versions,
                    ..Default::default()
                });
            }
        }

        // XFF handling
        if let Some(true) = cli_config.trust_all_x_forwarded_for {
            self.http_client_address_info = HttpAddressInfo::XForwardForAllSourcesTrusted;
        }

        self
    }

    pub fn add_opt_toml_config(self, toml_config: Option<ServerConfigUntagged>) -> Self {
        // Can only proceed if the config is real
        let Some(toml_config) = toml_config else {
            return self;
        };

        match toml_config {
            ServerConfigUntagged::Version(ServerConfigVersion::V2 { values }) => {
                self.add_v2_config(values)
            }
            ServerConfigUntagged::Legacy(config) => self.add_legacy_config(config),
        }
    }

    fn add_legacy_config(mut self, config: ServerConfig) -> Self {
        if config.domain.is_some() {
            self.domain = config.domain;
        }

        if config.origin.is_some() {
            self.origin = config.origin;
        }

        if config.db_path.is_some() {
            self.db_path = config.db_path;
        }

        if config.db_fs_type.is_some() {
            self.db_fs_type = config.db_fs_type;
        }

        if config.tls_key.is_some() {
            self.tls_key = config.tls_key;
        }

        if config.tls_chain.is_some() {
            self.tls_chain = config.tls_chain;
        }

        if config.tls_client_ca.is_some() {
            self.tls_client_ca = config.tls_client_ca;
        }

        if config.bindaddress.is_some() {
            self.bindaddress = config.bindaddress.map(|a| vec![a]);
        }

        if config.ldapbindaddress.is_some() {
            self.ldapbindaddress = config.ldapbindaddress.map(|a| vec![a]);
        }

        if let Some(adminbindpath) = config.adminbindpath {
            self.adminbindpath = adminbindpath;
        }

        if config.role.is_some() {
            self.role = config.role;
        }

        if config.log_level.is_some() {
            self.log_level = config.log_level;
        }

        if let Some(threads) = config.thread_count {
            self.threads = threads;
        }

        if let Some(maximum) = config.maximum_request_size_bytes {
            self.maximum_request = maximum;
        }

        if config.db_arc_size.is_some() {
            self.db_arc_size = config.db_arc_size;
        }

        if config.trust_x_forward_for == Some(true) {
            self.http_client_address_info = HttpAddressInfo::XForwardForAllSourcesTrusted;
        }

        if config.online_backup.is_some() {
            self.online_backup = config.online_backup;
        }

        if config.repl_config.is_some() {
            self.repl_config = config.repl_config;
        }

        if config.otel_grpc_endpoint.is_some() {
            self.otel_grpc_endpoint = config.otel_grpc_endpoint;
        }

        if config.pip_config.is_some() {
            self.pip_config = config.pip_config;
        }

        self
    }

    fn add_v2_config(mut self, config: ServerConfigV2) -> Self {
        if config.domain.is_some() {
            self.domain = config.domain;
        }

        if config.origin.is_some() {
            self.origin = config.origin;
        }

        if config.db_path.is_some() {
            self.db_path = config.db_path;
        }

        if config.migration_path.is_some() {
            self.migration_path = config.migration_path;
        }

        if config.db_fs_type.is_some() {
            self.db_fs_type = config.db_fs_type;
        }

        if config.tls_key.is_some() {
            self.tls_key = config.tls_key;
        }

        if config.tls_chain.is_some() {
            self.tls_chain = config.tls_chain;
        }

        if config.tls_client_ca.is_some() {
            self.tls_client_ca = config.tls_client_ca;
        }

        if config.bindaddress.is_some() {
            self.bindaddress = config.bindaddress;
        }

        if config.ldapbindaddress.is_some() {
            self.ldapbindaddress = config.ldapbindaddress;
        }

        if let Some(adminbindpath) = config.adminbindpath {
            self.adminbindpath = adminbindpath;
        }

        if config.role.is_some() {
            self.role = config.role;
        }

        if config.log_level.is_some() {
            self.log_level = config.log_level;
        }

        if let Some(threads) = config.thread_count {
            self.threads = threads;
        }

        if let Some(maximum) = config.maximum_request_size_bytes {
            self.maximum_request = maximum;
        }

        if config.db_arc_size.is_some() {
            self.db_arc_size = config.db_arc_size;
        }

        if let Some(http_server_versions) = config.http_server_versions {
            self.http_server_versions = http_server_versions
        }

        if let Some(http_client_address_info) = config.http_client_address_info {
            self.http_client_address_info = http_client_address_info
        }

        if let Some(ldap_client_address_info) = config.ldap_client_address_info {
            self.ldap_client_address_info = ldap_client_address_info
        }

        if config.online_backup.is_some() {
            self.online_backup = config.online_backup;
        }

        if config.repl_config.is_some() {
            self.repl_config = config.repl_config;
        }

        if config.otel_grpc_endpoint.is_some() {
            self.otel_grpc_endpoint = config.otel_grpc_endpoint;
        }

        if config.pip_config.is_some() {
            self.pip_config = config.pip_config;
        }

        self
    }

    // We always set threads to 1 unless it's the main server.
    pub fn is_server_mode(mut self, is_server: bool) -> Self {
        if !is_server {
            self.threads = 1;
        }
        self
    }

    pub fn finish(self) -> Option<Configuration> {
        let ConfigurationBuilder {
            bindaddress,
            ldapbindaddress,
            adminbindpath,
            threads,
            db_path,
            db_fs_type,
            db_arc_size,
            migration_path,
            maximum_request,
            http_server_versions,
            http_client_address_info,
            ldap_client_address_info,
            tls_key,
            tls_chain,
            tls_client_ca,
            mut online_backup,
            domain,
            origin,
            role,
            log_level,
            repl_config,
            otel_grpc_endpoint,
            pip_config,
        } = self;

        let tls_config = match (tls_key, tls_chain, tls_client_ca) {
            (Some(key), Some(chain), client_ca) => Some(TlsConfiguration {
                chain,
                key,
                client_ca,
            }),
            _ => {
                eprintln!("ERROR: Tls Private Key and Certificate Chain are required.");
                return None;
            }
        };

        let domain = domain.or_else(|| {
            eprintln!("ERROR: domain was not set.");
            None
        })?;

        let origin = origin.or_else(|| {
            eprintln!("ERROR: origin was not set.");
            None
        })?;

        if let Some(online_backup_ref) = online_backup.as_mut() {
            if let Err(reason) = online_backup_ref.validate() {
                eprintln!("ERROR: {reason}");
                return None;
            }

            if online_backup_ref.path.is_none() {
                if let Some(db_path) = db_path.as_ref() {
                    if let Some(db_parent_path) = db_path.parent() {
                        online_backup_ref.path = Some(db_parent_path.to_path_buf());
                    } else {
                        eprintln!("ERROR: when db_path has no parent, and can not be used for online backups.");
                        return None;
                    }
                } else {
                    eprintln!("ERROR: when db_path is unset (in memory) then online backup paths must be declared.");
                    return None;
                }
            }

            if online_backup_ref
                .wal_archive
                .as_ref()
                .is_some_and(|wal| wal.enabled && wal.local_path.is_none())
                && db_path.is_none()
            {
                eprintln!("ERROR: online_backup.wal_archive: local_path must be set when db_path is unset (in memory).");
                return None;
            }
        };

        // Apply any defaults if needed
        let address = bindaddress.unwrap_or(vec![DEFAULT_SERVER_ADDRESS.to_string()]);
        let role = role.unwrap_or(ServerRole::WriteReplica);
        let log_level = log_level.unwrap_or_default();

        Some(Configuration {
            address,
            ldapbindaddress,
            adminbindpath,
            threads,
            db_path,
            db_fs_type,
            db_arc_size,
            migration_path,
            maximum_request,
            http_server_versions,
            http_client_address_info,
            ldap_client_address_info,
            tls_config,
            online_backup,
            domain,
            origin,
            role,
            log_level,
            repl_config,
            otel_grpc_endpoint,
            integration_repl_config: None,
            integration_test_config: None,
            pip_config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
    use kubidm_proto::backup::{
        EncryptionKeySource, ReplicationRegionConfig, S3ServerSideEncryption,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    const BASE_V2_CONFIG: &str = r#"
version = "2"
domain = "idm.example.com"
origin = "https://idm.example.com"
db_path = "/var/lib/kubidm/kubidm.db"
tls_chain = "/etc/kubidm/chain.pem"
tls_key = "/etc/kubidm/key.pem"

[online_backup]
path = "/var/lib/kubidm/backups/"
schedule = "@daily"
"#;

    fn build_from_toml(contents: &str) -> Option<Configuration> {
        let values = toml::from_str::<ServerConfigV2>(contents).expect("config must parse");
        Configuration::build()
            .add_opt_toml_config(Some(ServerConfigUntagged::Version(
                ServerConfigVersion::V2 { values },
            )))
            .finish()
    }

    #[test]
    fn online_backup_without_unavailable_features_is_accepted() {
        assert!(build_from_toml(BASE_V2_CONFIG).is_some());
    }

    #[test]
    fn online_backup_versions_must_keep_at_least_one_backup() {
        let config = build_from_toml(&format!("{BASE_V2_CONFIG}versions = 1\n"))
            .expect("one version is accepted");
        assert_eq!(config.online_backup.map(|backup| backup.versions), Some(1));

        assert!(
            build_from_toml(&format!("{BASE_V2_CONFIG}versions = 0\n")).is_none(),
            "versions = 0 must be rejected"
        );

        // `--online-backup-versions` lands in the same section before `finish` validates
        // it, so the override is rejected the same way.
        let err = OnlineBackup {
            versions: 0,
            ..OnlineBackup::default()
        }
        .validate()
        .expect_err("versions = 0 must be rejected");
        assert!(err.starts_with("online_backup.versions"), "{err}");
    }

    #[test]
    fn online_backup_encryption_needs_a_resolvable_key_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let passphrase_file = dir.path().join("passphrase");
        std::fs::write(&passphrase_file, "correct horse battery staple\n").expect("write");
        let key_file = dir.path().join("backup.key");
        std::fs::write(&key_file, [42u8; 32]).expect("write");

        // Disabled encryption is accepted with any other setting.
        let disabled = format!(
            "{BASE_V2_CONFIG}
[online_backup.encryption]
enabled = false
"
        );
        assert!(build_from_toml(&disabled).is_some());

        // Enabled with a passphrase file that exists.
        let passphrase = format!(
            "{BASE_V2_CONFIG}
[online_backup.encryption]
enabled = true
key_source = \"Passphrase\"
passphrase_file = {passphrase_file:?}
key_identifier = \"prod-2026\"
"
        );
        let config = build_from_toml(&passphrase).expect("accepted");
        let encryption = config.online_backup.expect("online backup").encryption;
        assert!(encryption.enabled);
        assert_eq!(encryption.key_source, EncryptionKeySource::Passphrase);
        assert_eq!(
            encryption.passphrase_file.as_deref(),
            Some(passphrase_file.as_path())
        );
        assert_eq!(encryption.key_identifier.as_deref(), Some("prod-2026"));

        // Enabled with a passphrase file that does not exist.
        let missing = format!(
            "{BASE_V2_CONFIG}
[online_backup.encryption]
enabled = true
passphrase_file = {:?}
",
            dir.path().join("missing")
        );
        assert!(build_from_toml(&missing).is_none());

        // Enabled with a key file that exists, and with one that does not.
        let key = format!(
            "{BASE_V2_CONFIG}
[online_backup.encryption]
enabled = true
[online_backup.encryption.key_source.File]
path = {key_file:?}
"
        );
        let config = build_from_toml(&key).expect("accepted");
        assert_eq!(
            config
                .online_backup
                .expect("online backup")
                .encryption
                .key_source,
            EncryptionKeySource::File {
                path: key_file.to_string_lossy().into_owned()
            }
        );
        let missing_key = format!(
            "{BASE_V2_CONFIG}
[online_backup.encryption]
enabled = true
[online_backup.encryption.key_source.File]
path = {:?}
",
            dir.path().join("missing.key")
        );
        assert!(build_from_toml(&missing_key).is_none());

        // An HTTP key source only needs a well formed http(s) URL at this point.
        let endpoint = format!(
            "{BASE_V2_CONFIG}
[online_backup.encryption]
enabled = true
key_source = {{ HttpEndpoint = {{ url = \"https://vault.example.com/v1/backup-key\" }} }}
"
        );
        assert!(build_from_toml(&endpoint).is_some());
        let bad_endpoint = format!(
            "{BASE_V2_CONFIG}
[online_backup.encryption]
enabled = true
key_source = {{ HttpEndpoint = {{ url = \"vault.example.com\" }} }}
"
        );
        assert!(build_from_toml(&bad_endpoint).is_none());

        // Key derivation parameters outside the accepted bounds.
        let weak_kdf = format!(
            "{BASE_V2_CONFIG}
[online_backup.encryption]
enabled = true
passphrase_file = {passphrase_file:?}
[online_backup.encryption.key_derivation]
m_cost = 1024
"
        );
        assert!(build_from_toml(&weak_kdf).is_none());
    }

    #[test]
    fn online_backup_verify_schedule_and_metrics_endpoint_are_off_by_default() {
        let config = build_from_toml(BASE_V2_CONFIG).expect("config");
        let online_backup = config.online_backup.expect("online backup");
        assert_eq!(online_backup.verify_schedule, None);
        assert!(!online_backup.metrics_endpoint);
    }

    #[test]
    fn online_backup_verify_schedule_is_validated() {
        for schedule in ["@weekly", "30 3 * * Sun", "0 30 3 * * Sun *"] {
            let config = build_from_toml(&format!(
                "{BASE_V2_CONFIG}verify_schedule = \"{schedule}\"\nmetrics_endpoint = true\n"
            ))
            .unwrap_or_else(|| panic!("{schedule} must be accepted"));
            let online_backup = config.online_backup.expect("online backup");
            assert_eq!(online_backup.verify_schedule.as_deref(), Some(schedule));
            assert!(online_backup.metrics_endpoint);
        }

        // Not a schedule, or one that never runs.
        for schedule in ["sometimes", "0 0 0 1 1 * 2001"] {
            let err = OnlineBackup {
                verify_schedule: Some(schedule.to_string()),
                ..OnlineBackup::default()
            }
            .validate()
            .expect_err("an invalid schedule must be rejected");
            assert!(err.starts_with("online_backup.verify_schedule"), "{err}");
            assert!(
                build_from_toml(&format!(
                    "{BASE_V2_CONFIG}verify_schedule = \"{schedule}\"\n"
                ))
                .is_none(),
                "{schedule} must be rejected"
            );
        }

        // A host that does not take backups verifies them with the command instead.
        let err = OnlineBackup {
            enabled: false,
            verify_schedule: Some("@daily".to_string()),
            ..OnlineBackup::default()
        }
        .validate()
        .expect_err("a disabled online backup must not be verified on a schedule");
        assert!(err.contains("online_backup.enabled = true"), "{err}");
    }

    #[test]
    fn online_backup_metrics_token_file_is_validated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "  s3cret\n").expect("write");
        assert_eq!(read_metrics_token(&token_file).as_deref(), Ok("s3cret"));

        let with_token = |metrics_endpoint: bool, path: &Path| OnlineBackup {
            metrics_endpoint,
            metrics_token_file: Some(path.to_path_buf()),
            ..OnlineBackup::default()
        };
        assert!(with_token(true, &token_file).validate().is_ok());

        // A token for an endpoint that is not served is a mistake.
        let err = with_token(false, &token_file)
            .validate()
            .expect_err("a token without the endpoint must be rejected");
        assert!(err.contains("metrics_endpoint = true"), "{err}");

        // The file is read by the server only: an offline command (a restore or recovery
        // from a rescue container) validates the configuration without it.
        assert!(with_token(true, &dir.path().join("missing"))
            .validate()
            .is_ok());

        // The server never serves the metrics without the token the operator asked for.
        let err = read_metrics_token(&dir.path().join("missing"))
            .expect_err("a missing token file must be rejected");
        assert!(err.contains("unable to read"), "{err}");
        std::fs::write(&token_file, " \n").expect("write");
        let err = read_metrics_token(&token_file).expect_err("an empty token must be rejected");
        assert!(err.contains("holds no token"), "{err}");
    }

    /// Every subcommand builds the configuration: one whose metrics token file is not
    /// readable here (not mounted in a rescue container, or readable by the server's user
    /// only) still builds, so that `database restore` or `recover` never need it.
    #[test]
    fn offline_commands_build_a_configuration_whose_token_file_is_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = build_from_toml(&format!(
            "{BASE_V2_CONFIG}metrics_endpoint = true\nmetrics_token_file = \"{}\"\n",
            dir.path().join("not-mounted").display()
        ))
        .expect("the configuration of an offline command must build");
        assert!(config
            .online_backup
            .and_then(|online_backup| online_backup.metrics_token_file)
            .is_some());
    }

    #[test]
    fn online_backup_schedule_is_validated_at_load() {
        for schedule in ["@monthly", "0 30 3 * * Sun", "00 22 * * *"] {
            assert!(
                build_from_toml(&BASE_V2_CONFIG.replace(
                    "schedule = \"@daily\"",
                    &format!("schedule = \"{schedule}\"")
                ))
                .is_some(),
                "{schedule} must be accepted"
            );
        }
        let err = OnlineBackup {
            schedule: "whenever".to_string(),
            ..OnlineBackup::default()
        }
        .validate()
        .expect_err("an invalid schedule must be rejected");
        assert!(err.starts_with("online_backup.schedule"), "{err}");
        assert!(err.contains("@monthly"), "{err}");

        // A disabled online backup never runs its schedule.
        assert!(OnlineBackup {
            enabled: false,
            schedule: "whenever".to_string(),
            ..OnlineBackup::default()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn online_backup_wal_archive_is_validated() {
        let enabled = format!(
            "{BASE_V2_CONFIG}
[online_backup.wal_archive]
enabled = true
"
        );
        let config = build_from_toml(&enabled).expect("WAL archiving must be accepted");
        let wal = config
            .online_backup
            .as_ref()
            .and_then(|b| b.wal_archive.as_ref())
            .expect("wal_archive must be parsed");
        assert!(wal.enabled);
        assert_eq!(wal.segment_interval_seconds, 300);
        assert_eq!(wal.retention_days, 7);
        assert!(wal.local_path.is_none());

        let disabled = format!(
            "{BASE_V2_CONFIG}
[online_backup.wal_archive]
enabled = false
"
        );
        assert!(build_from_toml(&disabled).is_some());

        let zero_interval = format!(
            "{BASE_V2_CONFIG}
[online_backup.wal_archive]
enabled = true
segment_interval_seconds = 0
"
        );
        assert!(build_from_toml(&zero_interval).is_none());

        let zero_retention = format!(
            "{BASE_V2_CONFIG}
[online_backup.wal_archive]
enabled = true
retention_days = 0
"
        );
        assert!(build_from_toml(&zero_retention).is_none());

        let zero_size = format!(
            "{BASE_V2_CONFIG}
[online_backup.wal_archive]
enabled = true
segment_size_bytes = 0
"
        );
        assert!(build_from_toml(&zero_size).is_none());

        let tuned = format!(
            "{BASE_V2_CONFIG}
[online_backup.wal_archive]
enabled = true
segment_interval_seconds = 60
segment_size_bytes = 1048576
retention_days = 14
local_path = \"/srv/kubidm/wal\"
"
        );
        let config = build_from_toml(&tuned).expect("tuned WAL archiving must be accepted");
        let wal = config
            .online_backup
            .as_ref()
            .and_then(|b| b.wal_archive.as_ref())
            .expect("wal_archive must be parsed");
        assert_eq!(wal.segment_interval_seconds, 60);
        assert_eq!(wal.segment_size_bytes, 1048576);
        assert_eq!(wal.retention_days, 14);
        assert_eq!(wal.local_path, Some(PathBuf::from("/srv/kubidm/wal")));
        assert!(config.to_string().contains("wal_archive:"));

        // The archive replays on top of online backups, which must be enabled.
        let backups_disabled = BASE_V2_CONFIG.replace(
            "schedule = \"@daily\"",
            "schedule = \"@daily\"\nenabled = false",
        );
        let backups_disabled = format!(
            "{backups_disabled}
[online_backup.wal_archive]
enabled = true
"
        );
        assert!(build_from_toml(&backups_disabled).is_none());

        // An in-memory database has no directory to put the segments next to.
        let in_memory = BASE_V2_CONFIG.replace("db_path = \"/var/lib/kubidm/kubidm.db\"\n", "");
        let in_memory = format!(
            "{in_memory}
[online_backup.wal_archive]
enabled = true
"
        );
        assert!(build_from_toml(&in_memory).is_none());
        let in_memory_with_path = format!("{in_memory}local_path = \"/srv/kubidm/wal\"\n");
        assert!(build_from_toml(&in_memory_with_path).is_some());
    }

    const S3_SECTION: &str = r#"
[online_backup.s3]
bucket = "kubidm-backups"
region = "us-east-1"
"#;

    #[test]
    fn online_backup_s3_replication_is_accepted_when_coherent() {
        let config = build_from_toml(&format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true
sync_interval_seconds = 600

[[online_backup.s3.replication.regions]]
region = \"eu-west-1\"
bucket = \"kubidm-backups-eu\"
path_prefix = \"dr\"

[[online_backup.s3.replication.regions]]
region = \"ap-southeast-1\"
bucket = \"kubidm-backups-ap\"
endpoint = \"https://s3.ap.example.com\"
"
        ))
        .expect("a coherent replication section must be accepted");

        let replication = config
            .online_backup
            .and_then(|backup| backup.s3)
            .and_then(|s3| s3.replication)
            .expect("replication section missing");
        assert!(replication.enabled);
        assert_eq!(replication.sync_interval_seconds, 600);
        assert_eq!(replication.regions.len(), 2);
        assert_eq!(replication.regions[1].region, "ap-southeast-1");

        // An S3 section without any replication block is unaffected.
        assert!(build_from_toml(&format!("{BASE_V2_CONFIG}{S3_SECTION}")).is_some());
    }

    #[test]
    fn online_backup_s3_replication_enabled_without_regions_is_rejected() {
        let enabled = format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true
regions = []
"
        );
        assert!(build_from_toml(&enabled).is_none());

        // Disabled, the empty region list is irrelevant.
        let disabled = format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = false
regions = []
"
        );
        assert!(build_from_toml(&disabled).is_some());
    }

    #[test]
    fn online_backup_s3_replication_duplicate_region_is_rejected() {
        let duplicate = format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true

[[online_backup.s3.replication.regions]]
region = \"eu-west-1\"
bucket = \"kubidm-backups-eu\"

[[online_backup.s3.replication.regions]]
region = \"eu-west-1\"
bucket = \"kubidm-backups-eu-2\"
"
        );
        assert!(build_from_toml(&duplicate).is_none());

        // Two replicas in one signing region (two accounts or buckets in eu-west-1) are
        // told apart by their names.
        let named = format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true

[[online_backup.s3.replication.regions]]
name = \"eu-a\"
region = \"eu-west-1\"
bucket = \"kubidm-backups-eu\"

[[online_backup.s3.replication.regions]]
name = \"eu-b\"
region = \"eu-west-1\"
bucket = \"kubidm-backups-eu-2\"
"
        );
        let config = build_from_toml(&named).expect("distinct names are accepted");
        let regions = config
            .online_backup
            .and_then(|backup| backup.s3)
            .and_then(|s3| s3.replication)
            .map(|replication| replication.regions)
            .unwrap_or_default();
        let names: Vec<&str> = regions.iter().map(|region| region.name()).collect();
        assert_eq!(names, ["eu-a", "eu-b"]);
        assert!(regions.iter().all(|region| region.region == "eu-west-1"));

        // A name may not repeat another entry's default name either.
        let clash = named.replace("name = \"eu-b\"", "name = \"eu-a\"");
        assert!(build_from_toml(&clash).is_none());
        let empty = named.replace("name = \"eu-b\"", "name = \" \"");
        assert!(build_from_toml(&empty).is_none());
    }

    #[test]
    fn online_backup_s3_replication_empty_bucket_is_rejected() {
        let empty_bucket = format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true

[[online_backup.s3.replication.regions]]
region = \"eu-west-1\"
bucket = \"\"
"
        );
        assert!(build_from_toml(&empty_bucket).is_none());
    }

    #[test]
    fn online_backup_s3_replication_zero_interval_is_rejected() {
        let zero_interval = format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true
sync_interval_seconds = 0

[[online_backup.s3.replication.regions]]
region = \"eu-west-1\"
bucket = \"kubidm-backups-eu\"
"
        );
        assert!(build_from_toml(&zero_interval).is_none());
    }

    fn region(name: &str, bucket: &str) -> ReplicationRegionConfig {
        ReplicationRegionConfig {
            name: None,
            region: name.to_string(),
            endpoint: None,
            bucket: bucket.to_string(),
            path_prefix: None,
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            kms_key_id: None,
        }
    }

    fn primary_s3() -> S3Config {
        S3Config {
            bucket: "kubidm-backups".to_string(),
            region: Some("us-east-1".to_string()),
            endpoint: None,
            path_prefix: Some("prod".to_string()),
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            replication: None,
        }
    }

    #[test]
    fn s3_locations_that_s3_would_reject_are_refused_at_load() {
        // An archive storage class on the primary: backups that can not be read back.
        let glacier = format!("{BASE_V2_CONFIG}{S3_SECTION}storage_class = \"GLACIER\"\n");
        assert!(build_from_toml(&glacier).is_none());
        // A typo that used to become STANDARD silently.
        let typo = format!("{BASE_V2_CONFIG}{S3_SECTION}storage_class = \"STANDARD-IA\"\n");
        assert!(build_from_toml(&typo).is_none());

        let mut online_backup = OnlineBackup {
            s3: Some(primary_s3()),
            ..OnlineBackup::default()
        };
        assert!(online_backup.validate().is_ok());

        // AES256 with a KMS key on the primary.
        if let Some(s3) = online_backup.s3.as_mut() {
            s3.server_side_encryption = Some(S3ServerSideEncryption {
                algorithm: Some(S3EncryptionAlgorithm::Aes256),
                kms_key_id: Some("key".to_string()),
            });
        }
        let err = online_backup.validate().expect_err("AES256 with a KMS key");
        assert!(err.starts_with("online_backup.s3:"), "{err}");

        // On a region: an explicit AES256 block next to the kms_key_id shorthand.
        let mut eu = region("eu-west-1", "kubidm-backups-eu");
        eu.kms_key_id = Some("key".to_string());
        eu.server_side_encryption = Some(S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::Aes256),
            kms_key_id: None,
        });
        let replication = ReplicationConfig {
            enabled: true,
            regions: vec![eu],
            ..ReplicationConfig::default()
        };
        let err = validate_replication(&primary_s3(), &replication).expect_err("AES256 shorthand");
        assert!(err.contains("regions[0] (eu-west-1)"), "{err}");
        assert!(err.contains("shorthand"), "{err}");

        // And an archive class on a region.
        let mut eu = region("eu-west-1", "kubidm-backups-eu");
        eu.storage_class = "DEEP_ARCHIVE".to_string();
        let replication = ReplicationConfig {
            enabled: true,
            regions: vec![eu],
            ..ReplicationConfig::default()
        };
        let err = validate_replication(&primary_s3(), &replication).expect_err("archive class");
        assert!(err.contains("archive class"), "{err}");
    }

    #[test]
    fn validate_replication_rejects_a_region_at_the_primary_location() {
        let mut replication = ReplicationConfig {
            enabled: true,
            regions: vec![region("eu-west-1", "kubidm-backups")],
            ..ReplicationConfig::default()
        };

        // Same bucket, same (absent) endpoint, same prefix: the primary itself, whatever
        // the signing region.
        replication.regions[0].path_prefix = Some("prod/".to_string());
        let err = validate_replication(&primary_s3(), &replication).expect_err("primary itself");
        assert!(
            err.starts_with("online_backup.s3.replication.regions[0] (eu-west-1):"),
            "{err}"
        );
        assert!(err.contains("primary backup location"), "{err}");

        // Another prefix in the same bucket, or another endpoint, is a location of its own.
        replication.regions[0].path_prefix = Some("dr".to_string());
        assert!(validate_replication(&primary_s3(), &replication).is_ok());
        replication.regions[0].path_prefix = Some("prod".to_string());
        replication.regions[0].endpoint = Some("https://s3.eu.example.com".to_string());
        assert!(validate_replication(&primary_s3(), &replication).is_ok());

        // Two regions sharing a location are rejected too.
        let mut second = region("eu-central-1", "kubidm-backups");
        second.path_prefix = Some("prod".to_string());
        second.endpoint = Some("https://s3.eu.example.com/".to_string());
        replication.regions.push(second);
        let err = validate_replication(&primary_s3(), &replication).expect_err("shared location");
        assert!(
            err.starts_with("online_backup.s3.replication.regions[1] (eu-central-1):"),
            "{err}"
        );
        assert!(err.contains("\"eu-west-1\""), "{err}");
    }

    #[test]
    fn online_backup_s3_replication_to_the_primary_bucket_is_rejected() {
        let to_itself = format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true

[[online_backup.s3.replication.regions]]
region = \"eu-west-1\"
bucket = \"kubidm-backups\"
"
        );
        assert!(build_from_toml(&to_itself).is_none());

        let other_prefix = format!(
            "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true

[[online_backup.s3.replication.regions]]
region = \"eu-west-1\"
bucket = \"kubidm-backups\"
path_prefix = \"dr\"
"
        );
        assert!(build_from_toml(&other_prefix).is_some());
    }

    #[test]
    fn validate_replication_reports_the_offending_key() {
        let mut replication = ReplicationConfig {
            enabled: true,
            regions: vec![],
            ..ReplicationConfig::default()
        };
        let err = validate_replication(&primary_s3(), &replication).expect_err("no regions");
        assert!(err.starts_with("online_backup.s3.replication:"), "{err}");
        assert!(err.contains("at least one"), "{err}");

        replication.regions = vec![region("eu-west-1", "eu"), region("ap-southeast-1", "ap")];
        assert!(validate_replication(&primary_s3(), &replication).is_ok());

        replication.sync_interval_seconds = 0;
        let err = validate_replication(&primary_s3(), &replication).expect_err("zero interval");
        assert!(err.contains("sync_interval_seconds"), "{err}");
        replication.sync_interval_seconds = 300;

        replication.regions[1].bucket = " ".to_string();
        let err = validate_replication(&primary_s3(), &replication).expect_err("blank bucket");
        assert!(
            err.starts_with("online_backup.s3.replication.regions[1] (ap-southeast-1): bucket"),
            "{err}"
        );
        replication.regions[1].bucket = "ap".to_string();

        replication.regions[1].region = String::new();
        let err = validate_replication(&primary_s3(), &replication).expect_err("empty region name");
        assert!(
            err.starts_with("online_backup.s3.replication.regions[1]: region"),
            "{err}"
        );

        replication.regions[1].region = "eu-west-1".to_string();
        let err =
            validate_replication(&primary_s3(), &replication).expect_err("duplicate region name");
        assert!(err.contains("\"eu-west-1\""), "{err}");
        assert!(err.contains("unique"), "{err}");

        // Nothing is checked while replication is disabled.
        replication.enabled = false;
        assert!(validate_replication(&primary_s3(), &replication).is_ok());
    }

    #[test]
    fn online_backup_validate_reports_the_offending_key() {
        let mut online_backup = OnlineBackup::default();
        assert!(online_backup.validate().is_ok());

        // Enabled encryption whose passphrase file is missing: the key is the reason.
        online_backup.encryption.enabled = true;
        online_backup.encryption.passphrase_file = Some(PathBuf::from("/nonexistent/passphrase"));
        let err = online_backup.validate().expect_err("must be rejected");
        assert!(err.starts_with("online_backup.encryption:"), "{err}");
        assert!(err.contains("passphrase_file"), "{err}");
        online_backup.encryption.enabled = false;
        online_backup.encryption.passphrase_file = None;

        online_backup.wal_archive = Some(WalArchiveConfig {
            enabled: true,
            ..WalArchiveConfig::default()
        });
        assert!(online_backup.validate().is_ok());

        online_backup.wal_archive = Some(WalArchiveConfig {
            enabled: true,
            retention_days: 0,
            ..WalArchiveConfig::default()
        });
        let err = online_backup.validate().expect_err("must be rejected");
        assert!(err.starts_with("online_backup.wal_archive: retention_days"));

        // Point-in-time recovery replays the archive on top of online base backups.
        online_backup.wal_archive = Some(WalArchiveConfig {
            enabled: true,
            ..WalArchiveConfig::default()
        });
        online_backup.enabled = false;
        let err = online_backup.validate().expect_err("must be rejected");
        assert!(err.starts_with("online_backup.wal_archive:"));
        assert!(err.contains("online_backup.enabled"));
        online_backup.enabled = true;

        // A separate S3 location of the archive has its replication checked like the
        // backups' one, and the error names that location.
        let mut wal_s3 = S3Config::with_bucket("kubidm-wal".to_string());
        wal_s3.replication = Some(ReplicationConfig {
            enabled: true,
            regions: Vec::new(),
            ..ReplicationConfig::default()
        });
        online_backup.wal_archive = Some(WalArchiveConfig {
            enabled: true,
            s3: Some(wal_s3),
            ..WalArchiveConfig::default()
        });
        let err = online_backup.validate().expect_err("must be rejected");
        assert!(
            err.starts_with("online_backup.wal_archive.s3.replication:"),
            "{err}"
        );
    }

    #[test]
    fn online_backup_encryption_and_replication_are_validated_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let passphrase_file = dir.path().join("passphrase");
        std::fs::write(&passphrase_file, "correct horse battery staple\n").expect("write");

        let config = |passphrase_file: &Path, replica_bucket: &str| {
            format!(
                "{BASE_V2_CONFIG}{S3_SECTION}
[online_backup.s3.replication]
enabled = true

[[online_backup.s3.replication.regions]]
region = \"eu-west-1\"
bucket = {replica_bucket:?}

[online_backup.encryption]
enabled = true
passphrase_file = {passphrase_file:?}
"
            )
        };

        // Both features enabled and coherent: accepted, both sections kept.
        let accepted = build_from_toml(&config(&passphrase_file, "kubidm-backups-eu"))
            .expect("encryption and replication together must be accepted");
        let online_backup = accepted.online_backup.expect("online backup");
        assert!(online_backup.encryption.enabled);
        assert!(online_backup
            .s3
            .and_then(|s3| s3.replication)
            .is_some_and(|replication| replication.enabled));

        // Either one being wrong rejects the whole configuration.
        assert!(
            build_from_toml(&config(&dir.path().join("missing"), "kubidm-backups-eu")).is_none()
        );
        assert!(build_from_toml(&config(&passphrase_file, "")).is_none());
    }

    #[test]
    fn assert_cidr_parsing_behaviour() {
        // Assert that we can parse individual hosts, and ranges
        let parsed_ip_cidr: IpCidr = serde_json::from_str("\"127.0.0.1\"").unwrap();
        let expect_ip_cidr = IpCidr::from(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(parsed_ip_cidr, expect_ip_cidr);

        let parsed_ip_cidr: IpCidr = serde_json::from_str("\"127.0.0.0/8\"").unwrap();
        let expect_ip_cidr = IpCidr::from(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        assert_eq!(parsed_ip_cidr, expect_ip_cidr);

        // Same for ipv6
        let parsed_ip_cidr: IpCidr = serde_json::from_str("\"2001:0db8::1\"").unwrap();
        let expect_ip_cidr = IpCidr::from(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001));
        assert_eq!(parsed_ip_cidr, expect_ip_cidr);

        let parsed_ip_cidr: IpCidr = serde_json::from_str("\"2001:0db8::/64\"").unwrap();
        let expect_ip_cidr = IpCidr::from(
            Ipv6Cidr::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 64).unwrap(),
        );
        assert_eq!(parsed_ip_cidr, expect_ip_cidr);
    }
}
