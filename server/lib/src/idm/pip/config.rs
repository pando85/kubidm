//! PIP Configuration
//!
//! This module defines the configuration schema for Policy Information Points,
//! including HTTP and LDAP source configurations.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

use super::PipAttributeValue;

/// Placeholder printed instead of a secret in `Debug` output.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Debug view of a header map that shows the header names but not their values,
/// since headers commonly carry credentials.
struct RedactedHeaders<'a>(&'a BTreeMap<String, String>);

impl fmt::Debug for RedactedHeaders<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|k| (k, Redacted)))
            .finish()
    }
}

/// Behavior when PIP fails to retrieve attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PipFallbackBehavior {
    /// Use the configured `fallback_values` (which must be non-empty).
    UseFallback,
    /// Deny the authorization request (fail closed). This is the default, since
    /// PIP attributes feed access decisions.
    #[default]
    Deny,
    /// Continue without the attributes (may affect policy evaluation)
    Ignore,
}

/// Authentication method for PIP sources
///
/// `Debug` is implemented manually and secret fields are skipped on
/// serialization, so that secrets are never logged or written back out.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PipAuthConfig {
    /// No authentication
    None,

    /// Basic authentication
    Basic {
        username: String,
        #[serde(skip_serializing)]
        password: String,
    },

    /// Bearer token authentication
    Bearer {
        #[serde(skip_serializing)]
        token: String,
    },

    /// API key authentication (header or query param)
    ApiKey {
        key_name: String,
        #[serde(skip_serializing)]
        key_value: String,
        location: ApiKeyLocation,
    },

    /// OAuth2 client credentials flow.
    ///
    /// Not yet supported: an HTTP PIP configured with it fails to construct.
    OAuth2ClientCredentials {
        token_url: Url,
        client_id: String,
        #[serde(skip_serializing)]
        client_secret: String,
        scope: Option<String>,
    },

    /// Mutual TLS authentication.
    ///
    /// Not yet supported: an HTTP PIP configured with it fails to construct.
    MutualTls {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

impl fmt::Debug for PipAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipAuthConfig::None => f.write_str("None"),
            PipAuthConfig::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &Redacted)
                .finish(),
            PipAuthConfig::Bearer { .. } => {
                f.debug_struct("Bearer").field("token", &Redacted).finish()
            }
            PipAuthConfig::ApiKey {
                key_name, location, ..
            } => f
                .debug_struct("ApiKey")
                .field("key_name", key_name)
                .field("key_value", &Redacted)
                .field("location", location)
                .finish(),
            PipAuthConfig::OAuth2ClientCredentials {
                token_url,
                client_id,
                scope,
                ..
            } => f
                .debug_struct("OAuth2ClientCredentials")
                .field("token_url", token_url)
                .field("client_id", client_id)
                .field("client_secret", &Redacted)
                .field("scope", scope)
                .finish(),
            PipAuthConfig::MutualTls {
                cert_path,
                key_path,
            } => f
                .debug_struct("MutualTls")
                .field("cert_path", cert_path)
                .field("key_path", key_path)
                .finish(),
        }
    }
}

/// Where to place the API key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyLocation {
    #[default]
    Header,
    QueryParam,
}

/// TLS configuration for PIP sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipTlsConfig {
    /// Path to CA certificate for server verification.
    ///
    /// Not yet supported: a PIP configured with it fails to construct.
    pub ca_path: Option<PathBuf>,
    /// Whether to verify the server certificate. Setting this to `false` disables
    /// certificate verification (a warning is logged).
    #[serde(default = "default_verify_server")]
    pub verify_server: bool,
    /// Allow insecure connections (for development only): disables certificate
    /// verification and permits plain-text `http://` / `ldap://` URLs. Without
    /// it, plain-text sources are rejected, since a network attacker could
    /// inject attributes that feed access decisions.
    #[serde(default)]
    pub allow_insecure: bool,
}

/// Reject credentials embedded in a source URL (`https://user:pass@host`).
pub(crate) fn validate_no_userinfo(id: &str, url: &Url) -> Result<(), String> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "PIP '{id}': credentials must not be embedded in the URL, use the auth/bind settings"
        ));
    }
    Ok(())
}

/// Is `id` a valid PIP source id? It is used in `pip:<source>:<attribute>` names, so it
/// is limited to ASCII letters, digits, `_`, `-` and `.`.
pub(crate) fn is_valid_source_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Validate the settings shared by every source type.
pub(crate) fn validate_common(
    id: &str,
    timeout_secs: u64,
    health_check: &PipHealthCheckConfig,
    fallback_behavior: PipFallbackBehavior,
    fallback_values: &BTreeMap<String, PipAttributeValue>,
) -> Result<(), String> {
    if !is_valid_source_id(id) {
        return Err(format!(
            "PIP '{id}': the id must be non-empty and only use ASCII letters, digits, '_', '-' \
             and '.'"
        ));
    }
    if timeout_secs == 0 {
        return Err(format!("PIP '{id}': timeout_secs must be greater than 0"));
    }
    if health_check.timeout_secs == 0 {
        return Err(format!(
            "PIP '{id}': health_check.timeout_secs must be greater than 0"
        ));
    }
    if health_check.failure_threshold == 0 {
        return Err(format!(
            "PIP '{id}': health_check.failure_threshold must be greater than 0"
        ));
    }
    if fallback_behavior == PipFallbackBehavior::UseFallback && fallback_values.is_empty() {
        // An empty fallback would silently behave like `ignore` (fail open).
        return Err(format!(
            "PIP '{id}': fallback_behavior = \"usefallback\" requires non-empty fallback_values \
             (use \"ignore\" to continue without attributes, or \"deny\")"
        ));
    }
    Ok(())
}

fn default_verify_server() -> bool {
    true
}

impl Default for PipTlsConfig {
    fn default() -> Self {
        PipTlsConfig {
            ca_path: None,
            verify_server: true,
            allow_insecure: false,
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipHealthCheckConfig {
    /// How often to check health (in seconds)
    #[serde(default = "default_health_check_interval")]
    pub interval_secs: u64,

    /// Number of consecutive failures before marking unhealthy
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Number of consecutive successes to mark healthy after being unhealthy
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,

    /// Timeout for health check requests (in seconds)
    #[serde(default = "default_health_check_timeout")]
    pub timeout_secs: u64,
}

fn default_health_check_interval() -> u64 {
    60
}

fn default_failure_threshold() -> u32 {
    3
}

fn default_success_threshold() -> u32 {
    2
}

fn default_health_check_timeout() -> u64 {
    5
}

impl Default for PipHealthCheckConfig {
    fn default() -> Self {
        PipHealthCheckConfig {
            interval_secs: default_health_check_interval(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            timeout_secs: default_health_check_timeout(),
        }
    }
}

/// HTTP PIP source configuration
///
/// `Debug` is implemented manually so that header values and credentials are
/// never logged.
#[derive(Clone, Serialize, Deserialize)]
pub struct HttpPipConfig {
    /// Unique identifier for this PIP source
    pub id: String,

    /// Base URL for the HTTP endpoint. Must be `https://` (or `http://` with
    /// `tls.allow_insecure`), without credentials, query or fragment.
    pub base_url: Url,

    /// Endpoint path template, starting with `/` (supports variables like
    /// {uuid}, {username}, {email} and subject context keys). Substituted
    /// values must be non-empty and are percent-encoded; the resulting URL must
    /// not be altered by URL normalisation.
    pub endpoint_path: String,

    /// HTTP method to use
    #[serde(default = "default_http_method")]
    pub method: HttpMethod,

    /// Authentication configuration
    #[serde(default)]
    pub auth: Option<PipAuthConfig>,

    /// TLS configuration
    #[serde(default)]
    pub tls: PipTlsConfig,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Headers to include in requests (also sent with health checks). Values may
    /// carry credentials, so they are never serialized or logged.
    #[serde(default, skip_serializing)]
    pub headers: BTreeMap<String, String>,

    /// Fallback behavior when source is unavailable (default: deny)
    #[serde(default)]
    pub fallback_behavior: PipFallbackBehavior,

    /// Fallback attribute values, returned when `fallback_behavior = "usefallback"`
    #[serde(default)]
    pub fallback_values: BTreeMap<String, PipAttributeValue>,

    /// Health check configuration
    #[serde(default)]
    pub health_check: PipHealthCheckConfig,

    /// Health check endpoint path (relative to base_url, starting with `/`)
    pub health_check_path: Option<String>,

    /// Attributes that this source provides
    #[serde(default)]
    pub provided_attributes: Vec<String>,
}

impl fmt::Debug for HttpPipConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPipConfig")
            .field("id", &self.id)
            .field("base_url", &self.base_url)
            .field("endpoint_path", &self.endpoint_path)
            .field("method", &self.method)
            .field("auth", &self.auth)
            .field("tls", &self.tls)
            .field("timeout_secs", &self.timeout_secs)
            .field("cache_ttl_secs", &self.cache_ttl_secs)
            .field("headers", &RedactedHeaders(&self.headers))
            .field("fallback_behavior", &self.fallback_behavior)
            .field("fallback_values", &self.fallback_values)
            .field("health_check", &self.health_check)
            .field("health_check_path", &self.health_check_path)
            .field("provided_attributes", &self.provided_attributes)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    #[default]
    Get,
    Post,
}

fn default_timeout() -> u64 {
    30
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_http_method() -> HttpMethod {
    HttpMethod::Get
}

/// LDAP PIP source configuration
///
/// `Debug` is implemented manually so that the bind password is never logged.
#[derive(Clone, Serialize, Deserialize)]
pub struct LdapPipConfig {
    /// Unique identifier for this PIP source
    pub id: String,

    /// LDAP server URL. Must be `ldaps://` (or `ldap://` with
    /// `tls.allow_insecure`), without embedded credentials.
    pub url: Url,

    /// Base DN for searches
    pub base_dn: String,

    /// Bind DN for authentication
    pub bind_dn: String,

    /// Bind password (never serialized or logged)
    #[serde(skip_serializing)]
    pub bind_password: String,

    /// Search filter template (supports variables like {uuid}, {username},
    /// {email} and subject context keys). The template is parsed once; values
    /// are substituted into the parsed filter's assertion values, so they can
    /// never change the filter's structure. Substituted values must be
    /// non-empty; inside a DN-valued assertion (a template value containing
    /// `=`) they are RFC 4514 escaped. The search must match exactly one entry.
    pub search_filter: String,

    /// Attributes to retrieve from LDAP entries
    #[serde(default)]
    pub attributes: Vec<String>,

    /// TLS configuration (for ldaps://)
    #[serde(default)]
    pub tls: PipTlsConfig,

    /// Timeout in seconds for the whole connect + bind + search operation
    #[serde(default = "default_ldap_timeout")]
    pub timeout_secs: u64,

    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Fallback behavior when source is unavailable (default: deny)
    #[serde(default)]
    pub fallback_behavior: PipFallbackBehavior,

    /// Fallback attribute values
    #[serde(default)]
    pub fallback_values: BTreeMap<String, PipAttributeValue>,

    /// Health check configuration
    #[serde(default)]
    pub health_check: PipHealthCheckConfig,

    /// Attribute mapping: LDAP attribute name -> PIP attribute name
    #[serde(default)]
    pub attribute_mapping: BTreeMap<String, String>,
}

impl fmt::Debug for LdapPipConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapPipConfig")
            .field("id", &self.id)
            .field("url", &self.url)
            .field("base_dn", &self.base_dn)
            .field("bind_dn", &self.bind_dn)
            .field("bind_password", &Redacted)
            .field("search_filter", &self.search_filter)
            .field("attributes", &self.attributes)
            .field("tls", &self.tls)
            .field("timeout_secs", &self.timeout_secs)
            .field("cache_ttl_secs", &self.cache_ttl_secs)
            .field("fallback_behavior", &self.fallback_behavior)
            .field("fallback_values", &self.fallback_values)
            .field("health_check", &self.health_check)
            .field("attribute_mapping", &self.attribute_mapping)
            .finish()
    }
}

fn default_ldap_timeout() -> u64 {
    30
}

/// PIP source configuration (enum to support multiple source types)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PipSourceConfig {
    Http(HttpPipConfig),
    Ldap(LdapPipConfig),
}

/// Global PIP configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PipConfig {
    /// List of PIP sources
    #[serde(default)]
    pub sources: Vec<PipSourceConfig>,

    /// Enable/disable PIP globally
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// The time budget, in milliseconds, for prefetching the PIP attributes of one
    /// request's subject before its access decisions. Sources that have not answered
    /// within it contribute no attributes to that request, so the access controls
    /// conditioned on them do not match (fail closed).
    #[serde(default = "default_prefetch_timeout_ms")]
    pub prefetch_timeout_ms: u64,
}

fn default_enabled() -> bool {
    true
}

fn default_prefetch_timeout_ms() -> u64 {
    2000
}

impl PipSourceConfig {
    pub fn id(&self) -> &str {
        match self {
            PipSourceConfig::Http(config) => &config.id,
            PipSourceConfig::Ldap(config) => &config.id,
        }
    }

    pub fn cache_ttl(&self) -> Duration {
        match self {
            PipSourceConfig::Http(config) => Duration::from_secs(config.cache_ttl_secs),
            PipSourceConfig::Ldap(config) => Duration::from_secs(config.cache_ttl_secs),
        }
    }

    pub fn timeout(&self) -> Duration {
        match self {
            PipSourceConfig::Http(config) => Duration::from_secs(config.timeout_secs),
            PipSourceConfig::Ldap(config) => Duration::from_secs(config.timeout_secs),
        }
    }

    pub fn fallback_behavior(&self) -> PipFallbackBehavior {
        match self {
            PipSourceConfig::Http(config) => config.fallback_behavior,
            PipSourceConfig::Ldap(config) => config.fallback_behavior,
        }
    }

    pub fn fallback_values(&self) -> &BTreeMap<String, PipAttributeValue> {
        match self {
            PipSourceConfig::Http(config) => &config.fallback_values,
            PipSourceConfig::Ldap(config) => &config.fallback_values,
        }
    }
}

impl PipConfig {
    pub fn prefetch_timeout(&self) -> Duration {
        Duration::from_millis(self.prefetch_timeout_ms)
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pip_config_deserialization() {
        let config_str = r#"
sources = []

enabled = true
"#;

        let config: PipConfig = toml::from_str(config_str).expect("Failed to parse config");
        assert!(config.enabled);
        assert_eq!(config.prefetch_timeout_ms, 2000);
    }

    #[test]
    fn test_source_id_validation() {
        assert!(is_valid_source_id("hr_system"));
        assert!(is_valid_source_id("hr-system.v2"));
        assert!(!is_valid_source_id(""));
        assert!(!is_valid_source_id("hr:system"));
        assert!(!is_valid_source_id("hr system"));
        assert!(!is_valid_source_id("hr=x"));
    }

    #[test]
    fn test_http_pip_config() {
        let config_str = r#"
type = "http"
id = "hr_system"
base_url = "https://hr.example.com/api"
endpoint_path = "/employees/{username}"
timeout_secs = 30
cache_ttl_secs = 60
"#;

        let config: PipSourceConfig = toml::from_str(config_str).expect("Failed to parse config");
        assert!(matches!(config, PipSourceConfig::Http(_)));

        if let PipSourceConfig::Http(http_config) = config {
            assert_eq!(http_config.id, "hr_system");
            assert_eq!(http_config.base_url.as_str(), "https://hr.example.com/api");
            assert_eq!(http_config.endpoint_path, "/employees/{username}");
        }
    }

    #[test]
    fn test_ldap_pip_config() {
        let config_str = r#"
type = "ldap"
id = "company_ldap"
url = "ldaps://ldap.example.com"
base_dn = "dc=example,dc=com"
bind_dn = "cn=admin,dc=example,dc=com"
bind_password = "secret"
search_filter = "(uid={username})"
attributes = ["department", "manager", "location"]
"#;

        let config: PipSourceConfig = toml::from_str(config_str).expect("Failed to parse config");
        assert!(matches!(config, PipSourceConfig::Ldap(_)));

        if let PipSourceConfig::Ldap(ldap_config) = config {
            assert_eq!(ldap_config.id, "company_ldap");
            assert_eq!(ldap_config.attributes.len(), 3);
        }
    }

    #[test]
    fn test_fallback_behavior_defaults() {
        let http_config = HttpPipConfig {
            id: "test".to_string(),
            base_url: Url::parse("https://example.com").unwrap(),
            endpoint_path: "/test".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            headers: BTreeMap::new(),
            fallback_behavior: PipFallbackBehavior::default(),
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec!["test_attr".to_string()],
        };

        assert_eq!(http_config.fallback_behavior, PipFallbackBehavior::Deny);
    }

    #[test]
    fn test_fallback_behavior_default_is_deny() {
        let behavior = PipFallbackBehavior::default();
        assert_eq!(behavior, PipFallbackBehavior::Deny);

        // Also when omitted from the configuration file.
        let config_str = r#"
type = "http"
id = "hr_system"
base_url = "https://hr.example.com/api"
endpoint_path = "/employees/{username}"
"#;
        let PipSourceConfig::Http(http) = toml::from_str(config_str).unwrap() else {
            panic!("expected an http source");
        };
        assert_eq!(http.fallback_behavior, PipFallbackBehavior::Deny);
    }

    #[test]
    fn test_validate_common() {
        let health = PipHealthCheckConfig::default();
        let empty = BTreeMap::new();
        let mut values = BTreeMap::new();
        values.insert("a".to_string(), PipAttributeValue::Integer(0));

        assert!(validate_common("x", 30, &health, PipFallbackBehavior::Deny, &empty).is_ok());
        assert!(validate_common("x", 30, &health, PipFallbackBehavior::Ignore, &empty).is_ok());
        assert!(
            validate_common("x", 30, &health, PipFallbackBehavior::UseFallback, &values).is_ok()
        );
        // usefallback with no values would fail open.
        assert!(
            validate_common("x", 30, &health, PipFallbackBehavior::UseFallback, &empty).is_err()
        );
        assert!(validate_common("x", 0, &health, PipFallbackBehavior::Deny, &empty).is_err());

        let zero_failures = PipHealthCheckConfig {
            failure_threshold: 0,
            ..PipHealthCheckConfig::default()
        };
        assert!(
            validate_common("x", 30, &zero_failures, PipFallbackBehavior::Deny, &empty).is_err()
        );
        let zero_hc_timeout = PipHealthCheckConfig {
            timeout_secs: 0,
            ..PipHealthCheckConfig::default()
        };
        assert!(
            validate_common("x", 30, &zero_hc_timeout, PipFallbackBehavior::Deny, &empty).is_err()
        );
    }

    #[test]
    fn test_validate_no_userinfo() {
        let ok = Url::parse("https://example.com/api").unwrap();
        assert!(validate_no_userinfo("x", &ok).is_ok());
        let user = Url::parse("https://user@example.com/api").unwrap();
        assert!(validate_no_userinfo("x", &user).is_err());
        let both = Url::parse("ldaps://user:pw@ldap.example.com").unwrap();
        assert!(validate_no_userinfo("x", &both).is_err());
    }

    #[test]
    fn test_fallback_behavior_variants() {
        assert_eq!(
            PipFallbackBehavior::UseFallback,
            PipFallbackBehavior::UseFallback
        );
        assert_eq!(PipFallbackBehavior::Deny, PipFallbackBehavior::Deny);
        assert_eq!(PipFallbackBehavior::Ignore, PipFallbackBehavior::Ignore);
    }

    #[test]
    fn test_auth_config_none() {
        let auth = PipAuthConfig::None;
        let serialized = serde_json::to_string(&auth).unwrap();
        assert!(serialized.contains("none"));
    }

    #[test]
    fn test_auth_config_basic() {
        let auth = PipAuthConfig::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        let serialized = serde_json::to_string(&auth).unwrap();
        assert!(serialized.contains("basic"));
        assert!(serialized.contains("user"));
        // Secrets are never serialized.
        assert!(!serialized.contains("pass"));
    }

    #[test]
    fn test_auth_config_bearer() {
        let auth = PipAuthConfig::Bearer {
            token: "my_token".to_string(),
        };
        let serialized = serde_json::to_string(&auth).unwrap();
        assert!(serialized.contains("bearer"));
        assert!(!serialized.contains("my_token"));

        // Deserialization still reads the secret.
        let parsed: PipAuthConfig =
            serde_json::from_str(r#"{"type":"bearer","token":"my_token"}"#).unwrap();
        assert!(matches!(parsed, PipAuthConfig::Bearer { token } if token == "my_token"));
    }

    #[test]
    fn test_secret_fields_not_serialized() {
        let ldap = LdapPipConfig {
            id: "test".to_string(),
            url: Url::parse("ldaps://ldap.example.com").unwrap(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin".to_string(),
            bind_password: "s3cr3t-bind".to_string(),
            search_filter: "(uid={username})".to_string(),
            attributes: vec![],
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            fallback_behavior: PipFallbackBehavior::Deny,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            attribute_mapping: BTreeMap::new(),
        };
        assert!(!serde_json::to_string(&ldap).unwrap().contains("s3cr3t"));

        let auth = PipAuthConfig::ApiKey {
            key_name: "X-Key".to_string(),
            key_value: "s3cr3t-key".to_string(),
            location: ApiKeyLocation::Header,
        };
        assert!(!serde_json::to_string(&auth).unwrap().contains("s3cr3t"));
    }

    #[test]
    fn test_auth_config_api_key_header() {
        let auth = PipAuthConfig::ApiKey {
            key_name: "X-API-Key".to_string(),
            key_value: "secret".to_string(),
            location: ApiKeyLocation::Header,
        };
        assert!(matches!(auth, PipAuthConfig::ApiKey { .. }));
    }

    #[test]
    fn test_auth_config_api_key_query_param() {
        let auth = PipAuthConfig::ApiKey {
            key_name: "api_key".to_string(),
            key_value: "secret".to_string(),
            location: ApiKeyLocation::QueryParam,
        };
        assert!(matches!(
            auth,
            PipAuthConfig::ApiKey {
                location: ApiKeyLocation::QueryParam,
                ..
            }
        ));
    }

    #[test]
    fn test_auth_config_oauth2() {
        let auth = PipAuthConfig::OAuth2ClientCredentials {
            token_url: Url::parse("https://auth.example.com/token").unwrap(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            scope: Some("read".to_string()),
        };
        assert!(matches!(
            auth,
            PipAuthConfig::OAuth2ClientCredentials { .. }
        ));
    }

    #[test]
    fn test_auth_config_mutual_tls() {
        let auth = PipAuthConfig::MutualTls {
            cert_path: PathBuf::from("/path/to/cert.pem"),
            key_path: PathBuf::from("/path/to/key.pem"),
        };
        assert!(matches!(auth, PipAuthConfig::MutualTls { .. }));
    }

    #[test]
    fn test_auth_config_debug_redacts_secrets() {
        let cases = [
            PipAuthConfig::Basic {
                username: "user".to_string(),
                password: "s3cr3t-basic".to_string(),
            },
            PipAuthConfig::Bearer {
                token: "s3cr3t-bearer".to_string(),
            },
            PipAuthConfig::ApiKey {
                key_name: "X-API-Key".to_string(),
                key_value: "s3cr3t-apikey".to_string(),
                location: ApiKeyLocation::Header,
            },
            PipAuthConfig::OAuth2ClientCredentials {
                token_url: Url::parse("https://auth.example.com/token").unwrap(),
                client_id: "client".to_string(),
                client_secret: "s3cr3t-oauth".to_string(),
                scope: None,
            },
        ];
        for auth in cases {
            let debug = format!("{auth:?}");
            assert!(!debug.contains("s3cr3t"), "secret leaked: {debug}");
            assert!(debug.contains("<redacted>"));
        }
        assert!(format!(
            "{:?}",
            PipAuthConfig::Basic {
                username: "visible-user".to_string(),
                password: "x".to_string()
            }
        )
        .contains("visible-user"));
    }

    #[test]
    fn test_http_and_ldap_config_debug_redacts_secrets() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer s3cr3t-header".to_string(),
        );
        let http = HttpPipConfig {
            id: "test".to_string(),
            base_url: Url::parse("https://example.com").unwrap(),
            endpoint_path: "/test".to_string(),
            method: HttpMethod::Get,
            auth: Some(PipAuthConfig::Bearer {
                token: "s3cr3t-token".to_string(),
            }),
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            headers,
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec![],
        };
        let debug = format!("{http:?}");
        assert!(!debug.contains("s3cr3t"), "secret leaked: {debug}");
        assert!(debug.contains("Authorization"));

        let ldap = LdapPipConfig {
            id: "test".to_string(),
            url: Url::parse("ldaps://ldap.example.com").unwrap(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin".to_string(),
            bind_password: "s3cr3t-bind".to_string(),
            search_filter: "(uid={username})".to_string(),
            attributes: vec![],
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            attribute_mapping: BTreeMap::new(),
        };
        let debug = format!("{ldap:?}");
        assert!(!debug.contains("s3cr3t"), "secret leaked: {debug}");
        assert!(debug.contains("cn=admin"));

        // Redaction must survive the wrapping config types.
        let config = PipConfig {
            sources: vec![PipSourceConfig::Http(http), PipSourceConfig::Ldap(ldap)],
            enabled: true,
            prefetch_timeout_ms: 2000,
        };
        assert!(!format!("{config:?}").contains("s3cr3t"));
    }

    #[test]
    fn test_api_key_location_default() {
        let location = ApiKeyLocation::default();
        assert_eq!(location, ApiKeyLocation::Header);
    }

    #[test]
    fn test_tls_config_default() {
        let tls = PipTlsConfig::default();
        assert!(tls.verify_server);
        assert!(!tls.allow_insecure);
        assert!(tls.ca_path.is_none());
    }

    #[test]
    fn test_tls_config_with_insecure() {
        let tls = PipTlsConfig {
            ca_path: Some(PathBuf::from("/path/to/ca.pem")),
            verify_server: false,
            allow_insecure: true,
        };
        assert!(!tls.verify_server);
        assert!(tls.allow_insecure);
        assert!(tls.ca_path.is_some());
    }

    #[test]
    fn test_health_check_config_default() {
        let config = PipHealthCheckConfig::default();
        assert_eq!(config.interval_secs, 60);
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 2);
        assert_eq!(config.timeout_secs, 5);
    }

    #[test]
    fn test_health_check_config_custom() {
        let config = PipHealthCheckConfig {
            interval_secs: 30,
            failure_threshold: 5,
            success_threshold: 3,
            timeout_secs: 10,
        };
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.failure_threshold, 5);
    }

    #[test]
    fn test_http_method_variants() {
        assert_eq!(HttpMethod::Get, HttpMethod::Get);
        assert_eq!(HttpMethod::Post, HttpMethod::Post);
        assert_ne!(HttpMethod::Get, HttpMethod::Post);
    }

    #[test]
    fn test_pip_source_config_id() {
        let http = PipSourceConfig::Http(HttpPipConfig {
            id: "http_pip".to_string(),
            base_url: Url::parse("https://example.com").unwrap(),
            endpoint_path: "/test".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            headers: BTreeMap::new(),
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec!["attr".to_string()],
        });

        let ldap = PipSourceConfig::Ldap(LdapPipConfig {
            id: "ldap_pip".to_string(),
            url: Url::parse("ldap://localhost").unwrap(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin".to_string(),
            bind_password: "secret".to_string(),
            search_filter: "(uid={username})".to_string(),
            attributes: vec!["attr".to_string()],
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            attribute_mapping: BTreeMap::new(),
        });

        assert_eq!(http.id(), "http_pip");
        assert_eq!(ldap.id(), "ldap_pip");
    }

    #[test]
    fn test_pip_source_config_cache_ttl() {
        let http = PipSourceConfig::Http(HttpPipConfig {
            id: "test".to_string(),
            base_url: Url::parse("https://example.com").unwrap(),
            endpoint_path: "/test".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 120,
            headers: BTreeMap::new(),
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec!["attr".to_string()],
        });

        assert_eq!(http.cache_ttl(), Duration::from_secs(120));
    }

    #[test]
    fn test_pip_source_config_timeout() {
        let ldap = PipSourceConfig::Ldap(LdapPipConfig {
            id: "test".to_string(),
            url: Url::parse("ldap://localhost").unwrap(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin".to_string(),
            bind_password: "secret".to_string(),
            search_filter: "(uid={username})".to_string(),
            attributes: vec!["attr".to_string()],
            tls: PipTlsConfig::default(),
            timeout_secs: 45,
            cache_ttl_secs: 60,
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            attribute_mapping: BTreeMap::new(),
        });

        assert_eq!(ldap.timeout(), Duration::from_secs(45));
    }

    #[test]
    fn test_pip_source_config_fallback_behavior() {
        let http = PipSourceConfig::Http(HttpPipConfig {
            id: "test".to_string(),
            base_url: Url::parse("https://example.com").unwrap(),
            endpoint_path: "/test".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            headers: BTreeMap::new(),
            fallback_behavior: PipFallbackBehavior::Deny,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec!["attr".to_string()],
        });

        assert_eq!(http.fallback_behavior(), PipFallbackBehavior::Deny);
    }

    #[test]
    fn test_pip_source_config_fallback_values() {
        let mut fallback = BTreeMap::new();
        fallback.insert(
            "key".to_string(),
            PipAttributeValue::String("value".to_string()),
        );

        let http = PipSourceConfig::Http(HttpPipConfig {
            id: "test".to_string(),
            base_url: Url::parse("https://example.com").unwrap(),
            endpoint_path: "/test".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            headers: BTreeMap::new(),
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: fallback.clone(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec!["attr".to_string()],
        });

        assert!(http.fallback_values().contains_key("key"));
    }

    #[test]
    fn test_pip_config_default_values() {
        let config = PipConfig::default();
        assert!(config.sources.is_empty());
    }

    #[test]
    fn test_pip_config_is_empty() {
        let empty_config = PipConfig::default();
        assert!(empty_config.is_empty());

        let non_empty_config = PipConfig {
            sources: vec![PipSourceConfig::Http(HttpPipConfig {
                id: "test".to_string(),
                base_url: Url::parse("https://example.com").unwrap(),
                endpoint_path: "/test".to_string(),
                method: HttpMethod::Get,
                auth: None,
                tls: PipTlsConfig::default(),
                timeout_secs: 30,
                cache_ttl_secs: 60,
                headers: BTreeMap::new(),
                fallback_behavior: PipFallbackBehavior::UseFallback,
                fallback_values: BTreeMap::new(),
                health_check: PipHealthCheckConfig::default(),
                health_check_path: None,
                provided_attributes: vec!["attr".to_string()],
            })],
            enabled: true,
            prefetch_timeout_ms: 2000,
        };
        assert!(!non_empty_config.is_empty());
    }

    #[test]
    fn test_pip_config_source_count() {
        let config = PipConfig::default();
        assert_eq!(config.source_count(), 0);

        let config_with_sources = PipConfig {
            sources: vec![
                PipSourceConfig::Http(HttpPipConfig {
                    id: "http1".to_string(),
                    base_url: Url::parse("https://example.com").unwrap(),
                    endpoint_path: "/test".to_string(),
                    method: HttpMethod::Get,
                    auth: None,
                    tls: PipTlsConfig::default(),
                    timeout_secs: 30,
                    cache_ttl_secs: 60,
                    headers: BTreeMap::new(),
                    fallback_behavior: PipFallbackBehavior::UseFallback,
                    fallback_values: BTreeMap::new(),
                    health_check: PipHealthCheckConfig::default(),
                    health_check_path: None,
                    provided_attributes: vec!["attr".to_string()],
                }),
                PipSourceConfig::Ldap(LdapPipConfig {
                    id: "ldap1".to_string(),
                    url: Url::parse("ldap://localhost").unwrap(),
                    base_dn: "dc=example,dc=com".to_string(),
                    bind_dn: "cn=admin".to_string(),
                    bind_password: "secret".to_string(),
                    search_filter: "(uid={username})".to_string(),
                    attributes: vec!["attr".to_string()],
                    tls: PipTlsConfig::default(),
                    timeout_secs: 30,
                    cache_ttl_secs: 60,
                    fallback_behavior: PipFallbackBehavior::UseFallback,
                    fallback_values: BTreeMap::new(),
                    health_check: PipHealthCheckConfig::default(),
                    attribute_mapping: BTreeMap::new(),
                }),
            ],
            enabled: true,
            prefetch_timeout_ms: 2000,
        };
        assert_eq!(config_with_sources.source_count(), 2);
    }

    #[test]
    fn test_http_pip_config_with_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Custom-Header".to_string(), "value".to_string());
        headers.insert("Authorization".to_string(), "Bearer token".to_string());

        let config = HttpPipConfig {
            id: "test".to_string(),
            base_url: Url::parse("https://example.com").unwrap(),
            endpoint_path: "/test".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            headers: headers.clone(),
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec!["attr".to_string()],
        };

        assert_eq!(config.headers.len(), 2);
    }

    #[test]
    fn test_ldap_pip_config_with_attribute_mapping() {
        let mut mapping = BTreeMap::new();
        mapping.insert("cn".to_string(), "common_name".to_string());
        mapping.insert("uid".to_string(), "username".to_string());

        let config = LdapPipConfig {
            id: "test".to_string(),
            url: Url::parse("ldap://localhost").unwrap(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin".to_string(),
            bind_password: "secret".to_string(),
            search_filter: "(uid={username})".to_string(),
            attributes: vec!["cn".to_string(), "uid".to_string()],
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            attribute_mapping: mapping.clone(),
        };

        assert_eq!(config.attribute_mapping.len(), 2);
    }

    #[test]
    fn test_http_pip_config_health_check_path() {
        let config = HttpPipConfig {
            id: "test".to_string(),
            base_url: Url::parse("https://example.com").unwrap(),
            endpoint_path: "/test".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            headers: BTreeMap::new(),
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: Some("/health".to_string()),
            provided_attributes: vec!["attr".to_string()],
        };

        assert!(config.health_check_path.is_some());
        assert_eq!(config.health_check_path.unwrap(), "/health");
    }

    #[test]
    fn test_pip_config_disabled() {
        let config = PipConfig {
            sources: vec![],
            enabled: false,
            prefetch_timeout_ms: 2000,
        };
        assert!(!config.enabled);
    }

    #[test]
    fn test_ldap_pip_config_ldaps_url() {
        let config = LdapPipConfig {
            id: "test".to_string(),
            url: Url::parse("ldaps://ldap.example.com:636").unwrap(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin".to_string(),
            bind_password: "secret".to_string(),
            search_filter: "(uid={username})".to_string(),
            attributes: vec!["cn".to_string()],
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            attribute_mapping: BTreeMap::new(),
        };

        assert!(config.url.as_str().starts_with("ldaps://"));
    }

    #[test]
    fn test_ldap_pip_config_empty_attributes() {
        let config = LdapPipConfig {
            id: "test".to_string(),
            url: Url::parse("ldap://localhost").unwrap(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin".to_string(),
            bind_password: "secret".to_string(),
            search_filter: "(uid={username})".to_string(),
            attributes: vec![],
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            attribute_mapping: BTreeMap::new(),
        };

        assert!(config.attributes.is_empty());
    }
}
