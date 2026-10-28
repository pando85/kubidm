//! HTTP Policy Information Point Implementation
//!
//! This module provides a PIP implementation that retrieves attributes from
//! HTTP REST endpoints.

#![allow(dead_code)]

use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

use super::cache::PipAttributeCache;
use reqwest::header::{HeaderName, HeaderValue};

use super::config::{
    validate_common, validate_no_userinfo, ApiKeyLocation, HttpMethod, HttpPipConfig, PipAuthConfig,
};
use super::health::PipHealthTracker;
use super::{
    encode_url_value, render_template, PipAttributeName, PipAttributeSet, PipAttributeValue,
    PipFailure, PipHealthCheck, PipHealthStatus, PipId, PipResult, PipSubject,
    PolicyInformationPoint,
};
use crate::prelude::*;

/// Maximum size of a (decompressed) response body accepted from an HTTP PIP.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// A failed fetch, and whether it reflects on the health of the source.
///
/// Client-side problems (a URL that cannot be built for this subject, or a 4xx
/// such as "subject not found") are not the source's fault and must not mark
/// it unhealthy for everyone else.
struct FetchError {
    failure: PipFailure,
    source_fault: bool,
}

impl FetchError {
    fn source(failure: PipFailure) -> Self {
        FetchError {
            failure,
            source_fault: true,
        }
    }

    fn client(failure: PipFailure) -> Self {
        FetchError {
            failure,
            source_fault: false,
        }
    }
}

/// Describe a reqwest error without the request URL.
///
/// reqwest's `Display` appends `for url (<full url>)`, which would leak an API
/// key sent as a query parameter into failures, health state and logs.
fn describe_reqwest_error(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut message = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

fn map_reqwest_error(context: &str, e: reqwest::Error) -> PipFailure {
    if e.is_timeout() {
        PipFailure::Timeout
    } else if e.is_connect() {
        PipFailure::Unavailable(format!("{context}: {}", describe_reqwest_error(e)))
    } else {
        PipFailure::Error(format!("{context}: {}", describe_reqwest_error(e)))
    }
}

/// Join `base` and an already-encoded `path`, avoiding a doubled `/`.
///
/// `path` must start with `/`. The parsed URL must be exactly the joined
/// string: if URL normalisation changed it (e.g. resolved a `..` dot-segment
/// assembled from several values), the request is refused.
fn join_base(base: &Url, path: &str) -> Result<Url, String> {
    if !path.starts_with('/') {
        return Err("request path must start with '/'".to_string());
    }
    let joined = format!("{}{}", base.as_str().trim_end_matches('/'), path);
    let url = Url::parse(&joined).map_err(|e| format!("invalid request URL: {e}"))?;
    if url.as_str() != joined {
        return Err("request URL was altered by URL normalisation".to_string());
    }
    if url.origin() != base.origin() {
        return Err("request URL does not stay on the origin of base_url".to_string());
    }
    Ok(url)
}

/// Read a response body, failing once it exceeds `limit` bytes.
async fn read_body_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, PipFailure> {
    let too_large = || PipFailure::Error(format!("response body exceeds {limit} bytes"));

    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(too_large());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| map_reqwest_error("Failed to read response body", e))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// HTTP PIP implementation
pub struct HttpPip {
    id: PipId,
    config: HttpPipConfig,
    client: Client,
    cache: Arc<RwLock<PipAttributeCache>>,
    health: PipHealthTracker,
    provided_attributes: Vec<String>,
}

impl HttpPip {
    /// Create a new HTTP PIP from configuration.
    ///
    /// Fails for configuration that cannot be honoured or is unsafe:
    /// unsupported authentication modes (OAuth2 client credentials, mutual
    /// TLS), a custom CA path, a non-HTTP(S) base URL, plain `http://` without
    /// `tls.allow_insecure`, credentials/query/fragment in `base_url`, paths
    /// not starting with `/`, invalid headers, zero timeouts or thresholds, or
    /// `usefallback` without fallback values.
    pub fn new(config: HttpPipConfig) -> Result<Self, String> {
        Self::validate_config(&config)?;
        let client = Self::build_client(&config)?;
        let cache = Arc::new(RwLock::new(PipAttributeCache::with_settings(
            Duration::from_secs(config.cache_ttl_secs),
            1000,
        )));

        let provided_attributes = if config.provided_attributes.is_empty() {
            Self::extract_provided_attributes_from_endpoint(&config)?
        } else {
            config.provided_attributes.clone()
        };

        Ok(HttpPip {
            id: PipId::new(&config.id),
            config,
            client,
            cache,
            health: PipHealthTracker::new(),
            provided_attributes,
        })
    }

    fn validate_config(config: &HttpPipConfig) -> Result<(), String> {
        match &config.auth {
            Some(PipAuthConfig::OAuth2ClientCredentials { .. }) => {
                return Err(format!(
                    "PIP '{}': OAuth2 client credentials authentication is not supported yet",
                    config.id
                ));
            }
            Some(PipAuthConfig::MutualTls { .. }) => {
                return Err(format!(
                    "PIP '{}': mutual TLS authentication is not supported yet",
                    config.id
                ));
            }
            _ => {}
        }

        if config.tls.ca_path.is_some() {
            return Err(format!(
                "PIP '{}': tls.ca_path is not supported yet",
                config.id
            ));
        }

        validate_common(
            &config.id,
            config.timeout_secs,
            &config.health_check,
            config.fallback_behavior,
            &config.fallback_values,
        )?;

        match config.base_url.scheme() {
            "https" => {}
            // Plain-text responses could be forged by a network attacker, and the
            // attributes feed access decisions.
            "http" if !config.tls.allow_insecure => {
                return Err(format!(
                    "PIP '{}': refusing plain-text http:// (use https://, or set \
                     tls.allow_insecure for development)",
                    config.id
                ));
            }
            "http" => {}
            other => {
                return Err(format!(
                    "PIP '{}': unsupported base_url scheme '{other}'",
                    config.id
                ));
            }
        }

        validate_no_userinfo(&config.id, &config.base_url)?;
        if config.base_url.query().is_some() || config.base_url.fragment().is_some() {
            return Err(format!(
                "PIP '{}': base_url must not contain a query or fragment",
                config.id
            ));
        }

        if !config.endpoint_path.starts_with('/') {
            return Err(format!(
                "PIP '{}': endpoint_path must start with '/'",
                config.id
            ));
        }
        if let Some(path) = &config.health_check_path {
            join_base(&config.base_url, path)
                .map_err(|e| format!("PIP '{}': invalid health_check_path: {e}", config.id))?;
        }

        for (name, value) in &config.headers {
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("PIP '{}': invalid header name '{name}'", config.id))?;
            HeaderValue::from_str(value)
                .map_err(|_| format!("PIP '{}': invalid value for header '{name}'", config.id))?;
        }
        if let Some(PipAuthConfig::ApiKey {
            key_name,
            key_value,
            location: ApiKeyLocation::Header,
        }) = &config.auth
        {
            HeaderName::from_bytes(key_name.as_bytes()).map_err(|_| {
                format!(
                    "PIP '{}': invalid API key header name '{key_name}'",
                    config.id
                )
            })?;
            HeaderValue::from_str(key_value)
                .map_err(|_| format!("PIP '{}': invalid API key header value", config.id))?;
        }

        Ok(())
    }

    fn build_client(config: &HttpPipConfig) -> Result<Client, String> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .connect_timeout(Duration::from_secs(10))
            // Never follow redirects: they could forward credentials (e.g. API key
            // headers) to another host.
            .redirect(reqwest::redirect::Policy::none());

        if !config.tls.verify_server || config.tls.allow_insecure {
            admin_warn!(
                "PIP '{}' does not verify TLS server certificates (verify_server = false or allow_insecure = true) - this should only be used for development!",
                config.id
            );
            builder = builder.tls_danger_accept_invalid_certs(true);
        }

        builder
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))
    }

    fn extract_provided_attributes_from_endpoint(
        _config: &HttpPipConfig,
    ) -> Result<Vec<String>, String> {
        Ok(vec!["attributes".to_string()])
    }

    /// Build the request URL for `subject`.
    ///
    /// Substituted values are percent-encoded, so they cannot add path segments,
    /// query parameters or fragments, and the result must stay on the origin of
    /// `base_url`.
    fn build_url(&self, subject: &PipSubject) -> Result<Url, String> {
        let path = render_template(&self.config.endpoint_path, subject, encode_url_value)?;
        join_base(&self.config.base_url, &path)
    }

    fn build_request(&self, url: Url) -> reqwest::RequestBuilder {
        let builder = match self.config.method {
            HttpMethod::Get => self.client.get(url),
            HttpMethod::Post => self.client.post(url),
        };

        self.apply_headers_and_auth(builder)
    }

    /// Add the configured headers and authentication (used for both attribute
    /// requests and health checks, so an authenticated endpoint does not fail
    /// its health check with 401).
    fn apply_headers_and_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut builder = builder;
        for (key, value) in &self.config.headers {
            builder = builder.header(key, value);
        }

        self.apply_auth(builder)
    }

    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.config.auth {
            None | Some(PipAuthConfig::None) => builder,
            Some(PipAuthConfig::Basic { username, password }) => {
                builder.basic_auth(username, Some(password))
            }
            Some(PipAuthConfig::Bearer { token }) => builder.bearer_auth(token),
            Some(PipAuthConfig::ApiKey {
                key_name,
                key_value,
                location,
            }) => match location {
                ApiKeyLocation::Header => builder.header(key_name, key_value),
                ApiKeyLocation::QueryParam => builder.query(&[(key_name, key_value)]),
            },
            // Rejected in `validate_config`, so never reached at runtime.
            Some(PipAuthConfig::OAuth2ClientCredentials { .. })
            | Some(PipAuthConfig::MutualTls { .. }) => builder,
        }
    }

    fn parse_response(&self, json: Value) -> PipAttributeSet {
        let mut attrs = PipAttributeSet::new();

        let attr_map = match json {
            Value::Object(map) => map,
            Value::Array(arr) if arr.len() == 1 && arr.first().is_some_and(|v| v.is_object()) => {
                arr.first()
                    .and_then(|v| v.as_object().cloned())
                    .unwrap_or_default()
            }
            _ => {
                admin_debug!("PIP response is not a JSON object, wrapping in 'response' attribute");
                attrs.insert(
                    PipAttributeName::new(&self.id, "response"),
                    Self::json_to_attribute_value(json),
                );
                return attrs;
            }
        };

        for (key, value) in attr_map {
            let attr_name = PipAttributeName::new(&self.id, &key);
            let attr_value = Self::json_to_attribute_value(value);
            attrs.insert(attr_name, attr_value);
        }

        attrs
    }

    fn json_to_attribute_value(value: Value) -> PipAttributeValue {
        match value {
            Value::Null => PipAttributeValue::Json(Value::Null),
            Value::Bool(b) => PipAttributeValue::Boolean(b),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    PipAttributeValue::Integer(i)
                } else {
                    PipAttributeValue::Json(Value::Number(n))
                }
            }
            Value::String(s) => PipAttributeValue::String(s),
            Value::Array(arr) => PipAttributeValue::Array(
                arr.into_iter().map(Self::json_to_attribute_value).collect(),
            ),
            Value::Object(obj) => PipAttributeValue::Json(Value::Object(obj)),
        }
    }

    /// The configured fallback values, namespaced to this PIP.
    fn apply_fallback(&self) -> PipAttributeSet {
        PipAttributeSet::from_fallback_values(&self.id, &self.config.fallback_values)
    }

    /// Resolve a failure according to `fallback_behavior`.
    fn on_failure(&self, failure: PipFailure) -> PipResult {
        PipResult::from_failure(self.config.fallback_behavior, failure, || {
            self.apply_fallback()
        })
    }

    async fn fetch(&self, url: Url) -> Result<PipAttributeSet, FetchError> {
        let response = self
            .build_request(url)
            .send()
            .await
            .map_err(|e| FetchError::source(map_reqwest_error("Request failed", e)))?;

        let status = response.status();
        if status.is_client_error() {
            // A 4xx is about this request, not an outage: it does not mark the source
            // unhealthy, and it never uses fallback values. That includes 408 and 429: a
            // user can cause them (for example by flooding requests until the source
            // rate limits), and must not be given the fallback values for it.
            return Err(FetchError::client(PipFailure::Subject(format!(
                "HTTP error: {status}"
            ))));
        }
        if !status.is_success() {
            return Err(FetchError::source(PipFailure::Error(format!(
                "HTTP error: {status}"
            ))));
        }

        let body = read_body_limited(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(FetchError::source)?;

        let json: Value = serde_json::from_slice(&body).map_err(|e| {
            FetchError::source(PipFailure::Error(format!(
                "Failed to parse response JSON: {e}"
            )))
        })?;

        Ok(self.parse_response(json))
    }
}

#[async_trait]
impl PolicyInformationPoint for HttpPip {
    fn id(&self) -> &PipId {
        &self.id
    }

    async fn retrieve_attributes(&self, subject: &PipSubject) -> PipResult {
        {
            let mut cache = self.cache.write().await;
            if let Some(cached_attrs) = cache.get(&self.id, subject) {
                return PipResult::Success(cached_attrs);
            }
        }

        let url = match self.build_url(subject) {
            Ok(url) => url,
            Err(e) => return self.on_failure(PipFailure::Subject(e)),
        };

        if !self.health.try_begin_attempt(&self.config.health_check) {
            return self.on_failure(PipFailure::Unavailable(
                "PIP source is unhealthy, waiting for the retry interval".to_string(),
            ));
        }

        match self.fetch(url).await {
            Ok(attrs) => {
                self.health.record_success(&self.config.health_check);
                {
                    let mut cache = self.cache.write().await;
                    cache.put(&self.id, subject, attrs.clone());
                }
                PipResult::Success(attrs)
            }
            Err(FetchError {
                failure,
                source_fault,
            }) => {
                if source_fault {
                    self.health
                        .record_failure(&self.config.health_check, failure.to_string());
                }
                self.on_failure(failure)
            }
        }
    }

    async fn retrieve_named_attributes(
        &self,
        subject: &PipSubject,
        attribute_names: &[String],
    ) -> PipResult {
        self.retrieve_attributes(subject)
            .await
            .filter_named(&self.id, attribute_names)
    }

    async fn health_check(&self) -> PipHealthCheck {
        let start = Instant::now();

        let health_url = match &self.config.health_check_path {
            Some(path) => join_base(&self.config.base_url, path),
            None => Ok(self.config.base_url.clone()),
        };

        let result = match health_url {
            Ok(url) => self
                .apply_headers_and_auth(self.client.get(url))
                .timeout(Duration::from_secs(self.config.health_check.timeout_secs))
                .send()
                .await
                .map_err(|e| format!("Health check failed: {}", describe_reqwest_error(e)))
                .and_then(|response| {
                    if response.status().is_success() {
                        Ok(())
                    } else {
                        Err(format!("Health check returned: {}", response.status()))
                    }
                }),
            Err(e) => Err(format!("Health check failed: {e}")),
        };

        let latency_ms = start.elapsed().as_millis() as u64;

        let error_message = match result {
            Ok(()) => {
                self.health.record_success(&self.config.health_check);
                None
            }
            Err(error) => {
                self.health
                    .record_failure(&self.config.health_check, error.clone());
                Some(error)
            }
        };

        PipHealthCheck {
            pip_id: self.id.clone(),
            status: self.health.status(),
            last_check: Instant::now(),
            latency_ms: Some(latency_ms),
            error_message,
        }
    }

    fn cached_health_status(&self) -> PipHealthStatus {
        self.health.status()
    }

    fn provided_attributes(&self) -> &[String] {
        &self.provided_attributes
    }

    async fn clear_cache(&self, subject: &PipSubject) {
        let mut cache = self.cache.write().await;
        cache.remove(&self.id, subject);
    }

    async fn clear_all_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    fn record_source_failure(&self, error: String) {
        self.health.record_failure(&self.config.health_check, error);
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::{PipFallbackBehavior, PipHealthCheckConfig, PipTlsConfig};
    use super::super::{PipError, PipManager};
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    fn create_test_config() -> HttpPipConfig {
        HttpPipConfig {
            id: "test_http_pip".to_string(),
            base_url: Url::parse("https://example.com/api").unwrap(),
            endpoint_path: "/users/{username}".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            headers: BTreeMap::new(),
            fallback_behavior: PipFallbackBehavior::Deny,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: Some("/health".to_string()),
            provided_attributes: vec!["department".to_string(), "role".to_string()],
        }
    }

    /// Test config for `base_url`; plain `http://` (the local test servers) is
    /// explicitly opted in with `tls.allow_insecure`.
    fn config_with(base_url: &str, endpoint_path: &str) -> HttpPipConfig {
        HttpPipConfig {
            id: "test".to_string(),
            base_url: Url::parse(base_url).unwrap(),
            endpoint_path: endpoint_path.to_string(),
            provided_attributes: vec!["attr".to_string()],
            health_check_path: None,
            tls: PipTlsConfig {
                allow_insecure: base_url.starts_with("http://"),
                ..PipTlsConfig::default()
            },
            ..create_test_config()
        }
    }

    fn fallback_department() -> BTreeMap<String, PipAttributeValue> {
        let mut fallback = BTreeMap::new();
        fallback.insert(
            "department".to_string(),
            PipAttributeValue::String("Unknown".to_string()),
        );
        fallback
    }

    /// A tiny HTTP server on a std thread that answers each incoming connection
    /// with the next canned response, and returns the request heads it saw.
    fn serve(responses: Vec<Vec<u8>>) -> (Url, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut request_heads = Vec::new();
            for response in responses {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                request_heads.push(String::from_utf8_lossy(&buf).to_string());
                // The client may hang up early (e.g. body too large).
                let _ = sock.write_all(&response);
            }
            request_heads
        });
        (Url::parse(&format!("http://{addr}")).unwrap(), handle)
    }

    fn request_line(head: &str) -> &str {
        head.lines().next().unwrap_or_default()
    }

    fn http_response(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// An address on which nothing listens.
    fn refused_url() -> Url {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        Url::parse(&format!("http://{addr}")).unwrap()
    }

    #[test]
    fn test_http_pip_creation() {
        let config = create_test_config();
        let pip = HttpPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_url_building_with_username() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("testuser");

        let url = pip.build_url(&subject).unwrap();
        assert_eq!(url.as_str(), "https://example.com/api/users/testuser");
    }

    #[test]
    fn test_url_building_with_uuid() {
        let pip = HttpPip::new(config_with("https://example.com", "/users/{uuid}")).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let subject = PipSubject::from_uuid(uuid);

        let url = pip.build_url(&subject).unwrap();
        assert_eq!(url.as_str(), format!("https://example.com/users/{uuid}"));
    }

    #[test]
    fn test_url_building_with_email() {
        let pip = HttpPip::new(config_with("https://example.com", "/lookup/{email}")).unwrap();

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_email("test@example.com");

        let url = pip.build_url(&subject).unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.com/lookup/test%40example.com"
        );
    }

    #[test]
    fn test_url_building_with_context() {
        let pip = HttpPip::new(config_with(
            "https://example.com",
            "/users/{username}/devices/{device_id}",
        ))
        .unwrap();

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4())
            .with_username("testuser")
            .with_context("device_id", "device123");

        let url = pip.build_url(&subject).unwrap();
        assert!(url.as_str().ends_with("/users/testuser/devices/device123"));
    }

    #[test]
    fn test_url_building_escapes_injection() {
        let pip = HttpPip::new(config_with(
            "https://example.com/api",
            "/users/{username}?dept={dept}",
        ))
        .unwrap();

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4())
            .with_username("../admin/x?role=admin#frag")
            .with_context("dept", "eng&admin=true");

        let url = pip.build_url(&subject).unwrap();
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(
            url.path(),
            "/api/users/..%2Fadmin%2Fx%3Frole%3Dadmin%23frag"
        );
        assert_eq!(url.fragment(), None);
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            vec![("dept".to_string(), "eng&admin=true".to_string())]
        );
    }

    #[test]
    fn test_url_building_rejects_dot_segments_and_origin_escape() {
        let pip =
            HttpPip::new(config_with("https://example.com/api", "/users/{username}")).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("..");
        assert!(pip.build_url(&subject).is_err());

        // A template without a leading '/' could rewrite the host: rejected at
        // construction, and by join_base as a second line of defence.
        assert!(HttpPip::new(config_with("https://example.com", "{username}")).is_err());
        let base = Url::parse("https://example.com").unwrap();
        assert!(join_base(&base, "evil.com").is_err());
    }

    #[test]
    fn test_url_building_rejects_combined_dot_segment() {
        // Each value alone is fine, but together they would form "..".
        let pip = HttpPip::new(config_with("https://example.com/api", "/users/{a}{b}/x")).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4())
            .with_context("a", ".")
            .with_context("b", ".");
        assert!(pip.build_url(&subject).is_err());

        // Empty values are rejected too ("{a}{b}" with a="" and b="..").
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4())
            .with_context("a", "")
            .with_context("b", "x");
        assert!(pip.build_url(&subject).is_err());

        // A normal pair still works.
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4())
            .with_context("a", "ab")
            .with_context("b", "cd");
        assert_eq!(
            pip.build_url(&subject).unwrap().as_str(),
            "https://example.com/api/users/abcd/x"
        );

        // A literal dot plus a "." value would also form "..". (The
        // normalisation check itself is exercised in test_join_base_*.)
        let pip = HttpPip::new(config_with("https://example.com/api", "/users/.{a}/x")).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_context("a", ".");
        assert!(pip.build_url(&subject).is_err());
    }

    #[test]
    fn test_join_base_rejects_normalised_urls() {
        let base = Url::parse("https://example.com/api").unwrap();
        assert!(join_base(&base, "/a/../b").is_err());
        assert!(join_base(&base, "/a/./b").is_err());
        assert!(join_base(&base, "/a b").is_err());
        assert_eq!(
            join_base(&base, "/a/b?c=d").unwrap().as_str(),
            "https://example.com/api/a/b?c=d"
        );
    }

    #[test]
    fn test_url_building_missing_value_is_error() {
        let pip = HttpPip::new(create_test_config()).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4());
        assert!(pip.build_url(&subject).is_err());
    }

    #[test]
    fn test_json_to_attribute_value_string() {
        let string_val = HttpPip::json_to_attribute_value(Value::String("test".to_string()));
        assert_eq!(string_val.as_str(), Some("test"));
    }

    #[test]
    fn test_json_to_attribute_value_integer() {
        let int_val = HttpPip::json_to_attribute_value(Value::Number(serde_json::Number::from(42)));
        assert_eq!(int_val.as_int(), Some(42));
    }

    #[test]
    fn test_json_to_attribute_value_boolean() {
        let bool_val = HttpPip::json_to_attribute_value(Value::Bool(true));
        assert_eq!(bool_val.as_bool(), Some(true));
    }

    #[test]
    fn test_json_to_attribute_value_null() {
        let null_val = HttpPip::json_to_attribute_value(Value::Null);
        assert!(matches!(null_val, PipAttributeValue::Json(Value::Null)));
    }

    #[test]
    fn test_json_to_attribute_value_array() {
        let arr = Value::Array(vec![
            Value::String("a".to_string()),
            Value::Number(serde_json::Number::from(1)),
        ]);
        let array_val = HttpPip::json_to_attribute_value(arr);
        assert_eq!(array_val.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_json_to_attribute_value_object() {
        let obj = Value::Object(serde_json::Map::from_iter(vec![(
            "key".to_string(),
            Value::String("value".to_string()),
        )]));
        let obj_val = HttpPip::json_to_attribute_value(obj);
        assert!(matches!(obj_val, PipAttributeValue::Json(_)));
    }

    #[test]
    fn test_provided_attributes() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        assert_eq!(pip.provided_attributes().len(), 2);
        assert!(pip
            .provided_attributes()
            .contains(&"department".to_string()));
    }

    #[test]
    fn test_provided_attributes_empty() {
        let config = HttpPipConfig {
            provided_attributes: vec![],
            ..config_with("https://example.com", "/test")
        };
        let pip = HttpPip::new(config).unwrap();

        assert_eq!(pip.provided_attributes().len(), 1);
        assert!(pip
            .provided_attributes()
            .contains(&"attributes".to_string()));
    }

    #[test]
    fn test_parse_response_object() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        let json = serde_json::json!({
            "department": "Engineering",
            "role": "Developer"
        });

        let attrs = pip.parse_response(json);
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn test_parse_response_array() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        let json = serde_json::json!([{
            "department": "Engineering"
        }]);

        let attrs = pip.parse_response(json);
        assert_eq!(attrs.len(), 1);
    }

    #[test]
    fn test_parse_response_empty_array() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        let json = serde_json::json!([]);

        let attrs = pip.parse_response(json);
        assert_eq!(attrs.len(), 1);
        assert!(attrs
            .get(&PipAttributeName::new(&pip.id, "response"))
            .is_some());
    }

    #[test]
    fn test_parse_response_primitive() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        let json = serde_json::json!("simple_value");

        let attrs = pip.parse_response(json);
        assert_eq!(attrs.len(), 1);
    }

    #[test]
    fn test_apply_fallback_empty() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        let attrs = pip.apply_fallback();
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_apply_fallback_with_values() {
        let mut fallback = BTreeMap::new();
        fallback.insert(
            "department".to_string(),
            PipAttributeValue::String("Unknown".to_string()),
        );
        fallback.insert("level".to_string(), PipAttributeValue::Integer(0));

        let config = HttpPipConfig {
            fallback_values: fallback,
            ..config_with("https://example.com", "/test")
        };
        let pip = HttpPip::new(config).unwrap();

        let attrs = pip.apply_fallback();
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn test_pip_id() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        assert_eq!(pip.id().as_str(), "test_http_pip");
    }

    #[test]
    fn test_cached_health_status_initial() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        let status = pip.cached_health_status();
        assert_eq!(status, PipHealthStatus::Unknown);
    }

    #[test]
    fn test_http_pip_with_post_method() {
        let config = HttpPipConfig {
            method: HttpMethod::Post,
            ..config_with("https://example.com", "/users")
        };
        let pip = HttpPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_http_pip_with_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("X-API-Key".to_string(), "secret".to_string());
        headers.insert("X-Custom".to_string(), "value".to_string());

        let config = HttpPipConfig {
            headers,
            ..config_with("https://example.com", "/test")
        };
        let pip = HttpPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_http_pip_with_insecure_tls() {
        let config = HttpPipConfig {
            tls: PipTlsConfig {
                ca_path: None,
                verify_server: false,
                allow_insecure: true,
            },
            ..config_with("https://example.com", "/test")
        };
        let pip = HttpPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_http_pip_verify_server_false_is_accepted() {
        // verify_server = false is honoured (certificate checks disabled, with a
        // warning), not silently ignored.
        let config = HttpPipConfig {
            tls: PipTlsConfig {
                ca_path: None,
                verify_server: false,
                allow_insecure: false,
            },
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(config).is_ok());
    }

    #[test]
    fn test_http_pip_rejects_unsupported_config() {
        let oauth2 = HttpPipConfig {
            auth: Some(PipAuthConfig::OAuth2ClientCredentials {
                token_url: Url::parse("https://auth.example.com/token").unwrap(),
                client_id: "client".to_string(),
                client_secret: "secret".to_string(),
                scope: None,
            }),
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(oauth2).is_err());

        let mtls = HttpPipConfig {
            auth: Some(PipAuthConfig::MutualTls {
                cert_path: PathBuf::from("/cert.pem"),
                key_path: PathBuf::from("/key.pem"),
            }),
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(mtls).is_err());

        let ca_path = HttpPipConfig {
            tls: PipTlsConfig {
                ca_path: Some(PathBuf::from("/ca.pem")),
                ..PipTlsConfig::default()
            },
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(ca_path).is_err());

        let ftp = config_with("ftp://example.com", "/test");
        assert!(HttpPip::new(ftp).is_err());
    }

    #[test]
    fn test_http_pip_rejects_plain_http_without_opt_in() {
        // Even without credentials: a forged plain-text response would inject
        // attributes into access decisions.
        let plain = HttpPipConfig {
            tls: PipTlsConfig::default(),
            ..config_with("http://example.com", "/test")
        };
        assert!(HttpPip::new(plain.clone()).is_err());

        let with_auth = HttpPipConfig {
            auth: Some(PipAuthConfig::Bearer {
                token: "t".to_string(),
            }),
            ..plain.clone()
        };
        assert!(HttpPip::new(with_auth).is_err());

        let insecure = HttpPipConfig {
            tls: PipTlsConfig {
                allow_insecure: true,
                ..PipTlsConfig::default()
            },
            ..plain
        };
        assert!(HttpPip::new(insecure).is_ok());
    }

    #[test]
    fn test_http_pip_rejects_invalid_base_url_and_paths() {
        let userinfo = config_with("https://user:pw@example.com/api", "/test");
        assert!(HttpPip::new(userinfo).is_err());

        let query = config_with("https://example.com/api?x=1", "/test");
        assert!(HttpPip::new(query).is_err());

        let relative = config_with("https://example.com", "users/{username}");
        assert!(HttpPip::new(relative).is_err());

        let health = HttpPipConfig {
            health_check_path: Some("health".to_string()),
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(health).is_err());
    }

    #[test]
    fn test_http_pip_rejects_invalid_headers_timeouts_and_fallback() {
        let mut bad_name = BTreeMap::new();
        bad_name.insert("Bad Header".to_string(), "v".to_string());
        let config = HttpPipConfig {
            headers: bad_name,
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(config).is_err());

        let mut bad_value = BTreeMap::new();
        bad_value.insert("X-Ok".to_string(), "line\r\nbreak".to_string());
        let config = HttpPipConfig {
            headers: bad_value,
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(config).is_err());

        let config = HttpPipConfig {
            auth: Some(PipAuthConfig::ApiKey {
                key_name: "bad key".to_string(),
                key_value: "v".to_string(),
                location: ApiKeyLocation::Header,
            }),
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(config).is_err());

        let config = HttpPipConfig {
            timeout_secs: 0,
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(config).is_err());

        let config = HttpPipConfig {
            health_check: PipHealthCheckConfig {
                failure_threshold: 0,
                ..PipHealthCheckConfig::default()
            },
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(config).is_err());

        // usefallback without values would silently fail open.
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            ..config_with("https://example.com", "/test")
        };
        assert!(HttpPip::new(config).is_err());
    }

    #[test]
    fn test_fallback_behavior_deny() {
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::Deny,
            ..config_with("https://example.com", "/test")
        };
        let pip = HttpPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_fallback_behavior_ignore() {
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::Ignore,
            ..config_with("https://example.com", "/test")
        };
        let pip = HttpPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_health_check_url_without_custom_path() {
        let pip = HttpPip::new(config_with("https://example.com/api", "/test")).unwrap();

        assert!(pip.config.health_check_path.is_none());
    }

    #[test]
    fn test_health_check_url_with_custom_path() {
        let config = create_test_config();
        let pip = HttpPip::new(config).unwrap();

        assert_eq!(pip.config.health_check_path, Some("/health".to_string()));
    }

    #[tokio::test]
    async fn test_retrieve_in_async_context_does_not_panic_and_uses_fallback() {
        // Previously cached_health_status() used blocking_read(), which panics
        // inside a tokio runtime.
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: fallback_department(),
            ..config_with(refused_url().as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();
        assert_eq!(pip.cached_health_status(), PipHealthStatus::Unknown);

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");
        let result = pip.retrieve_attributes(&subject).await;

        assert!(result.fallback_used());
        assert!(matches!(result.failure(), Some(PipFailure::Unavailable(_))));
        assert_eq!(
            result
                .attributes()
                .and_then(|a| a.get(&PipAttributeName::new(&pip.id, "department"))),
            Some(&PipAttributeValue::String("Unknown".to_string()))
        );
        assert_eq!(pip.cached_health_status(), PipHealthStatus::Degraded);
    }

    #[tokio::test]
    async fn test_manager_with_http_pip_deny_fails_closed() {
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::Deny,
            ..config_with(refused_url().as_str(), "/users/{username}")
        };
        let mut manager = PipManager::new();
        manager.register(Arc::new(HttpPip::new(config).unwrap()));

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");
        let err = manager
            .retrieve_all_attributes(&subject)
            .await
            .expect_err("deny must fail closed");
        assert!(matches!(err, PipError::Denied { .. }));
        assert_eq!(
            manager.health_summary().get(&PipId::new("test")),
            Some(&PipHealthStatus::Degraded)
        );
    }

    #[tokio::test]
    async fn test_unhealthy_source_short_circuits_until_interval() {
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::Ignore,
            health_check: PipHealthCheckConfig {
                interval_secs: 3600,
                failure_threshold: 1,
                success_threshold: 1,
                timeout_secs: 5,
            },
            ..config_with(refused_url().as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");

        let first = pip.retrieve_attributes(&subject).await;
        assert!(matches!(first, PipResult::Ignored(_)));
        assert_eq!(pip.cached_health_status(), PipHealthStatus::Unhealthy);

        // Within the retry interval the source is not contacted.
        let second = pip.retrieve_attributes(&subject).await;
        match second.failure() {
            Some(PipFailure::Unavailable(reason)) => assert!(reason.contains("unhealthy")),
            other => panic!("unexpected failure: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_unhealthy_source_recovers_after_interval() {
        let (base, server) = serve(vec![
            http_response("500 Internal Server Error", "{}"),
            http_response("200 OK", r#"{"department":"Engineering"}"#),
        ]);
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::Ignore,
            health_check: PipHealthCheckConfig {
                interval_secs: 0,
                failure_threshold: 1,
                success_threshold: 1,
                timeout_secs: 5,
            },
            ..config_with(base.as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");

        let first = pip.retrieve_attributes(&subject).await;
        assert!(matches!(first, PipResult::Ignored(PipFailure::Error(_))));
        assert_eq!(pip.cached_health_status(), PipHealthStatus::Unhealthy);

        let second = pip.retrieve_attributes(&subject).await;
        assert!(second.is_success());
        assert_eq!(pip.cached_health_status(), PipHealthStatus::Healthy);
        assert_eq!(
            second
                .attributes()
                .and_then(|a| a.get(&PipAttributeName::new(&pip.id, "department"))),
            Some(&PipAttributeValue::String("Engineering".to_string()))
        );

        let lines = server.join().unwrap();
        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn test_request_path_is_percent_encoded_on_the_wire() {
        let (base, server) = serve(vec![http_response("200 OK", r#"{"ok":true}"#)]);
        let pip = HttpPip::new(config_with(base.as_str(), "/users/{username}")).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("a b/../c?x=1");

        let result = pip.retrieve_attributes(&subject).await;
        assert!(result.is_success());
        assert_eq!(pip.cached_health_status(), PipHealthStatus::Healthy);

        let heads = server.join().unwrap();
        assert_eq!(heads.len(), 1);
        assert_eq!(
            heads.first().map(|h| request_line(h)),
            Some("GET /users/a%20b%2F..%2Fc%3Fx%3D1 HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn test_api_key_query_param_not_leaked_in_errors() {
        const KEY: &str = "sup3r-s3cret-k3y";
        let config = HttpPipConfig {
            auth: Some(PipAuthConfig::ApiKey {
                key_name: "api_key".to_string(),
                key_value: KEY.to_string(),
                location: ApiKeyLocation::QueryParam,
            }),
            fallback_behavior: PipFallbackBehavior::Deny,
            health_check_path: Some("/health".to_string()),
            ..config_with(refused_url().as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");

        let result = pip.retrieve_attributes(&subject).await;
        let failure = result.failure().expect("request must fail").to_string();
        assert!(!failure.contains(KEY), "API key leaked: {failure}");
        assert!(!failure.contains("api_key="), "query leaked: {failure}");

        let last_error = pip.health.snapshot().last_error.unwrap_or_default();
        assert!(!last_error.is_empty());
        assert!(!last_error.contains(KEY), "API key leaked: {last_error}");

        let check = pip.health_check().await;
        let message = check.error_message.expect("health check must fail");
        assert!(!message.contains(KEY), "API key leaked: {message}");
    }

    #[tokio::test]
    async fn test_health_check_sends_auth_and_headers() {
        let (base, server) = serve(vec![http_response("200 OK", "{}")]);
        let mut headers = BTreeMap::new();
        headers.insert("X-Tenant".to_string(), "acme".to_string());
        let config = HttpPipConfig {
            auth: Some(PipAuthConfig::Bearer {
                token: "health-token".to_string(),
            }),
            headers,
            health_check_path: Some("/health".to_string()),
            ..config_with(base.as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();

        let check = pip.health_check().await;
        assert!(check.error_message.is_none());
        assert_eq!(check.status, PipHealthStatus::Healthy);

        let heads = server.join().unwrap();
        let head = heads.first().expect("one request").to_ascii_lowercase();
        assert!(head.starts_with("get /health http/1.1"));
        assert!(head.contains("authorization: bearer health-token"));
        assert!(head.contains("x-tenant: acme"));
    }

    #[tokio::test]
    async fn test_client_error_does_not_mark_unhealthy() {
        let (base, server) = serve(vec![http_response("404 Not Found", "{}")]);
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::Ignore,
            health_check: PipHealthCheckConfig {
                failure_threshold: 1,
                ..PipHealthCheckConfig::default()
            },
            ..config_with(base.as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("ghost");

        let result = pip.retrieve_attributes(&subject).await;
        assert!(matches!(result, PipResult::Ignored(PipFailure::Subject(_))));
        assert_eq!(pip.cached_health_status(), PipHealthStatus::Unknown);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn test_usefallback_not_used_for_unknown_subject() {
        // A 404 (unknown account) is not an outage: usefallback must not grant the
        // fallback values, the source just contributes nothing.
        let (base, server) = serve(vec![
            http_response("404 Not Found", "{}"),
            http_response("429 Too Many Requests", "{}"),
            http_response("408 Request Timeout", "{}"),
        ]);
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: fallback_department(),
            ..config_with(base.as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("ghost");

        let result = pip.retrieve_attributes(&subject).await;
        assert!(!result.fallback_used());
        assert!(result.attributes().is_none());
        assert!(matches!(result, PipResult::Ignored(PipFailure::Subject(_))));

        // Nor when the source rate limits or times out the request: a user can cause
        // that, e.g. by flooding requests.
        for _ in 0..2 {
            let result = pip.retrieve_attributes(&subject).await;
            assert!(!result.fallback_used());
            assert!(matches!(result, PipResult::Ignored(PipFailure::Subject(_))));
        }
        server.join().unwrap();

        // Nor when the query can not be built for the subject (no username).
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4());
        let result = pip.retrieve_attributes(&subject).await;
        assert!(matches!(result, PipResult::Ignored(PipFailure::Subject(_))));
    }

    #[tokio::test]
    async fn test_body_over_limit_with_content_length_is_rejected() {
        let body = format!(r#"{{"x":"{}"}}"#, "a".repeat(MAX_RESPONSE_BYTES));
        let (base, server) = serve(vec![http_response("200 OK", &body)]);
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::Deny,
            ..config_with(base.as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");

        let result = pip.retrieve_attributes(&subject).await;
        match result {
            PipResult::Denied(PipFailure::Error(e)) => assert!(e.contains("exceeds")),
            other => panic!("unexpected result: {other:?}"),
        }
        server.join().unwrap();
    }

    #[tokio::test]
    async fn test_body_over_limit_without_content_length_is_rejected() {
        // No Content-Length: the body is streamed until the connection closes.
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                .to_vec();
        response.extend_from_slice(b"{\"x\":\"");
        response.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_BYTES + 1024));
        response.extend_from_slice(b"\"}");
        let (base, server) = serve(vec![response]);
        let config = HttpPipConfig {
            fallback_behavior: PipFallbackBehavior::Deny,
            ..config_with(base.as_str(), "/users/{username}")
        };
        let pip = HttpPip::new(config).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");

        let result = pip.retrieve_attributes(&subject).await;
        match result {
            PipResult::Denied(PipFailure::Error(e)) => assert!(e.contains("exceeds")),
            other => panic!("unexpected result: {other:?}"),
        }
        server.join().unwrap();
    }
}
