//! Prefetching PIP attributes for access decisions.
//!
//! Access decisions are synchronous and run inside a read or write transaction, but PIP
//! sources are remote. The attributes that access control profiles reference through
//! `acp_receiver_pip_condition` are therefore fetched for the request's subject before
//! its transaction, bounded by a short per-request timeout, and attached to the
//! request's [`Identity`] as [`PipPrefetchedAttributes`]. The access engine only reads
//! them.
//!
//! Conditions are stored with a case-insensitive syntax, so attribute names (including
//! the source id) and values are compared in lowercase.
//!
//! Every failure fails closed: an attribute that could not be fetched (source error,
//! `deny` or `ignore` fallback, timeout, unknown source) is simply absent, and a
//! condition on an absent attribute does not match. Other access controls are not
//! affected.

use super::config::{PipConfig, PipFallbackBehavior};
use super::{PipAttributeName, PipAttributeSet, PipAttributeValue, PipManager, PipSubject};
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The PIP attributes prefetched for the subject of one request.
///
/// Values are flattened to strings: integers and booleans use their canonical text,
/// arrays contribute each element, and JSON objects and nulls are dropped. Names and
/// values are lowercased.
///
/// `Debug` only shows the attribute names, as the values are external data about the
/// subject and identities are logged.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PipPrefetchedAttributes {
    /// The entry these attributes were fetched for. An identity only uses them when
    /// this is its own uuid.
    subject: Uuid,
    /// `pip:<source>:<attribute>` to its values, all lowercase.
    attributes: BTreeMap<String, BTreeSet<String>>,
}

impl PipPrefetchedAttributes {
    /// No attributes for `subject`.
    pub fn new(subject: Uuid) -> Self {
        PipPrefetchedAttributes {
            subject,
            attributes: BTreeMap::new(),
        }
    }

    /// Add `value` to the attribute `name` (`pip:<source>:<attribute>`).
    pub fn with_value(mut self, name: &str, value: &str) -> Self {
        self.attributes
            .entry(name.to_lowercase())
            .or_default()
            .insert(value.to_lowercase());
        self
    }

    /// Add the attributes of `set` whose (lowercase) name is in `wanted`.
    fn merge(&mut self, set: &PipAttributeSet, wanted: &BTreeSet<String>) {
        for (name, value) in set.iter() {
            let name = name.as_str().to_lowercase();
            if !wanted.contains(&name) {
                continue;
            }
            let mut values = BTreeSet::new();
            flatten_value(value, &mut values);
            if !values.is_empty() {
                self.attributes
                    .entry(name)
                    .or_default()
                    .extend(values.into_iter().map(|v| v.to_lowercase()));
            }
        }
    }

    pub fn subject(&self) -> Uuid {
        self.subject
    }

    /// The (lowercase) values of the attribute `name` (`pip:<source>:<attribute>`,
    /// matched case-insensitively), if it was fetched.
    pub fn values(&self, name: &str) -> Option<&BTreeSet<String>> {
        self.attributes.get(&name.to_lowercase())
    }

    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }
}

impl std::fmt::Debug for PipPrefetchedAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipPrefetchedAttributes")
            .field("subject", &self.subject)
            .field("attributes", &self.attributes.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn flatten_value(value: &PipAttributeValue, out: &mut BTreeSet<String>) {
    match value {
        PipAttributeValue::String(s) => {
            out.insert(s.clone());
        }
        PipAttributeValue::Integer(i) => {
            out.insert(i.to_string());
        }
        PipAttributeValue::Boolean(b) => {
            out.insert(b.to_string());
        }
        PipAttributeValue::Array(values) => {
            for value in values {
                flatten_value(value, out);
            }
        }
        PipAttributeValue::Json(json) => flatten_json(json, out),
    }
}

fn flatten_json(json: &serde_json::Value, out: &mut BTreeSet<String>) {
    match json {
        serde_json::Value::String(s) => {
            out.insert(s.clone());
        }
        serde_json::Value::Number(n) => {
            out.insert(n.to_string());
        }
        serde_json::Value::Bool(b) => {
            out.insert(b.to_string());
        }
        serde_json::Value::Array(values) => {
            for value in values {
                flatten_json(value, out);
            }
        }
        serde_json::Value::Null | serde_json::Value::Object(_) => {}
    }
}

/// What to prefetch for one request: built inside a transaction (which knows the
/// identity and the loaded access controls), and run after it.
#[derive(Debug, Clone)]
pub struct PipPrefetchRequest {
    subject: PipSubject,
    /// Lowercase `pip:<source>:<attribute>` names, grouped by lowercase source id.
    attributes: BTreeMap<String, BTreeSet<String>>,
}

impl PipPrefetchRequest {
    /// The request for `ident`, or `None` if nothing needs to be prefetched: no
    /// attribute is referenced, or the identity is not an authenticated user or service
    /// account (internal, synchronisation and anonymous identities never get PIP
    /// attributes, so PIP conditions never match them).
    ///
    /// The subject's `username` is the entry's `name` and its `email` is the primary
    /// `mail`, read from the current entry rather than from the session token.
    pub fn for_identity(ident: &Identity, attributes: &BTreeSet<String>) -> Option<Self> {
        if attributes.is_empty() {
            return None;
        }

        let IdentType::User(user) = &ident.origin else {
            return None;
        };
        let entry = &user.entry;
        let uuid = entry.get_uuid();
        if uuid == UUID_ANONYMOUS {
            return None;
        }

        let mut subject = PipSubject::from_uuid(uuid);
        if let Some(name) = entry.get_ava_single_iname(Attribute::Name) {
            subject = subject.with_username(name);
        }
        if let Some(mail) = entry.get_ava_mail_primary(Attribute::Mail) {
            subject = subject.with_email(mail);
        }

        let mut by_source: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for name in attributes {
            let name = name.to_lowercase();
            if let Some((source, _)) = PipAttributeName::parse(&name) {
                by_source
                    .entry(source.as_str().to_string())
                    .or_default()
                    .insert(name);
            }
        }

        if by_source.is_empty() {
            return None;
        }

        Some(PipPrefetchRequest {
            subject,
            attributes: by_source,
        })
    }

    pub fn subject(&self) -> &PipSubject {
        &self.subject
    }
}

/// Prefetches PIP attributes for requests, bounded by a per-request timeout.
pub struct PipPrefetcher {
    manager: Arc<PipManager>,
    timeout: Duration,
}

impl PipPrefetcher {
    pub fn new(manager: Arc<PipManager>, timeout: Duration) -> Self {
        PipPrefetcher { manager, timeout }
    }

    /// Build the prefetcher for `config`, or `None` when the PIP is disabled or has no
    /// sources (no request is then prefetched, and PIP conditions never match).
    pub fn from_config(config: &PipConfig) -> Result<Option<Self>, String> {
        if !config.enabled || config.sources.is_empty() {
            return Ok(None);
        }
        if config.prefetch_timeout_ms == 0 {
            return Err("pip_config: prefetch_timeout_ms must be greater than 0".to_string());
        }
        // A source must give up (and record the failure in its health tracking) before
        // the request stops waiting on it.
        let budget = config.prefetch_timeout();
        if let Some(source) = config.sources.iter().find(|s| s.timeout() > budget) {
            return Err(format!(
                "pip_config: source '{}' has timeout_secs = {}, which exceeds prefetch_timeout_ms = {}; \
                 a source's timeout_secs must not exceed the prefetch budget",
                source.id(),
                source.timeout().as_secs(),
                config.prefetch_timeout_ms
            ));
        }
        let manager = PipManager::from_config(config)?;
        for source in &config.sources {
            if source.fallback_behavior() == PipFallbackBehavior::UseFallback {
                admin_warn!(
                    source = %source.id(),
                    "PIP source uses fallback_behavior = \"usefallback\": while it is unreachable, \
                     failing or timing out, every account is given its fallback_values, which can \
                     grant access (fail open)"
                );
            }
        }
        Ok(Some(PipPrefetcher::new(
            Arc::new(manager),
            config.prefetch_timeout(),
        )))
    }

    pub fn manager(&self) -> &Arc<PipManager> {
        &self.manager
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Fetch the attributes of `request`.
    ///
    /// The sources are queried concurrently, each once, all within the per-request
    /// timeout, and the requested attributes are kept (matching names
    /// case-insensitively). A source that fails (including `deny`, `ignore`, an unknown
    /// source, and running out of time) contributes no attributes; the others still do.
    /// A source cancelled by the timeout has the failure recorded in its health
    /// tracking, so a hanging source becomes unhealthy and is then skipped without
    /// waiting. This never fails: missing attributes make PIP conditions not match.
    pub async fn prefetch(&self, request: &PipPrefetchRequest) -> PipPrefetchedAttributes {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let subject = &request.subject;

        let fetches = request.attributes.iter().filter_map(|(source, names)| {
            // Source ids are unique case-insensitively, see `PipManager::from_config`.
            let Some((pip_id, pip)) = self
                .manager
                .iter()
                .find(|(id, _)| id.as_str().eq_ignore_ascii_case(source))
            else {
                debug!(
                    %source,
                    "PIP condition names a source that is not configured, it does not match"
                );
                return None;
            };
            Some(async move {
                match tokio::time::timeout_at(deadline, pip.retrieve_attributes(subject)).await {
                    Ok(result) => Some((pip_id, result, names)),
                    Err(_) => {
                        pip.record_source_failure(format!(
                            "cancelled by the prefetch timeout of {} ms",
                            self.timeout.as_millis()
                        ));
                        admin_warn!(
                            %source,
                            subject = %subject.uuid,
                            timeout_ms = self.timeout.as_millis() as u64,
                            "PIP prefetch timed out, access controls conditioned on this source do not match"
                        );
                        None
                    }
                }
            })
        });

        let mut prefetched = PipPrefetchedAttributes::new(subject.uuid);
        for (pip_id, result, names) in futures::future::join_all(fetches)
            .await
            .into_iter()
            .flatten()
        {
            let mut set = PipAttributeSet::new();
            // Logs a failing source; `Err` is a source failing with `deny`.
            if PipManager::merge_result(pip_id, result, &mut set).is_ok() {
                prefetched.merge(&set, names);
            }
        }

        prefetched
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::{
        HttpMethod, HttpPipConfig, PipHealthCheckConfig, PipSourceConfig, PipTlsConfig,
    };
    use super::super::{PipHealthStatus, PipId};
    use super::*;
    use std::io::{Read, Write};

    fn http_config(id: &str, base_url: &Url, fallback: PipFallbackBehavior) -> HttpPipConfig {
        HttpPipConfig {
            id: id.to_string(),
            base_url: base_url.clone(),
            endpoint_path: "/users/{username}".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig {
                allow_insecure: true,
                ..PipTlsConfig::default()
            },
            timeout_secs: 1,
            cache_ttl_secs: 60,
            headers: BTreeMap::new(),
            fallback_behavior: fallback,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec!["department".to_string()],
        }
    }

    /// Answer each connection with `body`, `count` times.
    fn serve(body: &'static str, count: usize) -> Url {
        serve_status("200 OK", body, count)
    }

    /// Answer each connection with `status` and `body`, `count` times.
    fn serve_status(status: &'static str, body: &'static str, count: usize) -> Url {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for _ in 0..count {
                let Ok((mut sock, _)) = listener.accept() else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes());
            }
        });
        Url::parse(&format!("http://{addr}")).expect("url")
    }

    fn refused_url() -> Url {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        Url::parse(&format!("http://{addr}")).expect("url")
    }

    fn config(sources: Vec<PipSourceConfig>) -> PipConfig {
        PipConfig {
            sources,
            enabled: true,
            prefetch_timeout_ms: 2000,
        }
    }

    fn request(names: &[&str]) -> PipPrefetchRequest {
        let mut attributes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for name in names {
            let (source, _) = PipAttributeName::parse(name).expect("pip name");
            attributes
                .entry(source.as_str().to_string())
                .or_default()
                .insert(name.to_string());
        }
        PipPrefetchRequest {
            subject: PipSubject::from_uuid(Uuid::new_v4()).with_username("alice"),
            attributes,
        }
    }

    #[test]
    fn test_flatten_values() {
        let pip_id = PipId::new("hr");
        let mut set = PipAttributeSet::new();
        set.insert(
            PipAttributeName::new(&pip_id, "department"),
            PipAttributeValue::String("eng".to_string()),
        );
        set.insert(
            PipAttributeName::new(&pip_id, "level"),
            PipAttributeValue::Integer(5),
        );
        set.insert(
            PipAttributeName::new(&pip_id, "active"),
            PipAttributeValue::Boolean(true),
        );
        set.insert(
            PipAttributeName::new(&pip_id, "groups"),
            PipAttributeValue::Array(vec![
                PipAttributeValue::String("a".to_string()),
                PipAttributeValue::Integer(2),
            ]),
        );
        set.insert(
            PipAttributeName::new(&pip_id, "object"),
            PipAttributeValue::Json(serde_json::json!({"x": 1})),
        );

        let mut prefetched = PipPrefetchedAttributes::new(Uuid::new_v4());
        let wanted = set
            .iter()
            .map(|(name, _)| name.as_str().to_string())
            .collect();
        prefetched.merge(&set, &wanted);

        let values = |name: &str| prefetched.values(name).cloned().unwrap_or_default();
        assert_eq!(values("pip:hr:department"), btreeset!["eng".to_string()]);
        assert_eq!(values("pip:hr:level"), btreeset!["5".to_string()]);
        assert_eq!(values("pip:hr:active"), btreeset!["true".to_string()]);
        assert_eq!(
            values("pip:hr:groups"),
            btreeset!["2".to_string(), "a".to_string()]
        );
        assert!(prefetched.values("pip:hr:object").is_none());

        // Values are never shown by Debug, names are.
        let debug = format!("{prefetched:?}");
        assert!(debug.contains("pip:hr:department"));
        assert!(!debug.contains("eng"));
    }

    #[test]
    fn test_from_config_disabled_or_empty() {
        let mut cfg = config(Vec::new());
        assert!(matches!(PipPrefetcher::from_config(&cfg), Ok(None)));

        let url = Url::parse("https://hr.example.com").expect("url");
        cfg.sources = vec![PipSourceConfig::Http(http_config(
            "hr",
            &url,
            PipFallbackBehavior::Deny,
        ))];
        cfg.enabled = false;
        assert!(matches!(PipPrefetcher::from_config(&cfg), Ok(None)));

        cfg.enabled = true;
        let prefetcher = PipPrefetcher::from_config(&cfg)
            .expect("valid config")
            .expect("enabled");
        assert_eq!(prefetcher.timeout(), Duration::from_millis(2000));
        assert!(prefetcher.manager().get(&PipId::new("hr")).is_some());
    }

    #[test]
    fn test_from_config_rejects_invalid() {
        let url = Url::parse("https://hr.example.com").expect("url");
        let source = PipSourceConfig::Http(http_config("hr", &url, PipFallbackBehavior::Deny));

        // Duplicate ids, also when they only differ in case.
        let cfg = config(vec![source.clone(), source.clone()]);
        assert!(PipPrefetcher::from_config(&cfg).is_err());
        let cfg = config(vec![
            source.clone(),
            PipSourceConfig::Http(http_config("HR", &url, PipFallbackBehavior::Deny)),
        ]);
        assert!(PipPrefetcher::from_config(&cfg).is_err());

        // An id that can not be used in a `pip:<source>:<attribute>` name.
        let cfg = config(vec![PipSourceConfig::Http(http_config(
            "hr:x",
            &url,
            PipFallbackBehavior::Deny,
        ))]);
        assert!(PipPrefetcher::from_config(&cfg).is_err());

        // A source timeout above the prefetch budget: the request would stop waiting
        // before the source records a failure.
        let mut cfg = config(vec![source.clone()]);
        cfg.prefetch_timeout_ms = 999;
        let err = PipPrefetcher::from_config(&cfg).err().unwrap_or_default();
        assert!(err.contains("exceeds prefetch_timeout_ms"), "{err}");

        // A zero timeout.
        let mut cfg = config(vec![source]);
        cfg.prefetch_timeout_ms = 0;
        assert!(PipPrefetcher::from_config(&cfg).is_err());
    }

    #[tokio::test]
    async fn test_prefetch_success_and_failures_are_per_source() {
        let up = serve(r#"{"Department": "Eng", "unrelated": "x"}"#, 1);
        let down = refused_url();
        let cfg = config(vec![
            // Source ids, attribute names and values are matched case-insensitively.
            PipSourceConfig::Http(http_config("HR", &up, PipFallbackBehavior::Deny)),
            PipSourceConfig::Http(http_config("crm", &down, PipFallbackBehavior::Deny)),
        ]);
        let prefetcher = PipPrefetcher::from_config(&cfg)
            .expect("valid config")
            .expect("enabled");

        let req = request(&[
            "pip:hr:department",
            "pip:crm:department",
            "pip:unknown:department",
        ]);
        let prefetched = prefetcher.prefetch(&req).await;

        assert_eq!(prefetched.subject(), req.subject().uuid);
        assert_eq!(
            prefetched.values("pip:hr:department"),
            Some(&btreeset!["eng".to_string()])
        );
        // Only the requested attributes are kept.
        assert!(prefetched.values("pip:hr:unrelated").is_none());
        // The failing (deny) and the unknown source contribute nothing.
        assert!(prefetched.values("pip:crm:department").is_none());
        assert!(prefetched.values("pip:unknown:department").is_none());
    }

    #[tokio::test]
    async fn test_prefetch_usefallback_only_on_source_failure() {
        let fallback = || {
            let mut values = BTreeMap::new();
            values.insert(
                "department".to_string(),
                PipAttributeValue::String("Fallback".to_string()),
            );
            values
        };
        let down = refused_url();
        let unknown = serve_status("404 Not Found", "{}", 1);
        let mut down_cfg = http_config("down", &down, PipFallbackBehavior::UseFallback);
        down_cfg.fallback_values = fallback();
        let mut unknown_cfg = http_config("unknown", &unknown, PipFallbackBehavior::UseFallback);
        unknown_cfg.fallback_values = fallback();
        let cfg = config(vec![
            PipSourceConfig::Http(down_cfg),
            PipSourceConfig::Http(unknown_cfg),
        ]);
        let prefetcher = PipPrefetcher::from_config(&cfg)
            .expect("valid config")
            .expect("enabled");

        let prefetched = prefetcher
            .prefetch(&request(&["pip:down:department", "pip:unknown:department"]))
            .await;
        // An unreachable source uses its fallback values (fail open, as configured).
        assert_eq!(
            prefetched.values("pip:down:department"),
            Some(&btreeset!["fallback".to_string()])
        );
        // A source that does not know the account is not down: no fallback values.
        assert!(prefetched.values("pip:unknown:department").is_none());
    }

    #[tokio::test]
    async fn test_prefetch_timeout_trips_breaker_and_does_not_starve_other_sources() {
        // A source that accepts but never answers. Its name sorts first, so a serial
        // prefetch would spend the whole budget on it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hung = Url::parse(&format!("http://{addr}")).expect("url");
        // Answers once; the result is then cached.
        let up = serve(r#"{"department": "Eng"}"#, 1);

        let mut hung_cfg = http_config("aslow", &hung, PipFallbackBehavior::Deny);
        hung_cfg.health_check = PipHealthCheckConfig {
            interval_secs: 300,
            failure_threshold: 2,
            ..PipHealthCheckConfig::default()
        };
        let mut cfg = config(vec![
            PipSourceConfig::Http(hung_cfg),
            PipSourceConfig::Http(http_config("hr", &up, PipFallbackBehavior::Deny)),
        ]);
        cfg.prefetch_timeout_ms = 1000;
        let prefetcher = PipPrefetcher::from_config(&cfg)
            .expect("valid config")
            .expect("enabled");
        let req = request(&["pip:aslow:department", "pip:hr:department"]);
        let hung_status = || {
            prefetcher
                .manager()
                .get(&PipId::new("aslow"))
                .map(|pip| pip.cached_health_status())
        };

        for _ in 0..2 {
            let prefetched = prefetcher.prefetch(&req).await;
            assert!(prefetched.values("pip:aslow:department").is_none());
            // The other source is queried concurrently and still answers in time.
            assert_eq!(
                prefetched.values("pip:hr:department"),
                Some(&btreeset!["eng".to_string()])
            );
        }
        // Each cancelled call counted as a failure: the breaker is open.
        assert_eq!(hung_status(), Some(PipHealthStatus::Unhealthy));

        // Later requests do not wait on the hung source.
        let started = std::time::Instant::now();
        let prefetched = prefetcher.prefetch(&req).await;
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(prefetched.values("pip:aslow:department").is_none());
        assert!(prefetched.values("pip:hr:department").is_some());
        drop(listener);
    }
}
