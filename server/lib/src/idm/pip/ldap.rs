//! LDAP Policy Information Point Implementation
//!
//! This module provides a PIP implementation that retrieves attributes from
//! LDAP servers.

#![allow(dead_code)]

use async_trait::async_trait;
use ldap3_client::{
    proto::{LdapFilter, LdapMatchingRuleAssertion, LdapSearchScope, LdapSubstringFilter},
    LdapClient, LdapClientBuilder, LdapEntry,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use super::cache::PipAttributeCache;
use super::config::{validate_common, validate_no_userinfo, LdapPipConfig};
use super::health::PipHealthTracker;
use super::{
    render_template, PipAttributeName, PipAttributeSet, PipAttributeValue, PipFailure,
    PipHealthCheck, PipHealthStatus, PipId, PipResult, PipSubject, PolicyInformationPoint,
};
use crate::prelude::*;

/// LDAP PIP implementation
pub struct LdapPip {
    id: PipId,
    config: LdapPipConfig,
    /// `search_filter` parsed once at construction; placeholders are substituted
    /// into its assertion values per query.
    filter_template: LdapFilter,
    cache: Arc<RwLock<PipAttributeCache>>,
    health: PipHealthTracker,
    provided_attributes: Vec<String>,
    attribute_mapping: BTreeMap<String, String>,
}

impl LdapPip {
    /// Create a new LDAP PIP from configuration.
    ///
    /// Fails if the URL is not `ldaps://` (or `ldap://` with
    /// `tls.allow_insecure`), embeds credentials, if a custom CA path is set
    /// (not supported yet), if timeouts/thresholds are zero, if `usefallback`
    /// has no fallback values, or if `search_filter` does not parse.
    pub fn new(config: LdapPipConfig) -> Result<Self, String> {
        match config.url.scheme() {
            "ldaps" => {}
            // Plain-text answers could be forged by a network attacker, and the
            // attributes feed access decisions.
            "ldap" if !config.tls.allow_insecure => {
                return Err(format!(
                    "LDAP PIP '{}': refusing plain-text ldap:// (use ldaps://, or set \
                     tls.allow_insecure for development)",
                    config.id
                ));
            }
            "ldap" => {}
            other => {
                return Err(format!(
                    "LDAP PIP '{}': unsupported URL scheme '{other}'",
                    config.id
                ));
            }
        }

        validate_no_userinfo(&config.id, &config.url)?;

        if config.tls.ca_path.is_some() {
            return Err(format!(
                "LDAP PIP '{}': tls.ca_path is not supported yet",
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

        let filter_template = parse_ldap_filter(&config.search_filter)
            .map_err(|e| format!("LDAP PIP '{}': invalid search_filter: {e}", config.id))?;

        let cache = Arc::new(RwLock::new(PipAttributeCache::with_settings(
            Duration::from_secs(config.cache_ttl_secs),
            1000,
        )));

        let provided_attributes = if config.attributes.is_empty() {
            config.attribute_mapping.keys().cloned().collect()
        } else {
            config.attributes.clone()
        };

        let attribute_mapping = config.attribute_mapping.clone();

        Ok(LdapPip {
            id: PipId::new(&config.id),
            config,
            filter_template,
            cache,
            health: PipHealthTracker::new(),
            provided_attributes,
            attribute_mapping,
        })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_secs)
    }

    /// Build LDAP client with configuration.
    ///
    /// `LdapClientBuilder::build` resolves the host name with the blocking std
    /// resolver, so it runs on the blocking thread pool rather than stalling a
    /// runtime worker; the caller's timeout then covers DNS as well. The
    /// blocking task has its own (slightly longer) deadline so it can never
    /// outlive an abandoned request by much, e.g. on a hung TLS handshake.
    async fn build_client(&self) -> Result<LdapClient, String> {
        let builder = LdapClientBuilder::new(self.config.url.clone()).set_timeout(self.timeout());

        let builder = if !self.config.tls.verify_server || self.config.tls.allow_insecure {
            admin_warn!(
                "LDAP PIP '{}' does not verify TLS server certificates (verify_server = false or allow_insecure = true) - this should only be used for development!",
                self.config.id
            );
            builder.danger_accept_invalid_certs()
        } else {
            builder
        };

        let handle = tokio::runtime::Handle::current();
        let deadline = self.timeout().saturating_add(Duration::from_secs(1));
        tokio::task::spawn_blocking(move || {
            handle.block_on(async move { tokio::time::timeout(deadline, builder.build()).await })
        })
        .await
        .map_err(|e| format!("LDAP connect task failed: {e}"))?
        .map_err(|_| "LDAP connect timed out".to_string())?
        .map_err(|e| format!("Failed to create LDAP client: {:?}", e))
    }

    /// Build the search filter for `subject`.
    ///
    /// Subject values are substituted into the assertion values of the already
    /// parsed filter, never into the filter string, so a value such as
    /// `*)(uid=*` is matched literally and cannot alter the filter structure.
    fn build_search_filter(&self, subject: &PipSubject) -> Result<LdapFilter, String> {
        substitute_filter(&self.filter_template, subject)
    }

    /// Connect, bind and search, all bounded by a single `timeout_secs` deadline.
    async fn query(&self, filter: LdapFilter) -> Result<Vec<LdapEntry>, PipFailure> {
        let operation = async {
            let mut client = self.build_client().await.map_err(PipFailure::Unavailable)?;

            client
                .bind(
                    self.config.bind_dn.clone(),
                    self.config.bind_password.clone(),
                )
                .await
                .map_err(|e| PipFailure::Error(format!("LDAP bind failed: {e:?}")))?;

            client
                .search(self.config.base_dn.clone(), filter)
                .scope(LdapSearchScope::Subtree)
                .attrs(self.config.attributes.clone())
                .send()
                .await
                .map(|result| result.entries)
                .map_err(|e| PipFailure::Error(format!("LDAP search failed: {e:?}")))
        };

        tokio::time::timeout(self.timeout(), operation)
            .await
            .map_err(|_| PipFailure::Timeout)?
    }

    /// Turn search results into attributes: exactly one entry must match.
    fn entries_to_attributes(&self, entries: &[LdapEntry]) -> Result<PipAttributeSet, PipFailure> {
        match entries {
            [] => Err(PipFailure::Subject(
                "No LDAP entries found for subject".to_string(),
            )),
            [entry] => Ok(self.parse_ldap_entry(entry)),
            _ => Err(PipFailure::Subject(format!(
                "LDAP search matched {} entries for subject, expected exactly one",
                entries.len()
            ))),
        }
    }

    /// Parse LDAP entry attributes into PipAttributeSet
    fn parse_ldap_entry(&self, entry: &LdapEntry) -> PipAttributeSet {
        let mut attrs = PipAttributeSet::new();

        for (ldap_attr_name, values) in &entry.attrs {
            let pip_attr_name = self
                .attribute_mapping
                .get(ldap_attr_name)
                .cloned()
                .unwrap_or_else(|| ldap_attr_name.clone());

            let full_attr_name = PipAttributeName::new(&self.id, &pip_attr_name);

            if values.len() == 1 {
                if let Some(value) = values.iter().next() {
                    attrs.insert(full_attr_name, PipAttributeValue::String(value.clone()));
                }
            } else if values.len() > 1 {
                let pip_values: Vec<PipAttributeValue> = values
                    .iter()
                    .map(|value| PipAttributeValue::String(value.clone()))
                    .collect();
                attrs.insert(full_attr_name, PipAttributeValue::Array(pip_values));
            }
        }

        attrs
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
}

#[async_trait]
impl PolicyInformationPoint for LdapPip {
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

        let filter = match self.build_search_filter(subject) {
            Ok(filter) => filter,
            Err(e) => return self.on_failure(PipFailure::Subject(e)),
        };

        if !self.health.try_begin_attempt(&self.config.health_check) {
            return self.on_failure(PipFailure::Unavailable(
                "LDAP PIP source is unhealthy, waiting for the retry interval".to_string(),
            ));
        }

        let entries = match self.query(filter).await {
            Ok(entries) => entries,
            Err(failure) => {
                self.health
                    .record_failure(&self.config.health_check, failure.to_string());
                return self.on_failure(failure);
            }
        };

        // The server answered: the source is healthy even if the result is not
        // usable for this subject.
        self.health.record_success(&self.config.health_check);

        match self.entries_to_attributes(&entries) {
            Ok(attrs) => {
                {
                    let mut cache = self.cache.write().await;
                    cache.put(&self.id, subject, attrs.clone());
                }
                PipResult::Success(attrs)
            }
            Err(failure) => self.on_failure(failure),
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

        let operation = async {
            let mut client = self.build_client().await?;
            client
                .bind(
                    self.config.bind_dn.clone(),
                    self.config.bind_password.clone(),
                )
                .await
                .map_err(|e| format!("LDAP health check bind failed: {e:?}"))
        };

        let result = tokio::time::timeout(
            Duration::from_secs(self.config.health_check.timeout_secs),
            operation,
        )
        .await
        .unwrap_or_else(|_| Err("LDAP health check timed out".to_string()));

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
}

/// Parse LDAP filter string into LdapFilter
fn parse_ldap_filter(filter_str: &str) -> Result<LdapFilter, String> {
    ldap3_proto::filter::parse_ldap_filter_str(filter_str)
        .map_err(|e| format!("Failed to parse filter '{}': {:?}", filter_str, e))
}

/// Escape a value for use inside a DN attribute value, per RFC 4514 section 2.4.
fn escape_dn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (idx, c) in value.char_indices() {
        let first = idx == 0;
        let last = idx + c.len_utf8() == value.len();
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=' => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push_str("\\00"),
            '#' if first => out.push_str("\\#"),
            ' ' if first || last => out.push_str("\\ "),
            _ => out.push(c),
        }
    }
    out
}

/// Encode a subject value for one assertion value of the filter template.
///
/// Assertion values are sent as BER octets, not as a filter string, so no RFC
/// 4515 escaping is needed: `*`, `(`, `)`, `\` and NUL are matched literally.
/// But when the template value is itself a DN (it contains `=`, e.g.
/// `(member="uid={username},ou=people,dc=example,dc=com")`), the server parses
/// it as a DN, so the value is RFC 4514 escaped to keep `x,ou=admins` from
/// changing which DN is matched.
fn render_assertion_value(template: &str, subject: &PipSubject) -> Result<String, String> {
    if template.contains('=') {
        render_template(template, subject, |raw| Ok(escape_dn_value(raw)))
    } else {
        render_template(template, subject, |raw| Ok(raw.to_string()))
    }
}

/// Substitute subject values into the assertion values of a parsed filter.
///
/// Values are inserted into the parsed structure (see
/// [`render_assertion_value`]); attribute names and the filter structure come
/// only from the configured template.
fn substitute_filter(filter: &LdapFilter, subject: &PipSubject) -> Result<LdapFilter, String> {
    let value = |v: &str| render_assertion_value(v, subject);
    let all = |filters: &[LdapFilter]| {
        filters
            .iter()
            .map(|f| substitute_filter(f, subject))
            .collect::<Result<Vec<_>, _>>()
    };

    Ok(match filter {
        LdapFilter::And(filters) => LdapFilter::And(all(filters)?),
        LdapFilter::Or(filters) => LdapFilter::Or(all(filters)?),
        LdapFilter::Not(inner) => LdapFilter::Not(Box::new(substitute_filter(inner, subject)?)),
        LdapFilter::Equality(attr, v) => LdapFilter::Equality(attr.clone(), value(v)?),
        LdapFilter::GreaterOrEqual(attr, v) => LdapFilter::GreaterOrEqual(attr.clone(), value(v)?),
        LdapFilter::LessOrEqual(attr, v) => LdapFilter::LessOrEqual(attr.clone(), value(v)?),
        LdapFilter::Approx(attr, v) => LdapFilter::Approx(attr.clone(), value(v)?),
        LdapFilter::Present(attr) => LdapFilter::Present(attr.clone()),
        LdapFilter::Substring(attr, sub) => LdapFilter::Substring(
            attr.clone(),
            LdapSubstringFilter {
                initial: sub.initial.as_deref().map(value).transpose()?,
                any: sub
                    .any
                    .iter()
                    .map(|v| value(v))
                    .collect::<Result<Vec<_>, _>>()?,
                final_: sub.final_.as_deref().map(value).transpose()?,
            },
        ),
        LdapFilter::Extensible(rule) => LdapFilter::Extensible(LdapMatchingRuleAssertion {
            match_value: value(&rule.match_value)?,
            ..rule.clone()
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::super::config::{PipFallbackBehavior, PipHealthCheckConfig, PipTlsConfig};
    use super::super::{PipError, PipManager};
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use url::Url;

    fn create_test_config() -> LdapPipConfig {
        LdapPipConfig {
            id: "test_ldap_pip".to_string(),
            url: Url::parse("ldaps://localhost:636").unwrap(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin,dc=example,dc=com".to_string(),
            bind_password: "secret".to_string(),
            search_filter: "(uid={username})".to_string(),
            attributes: vec!["department".to_string(), "manager".to_string()],
            tls: PipTlsConfig::default(),
            timeout_secs: 30,
            cache_ttl_secs: 60,
            fallback_behavior: PipFallbackBehavior::Deny,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            attribute_mapping: BTreeMap::new(),
        }
    }

    fn config_with_filter(search_filter: &str) -> LdapPipConfig {
        LdapPipConfig {
            id: "test".to_string(),
            search_filter: search_filter.to_string(),
            attributes: vec!["cn".to_string()],
            ..create_test_config()
        }
    }

    fn entry(dn: &str, attrs: &[(&str, &[&str])]) -> LdapEntry {
        LdapEntry {
            dn: dn.to_string(),
            attrs: attrs
                .iter()
                .map(|(name, values)| {
                    (
                        name.to_string(),
                        values
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<BTreeSet<_>>(),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn test_ldap_pip_creation() {
        let config = create_test_config();
        let pip = LdapPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_search_filter_building_with_username() {
        let config = create_test_config();
        let pip = LdapPip::new(config).unwrap();

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("testuser");

        let filter = pip.build_search_filter(&subject).unwrap();
        assert_eq!(
            filter,
            LdapFilter::Equality("uid".to_string(), "testuser".to_string())
        );
    }

    #[test]
    fn test_search_filter_building_with_uuid() {
        let pip = LdapPip::new(config_with_filter("(entryUUID={uuid})")).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let subject = PipSubject::from_uuid(uuid);

        let filter = pip.build_search_filter(&subject).unwrap();
        assert_eq!(
            filter,
            LdapFilter::Equality("entryUUID".to_string(), uuid.to_string())
        );
    }

    #[test]
    fn test_search_filter_building_with_email() {
        let pip = LdapPip::new(config_with_filter("(mail={email})")).unwrap();

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_email("test@example.com");

        let filter = pip.build_search_filter(&subject).unwrap();
        assert_eq!(
            filter,
            LdapFilter::Equality("mail".to_string(), "test@example.com".to_string())
        );
    }

    #[test]
    fn test_search_filter_building_with_context() {
        let pip = LdapPip::new(config_with_filter("(&(uid={username})(ou={department}))")).unwrap();

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4())
            .with_username("testuser")
            .with_context("department", "Engineering");

        let filter = pip.build_search_filter(&subject).unwrap();
        assert_eq!(
            filter,
            LdapFilter::And(vec![
                LdapFilter::Equality("uid".to_string(), "testuser".to_string()),
                LdapFilter::Equality("ou".to_string(), "Engineering".to_string()),
            ])
        );
    }

    #[test]
    fn test_search_filter_injection_is_literal() {
        let pip = LdapPip::new(create_test_config()).unwrap();

        // Classic injection payloads must stay a single equality assertion whose
        // value is matched literally (RFC 4515 metacharacters included).
        for payload in ["*", "*)(uid=*", "admin)(|(objectClass=*", "a\\2a\0b"] {
            let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username(payload);
            let filter = pip.build_search_filter(&subject).unwrap();
            assert_eq!(
                filter,
                LdapFilter::Equality("uid".to_string(), payload.to_string()),
                "payload {payload:?} altered the filter"
            );
        }
    }

    #[test]
    fn test_search_filter_substring_and_extensible_substitution() {
        let pip = LdapPip::new(config_with_filter(
            "(|(cn={username}*)(cn=*{username}*{email})(cn:caseExactMatch:={username}))",
        ))
        .unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4())
            .with_username("a*b")
            .with_email("e");

        let LdapFilter::Or(filters) = pip.build_search_filter(&subject).unwrap() else {
            panic!("expected an OR filter");
        };
        assert_eq!(
            filters.first(),
            Some(&LdapFilter::Substring(
                "cn".to_string(),
                LdapSubstringFilter {
                    initial: Some("a*b".to_string()),
                    any: vec![],
                    final_: None,
                }
            ))
        );
        assert_eq!(
            filters.get(1),
            Some(&LdapFilter::Substring(
                "cn".to_string(),
                LdapSubstringFilter {
                    initial: None,
                    any: vec!["a*b".to_string()],
                    final_: Some("e".to_string()),
                }
            ))
        );
        match filters.get(2) {
            Some(LdapFilter::Extensible(rule)) => assert_eq!(rule.match_value, "a*b"),
            other => panic!("unexpected filter: {other:?}"),
        }
    }

    #[test]
    fn test_search_filter_missing_value_is_error() {
        let pip = LdapPip::new(create_test_config()).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4());
        assert!(pip.build_search_filter(&subject).is_err());
    }

    #[test]
    fn test_search_filter_empty_value_is_error() {
        // An empty value would turn (cn={username}*) into a match-everything
        // substring filter.
        let pip = LdapPip::new(config_with_filter("(cn={username}*)")).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("");
        assert!(pip.build_search_filter(&subject).is_err());
    }

    #[test]
    fn test_search_filter_dn_value_is_rfc4514_escaped() {
        let pip = LdapPip::new(config_with_filter(
            "(member=\"uid={username},ou=people,dc=example,dc=com\")",
        ))
        .unwrap();

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("x,ou=admins");
        assert_eq!(
            pip.build_search_filter(&subject).unwrap(),
            LdapFilter::Equality(
                "member".to_string(),
                "uid=x\\,ou\\=admins,ou=people,dc=example,dc=com".to_string()
            )
        );

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");
        assert_eq!(
            pip.build_search_filter(&subject).unwrap(),
            LdapFilter::Equality(
                "member".to_string(),
                "uid=alice,ou=people,dc=example,dc=com".to_string()
            )
        );
    }

    #[test]
    fn test_escape_dn_value() {
        assert_eq!(escape_dn_value("alice"), "alice");
        assert_eq!(
            escape_dn_value("a,b+c\"d\\e<f>g;h=i"),
            "a\\,b\\+c\\\"d\\\\e\\<f\\>g\\;h\\=i"
        );
        assert_eq!(escape_dn_value("#lead"), "\\#lead");
        assert_eq!(escape_dn_value("mid#dle"), "mid#dle");
        assert_eq!(escape_dn_value(" both "), "\\ both\\ ");
        assert_eq!(escape_dn_value("in side"), "in side");
        assert_eq!(escape_dn_value("nul\0"), "nul\\00");
        assert_eq!(escape_dn_value("é,"), "é\\,");
    }

    #[test]
    fn test_invalid_search_filter_rejected_at_construction() {
        assert!(LdapPip::new(config_with_filter("(uid={username}")).is_err());
    }

    #[test]
    fn test_entries_to_attributes_requires_exactly_one_entry() {
        let pip = LdapPip::new(create_test_config()).unwrap();

        let none = pip.entries_to_attributes(&[]);
        assert!(matches!(none, Err(PipFailure::Subject(_))));

        let one = pip
            .entries_to_attributes(&[entry(
                "uid=a,dc=example,dc=com",
                &[("department", &["Eng"])],
            )])
            .unwrap();
        assert_eq!(
            one.get(&PipAttributeName::new(&pip.id, "department")),
            Some(&PipAttributeValue::String("Eng".to_string()))
        );

        let many = pip.entries_to_attributes(&[
            entry("uid=a,dc=example,dc=com", &[("department", &["Eng"])]),
            entry("uid=b,dc=example,dc=com", &[("department", &["Sales"])]),
        ]);
        match many {
            Err(PipFailure::Subject(e)) => assert!(e.contains("matched 2 entries")),
            other => panic!("multiple matches must be an error, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_ldap_entry_multi_valued_and_mapping() {
        let mut mapping = BTreeMap::new();
        mapping.insert("cn".to_string(), "full_name".to_string());
        let config = LdapPipConfig {
            attribute_mapping: mapping,
            ..config_with_filter("(uid={username})")
        };
        let pip = LdapPip::new(config).unwrap();

        let attrs = pip.parse_ldap_entry(&entry(
            "uid=a,dc=example,dc=com",
            &[("cn", &["Alice"]), ("memberOf", &["g1", "g2"])],
        ));
        assert_eq!(
            attrs.get(&PipAttributeName::new(&pip.id, "full_name")),
            Some(&PipAttributeValue::String("Alice".to_string()))
        );
        assert_eq!(
            attrs
                .get(&PipAttributeName::new(&pip.id, "memberOf"))
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(2)
        );
    }

    #[test]
    fn test_provided_attributes() {
        let config = create_test_config();
        let pip = LdapPip::new(config).unwrap();

        assert_eq!(pip.provided_attributes().len(), 2);
        assert!(pip
            .provided_attributes()
            .contains(&"department".to_string()));
    }

    #[test]
    fn test_provided_attributes_from_mapping() {
        let mut mapping = BTreeMap::new();
        mapping.insert("cn".to_string(), "common_name".to_string());
        mapping.insert("uid".to_string(), "username".to_string());

        let config = LdapPipConfig {
            attributes: vec![],
            attribute_mapping: mapping,
            ..config_with_filter("(uid={username})")
        };
        let pip = LdapPip::new(config).unwrap();

        assert_eq!(pip.provided_attributes().len(), 2);
    }

    #[test]
    fn test_pip_id() {
        let config = create_test_config();
        let pip = LdapPip::new(config).unwrap();

        assert_eq!(pip.id().as_str(), "test_ldap_pip");
    }

    #[test]
    fn test_cached_health_status_initial() {
        let config = create_test_config();
        let pip = LdapPip::new(config).unwrap();

        let status = pip.cached_health_status();
        assert_eq!(status, PipHealthStatus::Unknown);
    }

    #[test]
    fn test_apply_fallback_empty() {
        let config = create_test_config();
        let pip = LdapPip::new(config).unwrap();

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

        let config = LdapPipConfig {
            fallback_values: fallback,
            ..config_with_filter("(uid={username})")
        };
        let pip = LdapPip::new(config).unwrap();

        let attrs = pip.apply_fallback();
        assert_eq!(attrs.len(), 1);
    }

    #[test]
    fn test_parse_ldap_filter_simple() {
        let result = parse_ldap_filter("(uid=testuser)");
        assert!(result.is_ok());

        let result = parse_ldap_filter("(objectClass=person)");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ldap_filter_complex() {
        let result = parse_ldap_filter("(&(objectClass=person)(uid=testuser))");
        assert!(result.is_ok());

        let result = parse_ldap_filter("(|(uid=user1)(uid=user2))");
        assert!(result.is_ok());

        let result = parse_ldap_filter("(!(status=inactive))");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ldap_filter_nested() {
        let result = parse_ldap_filter("(&(objectClass=person)(|(uid=user1)(uid=user2)))");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ldap_filter_invalid() {
        let result = parse_ldap_filter("invalid filter");
        assert!(result.is_err());

        let result = parse_ldap_filter("(unclosed");
        assert!(result.is_err());
    }

    #[test]
    fn test_ldap_pip_with_ldaps() {
        let config = LdapPipConfig {
            url: Url::parse("ldaps://ldap.example.com:636").unwrap(),
            ..config_with_filter("(uid={username})")
        };
        let pip = LdapPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_ldap_pip_rejects_plain_ldap_without_opt_in() {
        let plain = LdapPipConfig {
            url: Url::parse("ldap://localhost:389").unwrap(),
            ..create_test_config()
        };
        assert!(LdapPip::new(plain.clone()).is_err());

        // Even an anonymous bind: forged answers would inject attributes.
        let anonymous = LdapPipConfig {
            bind_dn: String::new(),
            bind_password: String::new(),
            ..plain.clone()
        };
        assert!(LdapPip::new(anonymous).is_err());

        // Explicit development opt-in.
        let insecure = LdapPipConfig {
            tls: PipTlsConfig {
                allow_insecure: true,
                ..PipTlsConfig::default()
            },
            ..plain
        };
        assert!(LdapPip::new(insecure).is_ok());
    }

    #[test]
    fn test_ldap_pip_rejects_unsupported_config() {
        let bad_scheme = LdapPipConfig {
            url: Url::parse("https://ldap.example.com").unwrap(),
            ..create_test_config()
        };
        assert!(LdapPip::new(bad_scheme).is_err());

        let userinfo = LdapPipConfig {
            url: Url::parse("ldaps://admin:pw@ldap.example.com").unwrap(),
            ..create_test_config()
        };
        assert!(LdapPip::new(userinfo).is_err());

        let zero_timeout = LdapPipConfig {
            timeout_secs: 0,
            ..create_test_config()
        };
        assert!(LdapPip::new(zero_timeout).is_err());

        let empty_fallback = LdapPipConfig {
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: BTreeMap::new(),
            ..create_test_config()
        };
        assert!(LdapPip::new(empty_fallback).is_err());

        let ca_path = LdapPipConfig {
            tls: PipTlsConfig {
                ca_path: Some(PathBuf::from("/ca.pem")),
                ..PipTlsConfig::default()
            },
            ..create_test_config()
        };
        assert!(LdapPip::new(ca_path).is_err());
    }

    #[test]
    fn test_ldap_pip_with_insecure_tls() {
        let config = LdapPipConfig {
            url: Url::parse("ldaps://ldap.example.com:636").unwrap(),
            tls: PipTlsConfig {
                ca_path: None,
                verify_server: false,
                allow_insecure: true,
            },
            ..config_with_filter("(uid={username})")
        };
        let pip = LdapPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_fallback_behavior_deny() {
        let config = LdapPipConfig {
            fallback_behavior: PipFallbackBehavior::Deny,
            ..config_with_filter("(uid={username})")
        };
        let pip = LdapPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_fallback_behavior_ignore() {
        let config = LdapPipConfig {
            fallback_behavior: PipFallbackBehavior::Ignore,
            ..config_with_filter("(uid={username})")
        };
        let pip = LdapPip::new(config);
        assert!(pip.is_ok());
    }

    #[test]
    fn test_attribute_mapping() {
        let mut mapping = BTreeMap::new();
        mapping.insert("cn".to_string(), "full_name".to_string());

        let config = LdapPipConfig {
            attribute_mapping: mapping,
            ..config_with_filter("(uid={username})")
        };
        let pip = LdapPip::new(config).unwrap();

        assert_eq!(
            pip.attribute_mapping.get("cn"),
            Some(&"full_name".to_string())
        );
    }

    /// An `ldaps://` address on which nothing listens.
    fn refused_url() -> Url {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        Url::parse(&format!("ldaps://{addr}")).unwrap()
    }

    #[tokio::test]
    async fn test_retrieve_in_async_context_uses_fallback_values() {
        let mut fallback = BTreeMap::new();
        fallback.insert(
            "department".to_string(),
            PipAttributeValue::String("Unknown".to_string()),
        );
        let config = LdapPipConfig {
            url: refused_url(),
            fallback_behavior: PipFallbackBehavior::UseFallback,
            fallback_values: fallback,
            ..create_test_config()
        };
        let pip = LdapPip::new(config).unwrap();
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
    async fn test_manager_with_ldap_pip_deny_fails_closed() {
        let config = LdapPipConfig {
            url: refused_url(),
            fallback_behavior: PipFallbackBehavior::Deny,
            ..create_test_config()
        };
        let mut manager = PipManager::new();
        manager.register(Arc::new(LdapPip::new(config).unwrap()));

        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");
        let err = manager
            .retrieve_named_attributes(&subject, &["pip:test_ldap_pip:department".to_string()])
            .await
            .expect_err("deny must fail closed");
        assert!(matches!(err, PipError::Denied { .. }));
    }

    #[tokio::test]
    async fn test_timeout_is_enforced() {
        // Accepts the TCP connection but never completes the TLS handshake.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hold = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        });

        let config = LdapPipConfig {
            url: Url::parse(&format!("ldaps://{addr}")).unwrap(),
            timeout_secs: 1,
            fallback_behavior: PipFallbackBehavior::Ignore,
            ..create_test_config()
        };
        let pip = LdapPip::new(config).unwrap();
        let subject = PipSubject::from_uuid(uuid::Uuid::new_v4()).with_username("alice");

        let start = Instant::now();
        let result = pip.retrieve_attributes(&subject).await;
        assert!(matches!(result, PipResult::Ignored(PipFailure::Timeout)));
        assert!(start.elapsed() < Duration::from_secs(10));
        hold.abort();
    }
}
