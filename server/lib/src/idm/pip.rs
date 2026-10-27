//! Policy Information Point (PIP) Framework
//!
//! This module provides a framework for retrieving external attributes from various
//! sources (HTTP REST APIs, LDAP servers, etc.) during authorization decisions.
//!
//! The PIP framework allows Kubidm to incorporate attributes from external systems
//! like HR databases, CRM systems, asset management tools, and risk signals from
//! SIEM/UEBA systems into access control decisions.
//!
//! NOTE: This framework is implemented but awaiting integration into the authorization
//! flow. Dead code warnings are suppressed until integration is complete.

#![allow(dead_code)]

use crate::prelude::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub mod cache;
pub mod config;
pub mod health;
pub mod http;
pub mod ldap;

use cache::PipAttributeCache;
use config::PipFallbackBehavior;

/// Unique identifier for a PIP instance
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct PipId(String);

impl PipId {
    pub fn new(id: impl Into<String>) -> Self {
        PipId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PipId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PipId {
    fn from(s: String) -> Self {
        PipId::new(s)
    }
}

impl From<&str> for PipId {
    fn from(s: &str) -> Self {
        PipId::new(s)
    }
}

/// External attribute name with namespace prefix to prevent collisions
/// with internal Kubidm attributes.
///
/// Format: `pip:<source_id>:<attribute_name>`
/// Example: `pip:hr_system:department`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct PipAttributeName(String);

impl PipAttributeName {
    const PREFIX: &'static str = "pip:";

    pub fn new(source_id: &PipId, attribute_name: &str) -> Self {
        PipAttributeName(format!(
            "{}{}:{}",
            Self::PREFIX,
            source_id.as_str(),
            attribute_name
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_pip_attribute(name: &str) -> bool {
        name.starts_with(Self::PREFIX)
    }

    pub fn parse(name: &str) -> Option<(PipId, String)> {
        if !Self::is_pip_attribute(name) {
            return None;
        }
        let rest = name.strip_prefix(Self::PREFIX)?;
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        let (first, second) = parts.first().zip(parts.get(1))?;
        Some((PipId::new(*first), (*second).to_string()))
    }
}

/// A single attribute value retrieved from a PIP
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PipAttributeValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Array(Vec<PipAttributeValue>),
    Json(serde_json::Value),
}

impl PipAttributeValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PipAttributeValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            PipAttributeValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PipAttributeValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[PipAttributeValue]> {
        match self {
            PipAttributeValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            PipAttributeValue::Json(v) => Some(v),
            _ => None,
        }
    }
}

/// A set of attributes retrieved from a PIP for a specific subject
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipAttributeSet {
    attributes: BTreeMap<PipAttributeName, PipAttributeValue>,
}

impl PipAttributeSet {
    pub fn new() -> Self {
        PipAttributeSet {
            attributes: BTreeMap::new(),
        }
    }

    /// Build an attribute set from configured fallback values, namespaced to `pip_id`.
    pub fn from_fallback_values(
        pip_id: &PipId,
        fallback_values: &BTreeMap<String, PipAttributeValue>,
    ) -> Self {
        let attributes = fallback_values
            .iter()
            .map(|(key, value)| (PipAttributeName::new(pip_id, key), value.clone()))
            .collect();
        PipAttributeSet { attributes }
    }

    pub fn insert(&mut self, name: PipAttributeName, value: PipAttributeValue) {
        self.attributes.insert(name, value);
    }

    pub fn get(&self, name: &PipAttributeName) -> Option<&PipAttributeValue> {
        self.attributes.get(name)
    }

    pub fn contains(&self, name: &PipAttributeName) -> bool {
        self.attributes.contains_key(name)
    }

    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PipAttributeName, &PipAttributeValue)> {
        self.attributes.iter()
    }

    pub fn merge(&mut self, other: PipAttributeSet) {
        for (name, value) in other.attributes {
            self.attributes.insert(name, value);
        }
    }

    /// Keep only the named (un-namespaced) attributes of `pip_id`.
    pub fn filter_named(&self, pip_id: &PipId, attribute_names: &[String]) -> PipAttributeSet {
        let mut filtered = PipAttributeSet::new();
        for name in attribute_names {
            let full_name = PipAttributeName::new(pip_id, name);
            if let Some(value) = self.attributes.get(&full_name) {
                filtered.insert(full_name, value.clone());
            }
        }
        filtered
    }
}

/// Subject identifier for PIP attribute queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipSubject {
    /// UUID of the user/entry being queried
    pub uuid: Uuid,
    /// Optional username
    pub username: Option<String>,
    /// Optional email
    pub email: Option<String>,
    /// Additional context attributes for the query
    pub context: BTreeMap<String, String>,
}

impl PipSubject {
    pub fn from_uuid(uuid: Uuid) -> Self {
        PipSubject {
            uuid,
            username: None,
            email: None,
            context: BTreeMap::new(),
        }
    }

    pub fn with_username(self, username: impl Into<String>) -> Self {
        PipSubject {
            username: Some(username.into()),
            ..self
        }
    }

    pub fn with_email(self, email: impl Into<String>) -> Self {
        PipSubject {
            email: Some(email.into()),
            ..self
        }
    }

    pub fn with_context(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut context = self.context;
        context.insert(key.into(), value.into());
        PipSubject { context, ..self }
    }

    /// Resolve a template placeholder name to the subject's raw value.
    ///
    /// The built-in names `uuid`, `username` and `email` take precedence over
    /// context keys with the same name.
    fn placeholder_value(&self, name: &str) -> Result<String, String> {
        match name {
            "uuid" => Ok(self.uuid.to_string()),
            "username" => self
                .username
                .clone()
                .ok_or_else(|| "template requires {username} but the subject has none".to_string()),
            "email" => self
                .email
                .clone()
                .ok_or_else(|| "template requires {email} but the subject has none".to_string()),
            other => self.context.get(other).cloned().ok_or_else(|| {
                format!("template placeholder {{{other}}} has no value for this subject")
            }),
        }
    }
}

fn is_placeholder_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Render a `{placeholder}` template for `subject` in a single pass.
///
/// Every substituted value is passed through `encode` (which must make it safe
/// for the target syntax, or reject it). The output of a substitution is never
/// re-scanned, so a value containing `{...}` cannot trigger further
/// substitution. A `{name}` placeholder that the subject cannot resolve is an
/// error rather than being sent verbatim. Braces that do not form a placeholder
/// are kept literally.
pub(crate) fn render_template<F>(
    template: &str,
    subject: &PipSubject,
    encode: F,
) -> Result<String, String>
where
    F: Fn(&str) -> Result<String, String>,
{
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find('{') {
        let (literal, from_brace) = rest.split_at(start);
        out.push_str(literal);
        let after_brace = from_brace.strip_prefix('{').unwrap_or(from_brace);

        let placeholder = after_brace.find('}').and_then(|end| {
            let (name, from_close) = after_brace.split_at(end);
            is_placeholder_name(name).then(|| (name, from_close.strip_prefix('}').unwrap_or("")))
        });

        match placeholder {
            Some((name, remainder)) => {
                let value = subject.placeholder_value(name)?;
                if value.is_empty() {
                    // An empty value can merge neighbouring template parts (e.g.
                    // `{a}{b}` into a dot-segment) or widen an LDAP assertion.
                    return Err(format!(
                        "template placeholder {{{name}}} has an empty value"
                    ));
                }
                out.push_str(&encode(&value)?);
                rest = remainder;
            }
            None => {
                out.push('{');
                rest = after_brace;
            }
        }
    }
    out.push_str(rest);

    Ok(out)
}

/// Percent-encode a value for use as (part of) a URL path segment or query
/// component. Everything except RFC 3986 "unreserved" characters is encoded, so
/// the value cannot introduce `/`, `?`, `#`, `&`, `=`, `@` or `%` sequences.
///
/// `url::form_urlencoded` is not used because it encodes a space as `+`, which is
/// only correct inside a query string, not in a path.
pub(crate) fn percent_encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Encode a subject value for substitution into a URL template.
///
/// Values `.` and `..` are rejected: URL parsers normalise them (even when
/// percent-encoded) as dot-segments, which would let a value walk up the path.
pub(crate) fn encode_url_value(value: &str) -> Result<String, String> {
    if value == "." || value == ".." {
        return Err(format!(
            "value '{value}' is not allowed in a URL template (dot-segment)"
        ));
    }
    Ok(percent_encode_component(value))
}

/// Why a PIP source could not provide attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipFailure {
    /// The source could not be reached, or is marked unhealthy and not due a retry.
    Unavailable(String),
    /// The request did not complete within the configured timeout.
    Timeout,
    /// The source answered but the answer could not be used, or the query could
    /// not be built for this subject.
    Error(String),
}

impl fmt::Display for PipFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipFailure::Unavailable(reason) => write!(f, "unavailable: {reason}"),
            PipFailure::Timeout => f.write_str("timed out"),
            PipFailure::Error(error) => write!(f, "error: {error}"),
        }
    }
}

/// Result of a PIP attribute retrieval operation.
///
/// Every failure is resolved according to the source's [`PipFallbackBehavior`]
/// into exactly one of `Fallback`, `Ignored` or `Denied`.
#[derive(Debug)]
pub enum PipResult {
    /// Successfully retrieved attributes
    Success(PipAttributeSet),
    /// The source failed and `fallback_behavior = "usefallback"`: `attributes`
    /// holds the configured `fallback_values` (empty if none are configured).
    Fallback {
        failure: PipFailure,
        attributes: PipAttributeSet,
    },
    /// The source failed and `fallback_behavior = "ignore"`: continue without
    /// attributes from this source.
    Ignored(PipFailure),
    /// The source failed and `fallback_behavior = "deny"`: the caller must fail
    /// closed and deny the request.
    Denied(PipFailure),
}

impl PipResult {
    /// Resolve a failure according to the configured fallback behaviour.
    pub fn from_failure(
        behavior: PipFallbackBehavior,
        failure: PipFailure,
        fallback: impl FnOnce() -> PipAttributeSet,
    ) -> Self {
        match behavior {
            PipFallbackBehavior::UseFallback => PipResult::Fallback {
                failure,
                attributes: fallback(),
            },
            PipFallbackBehavior::Ignore => PipResult::Ignored(failure),
            PipFallbackBehavior::Deny => PipResult::Denied(failure),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, PipResult::Success(_))
    }

    /// The attributes to use: the retrieved ones, or the fallback values.
    pub fn attributes(&self) -> Option<&PipAttributeSet> {
        match self {
            PipResult::Success(attrs)
            | PipResult::Fallback {
                attributes: attrs, ..
            } => Some(attrs),
            PipResult::Ignored(_) | PipResult::Denied(_) => None,
        }
    }

    pub fn fallback_used(&self) -> bool {
        matches!(self, PipResult::Fallback { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, PipResult::Denied(_))
    }

    pub fn failure(&self) -> Option<&PipFailure> {
        match self {
            PipResult::Success(_) => None,
            PipResult::Fallback { failure, .. }
            | PipResult::Ignored(failure)
            | PipResult::Denied(failure) => Some(failure),
        }
    }

    /// Restrict the attributes of this result to the named ones of `pip_id`.
    pub fn filter_named(self, pip_id: &PipId, attribute_names: &[String]) -> PipResult {
        match self {
            PipResult::Success(attrs) => {
                PipResult::Success(attrs.filter_named(pip_id, attribute_names))
            }
            PipResult::Fallback {
                failure,
                attributes,
            } => PipResult::Fallback {
                failure,
                attributes: attributes.filter_named(pip_id, attribute_names),
            },
            other => other,
        }
    }
}

/// Error returned by [`PipManager`] when attributes cannot be provided and the
/// caller must fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipError {
    /// A source failed and is configured with `fallback_behavior = "deny"`.
    Denied { pip_id: PipId, failure: PipFailure },
    /// An attribute names a PIP source that is not registered.
    UnknownSource(PipId),
}

impl fmt::Display for PipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipError::Denied { pip_id, failure } => {
                write!(
                    f,
                    "PIP source '{pip_id}' failed and denies access: {failure}"
                )
            }
            PipError::UnknownSource(pip_id) => write!(f, "unknown PIP source '{pip_id}'"),
        }
    }
}

impl std::error::Error for PipError {}

/// Health status of a PIP source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipHealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl PipHealthStatus {
    pub fn is_healthy(self) -> bool {
        matches!(self, PipHealthStatus::Healthy)
    }

    /// Whether requests may be sent to the source without waiting for a retry
    /// interval. `Unknown` (never contacted) is retrievable so that the first
    /// request establishes the source's health.
    pub fn can_retrieve(self) -> bool {
        matches!(
            self,
            PipHealthStatus::Healthy | PipHealthStatus::Degraded | PipHealthStatus::Unknown
        )
    }
}

/// Health check result for a PIP
#[derive(Debug, Clone)]
pub struct PipHealthCheck {
    pub pip_id: PipId,
    pub status: PipHealthStatus,
    pub last_check: Instant,
    pub latency_ms: Option<u64>,
    pub error_message: Option<String>,
}

/// The Policy Information Point trait that all PIP implementations must implement.
///
/// This trait defines the interface for retrieving external attributes during
/// authorization decisions.
#[async_trait]
pub trait PolicyInformationPoint: Send + Sync {
    /// Unique identifier for this PIP instance
    fn id(&self) -> &PipId;

    /// Retrieve attributes for the given subject.
    ///
    /// This method should:
    /// - Return cached values if available and within TTL
    /// - Query the external source for attributes, bounded by a timeout
    /// - Resolve any failure through the configured fallback behaviour
    async fn retrieve_attributes(&self, subject: &PipSubject) -> PipResult;

    /// Retrieve specific named attributes for the given subject.
    ///
    /// If the PIP supports selective attribute retrieval, this can be more efficient
    /// than retrieving all attributes.
    async fn retrieve_named_attributes(
        &self,
        subject: &PipSubject,
        attribute_names: &[String],
    ) -> PipResult;

    /// Perform a health check on the PIP source.
    ///
    /// This should verify connectivity and basic functionality without
    /// performing a full attribute retrieval.
    async fn health_check(&self) -> PipHealthCheck;

    /// Get the current cached health status without performing a check.
    ///
    /// This must never block: it is called from async contexts.
    fn cached_health_status(&self) -> PipHealthStatus;

    /// Get the list of attribute names this PIP can provide.
    fn provided_attributes(&self) -> &[String];

    /// Clear any cached attributes for the given subject.
    async fn clear_cache(&self, subject: &PipSubject);

    /// Clear all cached attributes.
    async fn clear_all_cache(&self);
}

/// Manager for multiple PIP instances
pub struct PipManager {
    pips: BTreeMap<PipId, Arc<dyn PolicyInformationPoint>>,
    cache: Arc<RwLock<PipAttributeCache>>,
}

impl PipManager {
    pub fn new(cache_ttl: Duration) -> Self {
        PipManager {
            pips: BTreeMap::new(),
            cache: Arc::new(RwLock::new(PipAttributeCache::new(cache_ttl))),
        }
    }

    pub fn register(&mut self, pip: Arc<dyn PolicyInformationPoint>) {
        self.pips.insert(pip.id().clone(), pip);
    }

    pub fn get(&self, id: &PipId) -> Option<Arc<dyn PolicyInformationPoint>> {
        self.pips.get(id).cloned()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PipId, Arc<dyn PolicyInformationPoint>)> {
        self.pips.iter().map(|(id, pip)| (id, pip.clone()))
    }

    /// Fold one source's result into `all_attributes`, failing closed on `Denied`.
    fn merge_result(
        pip_id: &PipId,
        result: PipResult,
        all_attributes: &mut PipAttributeSet,
    ) -> Result<(), PipError> {
        match result {
            PipResult::Success(attrs) => all_attributes.merge(attrs),
            PipResult::Fallback {
                failure,
                attributes,
            } => {
                admin_warn!(
                    "PIP source '{}' failed ({}), using {} fallback value(s)",
                    pip_id,
                    failure,
                    attributes.len()
                );
                all_attributes.merge(attributes);
            }
            PipResult::Ignored(failure) => {
                admin_warn!(
                    "PIP source '{}' failed ({}), continuing without its attributes",
                    pip_id,
                    failure
                );
            }
            PipResult::Denied(failure) => {
                admin_warn!(
                    "PIP source '{}' failed ({}), denying the request",
                    pip_id,
                    failure
                );
                return Err(PipError::Denied {
                    pip_id: pip_id.clone(),
                    failure,
                });
            }
        }
        Ok(())
    }

    /// Retrieve attributes from all registered PIPs for the given subject.
    ///
    /// Attributes from all sources (retrieved or fallback values) are merged into
    /// a single set. If any source fails with `fallback_behavior = "deny"`, an
    /// error is returned and the caller must deny the request.
    pub async fn retrieve_all_attributes(
        &self,
        subject: &PipSubject,
    ) -> Result<PipAttributeSet, PipError> {
        let mut all_attributes = PipAttributeSet::new();

        for (pip_id, pip) in &self.pips {
            let result = pip.retrieve_attributes(subject).await;
            Self::merge_result(pip_id, result, &mut all_attributes)?;
        }

        Ok(all_attributes)
    }

    /// Retrieve specific attributes from the appropriate PIP(s).
    ///
    /// Parses the `pip:<source>:<name>` attribute names to determine which PIP(s)
    /// to query; each source is queried once. Names without the `pip:` prefix are
    /// skipped. A name referencing an unregistered source, or a source failing
    /// with `fallback_behavior = "deny"`, is an error.
    pub async fn retrieve_named_attributes(
        &self,
        subject: &PipSubject,
        attribute_names: &[String],
    ) -> Result<PipAttributeSet, PipError> {
        let mut by_source: BTreeMap<PipId, Vec<String>> = BTreeMap::new();
        for attr_name in attribute_names {
            if let Some((pip_id, internal_name)) = PipAttributeName::parse(attr_name) {
                by_source.entry(pip_id).or_default().push(internal_name);
            }
        }

        let mut all_attributes = PipAttributeSet::new();

        for (pip_id, names) in by_source {
            let pip = self
                .pips
                .get(&pip_id)
                .ok_or_else(|| PipError::UnknownSource(pip_id.clone()))?;
            let result = pip.retrieve_named_attributes(subject, &names).await;
            Self::merge_result(&pip_id, result, &mut all_attributes)?;
        }

        Ok(all_attributes)
    }

    /// Perform health checks on all registered PIPs.
    pub async fn health_check_all(&self) -> Vec<PipHealthCheck> {
        let mut checks = Vec::new();
        for pip in self.pips.values() {
            let check = pip.health_check().await;
            checks.push(check);
        }
        checks
    }

    /// Get health status summary for all PIPs
    pub fn health_summary(&self) -> BTreeMap<PipId, PipHealthStatus> {
        self.pips
            .iter()
            .map(|(id, pip)| (id.clone(), pip.cached_health_status()))
            .collect()
    }

    /// Clear all cached attributes across all PIPs
    pub async fn clear_all_cache(&self) {
        for pip in self.pips.values() {
            pip.clear_all_cache().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pip_id_creation() {
        let id = PipId::new("test_pip");
        assert_eq!(id.as_str(), "test_pip");

        let id_from_str: PipId = "another_pip".into();
        assert_eq!(id_from_str.as_str(), "another_pip");

        let id_from_string: PipId = String::from("string_pip").into();
        assert_eq!(id_from_string.as_str(), "string_pip");
    }

    #[test]
    fn test_pip_id_equality_and_ordering() {
        let id1 = PipId::new("alpha");
        let id2 = PipId::new("beta");
        let id3 = PipId::new("alpha");

        assert_eq!(id1, id3);
        assert_ne!(id1, id2);
        assert!(id1 < id2);
    }

    #[test]
    fn test_pip_attribute_name_format() {
        let pip_id = PipId::new("hr_system");
        let attr_name = PipAttributeName::new(&pip_id, "department");

        assert_eq!(attr_name.as_str(), "pip:hr_system:department");
        assert!(PipAttributeName::is_pip_attribute(
            "pip:hr_system:department"
        ));
        assert!(!PipAttributeName::is_pip_attribute("department"));
    }

    #[test]
    fn test_pip_attribute_name_parse_valid() {
        let parsed = PipAttributeName::parse("pip:hr_system:department");
        assert!(parsed.is_some());

        let (pip_id, internal_name) = parsed.unwrap();
        assert_eq!(pip_id.as_str(), "hr_system");
        assert_eq!(internal_name, "department");
    }

    #[test]
    fn test_pip_attribute_name_parse_invalid() {
        assert!(PipAttributeName::parse("department").is_none());
        assert!(PipAttributeName::parse("pip:").is_none());
        assert!(PipAttributeName::parse("pip:only_source").is_none());
        assert!(PipAttributeName::parse("").is_none());
    }

    #[test]
    fn test_pip_attribute_name_special_characters() {
        let pip_id = PipId::new("source-with-dashes");
        let attr_name = PipAttributeName::new(&pip_id, "attr_with_underscores");
        assert_eq!(
            attr_name.as_str(),
            "pip:source-with-dashes:attr_with_underscores"
        );

        let parsed = PipAttributeName::parse("pip:source-with-dashes:attr_with_underscores");
        assert!(parsed.is_some());
    }

    #[test]
    fn test_pip_attribute_set_insert_and_get() {
        let mut set = PipAttributeSet::new();
        let pip_id = PipId::new("hr_system");

        let dept_attr = PipAttributeName::new(&pip_id, "department");
        set.insert(
            dept_attr.clone(),
            PipAttributeValue::String("Engineering".to_string()),
        );

        assert!(set.contains(&dept_attr));
        assert_eq!(set.len(), 1);
        assert_eq!(set.get(&dept_attr).unwrap().as_str(), Some("Engineering"));
    }

    #[test]
    fn test_pip_attribute_set_multiple_attributes() {
        let mut set = PipAttributeSet::new();
        let pip_id = PipId::new("hr_system");

        set.insert(
            PipAttributeName::new(&pip_id, "department"),
            PipAttributeValue::String("Engineering".to_string()),
        );
        set.insert(
            PipAttributeName::new(&pip_id, "role"),
            PipAttributeValue::String("Developer".to_string()),
        );
        set.insert(
            PipAttributeName::new(&pip_id, "level"),
            PipAttributeValue::Integer(5),
        );

        assert_eq!(set.len(), 3);
        assert!(set.contains(&PipAttributeName::new(&pip_id, "department")));
        assert!(set.contains(&PipAttributeName::new(&pip_id, "role")));
        assert!(set.contains(&PipAttributeName::new(&pip_id, "level")));
    }

    #[test]
    fn test_pip_attribute_set_merge() {
        let mut set1 = PipAttributeSet::new();
        let pip_id = PipId::new("source1");
        set1.insert(
            PipAttributeName::new(&pip_id, "attr1"),
            PipAttributeValue::String("value1".to_string()),
        );

        let mut set2 = PipAttributeSet::new();
        let pip_id2 = PipId::new("source2");
        set2.insert(
            PipAttributeName::new(&pip_id2, "attr2"),
            PipAttributeValue::String("value2".to_string()),
        );

        set1.merge(set2);
        assert_eq!(set1.len(), 2);
        assert!(set1.contains(&PipAttributeName::new(&pip_id, "attr1")));
        assert!(set1.contains(&PipAttributeName::new(&pip_id2, "attr2")));
    }

    #[test]
    fn test_pip_attribute_set_empty() {
        let set = PipAttributeSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_pip_attribute_set_default() {
        let set = PipAttributeSet::default();
        assert!(set.is_empty());
    }

    #[test]
    fn test_pip_attribute_set_from_fallback_values_and_filter() {
        let pip_id = PipId::new("hr");
        let mut fallback = BTreeMap::new();
        fallback.insert(
            "department".to_string(),
            PipAttributeValue::String("Unknown".to_string()),
        );
        fallback.insert("level".to_string(), PipAttributeValue::Integer(0));

        let set = PipAttributeSet::from_fallback_values(&pip_id, &fallback);
        assert_eq!(set.len(), 2);
        assert_eq!(
            set.get(&PipAttributeName::new(&pip_id, "department")),
            Some(&PipAttributeValue::String("Unknown".to_string()))
        );

        let filtered = set.filter_named(&pip_id, &["level".to_string(), "missing".to_string()]);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains(&PipAttributeName::new(&pip_id, "level")));
    }

    #[test]
    fn test_pip_attribute_value_string() {
        let val = PipAttributeValue::String("test".to_string());
        assert_eq!(val.as_str(), Some("test"));
        assert_eq!(val.as_int(), None);
        assert_eq!(val.as_bool(), None);
        assert_eq!(val.as_array(), None);
        assert_eq!(val.as_json(), None);
    }

    #[test]
    fn test_pip_attribute_value_integer() {
        let val = PipAttributeValue::Integer(42);
        assert_eq!(val.as_int(), Some(42));
        assert_eq!(val.as_str(), None);
        assert_eq!(val.as_bool(), None);
    }

    #[test]
    fn test_pip_attribute_value_boolean() {
        let val_true = PipAttributeValue::Boolean(true);
        assert_eq!(val_true.as_bool(), Some(true));

        let val_false = PipAttributeValue::Boolean(false);
        assert_eq!(val_false.as_bool(), Some(false));
    }

    #[test]
    fn test_pip_attribute_value_array() {
        let arr = vec![
            PipAttributeValue::String("a".to_string()),
            PipAttributeValue::Integer(1),
            PipAttributeValue::Boolean(true),
        ];
        let val = PipAttributeValue::Array(arr);
        assert_eq!(val.as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_pip_attribute_value_json() {
        let json = serde_json::json!({"key": "value"});
        let val = PipAttributeValue::Json(json.clone());
        assert_eq!(val.as_json(), Some(&json));
    }

    #[test]
    fn test_pip_attribute_value_equality() {
        assert_eq!(
            PipAttributeValue::String("test".to_string()),
            PipAttributeValue::String("test".to_string())
        );
        assert_ne!(
            PipAttributeValue::String("test".to_string()),
            PipAttributeValue::String("other".to_string())
        );
        assert_eq!(
            PipAttributeValue::Integer(42),
            PipAttributeValue::Integer(42)
        );
        assert_eq!(
            PipAttributeValue::Boolean(true),
            PipAttributeValue::Boolean(true)
        );
    }

    #[test]
    fn test_pip_subject_from_uuid() {
        let uuid = Uuid::new_v4();
        let subject = PipSubject::from_uuid(uuid);
        assert_eq!(subject.uuid, uuid);
        assert!(subject.username.is_none());
        assert!(subject.email.is_none());
        assert!(subject.context.is_empty());
    }

    #[test]
    fn test_pip_subject_with_username() {
        let subject = PipSubject::from_uuid(Uuid::new_v4()).with_username("testuser");
        assert_eq!(subject.username, Some("testuser".to_string()));
    }

    #[test]
    fn test_pip_subject_with_email() {
        let subject = PipSubject::from_uuid(Uuid::new_v4()).with_email("test@example.com");
        assert_eq!(subject.email, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_pip_subject_with_context() {
        let subject = PipSubject::from_uuid(Uuid::new_v4())
            .with_context("device_id", "device123")
            .with_context("location", "office");
        assert_eq!(
            subject.context.get("device_id"),
            Some(&"device123".to_string())
        );
        assert_eq!(subject.context.get("location"), Some(&"office".to_string()));
    }

    #[test]
    fn test_pip_subject_full() {
        let subject = PipSubject::from_uuid(Uuid::new_v4())
            .with_username("testuser")
            .with_email("test@example.com")
            .with_context("device_id", "device123");

        assert!(subject.username.is_some());
        assert!(subject.email.is_some());
        assert!(subject.context.contains_key("device_id"));
    }

    #[test]
    fn test_render_template_substitutes_and_encodes() {
        let uuid = Uuid::new_v4();
        let subject = PipSubject::from_uuid(uuid)
            .with_username("alice")
            .with_context("device_id", "dev 1");

        let rendered = render_template(
            "/u/{username}/{uuid}/d/{device_id}",
            &subject,
            encode_url_value,
        )
        .unwrap();
        assert_eq!(rendered, format!("/u/alice/{uuid}/d/dev%201"));
    }

    fn raw(v: &str) -> Result<String, String> {
        Ok(v.to_string())
    }

    #[test]
    fn test_render_template_is_single_pass() {
        // A value that looks like a placeholder must not be expanded again.
        let subject = PipSubject::from_uuid(Uuid::new_v4())
            .with_username("{email}")
            .with_email("victim@example.com");

        let rendered = render_template("{username}", &subject, raw).unwrap();
        assert_eq!(rendered, "{email}");
    }

    #[test]
    fn test_render_template_missing_value_is_error() {
        let subject = PipSubject::from_uuid(Uuid::new_v4());
        assert!(render_template("/u/{username}", &subject, raw).is_err());
        assert!(render_template("/u/{email}", &subject, raw).is_err());
        assert!(render_template("/u/{nope}", &subject, raw).is_err());
    }

    #[test]
    fn test_render_template_empty_value_is_error() {
        let subject = PipSubject::from_uuid(Uuid::new_v4())
            .with_username("")
            .with_context("a", "");
        assert!(render_template("/u/{username}", &subject, raw).is_err());
        assert!(render_template("(uid={a})", &subject, raw).is_err());
    }

    #[test]
    fn test_render_template_keeps_non_placeholder_braces() {
        let subject = PipSubject::from_uuid(Uuid::new_v4());
        assert_eq!(
            render_template("{ } {} {a b} {", &subject, raw).unwrap(),
            "{ } {} {a b} {"
        );
    }

    #[test]
    fn test_encode_url_value_rejects_dot_segments() {
        assert!(encode_url_value(".").is_err());
        assert!(encode_url_value("..").is_err());
        assert_eq!(encode_url_value("...").unwrap(), "...");
        assert_eq!(encode_url_value("a/../b").unwrap(), "a%2F..%2Fb");
    }

    #[test]
    fn test_percent_encode_component() {
        assert_eq!(percent_encode_component("abc-._~XYZ09"), "abc-._~XYZ09");
        assert_eq!(
            percent_encode_component("../a b/?x=1&y#z@h%"),
            "..%2Fa%20b%2F%3Fx%3D1%26y%23z%40h%25"
        );
        assert_eq!(percent_encode_component("é"), "%C3%A9");
    }

    #[test]
    fn test_pip_result_success() {
        let attrs = PipAttributeSet::new();
        let result = PipResult::Success(attrs);
        assert!(result.is_success());
        assert!(result.attributes().is_some());
        assert!(!result.fallback_used());
        assert!(!result.is_denied());
        assert!(result.failure().is_none());
    }

    #[test]
    fn test_pip_result_from_failure_use_fallback_returns_values() {
        let pip_id = PipId::new("hr");
        let mut fallback = BTreeMap::new();
        fallback.insert(
            "department".to_string(),
            PipAttributeValue::String("Unknown".to_string()),
        );

        let result = PipResult::from_failure(
            PipFallbackBehavior::UseFallback,
            PipFailure::Timeout,
            || PipAttributeSet::from_fallback_values(&pip_id, &fallback),
        );
        assert!(!result.is_success());
        assert!(result.fallback_used());
        assert!(!result.is_denied());
        assert_eq!(result.failure(), Some(&PipFailure::Timeout));
        let attrs = result
            .attributes()
            .expect("fallback values must be returned");
        assert_eq!(
            attrs.get(&PipAttributeName::new(&pip_id, "department")),
            Some(&PipAttributeValue::String("Unknown".to_string()))
        );
    }

    #[test]
    fn test_pip_result_from_failure_ignore() {
        let result = PipResult::from_failure(
            PipFallbackBehavior::Ignore,
            PipFailure::Unavailable("source down".to_string()),
            PipAttributeSet::new,
        );
        assert!(matches!(result, PipResult::Ignored(_)));
        assert!(result.attributes().is_none());
        assert!(!result.fallback_used());
        assert!(!result.is_denied());
    }

    #[test]
    fn test_pip_result_from_failure_deny() {
        let result = PipResult::from_failure(
            PipFallbackBehavior::Deny,
            PipFailure::Error("connection failed".to_string()),
            || panic!("fallback values must not be computed for deny"),
        );
        assert!(result.is_denied());
        assert!(result.attributes().is_none());
        assert!(!result.fallback_used());
        assert_eq!(
            result.failure(),
            Some(&PipFailure::Error("connection failed".to_string()))
        );
    }

    #[test]
    fn test_pip_health_status_healthy() {
        let status = PipHealthStatus::Healthy;
        assert!(status.is_healthy());
        assert!(status.can_retrieve());
    }

    #[test]
    fn test_pip_health_status_degraded() {
        let status = PipHealthStatus::Degraded;
        assert!(!status.is_healthy());
        assert!(status.can_retrieve());
    }

    #[test]
    fn test_pip_health_status_unhealthy() {
        let status = PipHealthStatus::Unhealthy;
        assert!(!status.is_healthy());
        assert!(!status.can_retrieve());
    }

    #[test]
    fn test_pip_health_status_unknown() {
        let status = PipHealthStatus::Unknown;
        assert!(!status.is_healthy());
        // Never contacted: the first request must be allowed to establish health.
        assert!(status.can_retrieve());
    }

    #[test]
    fn test_pip_health_check_fields() {
        let check = PipHealthCheck {
            pip_id: PipId::new("test"),
            status: PipHealthStatus::Healthy,
            last_check: Instant::now(),
            latency_ms: Some(50),
            error_message: None,
        };
        assert_eq!(check.pip_id.as_str(), "test");
        assert!(check.status.is_healthy());
        assert!(check.latency_ms.is_some());
        assert!(check.error_message.is_none());
    }

    #[test]
    fn test_pip_health_check_with_error() {
        let check = PipHealthCheck {
            pip_id: PipId::new("test"),
            status: PipHealthStatus::Unhealthy,
            last_check: Instant::now(),
            latency_ms: None,
            error_message: Some("connection timeout".to_string()),
        };
        assert!(check.error_message.is_some());
        assert!(check.latency_ms.is_none());
    }

    #[test]
    fn test_pip_manager_new() {
        let manager = PipManager::new(Duration::from_secs(300));
        assert!(manager.health_summary().is_empty());
    }

    #[test]
    fn test_pip_manager_register_and_get() {
        let mut manager = PipManager::new(Duration::from_secs(300));
        let mock_pip = Arc::new(MockPip::success(PipId::new("test_pip")));
        manager.register(mock_pip.clone());

        assert!(manager.get(&PipId::new("test_pip")).is_some());
        assert!(manager.get(&PipId::new("nonexistent")).is_none());
    }

    #[test]
    fn test_pip_manager_iter() {
        let mut manager = PipManager::new(Duration::from_secs(300));
        manager.register(Arc::new(MockPip::success(PipId::new("pip1"))));
        manager.register(Arc::new(MockPip::success(PipId::new("pip2"))));

        let count = manager.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_pip_manager_health_summary() {
        let mut manager = PipManager::new(Duration::from_secs(300));
        manager.register(Arc::new(MockPip::success(PipId::new("healthy_pip"))));

        let summary = manager.health_summary();
        assert_eq!(summary.len(), 1);
        assert_eq!(
            summary.get(&PipId::new("healthy_pip")),
            Some(&PipHealthStatus::Unknown)
        );
    }

    #[tokio::test]
    async fn test_pip_manager_merges_success_and_fallback() {
        let mut manager = PipManager::new(Duration::from_secs(300));
        manager.register(Arc::new(MockPip::success(PipId::new("ok"))));
        manager.register(Arc::new(MockPip::failing(
            PipId::new("down"),
            PipFallbackBehavior::UseFallback,
        )));
        manager.register(Arc::new(MockPip::failing(
            PipId::new("optional"),
            PipFallbackBehavior::Ignore,
        )));

        let subject = PipSubject::from_uuid(Uuid::new_v4());
        let attrs = manager
            .retrieve_all_attributes(&subject)
            .await
            .expect("no source denies");

        assert_eq!(
            attrs.get(&PipAttributeName::new(&PipId::new("ok"), "attr")),
            Some(&PipAttributeValue::String("live".to_string()))
        );
        assert_eq!(
            attrs.get(&PipAttributeName::new(&PipId::new("down"), "attr")),
            Some(&PipAttributeValue::String("fallback".to_string()))
        );
        assert!(!attrs.contains(&PipAttributeName::new(&PipId::new("optional"), "attr")));
    }

    #[tokio::test]
    async fn test_pip_manager_deny_fails_closed() {
        let mut manager = PipManager::new(Duration::from_secs(300));
        manager.register(Arc::new(MockPip::success(PipId::new("ok"))));
        manager.register(Arc::new(MockPip::failing(
            PipId::new("strict"),
            PipFallbackBehavior::Deny,
        )));

        let subject = PipSubject::from_uuid(Uuid::new_v4());
        let err = manager
            .retrieve_all_attributes(&subject)
            .await
            .expect_err("deny must fail closed");
        assert_eq!(
            err,
            PipError::Denied {
                pip_id: PipId::new("strict"),
                failure: PipFailure::Unavailable("mock down".to_string()),
            }
        );

        let err = manager
            .retrieve_named_attributes(&subject, &["pip:strict:attr".to_string()])
            .await
            .expect_err("deny must fail closed");
        assert!(matches!(err, PipError::Denied { .. }));
    }

    #[tokio::test]
    async fn test_pip_manager_named_attributes() {
        let mut manager = PipManager::new(Duration::from_secs(300));
        manager.register(Arc::new(MockPip::success(PipId::new("ok"))));
        manager.register(Arc::new(MockPip::failing(
            PipId::new("down"),
            PipFallbackBehavior::UseFallback,
        )));

        let subject = PipSubject::from_uuid(Uuid::new_v4());
        let attrs = manager
            .retrieve_named_attributes(
                &subject,
                &[
                    "pip:ok:attr".to_string(),
                    "pip:ok:other".to_string(),
                    "pip:down:attr".to_string(),
                    "not_a_pip_attr".to_string(),
                ],
            )
            .await
            .expect("no source denies");
        assert_eq!(attrs.len(), 2);

        let err = manager
            .retrieve_named_attributes(&subject, &["pip:missing:attr".to_string()])
            .await
            .expect_err("unknown source must be an error");
        assert_eq!(err, PipError::UnknownSource(PipId::new("missing")));
    }

    struct MockPip {
        id: PipId,
        failing: Option<PipFallbackBehavior>,
    }

    impl MockPip {
        fn success(id: PipId) -> Self {
            MockPip { id, failing: None }
        }

        fn failing(id: PipId, behavior: PipFallbackBehavior) -> Self {
            MockPip {
                id,
                failing: Some(behavior),
            }
        }
    }

    #[async_trait]
    impl PolicyInformationPoint for MockPip {
        fn id(&self) -> &PipId {
            &self.id
        }

        async fn retrieve_attributes(&self, _subject: &PipSubject) -> PipResult {
            match self.failing {
                None => {
                    let mut attrs = PipAttributeSet::new();
                    attrs.insert(
                        PipAttributeName::new(&self.id, "attr"),
                        PipAttributeValue::String("live".to_string()),
                    );
                    PipResult::Success(attrs)
                }
                Some(behavior) => {
                    let mut fallback = BTreeMap::new();
                    fallback.insert(
                        "attr".to_string(),
                        PipAttributeValue::String("fallback".to_string()),
                    );
                    PipResult::from_failure(
                        behavior,
                        PipFailure::Unavailable("mock down".to_string()),
                        || PipAttributeSet::from_fallback_values(&self.id, &fallback),
                    )
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
            PipHealthCheck {
                pip_id: self.id.clone(),
                status: PipHealthStatus::Healthy,
                last_check: Instant::now(),
                latency_ms: Some(10),
                error_message: None,
            }
        }

        fn cached_health_status(&self) -> PipHealthStatus {
            PipHealthStatus::Unknown
        }

        fn provided_attributes(&self) -> &[String] {
            &[]
        }

        async fn clear_cache(&self, _subject: &PipSubject) {}

        async fn clear_all_cache(&self) {}
    }
}
