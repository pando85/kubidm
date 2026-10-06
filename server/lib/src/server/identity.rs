//! Contains structures related to the Identity that initiated an `Event` in the
//! server. Generally this Identity is what will have access controls applied to
//! and this provides the set of `Limits` to confine how many resources that the
//! identity may consume during operations to prevent denial-of-service.

use crate::{be::Limits, prelude::*, value::Session};
use kubidm_proto::internal::{ApiTokenPurpose, UatPurpose};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, hash::Hash, net::IpAddr, sync::Arc};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Internal,
    Https(IpAddr),
    Ldaps(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessScope {
    ReadOnly,
    ReadWrite,
    Synchronise,
}

impl std::fmt::Display for AccessScope {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AccessScope::ReadOnly => write!(f, "read only"),
            AccessScope::ReadWrite => write!(f, "read write"),
            AccessScope::Synchronise => write!(f, "synchronise"),
        }
    }
}

impl From<&ApiTokenPurpose> for AccessScope {
    fn from(purpose: &ApiTokenPurpose) -> Self {
        match purpose {
            ApiTokenPurpose::ReadOnly => AccessScope::ReadOnly,
            ApiTokenPurpose::ReadWrite => AccessScope::ReadWrite,
            ApiTokenPurpose::Synchronise => AccessScope::Synchronise,
        }
    }
}

impl From<&UatPurpose> for AccessScope {
    fn from(purpose: &UatPurpose) -> Self {
        match purpose {
            UatPurpose::ReadOnly => AccessScope::ReadOnly,
            UatPurpose::ReadWrite { .. } => AccessScope::ReadWrite,
        }
    }
}

#[derive(Debug, Clone)]
/// Metadata and the entry of the current Identity which is an external account/user.
pub struct IdentUser {
    pub entry: Arc<EntrySealedCommitted>,
    // IpAddr?
    // Other metadata?
}

#[derive(Debug, Clone)]
/// The internal role being used for this operation.
pub enum InternalRole {
    /// The internal database system. This has unlimited crab power.
    System,
    /// A migration operation being performed on the system.
    Migration,

    /// An anonymous account action - this could be a credential reset
    /// request, or a request to create a new account.
    AccountRequest,

    /// An internal role than can manage the outbound message queue.
    MessageQueue,
}

impl std::fmt::Display for InternalRole {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "System"),
            Self::Migration => write!(f, "Migration"),
            Self::AccountRequest => write!(f, "AccountRequest"),
            Self::MessageQueue => write!(f, "MessageQueue"),
        }
    }
}

impl InternalRole {
    pub fn get_uuid(&self) -> Uuid {
        match self {
            Self::System => UUID_SYSTEM,
            Self::Migration => UUID_INTERNAL_MIGRATION,
            Self::AccountRequest => UUID_INTERNAL_ACCOUNT_REQUEST,
            Self::MessageQueue => UUID_INTERNAL_MESSAGE_QUEUE,
        }
    }
}

#[derive(Debug, Clone)]
/// The type of Identity that is related to this session.
pub enum IdentType {
    User(IdentUser),
    Synch(Uuid),
    Internal(InternalRole),
}

#[derive(Debug, Clone, PartialEq, Hash, Ord, PartialOrd, Eq, Serialize, Deserialize)]
/// A unique identifier of this Identity, that can be associated to various
/// caching components.
pub enum IdentityId {
    // Time stamp of the originating event.
    // The uuid of the originating user
    User(Uuid),
    Synch(Uuid),
    Internal(Uuid),
}

impl From<&IdentityId> for Uuid {
    fn from(ident: &IdentityId) -> Uuid {
        match ident {
            IdentityId::User(uuid) | IdentityId::Synch(uuid) | IdentityId::Internal(uuid) => *uuid,
        }
    }
}

impl From<&IdentType> for IdentityId {
    fn from(idt: &IdentType) -> Self {
        match idt {
            IdentType::Internal(role) => IdentityId::Internal(role.get_uuid()),
            IdentType::User(u) => IdentityId::User(u.entry.get_uuid()),
            IdentType::Synch(u) => IdentityId::Synch(*u),
        }
    }
}

#[derive(Debug, Clone)]
/// An identity that initiated an `Event`. Contains extra details about the session
/// and other info that can assist with server decision making.
pub struct Identity {
    pub origin: IdentType,
    #[allow(dead_code)]
    source: Source,
    pub(crate) session_id: Uuid,
    pub(crate) scope: AccessScope,
    limits: Limits,
    last_verified_at: Option<OffsetDateTime>,
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.origin {
            IdentType::Internal(u) => write!(f, "Internal ({}) ({})", u, self.scope),
            IdentType::Synch(u) => write!(f, "Synchronise ({}) ({})", u, self.scope),
            IdentType::User(u) => {
                let nv = u.entry.get_uuid2spn();
                write!(
                    f,
                    "User( {}, {} ) ({}, {})",
                    nv.to_proto_string_clone(),
                    u.entry.get_uuid().as_hyphenated(),
                    self.session_id,
                    self.scope
                )
            }
        }
    }
}

impl Identity {
    pub(crate) fn new(
        origin: IdentType,
        source: Source,
        session_id: Uuid,
        scope: AccessScope,
        limits: Limits,
        last_verified_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            origin,
            source,
            session_id,
            scope,
            limits,
            last_verified_at,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn source(&self) -> &Source {
        &self.source
    }

    pub(crate) fn limits(&self) -> &Limits {
        &self.limits
    }

    #[cfg(test)]
    pub(crate) fn limits_mut(&mut self) -> &mut Limits {
        &mut self.limits
    }

    /// This is the time at which the session associated with this identity last
    /// had it's credentials postively verified at.
    pub(crate) fn last_verified_at(&self) -> Option<OffsetDateTime> {
        self.last_verified_at
    }

    pub(crate) fn migration() -> Self {
        Identity {
            origin: IdentType::Internal(InternalRole::Migration),
            source: Source::Internal,
            session_id: UUID_INTERNAL_SESSION_ID,
            scope: AccessScope::ReadWrite,
            limits: Limits::unlimited(),
            last_verified_at: None,
        }
    }

    pub(crate) fn account_request() -> Self {
        Identity {
            origin: IdentType::Internal(InternalRole::AccountRequest),
            source: Source::Internal,
            session_id: UUID_INTERNAL_SESSION_ID,
            scope: AccessScope::ReadOnly,
            limits: Limits::unlimited(),
            last_verified_at: None,
        }
    }

    pub(crate) fn message_queue() -> Self {
        Identity {
            origin: IdentType::Internal(InternalRole::MessageQueue),
            source: Source::Internal,
            session_id: UUID_INTERNAL_SESSION_ID,
            scope: AccessScope::ReadWrite,
            limits: Limits::unlimited(),
            last_verified_at: None,
        }
    }

    pub(crate) fn from_internal() -> Self {
        Identity {
            origin: IdentType::Internal(InternalRole::System),
            source: Source::Internal,
            session_id: UUID_INTERNAL_SESSION_ID,
            scope: AccessScope::ReadWrite,
            limits: Limits::unlimited(),
            last_verified_at: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_impersonate_entry_readonly(
        entry: Arc<Entry<EntrySealed, EntryCommitted>>,
    ) -> Self {
        Identity {
            origin: IdentType::User(IdentUser { entry }),
            source: Source::Internal,
            session_id: UUID_INTERNAL_SESSION_ID,
            scope: AccessScope::ReadOnly,
            limits: Limits::unlimited(),
            last_verified_at: None,
        }
    }

    pub fn from_impersonate_entry_readwrite(
        entry: Arc<Entry<EntrySealed, EntryCommitted>>,
    ) -> Self {
        Identity {
            origin: IdentType::User(IdentUser { entry }),
            source: Source::Internal,
            session_id: UUID_INTERNAL_SESSION_ID,
            scope: AccessScope::ReadWrite,
            limits: Limits::unlimited(),
            last_verified_at: None,
        }
    }

    pub fn access_scope(&self) -> AccessScope {
        self.scope
    }

    pub fn project_with_scope(&self, scope: AccessScope) -> Self {
        let mut new = self.clone();
        new.scope = scope;
        new
    }

    pub fn get_session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn get_session(&self) -> Option<&Session> {
        match &self.origin {
            IdentType::Internal(_) | IdentType::Synch(_) => None,
            IdentType::User(u) => u
                .entry
                .get_ava_as_session_map(Attribute::UserAuthTokenSession)
                .and_then(|sessions| sessions.get(&self.session_id)),
        }
    }

    pub fn get_user_entry(&self) -> Option<Arc<EntrySealedCommitted>> {
        match &self.origin {
            IdentType::Internal(_) | IdentType::Synch(_) => None,
            IdentType::User(u) => Some(u.entry.clone()),
        }
    }

    pub fn from_impersonate(ident: &Self) -> Self {
        // TODO #64 ?: In the future, we could change some of this data
        // to reflect the fact we are in fact impersonating the action
        // rather than the user explicitly requesting it. Could matter
        // to audits and logs to determine what happened.
        ident.clone()
    }

    pub fn is_internal(&self) -> bool {
        matches!(self.origin, IdentType::Internal(_))
    }

    pub fn get_uuid(&self) -> Uuid {
        match &self.origin {
            IdentType::Internal(role) => role.get_uuid(),
            IdentType::User(u) => u.entry.get_uuid(),
            IdentType::Synch(u) => *u,
        }
    }

    /// Indicate if the session associated with this identity has a session
    /// that can logout. Examples of sessions that *can not* logout are anonymous,
    /// tokens, or PIV sessions.
    pub fn can_logout(&self) -> bool {
        match &self.origin {
            IdentType::Internal(_) => false,
            IdentType::User(u) => u.entry.get_uuid() != UUID_ANONYMOUS,
            IdentType::Synch(_) => false,
        }
    }

    pub fn get_event_origin_id(&self) -> IdentityId {
        IdentityId::from(&self.origin)
    }

    #[cfg(test)]
    pub fn has_claim(&self, claim: &str) -> bool {
        match &self.origin {
            IdentType::Internal(_) | IdentType::Synch(_) => false,
            IdentType::User(u) => u
                .entry
                .attribute_equality(Attribute::Claim, &PartialValue::new_iutf8(claim)),
        }
    }

    pub fn is_memberof(&self, group: Uuid) -> bool {
        match &self.origin {
            IdentType::Internal(_) | IdentType::Synch(_) => false,
            IdentType::User(u) => u
                .entry
                .attribute_equality(Attribute::MemberOf, &PartialValue::Refer(group)),
        }
    }

    pub fn get_memberof(&self) -> Option<&BTreeSet<Uuid>> {
        match &self.origin {
            IdentType::Internal(_) | IdentType::Synch(_) => None,
            IdentType::User(u) => u.entry.get_ava_refer(Attribute::MemberOf),
        }
    }

    pub fn get_oauth2_consent_scopes(&self, oauth2_rs: Uuid) -> Option<&BTreeSet<String>> {
        match &self.origin {
            IdentType::Internal(_) | IdentType::Synch(_) => None,
            IdentType::User(u) => u
                .entry
                .get_ava_as_oauthscopemaps(Attribute::OAuth2ConsentScopeMap)
                .and_then(|scope_map| scope_map.get(&oauth2_rs)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::be::Limits;
    use kubidm_proto::internal::{ApiTokenPurpose, UatPurpose};

    #[test]
    fn test_source_equality() {
        assert_eq!(Source::Internal, Source::Internal);
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(Source::Https(ip), Source::Https(ip));
        assert_eq!(Source::Ldaps(ip), Source::Ldaps(ip));
        assert_ne!(Source::Internal, Source::Https(ip));
        assert_ne!(Source::Https(ip), Source::Ldaps(ip));
    }

    #[test]
    fn test_source_debug() {
        let debug = format!("{:?}", Source::Internal);
        assert!(debug.contains("Internal"));
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let debug = format!("{:?}", Source::Https(ip));
        assert!(debug.contains("Https"));
    }

    #[test]
    fn test_source_clone() {
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let source = Source::Ldaps(ip);
        let cloned = source.clone();
        assert_eq!(source, cloned);
    }

    #[test]
    fn test_access_scope_display() {
        assert_eq!(AccessScope::ReadOnly.to_string(), "read only");
        assert_eq!(AccessScope::ReadWrite.to_string(), "read write");
        assert_eq!(AccessScope::Synchronise.to_string(), "synchronise");
    }

    #[test]
    fn test_access_scope_equality() {
        assert_eq!(AccessScope::ReadOnly, AccessScope::ReadOnly);
        assert_ne!(AccessScope::ReadOnly, AccessScope::ReadWrite);
        assert_ne!(AccessScope::ReadWrite, AccessScope::Synchronise);
    }

    #[test]
    fn test_access_scope_from_api_token_purpose() {
        assert_eq!(
            AccessScope::from(&ApiTokenPurpose::ReadOnly),
            AccessScope::ReadOnly
        );
        assert_eq!(
            AccessScope::from(&ApiTokenPurpose::ReadWrite),
            AccessScope::ReadWrite
        );
        assert_eq!(
            AccessScope::from(&ApiTokenPurpose::Synchronise),
            AccessScope::Synchronise
        );
    }

    #[test]
    fn test_access_scope_from_uat_purpose() {
        assert_eq!(
            AccessScope::from(&UatPurpose::ReadOnly),
            AccessScope::ReadOnly
        );
        assert_eq!(
            AccessScope::from(&UatPurpose::ReadWrite { expiry: None }),
            AccessScope::ReadWrite
        );
    }

    #[test]
    fn test_access_scope_copy() {
        let scope = AccessScope::ReadWrite;
        let copied = scope;
        assert_eq!(scope, copied);
    }

    #[test]
    fn test_internal_role_display() {
        assert_eq!(InternalRole::System.to_string(), "System");
        assert_eq!(InternalRole::Migration.to_string(), "Migration");
    }

    #[test]
    fn test_internal_role_get_uuid() {
        assert_eq!(InternalRole::System.get_uuid(), UUID_SYSTEM);
        assert_eq!(InternalRole::Migration.get_uuid(), UUID_INTERNAL_MIGRATION);
    }

    #[test]
    fn test_ident_type_debug() {
        let ident = IdentType::Internal(InternalRole::System);
        let debug = format!("{:?}", ident);
        assert!(debug.contains("Internal"));
    }

    #[test]
    fn test_identity_id_from_internal_ident_type() {
        let ident_type = IdentType::Internal(InternalRole::System);
        let id = IdentityId::from(&ident_type);
        assert_eq!(id, IdentityId::Internal(UUID_SYSTEM));
    }

    #[test]
    fn test_identity_id_from_synch_ident_type() {
        let sync_uuid = Uuid::new_v4();
        let ident_type = IdentType::Synch(sync_uuid);
        let id = IdentityId::from(&ident_type);
        assert_eq!(id, IdentityId::Synch(sync_uuid));
    }

    #[test]
    fn test_identity_id_to_uuid() {
        let uuid = Uuid::new_v4();
        let id = IdentityId::User(uuid);
        let result: Uuid = Uuid::from(&id);
        assert_eq!(result, uuid);

        let id = IdentityId::Internal(UUID_SYSTEM);
        let result: Uuid = Uuid::from(&id);
        assert_eq!(result, UUID_SYSTEM);

        let sync_uuid = Uuid::new_v4();
        let id = IdentityId::Synch(sync_uuid);
        let result: Uuid = Uuid::from(&id);
        assert_eq!(result, sync_uuid);
    }

    #[test]
    fn test_identity_id_serde_roundtrip() {
        let uuid = Uuid::new_v4();
        let variants = vec![
            IdentityId::User(uuid),
            IdentityId::Synch(Uuid::new_v4()),
            IdentityId::Internal(UUID_SYSTEM),
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: IdentityId = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, parsed);
        }
    }

    #[test]
    fn test_identity_id_hash_eq() {
        use std::collections::BTreeSet;
        let uuid = Uuid::new_v4();
        let mut set = BTreeSet::new();
        set.insert(IdentityId::User(uuid));
        assert!(set.contains(&IdentityId::User(uuid)));
        assert!(!set.contains(&IdentityId::Internal(uuid)));
    }

    #[test]
    fn test_identity_id_ordering() {
        assert!(IdentityId::User(Uuid::new_v4()) < IdentityId::Internal(UUID_SYSTEM));
        assert!(IdentityId::User(Uuid::new_v4()) < IdentityId::Synch(Uuid::new_v4()));
        assert!(IdentityId::Synch(Uuid::new_v4()) < IdentityId::Internal(UUID_SYSTEM));
    }

    #[test]
    fn test_identity_from_internal() {
        let ident = Identity::from_internal();
        assert!(ident.is_internal());
        assert_eq!(ident.get_uuid(), UUID_SYSTEM);
        assert_eq!(ident.access_scope(), AccessScope::ReadWrite);
        assert!(!ident.can_logout());
        assert_eq!(ident.get_session_id(), UUID_INTERNAL_SESSION_ID);
    }

    #[test]
    fn test_identity_migration() {
        let ident = Identity::migration();
        assert!(ident.is_internal());
        assert_eq!(ident.get_uuid(), UUID_INTERNAL_MIGRATION);
        assert_eq!(ident.access_scope(), AccessScope::ReadWrite);
    }

    #[test]
    fn test_identity_project_with_scope() {
        let ident = Identity::from_internal();
        let projected = ident.project_with_scope(AccessScope::ReadOnly);
        assert_eq!(projected.access_scope(), AccessScope::ReadOnly);
        assert_eq!(ident.access_scope(), AccessScope::ReadWrite);
    }

    #[test]
    fn test_identity_get_memberof_internal() {
        let ident = Identity::from_internal();
        assert!(ident.get_memberof().is_none());
    }

    #[test]
    fn test_identity_get_user_entry_internal() {
        let ident = Identity::from_internal();
        assert!(ident.get_user_entry().is_none());
    }

    #[test]
    fn test_identity_get_session_internal() {
        let ident = Identity::from_internal();
        assert!(ident.get_session().is_none());
    }

    #[test]
    fn test_identity_get_oauth2_consent_scopes_internal() {
        let ident = Identity::from_internal();
        assert!(ident.get_oauth2_consent_scopes(Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_identity_get_event_origin_id() {
        let ident = Identity::from_internal();
        let origin_id = ident.get_event_origin_id();
        assert_eq!(origin_id, IdentityId::Internal(UUID_SYSTEM));
    }

    #[test]
    fn test_identity_from_impersonate() {
        let ident = Identity::from_internal();
        let impersonated = Identity::from_impersonate(&ident);
        assert_eq!(impersonated.get_uuid(), ident.get_uuid());
        assert_eq!(impersonated.access_scope(), ident.access_scope());
    }

    #[test]
    fn test_identity_clone() {
        let ident = Identity::from_internal();
        let cloned = ident.clone();
        assert_eq!(cloned.get_uuid(), ident.get_uuid());
        assert_eq!(cloned.access_scope(), ident.access_scope());
    }

    #[test]
    fn test_identity_limits() {
        let ident = Identity::from_internal();
        let limits = ident.limits();
        assert!(limits.unindexed_allow);
    }

    #[test]
    fn test_identity_new_custom() {
        let ident = Identity::new(
            IdentType::Synch(Uuid::new_v4()),
            Source::Internal,
            Uuid::new_v4(),
            AccessScope::Synchronise,
            Limits::unlimited(),
            None,
        );
        assert!(!ident.is_internal());
        assert_eq!(ident.access_scope(), AccessScope::Synchronise);
        assert!(!ident.can_logout());
    }

    #[test]
    fn test_identity_source_method() {
        let ident = Identity::new(
            IdentType::Internal(InternalRole::System),
            Source::Internal,
            UUID_INTERNAL_SESSION_ID,
            AccessScope::ReadOnly,
            Limits::default(),
            None,
        );
        assert_eq!(*ident.source(), Source::Internal);
    }
}
