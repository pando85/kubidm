use super::{ScimMail, ScimOauth2ClaimMapJoinChar, ScimSshPublicKey};
use crate::{attribute::Attribute, internal::UiHint, v1::OutboundMessage};
use crypto_glue::s256::Sha256Output;
use scim_proto::{ScimEntry, ScimEntryHeader};
use serde::Serialize;
use serde_with::{base64, formats, hex::Hex, serde_as, skip_serializing_none};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

/// A strongly typed ScimEntry that is for transmission to clients. This uses
/// Kubidm internal strong types for values allowing direct serialisation and
/// transmission.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScimEntryKubidm {
    #[serde(flatten)]
    pub header: ScimEntryHeader,

    pub ext_access_check: Option<ScimEffectiveAccess>,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, ScimValueKubidm>,
}

impl ScimEntryKubidm {
    fn get_string_attr(&self, attr: &Attribute) -> Option<&String> {
        self.attrs.get(attr).and_then(|v| match v {
            ScimValueKubidm::String(s) => Some(s),
            _ => None,
        })
    }

    fn get_scim_refs_attr(&self, attr: &Attribute) -> Option<&Vec<ScimReference>> {
        let option = self.attrs.get(attr);
        option.and_then(|v| match v {
            ScimValueKubidm::EntryReferences(s) => Some(s),
            _ => None,
        })
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Clone, Debug, Default, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScimListResponse {
    pub schemas: Vec<String>,
    pub total_results: u64,
    #[schema(value_type = u64)]
    pub items_per_page: Option<NonZeroU64>,
    #[schema(value_type = u64)]
    pub start_index: Option<NonZeroU64>,
    #[schema(value_type = Vec<ScimEntry>)]
    pub resources: Vec<ScimEntryKubidm>,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub enum ScimAttributeEffectiveAccess {
    /// All attributes on the entry have this permission granted
    Grant,
    /// All attributes on the entry have this permission denied
    Deny,
    /// The following attributes on the entry have this permission granted
    Allow(BTreeSet<Attribute>),
}

impl ScimAttributeEffectiveAccess {
    /// Check if the effective access allows or denies this attribute
    pub fn check(&self, attr: &Attribute) -> bool {
        match self {
            Self::Grant => true,
            Self::Deny => false,
            Self::Allow(set) => set.contains(attr),
        }
    }

    /// Check if the effective access allows ANY of the attributes
    pub fn check_any(&self, attrs: &BTreeSet<Attribute>) -> bool {
        match self {
            Self::Grant => true,
            Self::Deny => false,
            Self::Allow(set) => attrs.intersection(set).next().is_some(),
        }
    }
}

#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimEffectiveAccess {
    /// The identity that inherits the effective permission
    pub ident: Uuid,
    /// If the ident may delete the target entry
    pub delete: bool,
    /// The set of effective access over search events
    pub search: ScimAttributeEffectiveAccess,
    /// The set of effective access over modify present events
    pub modify_present: ScimAttributeEffectiveAccess,
    /// The set of effective access over modify remove events
    pub modify_remove: ScimAttributeEffectiveAccess,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimAddress {
    pub formatted: String,
    pub street_address: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimApplicationPasswordReference {
    pub uuid: Uuid,
    pub application_uuid: Uuid,
    pub label: String,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimBinary {
    pub label: String,
    #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
    pub value: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimCertificate {
    #[serde_as(as = "Hex")]
    pub s256: Vec<u8>,
    #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
    pub der: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimAuditString {
    #[serde_as(as = "Rfc3339")]
    pub date_time: OffsetDateTime,
    pub value: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ScimIntentTokenState {
    Valid,
    InProgress,
    Consumed,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimIntentToken {
    pub token_id: String,
    pub state: ScimIntentTokenState,
    #[serde_as(as = "Rfc3339")]
    pub expires: OffsetDateTime,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimKeyInternal {
    pub key_id: String,
    pub status: String,
    pub usage: String,
    #[serde_as(as = "Rfc3339")]
    pub valid_from: OffsetDateTime,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimAuthSession {
    pub id: Uuid,
    #[serde_as(as = "Option<Rfc3339>")]
    pub expires: Option<OffsetDateTime>,
    #[serde_as(as = "Option<Rfc3339>")]
    pub revoked: Option<OffsetDateTime>,
    #[serde_as(as = "Rfc3339")]
    pub issued_at: OffsetDateTime,
    pub issued_by: Uuid,
    pub credential_id: Uuid,
    pub auth_type: String,
    pub session_scope: String,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2Session {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub client_id: Uuid,
    #[serde_as(as = "Rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde_as(as = "Option<Rfc3339>")]
    pub expires: Option<OffsetDateTime>,
    #[serde_as(as = "Option<Rfc3339>")]
    pub revoked: Option<OffsetDateTime>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimApiToken {
    pub id: Uuid,
    pub label: String,
    #[serde_as(as = "Option<Rfc3339>")]
    pub expires: Option<OffsetDateTime>,
    #[serde_as(as = "Rfc3339")]
    pub issued_at: OffsetDateTime,
    pub issued_by: Uuid,
    pub scope: String,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2ScopeMap {
    pub group: String,
    pub group_uuid: Uuid,
    pub scopes: BTreeSet<String>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2ClaimMap {
    pub group: String,
    pub group_uuid: Uuid,
    pub claim: String,
    pub join_char: ScimOauth2ClaimMapJoinChar,
    pub values: BTreeSet<String>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimReference {
    pub uuid: Uuid,
    pub value: String,
}

/// This is a strongly typed ScimValue for Kubidm. It is for serialisation only
/// since on a deserialisation path we can not know the intent of the sender
/// to how we deserialise strings. Additionally during deserialisation we need
/// to accept optional or partial types too.
#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(untagged)]
pub enum ScimValueKubidm {
    Bool(bool),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    Integer(i64),
    Decimal(f64),
    String(String),

    // Other strong outbound types.
    DateTime(#[serde_as(as = "Rfc3339")] OffsetDateTime),
    Reference(Url),
    Uuid(Uuid),
    EntryReference(ScimReference),
    EntryReferences(Vec<ScimReference>),

    ArrayString(Vec<String>),
    ArrayDateTime(#[serde_as(as = "Vec<Rfc3339>")] Vec<OffsetDateTime>),
    ArrayUuid(Vec<Uuid>),
    ArrayBinary(Vec<ScimBinary>),
    ArrayCertificate(Vec<ScimCertificate>),

    Address(Vec<ScimAddress>),
    Mail(Vec<ScimMail>),
    ApplicationPassword(Vec<ScimApplicationPasswordReference>),
    AuditString(Vec<ScimAuditString>),
    SshPublicKey(Vec<ScimSshPublicKey>),
    AuthSession(Vec<ScimAuthSession>),
    OAuth2Session(Vec<ScimOAuth2Session>),
    ApiToken(Vec<ScimApiToken>),
    IntentToken(Vec<ScimIntentToken>),
    OAuth2ScopeMap(Vec<ScimOAuth2ScopeMap>),
    OAuth2ClaimMap(Vec<ScimOAuth2ClaimMap>),
    KeyInternal(Vec<ScimKeyInternal>),
    UiHints(Vec<UiHint>),

    Message(OutboundMessage),

    #[schema(value_type = Vec<String>)]
    Sha256(#[serde_as(as = "Vec<Hex>")] Vec<Sha256Output>),
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimPerson {
    pub uuid: Uuid,
    pub name: String,
    pub displayname: String,
    pub spn: String,
    pub description: Option<String>,
    pub mails: Vec<ScimMail>,
    pub managed_by: Option<ScimReference>,
    pub groups: Vec<ScimReference>,
}

impl ScimPerson {
    pub fn get_primary_mail(&self) -> Option<String> {
        self.mails
            .iter()
            .find(|m| m.primary)
            .map(|primary_mail| primary_mail.value.clone())
    }
}

impl TryFrom<ScimEntryKubidm> for ScimPerson {
    type Error = ();

    fn try_from(scim_entry: ScimEntryKubidm) -> Result<Self, Self::Error> {
        let uuid = scim_entry.header.id;
        let name = scim_entry
            .get_string_attr(&Attribute::Name)
            .cloned()
            .ok_or(())?;
        let displayname = scim_entry
            .get_string_attr(&Attribute::DisplayName)
            .cloned()
            .ok_or(())?;
        let spn = scim_entry
            .get_string_attr(&Attribute::Spn)
            .cloned()
            .ok_or(())?;
        let description = scim_entry.get_string_attr(&Attribute::Description).cloned();

        let mails = scim_entry
            .attrs
            .get(&Attribute::Mail)
            .and_then(|v| match v {
                ScimValueKubidm::Mail(m) => Some(m.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let groups = scim_entry
            .get_scim_refs_attr(&Attribute::DirectMemberOf)
            .cloned()
            .unwrap_or_default();

        let managed_by = scim_entry
            .attrs
            .get(&Attribute::EntryManagedBy)
            .and_then(|v| match v {
                ScimValueKubidm::EntryReference(v) => Some(v.clone()),
                _ => None,
            });

        Ok(ScimPerson {
            uuid,
            name,
            displayname,
            spn,
            description,
            mails,
            managed_by,
            groups,
        })
    }
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimGroup {
    pub uuid: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub members: Vec<ScimReference>,
}

impl TryFrom<ScimEntryKubidm> for ScimGroup {
    type Error = ();

    fn try_from(scim_entry: ScimEntryKubidm) -> Result<Self, Self::Error> {
        let uuid = scim_entry.header.id;
        let name = scim_entry
            .get_string_attr(&Attribute::Name)
            .cloned()
            .ok_or(())?;
        let description = scim_entry.get_string_attr(&Attribute::Description).cloned();
        let members = scim_entry
            .get_scim_refs_attr(&Attribute::Member)
            .cloned()
            .unwrap_or_default();

        Ok(ScimGroup {
            uuid,
            name,
            description,
            members,
        })
    }
}

impl From<bool> for ScimValueKubidm {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<OffsetDateTime> for ScimValueKubidm {
    fn from(odt: OffsetDateTime) -> Self {
        Self::DateTime(odt)
    }
}

impl From<Vec<UiHint>> for ScimValueKubidm {
    fn from(set: Vec<UiHint>) -> Self {
        Self::UiHints(set)
    }
}

impl From<Vec<OffsetDateTime>> for ScimValueKubidm {
    fn from(set: Vec<OffsetDateTime>) -> Self {
        Self::ArrayDateTime(set)
    }
}

impl From<String> for ScimValueKubidm {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for ScimValueKubidm {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<Vec<String>> for ScimValueKubidm {
    fn from(set: Vec<String>) -> Self {
        Self::ArrayString(set)
    }
}

impl From<Uuid> for ScimValueKubidm {
    fn from(u: Uuid) -> Self {
        Self::Uuid(u)
    }
}

impl From<Vec<Uuid>> for ScimValueKubidm {
    fn from(set: Vec<Uuid>) -> Self {
        Self::ArrayUuid(set)
    }
}

impl From<u32> for ScimValueKubidm {
    fn from(u: u32) -> Self {
        Self::Uint32(u)
    }
}

impl From<i64> for ScimValueKubidm {
    fn from(u: i64) -> Self {
        Self::Int64(u)
    }
}

impl From<u64> for ScimValueKubidm {
    fn from(u: u64) -> Self {
        Self::Uint64(u)
    }
}

impl From<Vec<ScimAddress>> for ScimValueKubidm {
    fn from(set: Vec<ScimAddress>) -> Self {
        Self::Address(set)
    }
}

impl From<Vec<ScimMail>> for ScimValueKubidm {
    fn from(set: Vec<ScimMail>) -> Self {
        Self::Mail(set)
    }
}

impl From<Vec<ScimApplicationPasswordReference>> for ScimValueKubidm {
    fn from(set: Vec<ScimApplicationPasswordReference>) -> Self {
        Self::ApplicationPassword(set)
    }
}

impl From<Vec<ScimAuditString>> for ScimValueKubidm {
    fn from(set: Vec<ScimAuditString>) -> Self {
        Self::AuditString(set)
    }
}

impl From<Vec<ScimBinary>> for ScimValueKubidm {
    fn from(set: Vec<ScimBinary>) -> Self {
        Self::ArrayBinary(set)
    }
}

impl From<Vec<ScimCertificate>> for ScimValueKubidm {
    fn from(set: Vec<ScimCertificate>) -> Self {
        Self::ArrayCertificate(set)
    }
}

impl From<Vec<ScimSshPublicKey>> for ScimValueKubidm {
    fn from(set: Vec<ScimSshPublicKey>) -> Self {
        Self::SshPublicKey(set)
    }
}

impl From<Vec<ScimAuthSession>> for ScimValueKubidm {
    fn from(set: Vec<ScimAuthSession>) -> Self {
        Self::AuthSession(set)
    }
}

impl From<Vec<ScimOAuth2Session>> for ScimValueKubidm {
    fn from(set: Vec<ScimOAuth2Session>) -> Self {
        Self::OAuth2Session(set)
    }
}

impl From<Vec<ScimApiToken>> for ScimValueKubidm {
    fn from(set: Vec<ScimApiToken>) -> Self {
        Self::ApiToken(set)
    }
}

impl From<Vec<ScimIntentToken>> for ScimValueKubidm {
    fn from(set: Vec<ScimIntentToken>) -> Self {
        Self::IntentToken(set)
    }
}

impl From<Vec<ScimOAuth2ScopeMap>> for ScimValueKubidm {
    fn from(set: Vec<ScimOAuth2ScopeMap>) -> Self {
        Self::OAuth2ScopeMap(set)
    }
}

impl From<Vec<ScimOAuth2ClaimMap>> for ScimValueKubidm {
    fn from(set: Vec<ScimOAuth2ClaimMap>) -> Self {
        Self::OAuth2ClaimMap(set)
    }
}

impl From<Vec<ScimKeyInternal>> for ScimValueKubidm {
    fn from(set: Vec<ScimKeyInternal>) -> Self {
        Self::KeyInternal(set)
    }
}

impl From<OutboundMessage> for ScimValueKubidm {
    fn from(message: OutboundMessage) -> Self {
        Self::Message(message)
    }
}

impl From<Vec<Sha256Output>> for ScimValueKubidm {
    fn from(set: Vec<Sha256Output>) -> Self {
        Self::Sha256(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::Attribute;
    use crate::scim_v1::{ScimMail, ScimOauth2ClaimMapJoinChar};

    fn test_datetime() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1700000000).unwrap()
    }

    #[test]
    fn scim_effective_access_serialize() {
        let ea = ScimEffectiveAccess {
            ident: Uuid::new_v4(),
            delete: true,
            search: ScimAttributeEffectiveAccess::Grant,
            modify_present: ScimAttributeEffectiveAccess::Deny,
            modify_remove: ScimAttributeEffectiveAccess::Allow(BTreeSet::from([Attribute::Name])),
        };
        let json = serde_json::to_value(&ea).unwrap();
        assert!(json.get("ident").is_some());
        assert_eq!(json["delete"], true);
        assert!(json.get("search").is_some());
        assert!(json.get("modifyPresent").is_some());
        assert!(json.get("modifyRemove").is_some());
    }

    #[test]
    fn scim_attribute_effective_access_grant() {
        let json = serde_json::to_value(ScimAttributeEffectiveAccess::Grant).unwrap();
        assert_eq!(json, serde_json::json!("Grant"));
    }

    #[test]
    fn scim_attribute_effective_access_deny() {
        let json = serde_json::to_value(ScimAttributeEffectiveAccess::Deny).unwrap();
        assert_eq!(json, serde_json::json!("Deny"));
    }

    #[test]
    fn scim_attribute_effective_access_allow() {
        let json = serde_json::to_value(ScimAttributeEffectiveAccess::Allow(BTreeSet::from([
            Attribute::Name,
            Attribute::Spn,
        ])))
        .unwrap();
        assert!(json.is_object());
        assert!(json.get("Allow").is_some());
    }

    #[test]
    fn scim_application_password_reference_serialize() {
        let r = ScimApplicationPasswordReference {
            uuid: Uuid::new_v4(),
            application_uuid: Uuid::new_v4(),
            label: "myapp".to_string(),
        };
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("uuid").is_some());
        assert!(json.get("applicationUuid").is_some());
        assert_eq!(json["label"], "myapp");
    }

    #[test]
    fn scim_binary_serialize() {
        let bin = ScimBinary {
            label: "testfile".to_string(),
            value: vec![0x01, 0x02, 0x03, 0x04],
        };
        let json = serde_json::to_value(&bin).unwrap();
        assert_eq!(json["label"], "testfile");
        assert!(json.get("value").is_some());
    }

    #[test]
    fn scim_certificate_serialize() {
        let cert = ScimCertificate {
            s256: vec![0xAB, 0xCD],
            der: vec![0x01, 0x02, 0x03],
        };
        let json = serde_json::to_value(&cert).unwrap();
        assert!(json.get("s256").is_some());
        assert!(json.get("der").is_some());
    }

    #[test]
    fn scim_audit_string_serialize() {
        let audit = ScimAuditString {
            date_time: test_datetime(),
            value: "test audit entry".to_string(),
        };
        let json = serde_json::to_value(&audit).unwrap();
        assert!(json.get("dateTime").is_some());
        assert_eq!(json["value"], "test audit entry");
    }

    #[test]
    fn scim_intent_token_state_serialize() {
        assert_eq!(
            serde_json::to_value(ScimIntentTokenState::Valid).unwrap(),
            serde_json::json!("valid")
        );
        assert_eq!(
            serde_json::to_value(ScimIntentTokenState::InProgress).unwrap(),
            serde_json::json!("inProgress")
        );
        assert_eq!(
            serde_json::to_value(ScimIntentTokenState::Consumed).unwrap(),
            serde_json::json!("consumed")
        );
    }

    #[test]
    fn scim_intent_token_serialize() {
        let token = ScimIntentToken {
            token_id: "abc123".to_string(),
            state: ScimIntentTokenState::Valid,
            expires: test_datetime(),
        };
        let json = serde_json::to_value(&token).unwrap();
        assert_eq!(json["tokenId"], "abc123");
        assert_eq!(json["state"], "valid");
        assert!(json.get("expires").is_some());
    }

    #[test]
    fn scim_key_internal_serialize() {
        let key = ScimKeyInternal {
            key_id: "key1".to_string(),
            status: "valid".to_string(),
            usage: "encryption".to_string(),
            valid_from: test_datetime(),
        };
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["keyId"], "key1");
        assert_eq!(json["status"], "valid");
        assert!(json.get("validFrom").is_some());
    }

    #[test]
    fn scim_auth_session_serialize() {
        let session = ScimAuthSession {
            id: Uuid::new_v4(),
            expires: Some(test_datetime()),
            revoked: None,
            issued_at: test_datetime(),
            issued_by: Uuid::new_v4(),
            credential_id: Uuid::new_v4(),
            auth_type: "password".to_string(),
            session_scope: "read".to_string(),
        };
        let json = serde_json::to_value(&session).unwrap();
        assert!(json.get("id").is_some());
        assert!(json.get("expires").is_some());
        assert!(json.get("revoked").is_none());
        assert!(json.get("issuedAt").is_some());
        assert_eq!(json["authType"], "password");
    }

    #[test]
    fn scim_oauth2_session_serialize() {
        let session = ScimOAuth2Session {
            id: Uuid::new_v4(),
            parent_id: Some(Uuid::new_v4()),
            client_id: Uuid::new_v4(),
            issued_at: test_datetime(),
            expires: None,
            revoked: None,
        };
        let json = serde_json::to_value(&session).unwrap();
        assert!(json.get("id").is_some());
        assert!(json.get("parentId").is_some());
        assert!(json.get("clientId").is_some());
        assert!(json.get("expires").is_none());
    }

    #[test]
    fn scim_api_token_serialize() {
        let token = ScimApiToken {
            id: Uuid::new_v4(),
            label: "mytoken".to_string(),
            expires: None,
            issued_at: test_datetime(),
            issued_by: Uuid::new_v4(),
            scope: "read write".to_string(),
        };
        let json = serde_json::to_value(&token).unwrap();
        assert_eq!(json["label"], "mytoken");
        assert!(json.get("expires").is_none());
        assert_eq!(json["scope"], "read write");
    }

    #[test]
    fn scim_oauth2_scope_map_server_serialize() {
        let sm = ScimOAuth2ScopeMap {
            group: "testgroup".to_string(),
            group_uuid: Uuid::new_v4(),
            scopes: BTreeSet::from(["read".to_string(), "write".to_string()]),
        };
        let json = serde_json::to_value(&sm).unwrap();
        assert_eq!(json["group"], "testgroup");
        assert!(json.get("groupUuid").is_some());
    }

    #[test]
    fn scim_oauth2_claim_map_server_serialize() {
        let cm = ScimOAuth2ClaimMap {
            group: "testgroup".to_string(),
            group_uuid: Uuid::new_v4(),
            claim: "email".to_string(),
            join_char: ScimOauth2ClaimMapJoinChar::CommaSeparatedValue,
            values: BTreeSet::from(["a@example.com".to_string()]),
        };
        let json = serde_json::to_value(&cm).unwrap();
        assert_eq!(json["claim"], "email");
    }

    #[test]
    fn scim_value_kubidm_bool() {
        let json = serde_json::to_value(ScimValueKubidm::Bool(true)).unwrap();
        assert_eq!(json, serde_json::json!(true));
    }

    #[test]
    fn scim_value_kubidm_uint32() {
        let json = serde_json::to_value(ScimValueKubidm::Uint32(42)).unwrap();
        assert_eq!(json, serde_json::json!(42));
    }

    #[test]
    fn scim_value_kubidm_int64() {
        let json = serde_json::to_value(ScimValueKubidm::Int64(-100)).unwrap();
        assert_eq!(json, serde_json::json!(-100));
    }

    #[test]
    fn scim_value_kubidm_uint64() {
        let json = serde_json::to_value(ScimValueKubidm::Uint64(999)).unwrap();
        assert_eq!(json, serde_json::json!(999));
    }

    #[test]
    fn scim_value_kubidm_integer() {
        let json = serde_json::to_value(ScimValueKubidm::Integer(-42)).unwrap();
        assert_eq!(json, serde_json::json!(-42));
    }

    #[test]
    fn scim_value_kubidm_decimal() {
        let json = serde_json::to_value(ScimValueKubidm::Decimal(2.5)).unwrap();
        assert!(json.is_number());
    }

    #[test]
    fn scim_value_kubidm_string() {
        let json = serde_json::to_value(ScimValueKubidm::String("hello".to_string())).unwrap();
        assert_eq!(json, serde_json::json!("hello"));
    }

    #[test]
    fn scim_value_kubidm_datetime() {
        let json = serde_json::to_value(ScimValueKubidm::DateTime(test_datetime())).unwrap();
        assert!(json.is_string());
    }

    #[test]
    fn scim_value_kubidm_reference() {
        let json = serde_json::to_value(ScimValueKubidm::Reference(
            Url::parse("https://example.com").unwrap(),
        ))
        .unwrap();
        assert_eq!(json, "https://example.com/");
    }

    #[test]
    fn scim_value_kubidm_uuid() {
        let uuid = Uuid::new_v4();
        let json = serde_json::to_value(ScimValueKubidm::Uuid(uuid)).unwrap();
        assert_eq!(json, uuid.to_string());
    }

    #[test]
    fn scim_value_kubidm_entry_reference() {
        let json = serde_json::to_value(ScimValueKubidm::EntryReference(ScimReference {
            uuid: Uuid::new_v4(),
            value: "test".to_string(),
        }))
        .unwrap();
        assert!(json.is_object());
    }

    #[test]
    fn scim_value_kubidm_entry_references() {
        let json = serde_json::to_value(ScimValueKubidm::EntryReferences(vec![
            ScimReference {
                uuid: Uuid::new_v4(),
                value: "a".to_string(),
            },
            ScimReference {
                uuid: Uuid::new_v4(),
                value: "b".to_string(),
            },
        ]))
        .unwrap();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 2);
    }

    #[test]
    fn scim_value_kubidm_array_string() {
        let json = serde_json::to_value(ScimValueKubidm::ArrayString(vec![
            "a".to_string(),
            "b".to_string(),
        ]))
        .unwrap();
        assert_eq!(json, serde_json::json!(["a", "b"]));
    }

    #[test]
    fn scim_value_kubidm_array_datetime() {
        let json = serde_json::to_value(ScimValueKubidm::ArrayDateTime(vec![
            test_datetime(),
            test_datetime(),
        ]))
        .unwrap();
        assert!(json.is_array());
    }

    #[test]
    fn scim_value_kubidm_array_uuid() {
        let uuids = vec![Uuid::new_v4(), Uuid::new_v4()];
        let json = serde_json::to_value(ScimValueKubidm::ArrayUuid(uuids.clone())).unwrap();
        assert_eq!(json[0], uuids[0].to_string());
        assert_eq!(json[1], uuids[1].to_string());
    }

    #[test]
    fn scim_value_kubidm_mail() {
        let json = serde_json::to_value(ScimValueKubidm::Mail(vec![ScimMail {
            primary: true,
            value: "test@example.com".to_string(),
        }]))
        .unwrap();
        assert!(json.is_array());
    }

    #[test]
    fn scim_value_kubidm_address() {
        let json = serde_json::to_value(ScimValueKubidm::Address(vec![super::ScimAddress {
            formatted: String::new(),
            street_address: "123 Main".to_string(),
            locality: "Town".to_string(),
            region: "ST".to_string(),
            postal_code: "00000".to_string(),
            country: "US".to_string(),
        }]))
        .unwrap();
        assert!(json.is_array());
    }

    #[test]
    fn scim_person_serialize() {
        let person = ScimPerson {
            uuid: Uuid::new_v4(),
            name: "testuser".to_string(),
            displayname: "Test User".to_string(),
            spn: "testuser@example.com".to_string(),
            description: Some("A test user".to_string()),
            mails: vec![ScimMail {
                primary: true,
                value: "test@example.com".to_string(),
            }],
            managed_by: Some(ScimReference {
                uuid: Uuid::new_v4(),
                value: "admin".to_string(),
            }),
            groups: vec![ScimReference {
                uuid: Uuid::new_v4(),
                value: "group1".to_string(),
            }],
        };
        let json = serde_json::to_value(&person).unwrap();
        assert_eq!(json["name"], "testuser");
        assert_eq!(json["displayname"], "Test User");
        assert_eq!(json["spn"], "testuser@example.com");
        assert!(json.get("description").is_some());
        assert!(json.get("mails").is_some());
        assert!(json.get("managed_by").is_some());
        assert!(json.get("groups").is_some());
    }

    #[test]
    fn scim_group_serialize() {
        let group = ScimGroup {
            uuid: Uuid::new_v4(),
            name: "testgroup".to_string(),
            description: Some("A test group".to_string()),
            members: vec![ScimReference {
                uuid: Uuid::new_v4(),
                value: "user1".to_string(),
            }],
        };
        let json = serde_json::to_value(&group).unwrap();
        assert_eq!(json["name"], "testgroup");
        assert!(json.get("description").is_some());
        assert!(json.get("members").is_some());
        assert_eq!(json["members"].as_array().unwrap().len(), 1);
    }
}
