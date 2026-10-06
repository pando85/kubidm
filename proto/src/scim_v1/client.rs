//! These are types that a client will send to the server.
use super::{ScimEntryGeneric, ScimEntryGetQuery, ScimMail, ScimOauth2ClaimMapJoinChar};
use crate::{attribute::Attribute, v1::OutboundMessage};
use scim_proto::ScimEntryHeader;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::{
    base64, formats, formats::PreferMany, serde_as, skip_serializing_none, OneOrMany,
};
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

pub type ScimSshPublicKeys = Vec<ScimSshPublicKey>;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScimSshPublicKey {
    pub label: String,
    pub value: SshPublicKey,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScimReferenceAdapter {
    Complete { uuid: Uuid, value: String },
    Uuid { uuid: Uuid },
    UuidX(Uuid),
    Value { value: String },
    ValueX(String),
}

impl From<ScimReferenceAdapter> for ScimReference {
    fn from(scr: ScimReferenceAdapter) -> Self {
        match scr {
            ScimReferenceAdapter::Complete { uuid, value } => ScimReference {
                uuid: Some(uuid),
                value: Some(value),
            },
            ScimReferenceAdapter::Uuid { uuid } | ScimReferenceAdapter::UuidX(uuid) => {
                ScimReference {
                    uuid: Some(uuid),
                    value: None,
                }
            }
            ScimReferenceAdapter::Value { value } | ScimReferenceAdapter::ValueX(value) => {
                ScimReference {
                    uuid: None,
                    value: Some(value),
                }
            }
        }
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    from = "ScimReferenceAdapter"
)]
pub struct ScimReference {
    pub uuid: Option<Uuid>,
    pub value: Option<String>,
}

impl<T> From<T> for ScimReference
where
    T: AsRef<str>,
{
    fn from(value: T) -> Self {
        ScimReference {
            uuid: None,
            value: Some(value.as_ref().to_string()),
        }
    }
}

pub type ScimReferences = Vec<ScimReference>;

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct ScimDateTime {
    #[serde_as(as = "Rfc3339")]
    pub date_time: OffsetDateTime,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScimCertificate {
    #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
    pub der: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScimAddress {
    pub street_address: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2ClaimMap {
    pub group: Option<String>,
    pub group_uuid: Option<Uuid>,
    pub claim: String,
    pub join_char: ScimOauth2ClaimMapJoinChar,
    pub values: BTreeSet<String>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2ScopeMap {
    pub group: Option<String>,
    pub group_uuid: Option<Uuid>,
    pub scopes: BTreeSet<String>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScimListEntry {
    pub schemas: Vec<String>,
    pub total_results: u64,
    pub items_per_page: Option<NonZeroU64>,
    pub start_index: Option<NonZeroU64>,
    pub resources: Vec<ScimEntryGeneric>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScimEntryApplicationPost {
    pub name: String,
    pub displayname: String,
    pub linked_group: ScimReference,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScimEntryApplication {
    #[serde(flatten)]
    pub header: ScimEntryHeader,

    pub name: String,
    pub displayname: String,

    pub linked_group: Vec<super::ScimReference>,

    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScimListApplication {
    pub schemas: Vec<String>,
    pub total_results: u64,
    pub items_per_page: Option<NonZeroU64>,
    pub start_index: Option<NonZeroU64>,
    pub resources: Vec<ScimEntryApplication>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScimEntryMessage {
    #[serde(flatten)]
    pub header: ScimEntryHeader,

    pub message_template: OutboundMessage,
    pub send_after: ScimDateTime,
    pub delete_after: ScimDateTime,
    pub sent_at: Option<ScimDateTime>,
    pub mail_destination: Vec<ScimMail>,

    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScimListMessage {
    pub schemas: Vec<String>,
    pub total_results: u64,
    pub items_per_page: Option<NonZeroU64>,
    pub start_index: Option<NonZeroU64>,
    pub resources: Vec<ScimEntryMessage>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScimEntrySchemaClass {
    #[serde(flatten)]
    pub header: ScimEntryHeader,

    // pub name: String,
    // pub displayname: String,
    // pub linked_group: Vec<super::ScimReference>,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[serde_as]
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScimListSchemaClass {
    pub schemas: Vec<String>,
    pub total_results: u64,
    pub items_per_page: Option<NonZeroU64>,
    pub start_index: Option<NonZeroU64>,
    pub resources: Vec<ScimEntrySchemaClass>,
}

#[serde_as]
#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ScimEntrySchemaAttribute {
    #[serde(flatten)]
    pub header: ScimEntryHeader,

    pub attributename: String,
    pub description: String,
    // TODO: To be removed
    pub multivalue: bool,
    pub unique: bool,
    pub syntax: String,
    // pub linked_group: Vec<super::ScimReference>,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[serde_as]
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScimListSchemaAttribute {
    pub schemas: Vec<String>,
    pub total_results: u64,
    pub items_per_page: Option<NonZeroU64>,
    pub start_index: Option<NonZeroU64>,
    pub resources: Vec<ScimEntrySchemaAttribute>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ScimEntryPutKubidm {
    pub id: Uuid,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, Option<super::server::ScimValueKubidm>>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScimStrings(#[serde_as(as = "OneOrMany<_, PreferMany>")] pub Vec<String>);

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScimUrls(#[serde_as(as = "OneOrMany<_, PreferMany>")] pub Vec<Url>);

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct ScimEntryPostGeneric {
    /// Create an attribute to contain the following value state.
    #[serde(flatten)]
    #[schema(value_type = Object, additional_properties = true)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase", tag = "state")]
pub enum ScimEntryAssertion {
    /// The entry should be present, with this id/UUID, and
    /// the content of these attributes must be as shown. If an
    /// attribute is not present in the assertion, it will not be
    /// altered. To remove an attribute, set the attribute to "null".
    Present {
        id: Uuid,
        #[schema(value_type = BTreeMap<String, Value>)]
        #[serde(flatten)]
        attrs: BTreeMap<Attribute, Option<JsonValue>>,
    },
    /// The entry should be absent (removed) from the database. Once
    /// removed, the entry can not be re-asserted. You will need to create
    /// a new entry with a unique ID.
    Absent { id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct ScimAssertGeneric {
    /// The ID of this assertion.
    pub id: Uuid,

    /// A set of assertions about expected entry state.
    pub assertions: Vec<ScimEntryAssertion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct ScimEntryPutGeneric {
    // id is only used to target the entry in question
    pub id: Uuid,

    #[serde(flatten)]
    /// Non-standard extension - allow query options to be set in a put request. This
    /// is because a put request also returns the entry state post put, so we want
    /// to allow putters to adjust and control what is returned here.
    pub query: ScimEntryGetQuery,

    // external_id can't be set by put
    // meta is skipped on put
    // Schemas are decoded as part of "attrs".
    /// Update an attribute to contain the following value state.
    /// If the attribute is None, it is removed.
    #[schema(value_type = BTreeMap<String, Value>)]
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, Option<JsonValue>>,
}

impl TryFrom<ScimEntryPutKubidm> for ScimEntryPutGeneric {
    type Error = serde_json::Error;

    fn try_from(value: ScimEntryPutKubidm) -> Result<Self, Self::Error> {
        let ScimEntryPutKubidm { id, attrs } = value;

        let attrs = attrs
            .into_iter()
            .map(|(attr, value)| {
                if let Some(v) = value {
                    serde_json::to_value(v).map(|json_value| (attr, Some(json_value)))
                } else {
                    Ok((attr, None))
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(ScimEntryPutGeneric {
            id,
            attrs,
            query: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim_v1::{ScimEntryGeneric, ScimEntryGetQuery, ScimOauth2ClaimMapJoinChar};
    use scim_proto::ScimEntryHeader;
    use sshkey_attest::proto::PublicKey as SshPublicKey;

    const TEST_SSH_ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl testuser";

    fn test_datetime() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1700000000).unwrap()
    }

    #[test]
    fn scim_ssh_public_key_roundtrip() {
        let key = ScimSshPublicKey {
            label: "testkey".to_string(),
            value: SshPublicKey::from_string(TEST_SSH_ED25519).unwrap(),
        };
        let json = serde_json::to_string(&key).unwrap();
        let de: ScimSshPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(de.label, "testkey");
    }

    #[test]
    fn scim_reference_roundtrip() {
        let uuid = Uuid::new_v4();
        let r = ScimReference {
            uuid: Some(uuid),
            value: Some("testgroup".to_string()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let de: ScimReference = serde_json::from_str(&json).unwrap();
        assert_eq!(de.uuid, Some(uuid));
        assert_eq!(de.value, Some("testgroup".to_string()));
    }

    #[test]
    fn scim_reference_deserialize_from_string() {
        let de: ScimReference = serde_json::from_str("\"some_value\"").unwrap();
        assert_eq!(de.uuid, None);
        assert_eq!(de.value, Some("some_value".to_string()));
    }

    #[test]
    fn scim_reference_deserialize_from_uuid_string() {
        let uuid = Uuid::new_v4();
        let json = format!("\"{uuid}\"");
        let de: ScimReference = serde_json::from_str(&json).unwrap();
        assert_eq!(de.uuid, Some(uuid));
        assert_eq!(de.value, None);
    }

    #[test]
    fn scim_reference_deserialize_from_object_both() {
        let uuid = Uuid::new_v4();
        let json = serde_json::json!({"uuid": uuid.to_string(), "value": "mygroup"});
        let de: ScimReference = serde_json::from_value(json).unwrap();
        assert_eq!(de.uuid, Some(uuid));
        assert_eq!(de.value, Some("mygroup".to_string()));
    }

    #[test]
    fn scim_reference_deserialize_from_object_uuid_only() {
        let uuid = Uuid::new_v4();
        let json = serde_json::json!({"uuid": uuid.to_string()});
        let de: ScimReference = serde_json::from_value(json).unwrap();
        assert_eq!(de.uuid, Some(uuid));
        assert_eq!(de.value, None);
    }

    #[test]
    fn scim_reference_skip_serializing_none() {
        let r = ScimReference {
            uuid: None,
            value: Some("only_value".to_string()),
        };
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("uuid").is_none());
        assert_eq!(json["value"], "only_value");
    }

    #[test]
    fn scim_datetime_roundtrip() {
        let dt = ScimDateTime {
            date_time: test_datetime(),
        };
        let json = serde_json::to_string(&dt).unwrap();
        assert!(json.starts_with('"'));
        let de: ScimDateTime = serde_json::from_str(&json).unwrap();
        assert_eq!(de, dt);
    }

    #[test]
    fn scim_certificate_roundtrip() {
        let cert = ScimCertificate {
            der: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let json = serde_json::to_string(&cert).unwrap();
        let de: ScimCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(de, cert);
    }

    #[test]
    fn scim_address_roundtrip() {
        let addr = ScimAddress {
            street_address: "123 Main St".to_string(),
            locality: "Springfield".to_string(),
            region: "IL".to_string(),
            postal_code: "62701".to_string(),
            country: "US".to_string(),
        };
        let json = serde_json::to_string(&addr).unwrap();
        let de: ScimAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(de, addr);
    }

    #[test]
    fn scim_oauth2_claim_map_roundtrip() {
        let claim_map = ScimOAuth2ClaimMap {
            group: Some("testgroup".to_string()),
            group_uuid: Some(Uuid::new_v4()),
            claim: "test_claim".to_string(),
            join_char: ScimOauth2ClaimMapJoinChar::CommaSeparatedValue,
            values: BTreeSet::from(["val1".to_string(), "val2".to_string()]),
        };
        let json = serde_json::to_string(&claim_map).unwrap();
        let de: ScimOAuth2ClaimMap = serde_json::from_str(&json).unwrap();
        assert_eq!(de.claim, "test_claim");
        assert_eq!(de.values.len(), 2);
    }

    #[test]
    fn scim_oauth2_scope_map_roundtrip() {
        let scope_map = ScimOAuth2ScopeMap {
            group: Some("testgroup".to_string()),
            group_uuid: Some(Uuid::new_v4()),
            scopes: BTreeSet::from(["read".to_string(), "write".to_string()]),
        };
        let json = serde_json::to_string(&scope_map).unwrap();
        let de: ScimOAuth2ScopeMap = serde_json::from_str(&json).unwrap();
        assert_eq!(de.scopes.len(), 2);
    }

    #[test]
    fn scim_list_entry_roundtrip() {
        let entry = ScimEntryGeneric {
            header: ScimEntryHeader {
                schemas: vec!["urn:test:schema".to_string()],
                id: Uuid::new_v4(),
                external_id: None,
                meta: None,
            },
            attrs: BTreeMap::new(),
        };
        let list = ScimListEntry {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
            total_results: 1,
            items_per_page: None,
            start_index: None,
            resources: vec![entry],
        };
        let json = serde_json::to_string(&list).unwrap();
        let de: ScimListEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(de.total_results, 1);
        assert_eq!(de.resources.len(), 1);
    }

    #[test]
    fn scim_entry_application_post_serialize() {
        let post = ScimEntryApplicationPost {
            name: "testapp".to_string(),
            displayname: "Test Application".to_string(),
            linked_group: ScimReference {
                uuid: Some(Uuid::new_v4()),
                value: Some("testgroup".to_string()),
            },
        };
        let json = serde_json::to_value(&post).unwrap();
        assert_eq!(json["name"], "testapp");
        assert_eq!(json["displayname"], "Test Application");
        assert!(json.get("linked_group").is_some());
    }

    #[test]
    fn scim_entry_application_deserialize() {
        let uuid = Uuid::new_v4();
        let group_uuid = Uuid::new_v4();
        let json = serde_json::json!({
            "schemas": ["urn:test:schema"],
            "id": uuid.to_string(),
            "name": "testapp",
            "displayname": "Test App",
            "linked_group": [{"uuid": group_uuid.to_string(), "value": "group1"}]
        });
        let app: ScimEntryApplication = serde_json::from_value(json).unwrap();
        assert_eq!(app.name, "testapp");
        assert_eq!(app.displayname, "Test App");
        assert_eq!(app.linked_group.len(), 1);
    }

    #[test]
    fn scim_entry_assertion_present_roundtrip() {
        let uuid = Uuid::new_v4();
        let assertion = ScimEntryAssertion::Present {
            id: uuid,
            attrs: BTreeMap::from([(Attribute::Name, Some(serde_json::json!("testname")))]),
        };
        let json = serde_json::to_string(&assertion).unwrap();
        let de: ScimEntryAssertion = serde_json::from_str(&json).unwrap();
        match de {
            ScimEntryAssertion::Present { id, attrs } => {
                assert_eq!(id, uuid);
                assert!(attrs.contains_key(&Attribute::Name));
            }
            ScimEntryAssertion::Absent { .. } => panic!("Expected Present variant"),
        }
    }

    #[test]
    fn scim_entry_assertion_absent_roundtrip() {
        let uuid = Uuid::new_v4();
        let assertion = ScimEntryAssertion::Absent { id: uuid };
        let json = serde_json::to_string(&assertion).unwrap();
        let de: ScimEntryAssertion = serde_json::from_str(&json).unwrap();
        match de {
            ScimEntryAssertion::Absent { id } => assert_eq!(id, uuid),
            ScimEntryAssertion::Present { .. } => panic!("Expected Absent variant"),
        }
    }

    #[test]
    fn scim_entry_put_generic_roundtrip() {
        let uuid = Uuid::new_v4();
        let put = ScimEntryPutGeneric {
            id: uuid,
            query: ScimEntryGetQuery::default(),
            attrs: BTreeMap::from([(Attribute::Name, Some(serde_json::json!("testname")))]),
        };
        let json = serde_json::to_string(&put).unwrap();
        let de: ScimEntryPutGeneric = serde_json::from_str(&json).unwrap();
        assert_eq!(de.id, uuid);
        assert!(de.attrs.contains_key(&Attribute::Name));
    }

    #[test]
    fn scim_entry_post_generic_roundtrip() {
        let post = ScimEntryPostGeneric {
            attrs: BTreeMap::from([(Attribute::Name, serde_json::json!("testname"))]),
        };
        let json = serde_json::to_string(&post).unwrap();
        let de: ScimEntryPostGeneric = serde_json::from_str(&json).unwrap();
        assert!(de.attrs.contains_key(&Attribute::Name));
    }
}
