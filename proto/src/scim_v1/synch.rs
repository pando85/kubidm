use serde::{Deserialize, Serialize};
use serde_with::{base64, formats, serde_as};
use utoipa::ToSchema;
use uuid::Uuid;

use scim_proto::{user::MultiValueAttr, ScimEntry, ScimEntryHeader};
use serde_with::skip_serializing_none;

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub enum ScimSyncState {
    Refresh,
    Active {
        #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
        cookie: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub enum ScimSyncRetentionMode {
    /// No actions are to be taken - only update or create entries in the
    /// entries set.
    Ignore,
    /// All entries that have their uuid present in this set are retained.
    /// Anything not present will be deleted.
    Retain(Vec<Uuid>),
    /// Any entry with its UUID in this set will be deleted. Anything not
    /// present will be retained.
    Delete(Vec<Uuid>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ScimSyncRequest {
    pub from_state: ScimSyncState,
    pub to_state: ScimSyncState,

    // These entries are created with serde_json::to_value(ScimSyncGroup) for
    // example. This is how we can mix/match the different types.
    pub entries: Vec<ScimEntry>,

    pub retain: ScimSyncRetentionMode,
}

impl ScimSyncRequest {
    pub fn need_refresh(from_state: ScimSyncState) -> Self {
        ScimSyncRequest {
            from_state,
            to_state: ScimSyncState::Refresh,
            entries: Vec::default(),
            retain: ScimSyncRetentionMode::Ignore,
        }
    }
}

pub const SCIM_SCHEMA_SYNC_1: &str = "urn:ietf:params:scim:schemas:kubidm:sync:1:";
pub const SCIM_SCHEMA_SYNC_ACCOUNT: &str = "urn:ietf:params:scim:schemas:kubidm:sync:1:account";
pub const SCIM_SCHEMA_SYNC_GROUP: &str = "urn:ietf:params:scim:schemas:kubidm:sync:1:group";
pub const SCIM_SCHEMA_SYNC_PERSON: &str = "urn:ietf:params:scim:schemas:kubidm:sync:1:person";
pub const SCIM_SCHEMA_SYNC_OAUTH2_ACCOUNT: &str =
    "urn:ietf:params:scim:schemas:kubidm:sync:1:oauth2_account";
pub const SCIM_SCHEMA_SYNC_POSIXACCOUNT: &str =
    "urn:ietf:params:scim:schemas:kubidm:sync:1:posixaccount";
pub const SCIM_SCHEMA_SYNC_POSIXGROUP: &str =
    "urn:ietf:params:scim:schemas:kubidm:sync:1:posixgroup";

pub const SCIM_ALGO: &str = "algo";
pub const SCIM_DIGITS: &str = "digits";
pub const SCIM_SECRET: &str = "secret";
pub const SCIM_STEP: &str = "step";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimTotp {
    /// maps to "label" in kubidm.
    pub external_id: String,
    pub secret: String,
    pub algo: String,
    pub step: u32,
    pub digits: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimSshPubKey {
    pub label: String,
    pub value: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScimSyncPerson {
    #[serde(flatten)]
    pub entry: ScimEntryHeader,

    pub name: String,
    pub displayname: String,
    pub gidnumber: Option<u32>,
    pub password_import: Option<String>,
    pub unix_password_import: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub totp_import: Vec<ScimTotp>,
    pub loginshell: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mail: Vec<MultiValueAttr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_publickey: Vec<ScimSshPubKey>,
    pub account_valid_from: Option<String>,
    pub account_expire: Option<String>,
    pub oauth2_account_provider: Option<Uuid>,
    pub oauth2_account_unique_user_id: Option<String>,
}

impl TryInto<ScimEntry> for ScimSyncPerson {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<ScimEntry, Self::Error> {
        serde_json::to_value(self).and_then(serde_json::from_value)
    }
}

pub struct ScimSyncPersonBuilder {
    inner: ScimSyncPerson,
}

impl ScimSyncPerson {
    pub fn builder(
        id: Uuid,
        external_id: String,
        name: String,
        displayname: String,
    ) -> ScimSyncPersonBuilder {
        ScimSyncPersonBuilder {
            inner: ScimSyncPerson {
                entry: ScimEntryHeader {
                    schemas: vec![
                        SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
                        SCIM_SCHEMA_SYNC_PERSON.to_string(),
                    ],
                    id,
                    external_id: Some(external_id),
                    meta: None,
                },
                name,
                displayname,
                gidnumber: None,
                password_import: None,
                unix_password_import: None,
                totp_import: Vec::with_capacity(0),
                loginshell: None,
                mail: Vec::with_capacity(0),
                ssh_publickey: Vec::with_capacity(0),
                account_valid_from: None,
                account_expire: None,
                oauth2_account_provider: None,
                oauth2_account_unique_user_id: None,
            },
        }
    }
}

impl ScimSyncPersonBuilder {
    pub fn set_password_import(mut self, password_import: Option<String>) -> Self {
        self.inner.password_import = password_import;
        self
    }

    pub fn set_unix_password_import(mut self, unix_password_import: Option<String>) -> Self {
        self.inner.unix_password_import = unix_password_import;
        self
    }

    pub fn set_totp_import(mut self, totp_import: Vec<ScimTotp>) -> Self {
        self.inner.totp_import = totp_import;
        self
    }

    pub fn set_mail(mut self, mail: Vec<MultiValueAttr>) -> Self {
        self.inner.mail = mail;
        self
    }

    pub fn set_ssh_publickey(mut self, ssh_publickey: Vec<ScimSshPubKey>) -> Self {
        self.inner.ssh_publickey = ssh_publickey;
        self
    }

    pub fn set_login_shell(mut self, loginshell: Option<String>) -> Self {
        self.inner.loginshell = loginshell;
        self
    }

    pub fn set_account_valid_from(mut self, account_valid_from: Option<String>) -> Self {
        self.inner.account_valid_from = account_valid_from;
        self
    }

    pub fn set_account_expire(mut self, account_expire: Option<String>) -> Self {
        self.inner.account_expire = account_expire;
        self
    }

    pub fn set_gidnumber(mut self, gidnumber: Option<u32>) -> Self {
        self.inner.gidnumber = gidnumber;
        if self.inner.gidnumber.is_some() {
            self.inner.entry.schemas = vec![
                SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
                SCIM_SCHEMA_SYNC_PERSON.to_string(),
                SCIM_SCHEMA_SYNC_POSIXACCOUNT.to_string(),
            ];
        } else {
            self.inner.entry.schemas = vec![
                SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
                SCIM_SCHEMA_SYNC_PERSON.to_string(),
            ];
        }
        self
    }

    pub fn set_oauth2_account_provider(mut self, maybe_provider: Option<(Uuid, String)>) -> Self {
        if let Some((provider, unique_user_id)) = maybe_provider {
            self.inner
                .entry
                .schemas
                .push(SCIM_SCHEMA_SYNC_OAUTH2_ACCOUNT.to_string());
            self.inner.oauth2_account_provider = Some(provider);
            self.inner.oauth2_account_unique_user_id = Some(unique_user_id);
        } else {
            self.inner
                .entry
                .schemas
                .retain(|x| x != SCIM_SCHEMA_SYNC_OAUTH2_ACCOUNT);
            self.inner.oauth2_account_provider = None;
            self.inner.oauth2_account_unique_user_id = None;
        }
        self
    }

    pub fn build(self) -> ScimSyncPerson {
        self.inner
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimExternalMember {
    pub external_id: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScimSyncGroup {
    #[serde(flatten)]
    pub entry: ScimEntryHeader,

    pub name: String,
    pub description: Option<String>,
    pub gidnumber: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member: Vec<ScimExternalMember>,
}

impl TryInto<ScimEntry> for ScimSyncGroup {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<ScimEntry, Self::Error> {
        serde_json::to_value(self).and_then(serde_json::from_value)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimSyncGroupBuilder {
    inner: ScimSyncGroup,
}

impl ScimSyncGroup {
    pub fn builder(id: Uuid, external_id: String, name: String) -> ScimSyncGroupBuilder {
        ScimSyncGroupBuilder {
            inner: ScimSyncGroup {
                entry: ScimEntryHeader {
                    schemas: vec![SCIM_SCHEMA_SYNC_GROUP.to_string()],
                    id,
                    external_id: Some(external_id),
                    meta: None,
                },
                name,
                description: None,
                gidnumber: None,
                member: Vec::with_capacity(0),
            },
        }
    }
}

impl ScimSyncGroupBuilder {
    pub fn set_description(mut self, desc: Option<String>) -> Self {
        self.inner.description = desc;
        self
    }

    pub fn set_gidnumber(mut self, gidnumber: Option<u32>) -> Self {
        self.inner.gidnumber = gidnumber;
        if self.inner.gidnumber.is_some() {
            self.inner.entry.schemas = vec![
                SCIM_SCHEMA_SYNC_GROUP.to_string(),
                SCIM_SCHEMA_SYNC_POSIXGROUP.to_string(),
            ];
        } else {
            self.inner.entry.schemas = vec![SCIM_SCHEMA_SYNC_GROUP.to_string()];
        }
        self
    }

    pub fn set_members<I>(mut self, member_iter: I) -> Self
    where
        I: Iterator<Item = String>,
    {
        self.inner.member = member_iter
            .map(|external_id| ScimExternalMember { external_id })
            .collect();
        self
    }

    pub fn build(self) -> ScimSyncGroup {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn scim_sync_state_refresh_serde() {
        let state = ScimSyncState::Refresh;
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ScimSyncState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn scim_sync_state_active_serde() {
        let state = ScimSyncState::Active {
            cookie: vec![1, 2, 3, 4],
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ScimSyncState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn scim_sync_state_active_empty_cookie() {
        let state = ScimSyncState::Active { cookie: vec![] };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ScimSyncState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn scim_sync_retention_mode_ignore_serde() {
        let mode = ScimSyncRetentionMode::Ignore;
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: ScimSyncRetentionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn scim_sync_retention_mode_retain_serde() {
        let uuids = vec![Uuid::new_v4(), Uuid::new_v4()];
        let mode = ScimSyncRetentionMode::Retain(uuids.clone());
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: ScimSyncRetentionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn scim_sync_retention_mode_delete_serde() {
        let uuids = vec![Uuid::new_v4()];
        let mode = ScimSyncRetentionMode::Delete(uuids.clone());
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: ScimSyncRetentionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn scim_sync_request_need_refresh() {
        let req = ScimSyncRequest::need_refresh(ScimSyncState::Refresh);
        assert_eq!(req.from_state, ScimSyncState::Refresh);
        assert_eq!(req.to_state, ScimSyncState::Refresh);
        assert!(req.entries.is_empty());
        assert_eq!(req.retain, ScimSyncRetentionMode::Ignore);
    }

    #[test]
    fn scim_sync_request_serde_roundtrip() {
        let req = ScimSyncRequest {
            from_state: ScimSyncState::Refresh,
            to_state: ScimSyncState::Active { cookie: vec![42] },
            entries: Vec::new(),
            retain: ScimSyncRetentionMode::Retain(vec![]),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ScimSyncRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.from_state, deserialized.from_state);
        assert_eq!(req.to_state, deserialized.to_state);
        assert!(deserialized.entries.is_empty());
        assert_eq!(req.retain, deserialized.retain);
    }

    #[test]
    fn scim_totp_serde() {
        let totp = ScimTotp {
            external_id: "my_totp".to_string(),
            secret: "ABCDEFGH".to_string(),
            algo: "SHA1".to_string(),
            step: 30,
            digits: 6,
        };
        let json = serde_json::to_string(&totp).unwrap();
        let deserialized: ScimTotp = serde_json::from_str(&json).unwrap();
        let reserialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, reserialized);
    }

    #[test]
    fn scim_ssh_pubkey_serde() {
        let key = ScimSshPubKey {
            label: "workstation".to_string(),
            value: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test".to_string(),
        };
        let json = serde_json::to_string(&key).unwrap();
        let deserialized: ScimSshPubKey = serde_json::from_str(&json).unwrap();
        let reserialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, reserialized);
    }

    #[test]
    fn scim_sync_person_serde_minimal() {
        let person = ScimSyncPerson {
            entry: ScimEntryHeader {
                schemas: vec![SCIM_SCHEMA_SYNC_ACCOUNT.to_string()],
                id: Uuid::new_v4(),
                external_id: Some("cn=test".to_string()),
                meta: None,
            },
            name: "testuser".to_string(),
            displayname: "Test User".to_string(),
            gidnumber: None,
            password_import: None,
            unix_password_import: None,
            totp_import: vec![],
            loginshell: None,
            mail: vec![],
            ssh_publickey: vec![],
            account_valid_from: None,
            account_expire: None,
            oauth2_account_provider: None,
            oauth2_account_unique_user_id: None,
        };
        let json = serde_json::to_string(&person).unwrap();
        let deserialized: ScimSyncPerson = serde_json::from_str(&json).unwrap();
        assert_eq!(person.name, deserialized.name);
        assert_eq!(person.displayname, deserialized.displayname);
        assert_eq!(person.entry.id, deserialized.entry.id);
    }

    #[test]
    fn scim_sync_person_serde_full() {
        let person = ScimSyncPerson {
            entry: ScimEntryHeader {
                schemas: vec![
                    SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
                    SCIM_SCHEMA_SYNC_PERSON.to_string(),
                ],
                id: Uuid::new_v4(),
                external_id: Some("cn=fulluser".to_string()),
                meta: None,
            },
            name: "fulluser".to_string(),
            displayname: "Full User".to_string(),
            gidnumber: Some(1000),
            password_import: Some("password123".to_string()),
            unix_password_import: Some("unixpass".to_string()),
            totp_import: vec![ScimTotp {
                external_id: "totp1".to_string(),
                secret: "secret".to_string(),
                algo: "SHA256".to_string(),
                step: 30,
                digits: 6,
            }],
            loginshell: Some("/bin/bash".to_string()),
            mail: vec![MultiValueAttr {
                primary: Some(true),
                value: "user@example.com".to_string(),
                ..Default::default()
            }],
            ssh_publickey: vec![ScimSshPubKey {
                label: "mykey".to_string(),
                value: "ssh-rsa AAAA...".to_string(),
            }],
            account_valid_from: Some("2023-01-01T00:00:00Z".to_string()),
            account_expire: Some("2025-01-01T00:00:00Z".to_string()),
            oauth2_account_provider: Some(Uuid::new_v4()),
            oauth2_account_unique_user_id: Some("oauth2_id".to_string()),
        };
        let json = serde_json::to_string(&person).unwrap();
        let deserialized: ScimSyncPerson = serde_json::from_str(&json).unwrap();
        let reserialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, reserialized);
    }

    #[test]
    fn scim_sync_group_serde_minimal() {
        let group = ScimSyncGroup {
            entry: ScimEntryHeader {
                schemas: vec![SCIM_SCHEMA_SYNC_GROUP.to_string()],
                id: Uuid::new_v4(),
                external_id: Some("cn=testgroup".to_string()),
                meta: None,
            },
            name: "testgroup".to_string(),
            description: None,
            gidnumber: None,
            member: vec![],
        };
        let json = serde_json::to_string(&group).unwrap();
        let deserialized: ScimSyncGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(group.name, deserialized.name);
        assert_eq!(group.entry.id, deserialized.entry.id);
    }

    #[test]
    fn scim_sync_group_serde_full() {
        let group = ScimSyncGroup {
            entry: ScimEntryHeader {
                schemas: vec![SCIM_SCHEMA_SYNC_GROUP.to_string()],
                id: Uuid::new_v4(),
                external_id: Some("cn=fullgroup".to_string()),
                meta: None,
            },
            name: "fullgroup".to_string(),
            description: Some("A test group".to_string()),
            gidnumber: Some(2000),
            member: vec![
                ScimExternalMember {
                    external_id: "member_a".to_string(),
                },
                ScimExternalMember {
                    external_id: "member_b".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&group).unwrap();
        let deserialized: ScimSyncGroup = serde_json::from_str(&json).unwrap();
        let reserialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, reserialized);
    }

    #[test]
    fn person_builder_new() {
        let id = Uuid::new_v4();
        let person = ScimSyncPerson::builder(
            id,
            "cn=test".to_string(),
            "testuser".to_string(),
            "Test User".to_string(),
        )
        .build();
        assert_eq!(person.entry.id, id);
        assert_eq!(person.entry.external_id, Some("cn=test".to_string()));
        assert_eq!(person.name, "testuser");
        assert_eq!(person.displayname, "Test User");
        assert!(person.password_import.is_none());
        assert!(person.unix_password_import.is_none());
        assert!(person.totp_import.is_empty());
        assert!(person.mail.is_empty());
        assert!(person.ssh_publickey.is_empty());
        assert!(person.loginshell.is_none());
        assert!(person.account_valid_from.is_none());
        assert!(person.account_expire.is_none());
        assert!(person.gidnumber.is_none());
        assert!(person.oauth2_account_provider.is_none());
        assert!(person.oauth2_account_unique_user_id.is_none());
        assert_eq!(person.entry.schemas.len(), 2);
    }

    #[test]
    fn person_builder_set_password_import() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_password_import(Some("hashed_pw".to_string()))
        .build();
        assert_eq!(person.password_import, Some("hashed_pw".to_string()));
    }

    #[test]
    fn person_builder_set_unix_password_import() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_unix_password_import(Some("unix_hashed".to_string()))
        .build();
        assert_eq!(person.unix_password_import, Some("unix_hashed".to_string()));
    }

    #[test]
    fn person_builder_set_totp_import() {
        let totp = ScimTotp {
            external_id: "totp_label".to_string(),
            secret: "ASECRET".to_string(),
            algo: "SHA512".to_string(),
            step: 60,
            digits: 8,
        };
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_totp_import(vec![totp])
        .build();
        assert_eq!(person.totp_import.len(), 1);
        assert_eq!(person.totp_import[0].external_id, "totp_label");
        assert_eq!(person.totp_import[0].step, 60);
    }

    #[test]
    fn person_builder_set_ssh_publickey() {
        let key = ScimSshPubKey {
            label: "mykey".to_string(),
            value: "ssh-ed25519 AAAA".to_string(),
        };
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_ssh_publickey(vec![key])
        .build();
        assert_eq!(person.ssh_publickey.len(), 1);
        assert_eq!(person.ssh_publickey[0].label, "mykey");
    }

    #[test]
    fn person_builder_set_login_shell() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_login_shell(Some("/bin/zsh".to_string()))
        .build();
        assert_eq!(person.loginshell, Some("/bin/zsh".to_string()));
    }

    #[test]
    fn person_builder_set_mail() {
        let mail = MultiValueAttr {
            primary: Some(true),
            value: "a@b.com".to_string(),
            ..Default::default()
        };
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_mail(vec![mail])
        .build();
        assert_eq!(person.mail.len(), 1);
        assert_eq!(person.mail[0].value, "a@b.com");
    }

    #[test]
    fn person_builder_set_account_valid_from() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_account_valid_from(Some("2023-01-01T00:00:00Z".to_string()))
        .build();
        assert_eq!(
            person.account_valid_from,
            Some("2023-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn person_builder_set_account_expire() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_account_expire(Some("2025-12-31T23:59:59Z".to_string()))
        .build();
        assert_eq!(
            person.account_expire,
            Some("2025-12-31T23:59:59Z".to_string())
        );
    }

    #[test]
    fn person_builder_set_gidnumber_adds_posix_schema() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_gidnumber(Some(12345))
        .build();
        assert_eq!(person.gidnumber, Some(12345));
        assert_eq!(person.entry.schemas.len(), 3);
        assert!(person
            .entry
            .schemas
            .contains(&SCIM_SCHEMA_SYNC_POSIXACCOUNT.to_string()));
    }

    #[test]
    fn person_builder_set_gidnumber_none_keeps_base_schemas() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_gidnumber(None)
        .build();
        assert_eq!(person.entry.schemas.len(), 2);
        assert!(!person
            .entry
            .schemas
            .contains(&SCIM_SCHEMA_SYNC_POSIXACCOUNT.to_string()));
    }

    #[test]
    fn person_builder_set_oauth2_account_provider() {
        let provider_uuid = Uuid::new_v4();
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_oauth2_account_provider(Some((provider_uuid, "unique_id_123".to_string())))
        .build();
        assert_eq!(person.oauth2_account_provider, Some(provider_uuid));
        assert_eq!(
            person.oauth2_account_unique_user_id,
            Some("unique_id_123".to_string())
        );
        assert!(person
            .entry
            .schemas
            .contains(&SCIM_SCHEMA_SYNC_OAUTH2_ACCOUNT.to_string()));
    }

    #[test]
    fn person_builder_set_oauth2_account_provider_none() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_oauth2_account_provider(None)
        .build();
        assert!(person.oauth2_account_provider.is_none());
        assert!(!person
            .entry
            .schemas
            .contains(&SCIM_SCHEMA_SYNC_OAUTH2_ACCOUNT.to_string()));
    }

    #[test]
    fn person_builder_chained() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .set_password_import(Some("pw".to_string()))
        .set_unix_password_import(Some("unixpw".to_string()))
        .set_login_shell(Some("/bin/bash".to_string()))
        .set_account_valid_from(Some("2024-01-01T00:00:00Z".to_string()))
        .set_account_expire(Some("2026-01-01T00:00:00Z".to_string()))
        .build();
        assert_eq!(person.password_import, Some("pw".to_string()));
        assert_eq!(person.unix_password_import, Some("unixpw".to_string()));
        assert_eq!(person.loginshell, Some("/bin/bash".to_string()));
        assert_eq!(
            person.account_valid_from,
            Some("2024-01-01T00:00:00Z".to_string())
        );
        assert_eq!(
            person.account_expire,
            Some("2026-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn group_builder_new() {
        let id = Uuid::new_v4();
        let group = ScimSyncGroup::builder(id, "cn=grp".to_string(), "grp".to_string()).build();
        assert_eq!(group.entry.id, id);
        assert_eq!(group.entry.external_id, Some("cn=grp".to_string()));
        assert_eq!(group.name, "grp");
        assert!(group.description.is_none());
        assert!(group.gidnumber.is_none());
        assert!(group.member.is_empty());
        assert_eq!(
            group.entry.schemas,
            vec![SCIM_SCHEMA_SYNC_GROUP.to_string()]
        );
    }

    #[test]
    fn group_builder_set_description() {
        let group = ScimSyncGroup::builder(Uuid::new_v4(), "ext".to_string(), "grp".to_string())
            .set_description(Some("my group".to_string()))
            .build();
        assert_eq!(group.description, Some("my group".to_string()));
    }

    #[test]
    fn group_builder_set_gidnumber_adds_posix_schema() {
        let group = ScimSyncGroup::builder(Uuid::new_v4(), "ext".to_string(), "grp".to_string())
            .set_gidnumber(Some(54321))
            .build();
        assert_eq!(group.gidnumber, Some(54321));
        assert_eq!(group.entry.schemas.len(), 2);
        assert!(group
            .entry
            .schemas
            .contains(&SCIM_SCHEMA_SYNC_POSIXGROUP.to_string()));
    }

    #[test]
    fn group_builder_set_gidnumber_none_keeps_base_schema() {
        let group = ScimSyncGroup::builder(Uuid::new_v4(), "ext".to_string(), "grp".to_string())
            .set_gidnumber(None)
            .build();
        assert_eq!(group.entry.schemas.len(), 1);
    }

    #[test]
    fn group_builder_set_members() {
        let group = ScimSyncGroup::builder(Uuid::new_v4(), "ext".to_string(), "grp".to_string())
            .set_members(vec!["a".to_string(), "b".to_string(), "c".to_string()].into_iter())
            .build();
        assert_eq!(group.member.len(), 3);
        assert_eq!(group.member[0].external_id, "a");
        assert_eq!(group.member[1].external_id, "b");
        assert_eq!(group.member[2].external_id, "c");
    }

    #[test]
    fn group_builder_chained_full() {
        let id = Uuid::new_v4();
        let group = ScimSyncGroup::builder(id, "cn=full".to_string(), "fullgroup".to_string())
            .set_description(Some("desc".to_string()))
            .set_gidnumber(Some(9999))
            .set_members(vec!["x".to_string()].into_iter())
            .build();
        assert_eq!(group.name, "fullgroup");
        assert_eq!(group.description, Some("desc".to_string()));
        assert_eq!(group.gidnumber, Some(9999));
        assert_eq!(group.member.len(), 1);
        assert_eq!(group.entry.schemas.len(), 2);
    }

    #[test]
    fn schema_uri_constants_have_expected_prefix() {
        let prefix = "urn:ietf:params:scim:schemas:kubidm:sync:1:";
        assert!(SCIM_SCHEMA_SYNC_1.starts_with("urn:"));
        assert!(SCIM_SCHEMA_SYNC_ACCOUNT.starts_with(prefix));
        assert!(SCIM_SCHEMA_SYNC_GROUP.starts_with(prefix));
        assert!(SCIM_SCHEMA_SYNC_PERSON.starts_with(prefix));
        assert!(SCIM_SCHEMA_SYNC_OAUTH2_ACCOUNT.starts_with(prefix));
        assert!(SCIM_SCHEMA_SYNC_POSIXACCOUNT.starts_with(prefix));
        assert!(SCIM_SCHEMA_SYNC_POSIXGROUP.starts_with(prefix));
    }

    #[test]
    fn schema_uri_constants_end_with_type() {
        assert!(SCIM_SCHEMA_SYNC_ACCOUNT.ends_with("account"));
        assert!(SCIM_SCHEMA_SYNC_GROUP.ends_with("group"));
        assert!(SCIM_SCHEMA_SYNC_PERSON.ends_with("person"));
        assert!(SCIM_SCHEMA_SYNC_OAUTH2_ACCOUNT.ends_with("oauth2_account"));
        assert!(SCIM_SCHEMA_SYNC_POSIXACCOUNT.ends_with("posixaccount"));
        assert!(SCIM_SCHEMA_SYNC_POSIXGROUP.ends_with("posixgroup"));
    }

    #[test]
    fn person_try_into_scim_entry() {
        let person = ScimSyncPerson::builder(
            Uuid::new_v4(),
            "ext".to_string(),
            "user".to_string(),
            "User".to_string(),
        )
        .build();
        let entry: ScimEntry = person.try_into().unwrap();
        assert!(!entry.schemas.is_empty());
    }

    #[test]
    fn group_try_into_scim_entry() {
        let group =
            ScimSyncGroup::builder(Uuid::new_v4(), "ext".to_string(), "grp".to_string()).build();
        let entry: ScimEntry = group.try_into().unwrap();
        assert!(!entry.schemas.is_empty());
    }
}
