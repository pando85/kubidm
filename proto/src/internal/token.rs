use super::UiHint;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use serde_with::skip_serializing_none;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UatPurpose {
    ReadOnly,
    ReadWrite {
        /// If none, there is no expiry, and this is always rw. If there is
        /// an expiry, check that the current time < expiry.
        #[serde(with = "time::serde::timestamp::option")]
        expiry: Option<time::OffsetDateTime>,
    },
}

/// The currently authenticated user, and any required metadata for them
/// to properly authorise them. This is similar in nature to oauth and the krb
/// PAC/PAD structures. This information is transparent to clients and CAN
/// be parsed by them!
///
/// This structure and how it works will *very much* change over time from this
/// point onward! This means on updates, that sessions will invalidate in many
/// cases.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[skip_serializing_none]
#[serde(rename_all = "lowercase")]
pub struct UserAuthToken {
    pub session_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    /// If none, there is no expiry, and this is always valid. If there is
    /// an expiry, check that the current time < expiry.
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    pub purpose: UatPurpose,
    pub uuid: Uuid,
    pub displayname: String,
    pub spn: String,
    pub mail_primary: Option<String>,
    pub ui_hints: BTreeSet<UiHint>,

    pub limit_search_max_results: Option<u64>,
    pub limit_search_max_filter_test: Option<u64>,
}

impl fmt::Display for UserAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "spn: {}", self.spn)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "display: {}", self.displayname)?;
        if let Some(exp) = self.expiry {
            writeln!(f, "expiry: {exp}")?;
        } else {
            writeln!(f, "expiry: -")?;
        }
        match &self.purpose {
            UatPurpose::ReadOnly => writeln!(f, "purpose: read only")?,
            UatPurpose::ReadWrite {
                expiry: Some(expiry),
            } => writeln!(f, "purpose: read write (expiry: {expiry})")?,
            UatPurpose::ReadWrite { expiry: None } => {
                writeln!(f, "purpose: read write (expiry: none)")?
            }
        }
        Ok(())
    }
}

impl PartialEq for UserAuthToken {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
    }
}

impl Eq for UserAuthToken {}

pub enum PrivilegesActive {
    /// This session has active read write privs.
    True,
    /// This session can become read-write, but requires reauth to proceed.
    ReauthRequired,
    /// This session has no privileges and is read only
    False,
}

impl UserAuthToken {
    pub fn name(&self) -> &str {
        self.spn.split_once('@').map(|x| x.0).unwrap_or(&self.spn)
    }

    /// Show if the uat at a current point in time has active read-write
    /// capabilities.
    pub fn purpose_privilege_state(&self, ct: time::OffsetDateTime) -> PrivilegesActive {
        match self.purpose {
            UatPurpose::ReadWrite { expiry: Some(exp) } if ct < exp => PrivilegesActive::True,
            // The privileges have expired, or are not yet activated on this session.
            UatPurpose::ReadWrite { expiry: Some(_) } | UatPurpose::ReadWrite { expiry: None } => {
                PrivilegesActive::ReauthRequired
            }
            UatPurpose::ReadOnly => PrivilegesActive::False,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiTokenPurpose {
    #[default]
    ReadOnly,
    ReadWrite,
    Synchronise,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct ApiToken {
    // The account this is associated with.
    pub account_id: Uuid,
    pub token_id: Uuid,
    pub label: String,
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    // Defaults to ReadOnly if not present
    #[serde(default)]
    pub purpose: ApiTokenPurpose,
}

impl fmt::Display for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "account_id: {}", self.account_id)?;
        writeln!(f, "token_id: {}", self.token_id)?;
        writeln!(f, "label: {}", self.label)?;
        writeln!(f, "issued at: {}", self.issued_at)?;
        if let Some(expiry) = self.expiry {
            // if this fails we're in trouble!
            #[allow(clippy::expect_used)]
            let expiry_str = expiry
                .to_offset(
                    time::UtcOffset::local_offset_at(OffsetDateTime::UNIX_EPOCH)
                        .unwrap_or(time::UtcOffset::UTC),
                )
                .format(&time::format_description::well_known::Rfc3339)
                .expect("Failed to format timestamp to RFC3339");
            writeln!(f, "token expiry: {expiry_str}")
        } else {
            writeln!(f, "token expiry: never")
        }
    }
}

impl PartialEq for ApiToken {
    fn eq(&self, other: &Self) -> bool {
        self.token_id == other.token_id
    }
}

impl Eq for ApiToken {}

// This is similar to uat, but omits claims (they have no role in radius), and adds
// the radius secret field.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct RadiusAuthToken {
    pub name: String,
    pub displayname: String,
    pub uuid: String,
    pub secret: String,
    pub groups: Vec<Group>,
}

impl fmt::Display for RadiusAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "displayname: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "secret: {}", self.secret)?;
        self.groups
            .iter()
            .try_for_each(|g| writeln!(f, "group: {g}"))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct ScimSyncToken {
    // uuid of the token?
    pub token_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    #[serde(default)]
    pub purpose: ApiTokenPurpose,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Group {
    pub spn: String,
    pub uuid: String,
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ spn: {}, ", self.spn)?;
        write!(f, "uuid: {} ]", self.uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uat() -> UserAuthToken {
        UserAuthToken {
            session_id: Uuid::new_v4(),
            issued_at: OffsetDateTime::UNIX_EPOCH,
            expiry: None,
            purpose: UatPurpose::ReadOnly,
            uuid: Uuid::new_v4(),
            displayname: "Test User".to_string(),
            spn: "testuser@example.com".to_string(),
            mail_primary: Some("test@example.com".to_string()),
            ui_hints: BTreeSet::new(),
            limit_search_max_results: None,
            limit_search_max_filter_test: None,
        }
    }

    #[test]
    fn test_uat_purpose_serde_readonly() {
        let purpose = UatPurpose::ReadOnly;
        let json = serde_json::to_string(&purpose).expect("Failed to serialize");
        assert_eq!(json, "\"readonly\"");
        let deserialized: UatPurpose = serde_json::from_str(&json).expect("Failed to deserialize");
        assert!(matches!(deserialized, UatPurpose::ReadOnly));
    }

    #[test]
    fn test_uat_purpose_serde_readwrite_with_expiry() {
        let expiry = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let purpose = UatPurpose::ReadWrite {
            expiry: Some(expiry),
        };
        let json = serde_json::to_string(&purpose).expect("Failed to serialize");
        assert!(json.contains("readwrite"));
        let deserialized: UatPurpose = serde_json::from_str(&json).expect("Failed to deserialize");
        assert!(matches!(deserialized, UatPurpose::ReadWrite { .. }));
    }

    #[test]
    fn test_uat_purpose_serde_readwrite_no_expiry() {
        let purpose = UatPurpose::ReadWrite { expiry: None };
        let json = serde_json::to_string(&purpose).expect("Failed to serialize");
        assert!(json.contains("readwrite"));
        let deserialized: UatPurpose = serde_json::from_str(&json).expect("Failed to deserialize");
        assert!(matches!(
            deserialized,
            UatPurpose::ReadWrite { expiry: None }
        ));
    }

    #[test]
    fn test_uat_name() {
        let uat = make_uat();
        assert_eq!(uat.name(), "testuser");
    }

    #[test]
    fn test_uat_name_no_at() {
        let mut uat = make_uat();
        uat.spn = "testuser".to_string();
        assert_eq!(uat.name(), "testuser");
    }

    #[test]
    fn test_uat_display() {
        let uat = make_uat();
        let display = format!("{}", uat);
        assert!(display.contains("testuser@example.com"));
        assert!(display.contains("Test User"));
        assert!(display.contains("read only"));
    }

    #[test]
    fn test_uat_display_with_expiry() {
        let mut uat = make_uat();
        uat.expiry = Some(OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1));
        let display = format!("{}", uat);
        assert!(display.contains("expiry:"));
    }

    #[test]
    fn test_uat_display_readwrite_purpose() {
        let mut uat = make_uat();
        uat.purpose = UatPurpose::ReadWrite { expiry: None };
        let display = format!("{}", uat);
        assert!(display.contains("read write"));
    }

    #[test]
    fn test_uat_eq_by_session_id() {
        let uat1 = make_uat();
        let uat2 = uat1.clone();
        assert_eq!(uat1, uat2);

        let mut uat3 = make_uat();
        uat3.session_id = Uuid::new_v4();
        assert_ne!(uat1, uat3);
    }

    #[test]
    fn test_uat_purpose_privilege_state_readonly() {
        let uat = make_uat();
        let ct = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        assert!(matches!(
            uat.purpose_privilege_state(ct),
            PrivilegesActive::False
        ));
    }

    #[test]
    fn test_uat_purpose_privilege_state_readwrite_active() {
        let mut uat = make_uat();
        let future = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
        uat.purpose = UatPurpose::ReadWrite {
            expiry: Some(future),
        };
        let ct = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        assert!(matches!(
            uat.purpose_privilege_state(ct),
            PrivilegesActive::True
        ));
    }

    #[test]
    fn test_uat_purpose_privilege_state_readwrite_expired() {
        let mut uat = make_uat();
        let past = OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30);
        uat.purpose = UatPurpose::ReadWrite { expiry: Some(past) };
        let ct = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        assert!(matches!(
            uat.purpose_privilege_state(ct),
            PrivilegesActive::ReauthRequired
        ));
    }

    #[test]
    fn test_uat_purpose_privilege_state_readwrite_no_expiry() {
        let mut uat = make_uat();
        uat.purpose = UatPurpose::ReadWrite { expiry: None };
        let ct = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        assert!(matches!(
            uat.purpose_privilege_state(ct),
            PrivilegesActive::ReauthRequired
        ));
    }

    #[test]
    fn test_uat_serde_roundtrip() {
        let uat = make_uat();
        let json = serde_json::to_string(&uat).expect("Failed to serialize");
        let deserialized: UserAuthToken =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(uat.session_id, deserialized.session_id);
        assert_eq!(uat.spn, deserialized.spn);
        assert_eq!(uat.displayname, deserialized.displayname);
        assert_eq!(uat.uuid, deserialized.uuid);
    }

    #[test]
    fn test_api_token_purpose_serde() {
        assert_eq!(
            serde_json::to_string(&ApiTokenPurpose::ReadOnly).unwrap(),
            "\"readonly\""
        );
        assert_eq!(
            serde_json::to_string(&ApiTokenPurpose::ReadWrite).unwrap(),
            "\"readwrite\""
        );
        assert_eq!(
            serde_json::to_string(&ApiTokenPurpose::Synchronise).unwrap(),
            "\"synchronise\""
        );

        let deserialized: ApiTokenPurpose = serde_json::from_str("\"readonly\"").unwrap();
        assert!(matches!(deserialized, ApiTokenPurpose::ReadOnly));
    }

    #[test]
    fn test_api_token_display() {
        let token = ApiToken {
            account_id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            label: "my-token".to_string(),
            expiry: None,
            issued_at: OffsetDateTime::UNIX_EPOCH,
            purpose: ApiTokenPurpose::ReadOnly,
        };
        let display = format!("{}", token);
        assert!(display.contains("my-token"));
        assert!(display.contains("never"));
    }

    #[test]
    fn test_api_token_display_with_expiry() {
        let token = ApiToken {
            account_id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            label: "my-token".to_string(),
            expiry: Some(OffsetDateTime::UNIX_EPOCH + time::Duration::days(365)),
            issued_at: OffsetDateTime::UNIX_EPOCH,
            purpose: ApiTokenPurpose::ReadWrite,
        };
        let display = format!("{}", token);
        assert!(display.contains("my-token"));
        assert!(display.contains("token expiry:"));
    }

    #[test]
    fn test_api_token_eq_by_token_id() {
        let token1 = ApiToken {
            account_id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            label: "token1".to_string(),
            expiry: None,
            issued_at: OffsetDateTime::UNIX_EPOCH,
            purpose: ApiTokenPurpose::ReadOnly,
        };
        let mut token2 = token1.clone();
        token2.account_id = Uuid::new_v4();
        token2.label = "token2".to_string();
        // Same token_id means equal
        assert_eq!(token1, token2);

        let mut token3 = token1.clone();
        token3.token_id = Uuid::new_v4();
        assert_ne!(token1, token3);
    }

    #[test]
    fn test_api_token_default_purpose() {
        // When purpose is missing from JSON, it should default to ReadOnly
        let json = r#"{"account_id":"00000000-0000-0000-0000-000000000000","token_id":"00000000-0000-0000-0000-000000000001","label":"test","issued_at":0,"expiry":null}"#;
        let token: ApiToken = serde_json::from_str(json).expect("Failed to deserialize");
        assert!(matches!(token.purpose, ApiTokenPurpose::ReadOnly));
    }

    #[test]
    fn test_group_display() {
        let group = Group {
            spn: "group@example.com".to_string(),
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
        };
        let display = format!("{}", group);
        assert!(display.contains("group@example.com"));
        assert!(display.contains("00000000-0000-0000-0000-000000000001"));
    }

    #[test]
    fn test_radius_auth_token_display() {
        let token = RadiusAuthToken {
            name: "testuser".to_string(),
            displayname: "Test User".to_string(),
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            secret: "secret123".to_string(),
            groups: vec![Group {
                spn: "group@example.com".to_string(),
                uuid: "00000000-0000-0000-0000-000000000002".to_string(),
            }],
        };
        let display = format!("{}", token);
        assert!(display.contains("testuser"));
        assert!(display.contains("Test User"));
        assert!(display.contains("secret123"));
        assert!(display.contains("group@example.com"));
    }

    #[test]
    fn test_scim_sync_token_serde() {
        let token = ScimSyncToken {
            token_id: Uuid::new_v4(),
            issued_at: OffsetDateTime::UNIX_EPOCH,
            purpose: ApiTokenPurpose::Synchronise,
        };
        let json = serde_json::to_string(&token).expect("Failed to serialize");
        let deserialized: ScimSyncToken =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(token.token_id, deserialized.token_id);
        assert!(matches!(deserialized.purpose, ApiTokenPurpose::Synchronise));
    }

    #[test]
    fn test_scim_sync_token_default_purpose() {
        let json = r#"{"token_id":"00000000-0000-0000-0000-000000000000","issued_at":0}"#;
        let token: ScimSyncToken = serde_json::from_str(json).expect("Failed to deserialize");
        assert!(matches!(token.purpose, ApiTokenPurpose::ReadOnly));
    }
}
