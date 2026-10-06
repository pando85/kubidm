//! Kubidm Version 1
//!
//! Items defined in this module will remain stable, or change in ways that are forward
//! compatible with newer releases.

#![allow(non_upper_case_globals)]

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, fmt::Display};
use utoipa::ToSchema;
use uuid::Uuid;

mod auth;
mod message;
mod unix;

pub use self::{auth::*, message::*, unix::*};

/// The type of Account in use.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, ToSchema)]
pub enum AccountType {
    Person,
    ServiceAccount,
}

impl Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AccountType::Person => "person",
            AccountType::ServiceAccount => "service_account",
        })
    }
}

/* ===== higher level types ===== */
// These are all types that are conceptually layers on top of entry and
// friends. They allow us to process more complex requests and provide
// domain specific fields for the purposes of IDM, over the normal
// entry/ava/filter types. These related deeply to schema.

/// The current purpose of a User Auth Token. It may be read-only, read-write
/// or privilege capable (able to step up to read-write after re-authentication).
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UatPurposeStatus {
    ReadOnly,
    ReadWrite,
    PrivilegeCapable,
}

/// The expiry of the User Auth Token.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UatStatusState {
    #[serde(with = "time::serde::timestamp")]
    ExpiresAt(time::OffsetDateTime),
    NeverExpires,
    Revoked,
}

impl fmt::Display for UatStatusState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UatStatusState::ExpiresAt(odt) => write!(f, "expires at {odt}"),
            UatStatusState::NeverExpires => write!(f, "never expires"),
            UatStatusState::Revoked => write!(f, "revoked"),
        }
    }
}

/// The status of a User Auth Token
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct UatStatus {
    pub account_id: Uuid,
    pub session_id: Uuid,
    pub state: UatStatusState,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    pub purpose: UatPurposeStatus,
}

impl fmt::Display for UatStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "account_id: {}", self.account_id)?;
        writeln!(f, "session_id: {}", self.session_id)?;
        writeln!(f, "state: {}", self.state)?;
        writeln!(f, "issued_at: {}", self.issued_at)?;
        match &self.purpose {
            UatPurposeStatus::ReadOnly => writeln!(f, "purpose: read only")?,
            UatPurposeStatus::ReadWrite => writeln!(f, "purpose: read write")?,
            UatPurposeStatus::PrivilegeCapable => writeln!(f, "purpose: privilege capable")?,
        }
        Ok(())
    }
}

/// A request to generate a new API token for a service account
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct ApiTokenGenerate {
    pub label: String,
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    pub read_write: bool,
    #[serde(default)]
    pub compact: bool,
}

/* ===== low level proto types ===== */

/// A limited view of an entry in Kubidm.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default, ToSchema)]
pub struct Entry {
    pub attrs: BTreeMap<String, Vec<String>>,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "---")?;
        self.attrs
            .iter()
            .try_for_each(|(k, vs)| vs.iter().try_for_each(|v| writeln!(f, "{k}: {v}")))
    }
}

/// A response to a whoami request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub struct WhoamiResponse {
    // Should we just embed the entry? Or destructure it?
    pub youare: Entry,
}

impl WhoamiResponse {
    pub fn new(youare: Entry) -> Self {
        WhoamiResponse { youare }
    }
}

// Simple string value provision.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SingleStringRequest {
    pub value: String,
}

impl SingleStringRequest {
    pub fn new(s: String) -> Self {
        SingleStringRequest { value: s }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalPattern {
    AnyOne,
    Majority,
    All,
}

impl fmt::Display for ApprovalPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ApprovalPattern {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalPattern::AnyOne => "any_one",
            ApprovalPattern::Majority => "majority",
            ApprovalPattern::All => "all",
        }
    }
}

impl std::str::FromStr for ApprovalPattern {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.to_lowercase().replace('-', "_");
        match normalized.as_str() {
            "any_one" | "anyone" => Ok(ApprovalPattern::AnyOne),
            "majority" => Ok(ApprovalPattern::Majority),
            "all" => Ok(ApprovalPattern::All),
            _ => Err("invalid approval pattern"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalOperationType {
    CreateHighPrivilegeEntry,
    DeleteHighPrivilegeEntry,
    ModifyHighPrivilegeEntry,
    CredentialResetHighPrivilege,
    PrivilegeGrant,
    PrivilegeRevoke,
    SchemaModify,
    AccessControlModify,
    DomainConfigModify,
    KeyProviderModify,
    SyncAccountModify,
    OAuth2ClientModify,
    ApplicationModify,
    GroupMembershipHighPrivilege,
}

impl fmt::Display for ApprovalOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ApprovalOperationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalOperationType::CreateHighPrivilegeEntry => "create_high_privilege_entry",
            ApprovalOperationType::DeleteHighPrivilegeEntry => "delete_high_privilege_entry",
            ApprovalOperationType::ModifyHighPrivilegeEntry => "modify_high_privilege_entry",
            ApprovalOperationType::CredentialResetHighPrivilege => {
                "credential_reset_high_privilege"
            }
            ApprovalOperationType::PrivilegeGrant => "privilege_grant",
            ApprovalOperationType::PrivilegeRevoke => "privilege_revoke",
            ApprovalOperationType::SchemaModify => "schema_modify",
            ApprovalOperationType::AccessControlModify => "access_control_modify",
            ApprovalOperationType::DomainConfigModify => "domain_config_modify",
            ApprovalOperationType::KeyProviderModify => "key_provider_modify",
            ApprovalOperationType::SyncAccountModify => "sync_account_modify",
            ApprovalOperationType::OAuth2ClientModify => "oauth2_client_modify",
            ApprovalOperationType::ApplicationModify => "application_modify",
            ApprovalOperationType::GroupMembershipHighPrivilege => {
                "group_membership_high_privilege"
            }
        }
    }
}

impl std::str::FromStr for ApprovalOperationType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.to_lowercase().replace('-', "_");
        match normalized.as_str() {
            "create_high_privilege_entry" => Ok(ApprovalOperationType::CreateHighPrivilegeEntry),
            "delete_high_privilege_entry" => Ok(ApprovalOperationType::DeleteHighPrivilegeEntry),
            "modify_high_privilege_entry" => Ok(ApprovalOperationType::ModifyHighPrivilegeEntry),
            "credential_reset_high_privilege" => {
                Ok(ApprovalOperationType::CredentialResetHighPrivilege)
            }
            "privilege_grant" => Ok(ApprovalOperationType::PrivilegeGrant),
            "privilege_revoke" => Ok(ApprovalOperationType::PrivilegeRevoke),
            "schema_modify" => Ok(ApprovalOperationType::SchemaModify),
            "access_control_modify" => Ok(ApprovalOperationType::AccessControlModify),
            "domain_config_modify" => Ok(ApprovalOperationType::DomainConfigModify),
            "key_provider_modify" => Ok(ApprovalOperationType::KeyProviderModify),
            "sync_account_modify" => Ok(ApprovalOperationType::SyncAccountModify),
            "oauth2_client_modify" => Ok(ApprovalOperationType::OAuth2ClientModify),
            "application_modify" => Ok(ApprovalOperationType::ApplicationModify),
            "group_membership_high_privilege" => {
                Ok(ApprovalOperationType::GroupMembershipHighPrivilege)
            }
            _ => Err("invalid approval operation type"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalRequestState {
    Pending,
    Approved,
    Rejected,
    Expired,
    Cancelled,
    Escalated,
}

impl fmt::Display for ApprovalRequestState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ApprovalRequestState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalRequestState::Pending => "pending",
            ApprovalRequestState::Approved => "approved",
            ApprovalRequestState::Rejected => "rejected",
            ApprovalRequestState::Expired => "expired",
            ApprovalRequestState::Cancelled => "cancelled",
            ApprovalRequestState::Escalated => "escalated",
        }
    }
}

impl std::str::FromStr for ApprovalRequestState {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(ApprovalRequestState::Pending),
            "approved" => Ok(ApprovalRequestState::Approved),
            "rejected" => Ok(ApprovalRequestState::Rejected),
            "expired" => Ok(ApprovalRequestState::Expired),
            "cancelled" => Ok(ApprovalRequestState::Cancelled),
            "escalated" => Ok(ApprovalRequestState::Escalated),
            _ => Err("invalid approval request state"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDecisionAction {
    Approve,
    Reject,
}

impl fmt::Display for ApprovalDecisionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ApprovalDecisionAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalDecisionAction::Approve => "approve",
            ApprovalDecisionAction::Reject => "reject",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct ApprovalDecision {
    pub approver_uuid: Uuid,
    pub approver_spn: String,
    #[serde(with = "time::serde::timestamp")]
    pub decision_time: time::OffsetDateTime,
    pub action: ApprovalDecisionAction,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct ApprovalRequest {
    pub uuid: Uuid,
    pub policy_uuid: Uuid,
    pub policy_name: String,
    pub operation_type: ApprovalOperationType,
    pub target_uuid: Uuid,
    pub target_spn: String,
    pub requestor_uuid: Uuid,
    pub requestor_spn: String,
    #[serde(with = "time::serde::timestamp")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::timestamp::option")]
    pub expires_at: Option<time::OffsetDateTime>,
    pub state: ApprovalRequestState,
    pub decisions: Vec<ApprovalDecision>,
    pub escalation_level: u32,
    pub required_decisions: u32,
    pub operation_details: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct ApprovalPolicy {
    pub uuid: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub operation_types: Vec<ApprovalOperationType>,
    pub approvers: Vec<Uuid>,
    pub backup_approvers: Vec<Uuid>,
    pub pattern: ApprovalPattern,
    pub timeout_seconds: u32,
    pub escalation_timeout_seconds: Option<u32>,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApprovalPolicyCreateRequest {
    pub name: String,
    pub description: Option<String>,
    pub operation_types: Vec<ApprovalOperationType>,
    pub approvers: Vec<Uuid>,
    pub backup_approvers: Vec<Uuid>,
    pub pattern: ApprovalPattern,
    pub timeout_seconds: u32,
    pub escalation_timeout_seconds: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApprovalDecisionRequest {
    pub action: ApprovalDecisionAction,
    pub comment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn test_account_type_serde_person() {
        let original = AccountType::Person;
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"Person\"");
        let restored: AccountType = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, AccountType::Person));
    }

    #[test]
    fn test_account_type_serde_service_account() {
        let original = AccountType::ServiceAccount;
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"ServiceAccount\"");
        let restored: AccountType = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, AccountType::ServiceAccount));
    }

    #[test]
    fn test_account_type_display() {
        assert_eq!(AccountType::Person.to_string(), "person");
        assert_eq!(AccountType::ServiceAccount.to_string(), "service_account");
    }

    #[test]
    fn test_approval_pattern_serde_any_one() {
        let original = ApprovalPattern::AnyOne;
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"anyone\"");
        let restored: ApprovalPattern = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, ApprovalPattern::AnyOne));
    }

    #[test]
    fn test_approval_pattern_serde_majority() {
        let original = ApprovalPattern::Majority;
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"majority\"");
        let restored: ApprovalPattern = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, ApprovalPattern::Majority));
    }

    #[test]
    fn test_approval_pattern_serde_all() {
        let original = ApprovalPattern::All;
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"all\"");
        let restored: ApprovalPattern = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, ApprovalPattern::All));
    }

    #[test]
    fn test_approval_pattern_from_str() {
        use std::str::FromStr;
        assert!(matches!(
            ApprovalPattern::from_str("any_one"),
            Ok(ApprovalPattern::AnyOne)
        ));
        assert!(matches!(
            ApprovalPattern::from_str("anyone"),
            Ok(ApprovalPattern::AnyOne)
        ));
        assert!(matches!(
            ApprovalPattern::from_str("majority"),
            Ok(ApprovalPattern::Majority)
        ));
        assert!(matches!(
            ApprovalPattern::from_str("all"),
            Ok(ApprovalPattern::All)
        ));
        assert!(ApprovalPattern::from_str("invalid").is_err());
    }

    #[test]
    fn test_approval_pattern_display() {
        assert_eq!(ApprovalPattern::AnyOne.to_string(), "any_one");
        assert_eq!(ApprovalPattern::Majority.to_string(), "majority");
        assert_eq!(ApprovalPattern::All.to_string(), "all");
    }

    #[test]
    fn test_approval_operation_type_serde_variants() {
        let variants = [
            ApprovalOperationType::CreateHighPrivilegeEntry,
            ApprovalOperationType::DeleteHighPrivilegeEntry,
            ApprovalOperationType::ModifyHighPrivilegeEntry,
            ApprovalOperationType::CredentialResetHighPrivilege,
            ApprovalOperationType::PrivilegeGrant,
            ApprovalOperationType::PrivilegeRevoke,
            ApprovalOperationType::SchemaModify,
            ApprovalOperationType::AccessControlModify,
            ApprovalOperationType::DomainConfigModify,
            ApprovalOperationType::KeyProviderModify,
            ApprovalOperationType::SyncAccountModify,
            ApprovalOperationType::OAuth2ClientModify,
            ApprovalOperationType::ApplicationModify,
            ApprovalOperationType::GroupMembershipHighPrivilege,
        ];
        for variant in variants {
            let restored = round_trip(&variant);
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn test_approval_operation_type_from_str() {
        use std::str::FromStr;
        assert!(matches!(
            ApprovalOperationType::from_str("create_high_privilege_entry"),
            Ok(ApprovalOperationType::CreateHighPrivilegeEntry)
        ));
        assert!(matches!(
            ApprovalOperationType::from_str("schema_modify"),
            Ok(ApprovalOperationType::SchemaModify)
        ));
        assert!(ApprovalOperationType::from_str("invalid").is_err());
    }

    #[test]
    fn test_approval_request_state_serde_variants() {
        let variants = [
            ApprovalRequestState::Pending,
            ApprovalRequestState::Approved,
            ApprovalRequestState::Rejected,
            ApprovalRequestState::Expired,
            ApprovalRequestState::Cancelled,
            ApprovalRequestState::Escalated,
        ];
        for variant in variants {
            let restored = round_trip(&variant);
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn test_approval_request_state_from_str() {
        use std::str::FromStr;
        assert!(matches!(
            ApprovalRequestState::from_str("pending"),
            Ok(ApprovalRequestState::Pending)
        ));
        assert!(matches!(
            ApprovalRequestState::from_str("approved"),
            Ok(ApprovalRequestState::Approved)
        ));
        assert!(matches!(
            ApprovalRequestState::from_str("rejected"),
            Ok(ApprovalRequestState::Rejected)
        ));
        assert!(matches!(
            ApprovalRequestState::from_str("expired"),
            Ok(ApprovalRequestState::Expired)
        ));
        assert!(matches!(
            ApprovalRequestState::from_str("cancelled"),
            Ok(ApprovalRequestState::Cancelled)
        ));
        assert!(matches!(
            ApprovalRequestState::from_str("escalated"),
            Ok(ApprovalRequestState::Escalated)
        ));
        assert!(ApprovalRequestState::from_str("invalid").is_err());
    }

    #[test]
    fn test_approval_decision_action_serde_approve() {
        let original = ApprovalDecisionAction::Approve;
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"approve\"");
        let restored: ApprovalDecisionAction = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, ApprovalDecisionAction::Approve));
    }

    #[test]
    fn test_approval_decision_action_serde_reject() {
        let original = ApprovalDecisionAction::Reject;
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"reject\"");
        let restored: ApprovalDecisionAction = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, ApprovalDecisionAction::Reject));
    }

    #[test]
    fn test_approval_decision_round_trip() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let original = ApprovalDecision {
            approver_uuid: Uuid::new_v4(),
            approver_spn: "admin@example.com".to_string(),
            decision_time: now,
            action: ApprovalDecisionAction::Approve,
            comment: Some("looks good".to_string()),
        };
        let restored = round_trip(&original);
        assert_eq!(restored.approver_uuid, original.approver_uuid);
        assert_eq!(restored.approver_spn, original.approver_spn);
        assert_eq!(restored.decision_time, original.decision_time);
        assert!(matches!(restored.action, ApprovalDecisionAction::Approve));
        assert_eq!(restored.comment, original.comment);
    }

    #[test]
    fn test_approval_decision_round_trip_no_comment() {
        let original = ApprovalDecision {
            approver_uuid: Uuid::new_v4(),
            approver_spn: "user@test.com".to_string(),
            decision_time: time::OffsetDateTime::UNIX_EPOCH,
            action: ApprovalDecisionAction::Reject,
            comment: None,
        };
        let restored = round_trip(&original);
        assert!(matches!(restored.action, ApprovalDecisionAction::Reject));
        assert!(restored.comment.is_none());
    }

    #[test]
    fn test_approval_request_round_trip() {
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let original = ApprovalRequest {
            uuid: Uuid::new_v4(),
            policy_uuid: Uuid::new_v4(),
            policy_name: "high_priv_policy".to_string(),
            operation_type: ApprovalOperationType::SchemaModify,
            target_uuid: Uuid::new_v4(),
            target_spn: "target@example.com".to_string(),
            requestor_uuid: Uuid::new_v4(),
            requestor_spn: "requestor@example.com".to_string(),
            created_at: ts,
            expires_at: Some(ts),
            state: ApprovalRequestState::Pending,
            decisions: vec![ApprovalDecision {
                approver_uuid: Uuid::new_v4(),
                approver_spn: "approver@example.com".to_string(),
                decision_time: ts,
                action: ApprovalDecisionAction::Approve,
                comment: None,
            }],
            escalation_level: 0,
            required_decisions: 2,
            operation_details: {
                let mut m = BTreeMap::new();
                m.insert("key".to_string(), "value".to_string());
                m
            },
        };
        let restored = round_trip(&original);
        assert_eq!(restored.uuid, original.uuid);
        assert_eq!(restored.policy_uuid, original.policy_uuid);
        assert_eq!(restored.policy_name, original.policy_name);
        assert_eq!(restored.operation_type, original.operation_type);
        assert_eq!(restored.target_uuid, original.target_uuid);
        assert_eq!(restored.requestor_uuid, original.requestor_uuid);
        assert_eq!(restored.state, original.state);
        assert_eq!(restored.decisions.len(), 1);
        assert_eq!(restored.escalation_level, 0);
        assert_eq!(restored.required_decisions, 2);
        assert_eq!(restored.expires_at, Some(ts));
    }

    #[test]
    fn test_approval_policy_round_trip() {
        let original = ApprovalPolicy {
            uuid: Uuid::new_v4(),
            name: "test_policy".to_string(),
            description: Some("a test policy".to_string()),
            operation_types: vec![ApprovalOperationType::SchemaModify],
            approvers: vec![Uuid::new_v4()],
            backup_approvers: vec![Uuid::new_v4()],
            pattern: ApprovalPattern::Majority,
            timeout_seconds: 3600,
            escalation_timeout_seconds: Some(1800),
            enabled: true,
        };
        let restored = round_trip(&original);
        assert_eq!(restored.uuid, original.uuid);
        assert_eq!(restored.name, original.name);
        assert_eq!(restored.description, original.description);
        assert_eq!(restored.operation_types, original.operation_types);
        assert_eq!(restored.approvers, original.approvers);
        assert_eq!(restored.backup_approvers, original.backup_approvers);
        assert_eq!(restored.pattern, ApprovalPattern::Majority);
        assert_eq!(restored.timeout_seconds, 3600);
        assert_eq!(restored.escalation_timeout_seconds, Some(1800));
        assert!(restored.enabled);
    }

    #[test]
    fn test_approval_policy_create_request_round_trip() {
        let original = ApprovalPolicyCreateRequest {
            name: "new_policy".to_string(),
            description: None,
            operation_types: vec![
                ApprovalOperationType::PrivilegeGrant,
                ApprovalOperationType::PrivilegeRevoke,
            ],
            approvers: vec![Uuid::new_v4(), Uuid::new_v4()],
            backup_approvers: vec![],
            pattern: ApprovalPattern::All,
            timeout_seconds: 7200,
            escalation_timeout_seconds: None,
        };
        let restored = round_trip(&original);
        assert_eq!(restored.name, original.name);
        assert!(restored.description.is_none());
        assert_eq!(restored.operation_types.len(), 2);
        assert_eq!(restored.approvers.len(), 2);
        assert!(restored.backup_approvers.is_empty());
        assert_eq!(restored.pattern, ApprovalPattern::All);
        assert_eq!(restored.timeout_seconds, 7200);
        assert!(restored.escalation_timeout_seconds.is_none());
    }

    #[test]
    fn test_approval_decision_request_round_trip() {
        let original = ApprovalDecisionRequest {
            action: ApprovalDecisionAction::Approve,
            comment: Some("approved by admin".to_string()),
        };
        let restored = round_trip(&original);
        assert!(matches!(restored.action, ApprovalDecisionAction::Approve));
        assert_eq!(restored.comment, Some("approved by admin".to_string()));
    }

    #[test]
    fn test_approval_decision_request_no_comment() {
        let original = ApprovalDecisionRequest {
            action: ApprovalDecisionAction::Reject,
            comment: None,
        };
        let restored = round_trip(&original);
        assert!(matches!(restored.action, ApprovalDecisionAction::Reject));
        assert!(restored.comment.is_none());
    }

    #[test]
    fn test_uat_purpose_status_serde_variants() {
        let json = serde_json::to_string(&UatPurposeStatus::ReadOnly).expect("serialize");
        assert_eq!(json, "\"readonly\"");
        let restored: UatPurposeStatus = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, UatPurposeStatus::ReadOnly));

        let json = serde_json::to_string(&UatPurposeStatus::ReadWrite).expect("serialize");
        assert_eq!(json, "\"readwrite\"");
        let restored: UatPurposeStatus = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, UatPurposeStatus::ReadWrite));

        let json = serde_json::to_string(&UatPurposeStatus::PrivilegeCapable).expect("serialize");
        assert_eq!(json, "\"privilegecapable\"");
        let restored: UatPurposeStatus = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, UatPurposeStatus::PrivilegeCapable));
    }

    #[test]
    fn test_uat_status_state_serde_expires_at() {
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let original = UatStatusState::ExpiresAt(ts);
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: UatStatusState = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(restored, UatStatusState::ExpiresAt(t) if t == ts));
    }

    #[test]
    fn test_uat_status_state_serde_never_expires() {
        let json = "\"neverexpires\"";
        let restored: UatStatusState = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(restored, UatStatusState::NeverExpires));
    }

    #[test]
    fn test_uat_status_state_serde_revoked() {
        let json = "\"revoked\"";
        let restored: UatStatusState = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(restored, UatStatusState::Revoked));
    }

    #[test]
    fn test_uat_status_state_display() {
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        assert!(UatStatusState::ExpiresAt(ts)
            .to_string()
            .contains("expires at"));
        assert_eq!(UatStatusState::NeverExpires.to_string(), "never expires");
        assert_eq!(UatStatusState::Revoked.to_string(), "revoked");
    }

    #[test]
    fn test_uat_status_round_trip() {
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let original = UatStatus {
            account_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            state: UatStatusState::ExpiresAt(ts),
            issued_at: ts,
            purpose: UatPurposeStatus::ReadWrite,
        };
        let restored = round_trip(&original);
        assert_eq!(restored.account_id, original.account_id);
        assert_eq!(restored.session_id, original.session_id);
        assert_eq!(restored.issued_at, original.issued_at);
        assert!(matches!(restored.purpose, UatPurposeStatus::ReadWrite));
    }

    #[test]
    fn test_uat_status_display() {
        let ts = time::OffsetDateTime::UNIX_EPOCH;
        let status = UatStatus {
            account_id: Uuid::nil(),
            session_id: Uuid::nil(),
            state: UatStatusState::NeverExpires,
            issued_at: ts,
            purpose: UatPurposeStatus::PrivilegeCapable,
        };
        let display = status.to_string();
        assert!(display.contains("account_id"));
        assert!(display.contains("session_id"));
        assert!(display.contains("privilege capable"));
    }

    #[test]
    fn test_api_token_generate_round_trip() {
        let original = ApiTokenGenerate {
            label: "test_token".to_string(),
            expiry: Some(time::OffsetDateTime::UNIX_EPOCH),
            read_write: true,
            compact: false,
        };
        let restored = round_trip(&original);
        assert_eq!(restored.label, original.label);
        assert_eq!(restored.expiry, original.expiry);
        assert!(restored.read_write);
        assert!(!restored.compact);
    }

    #[test]
    fn test_api_token_generate_no_expiry() {
        let original = ApiTokenGenerate {
            label: "readonly_token".to_string(),
            expiry: None,
            read_write: false,
            compact: true,
        };
        let restored = round_trip(&original);
        assert!(restored.expiry.is_none());
        assert!(!restored.read_write);
        assert!(restored.compact);
    }

    #[test]
    fn test_entry_serde_round_trip() {
        let mut attrs = BTreeMap::new();
        attrs.insert("name".to_string(), vec!["test".to_string()]);
        attrs.insert(
            "class".to_string(),
            vec!["account".to_string(), "person".to_string()],
        );
        let original = Entry { attrs };
        let restored = round_trip(&original);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_entry_default() {
        let entry = Entry::default();
        assert!(entry.attrs.is_empty());
    }

    #[test]
    fn test_entry_display() {
        let mut attrs = BTreeMap::new();
        attrs.insert("name".to_string(), vec!["test".to_string()]);
        let entry = Entry { attrs };
        let display = entry.to_string();
        assert!(display.contains("name: test"));
    }

    #[test]
    fn test_whoami_response_round_trip() {
        let mut attrs = BTreeMap::new();
        attrs.insert("spn".to_string(), vec!["admin@example.com".to_string()]);
        let response = WhoamiResponse::new(Entry { attrs });
        let restored = round_trip(&response);
        assert_eq!(restored, response);
    }

    #[test]
    fn test_single_string_request_round_trip() {
        let original = SingleStringRequest::new("hello world".to_string());
        let restored = round_trip(&original);
        assert_eq!(restored.value, "hello world");
    }
}
