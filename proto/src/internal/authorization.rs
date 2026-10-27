use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use utoipa::ToSchema;
use uuid::Uuid;

/// The maximum number of requests accepted by a single batch authorization call.
pub const AUTHORIZATION_BATCH_MAX: usize = 100;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationDecision {
    Allow,
    Deny,
    /// The current session is not privileged, but would be allowed once the caller
    /// re-authenticates.
    ReauthRequired,
    /// The resource does not exist, or is not visible to the caller. Only returned as
    /// an item of a batch response; a single request fails with an error instead.
    NotFound,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationAction {
    Search,
    Create,
    Modify,
    Delete,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationRequest {
    /// The subject of the decision. Only the authenticated caller is supported: if set,
    /// it must be the caller's own uuid.
    pub subject: Option<Uuid>,
    pub resource: Uuid,
    pub action: AuthorizationAction,
    /// The attributes to authorise. Unknown attribute names are denied. Required for
    /// `modify`, where every attribute must be both presentable and removable.
    #[serde(default)]
    pub attributes: Option<BTreeSet<String>>,
    #[serde(default)]
    pub include_explanation: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationResponse {
    pub decision: AuthorizationDecision,
    pub resource: Uuid,
    pub action: AuthorizationAction,
    /// For `search`, the readable attributes. For `modify`, the attributes that may be
    /// both added and removed.
    pub allowed_attributes: Option<BTreeSet<String>>,
    /// For `modify`, the attributes that may be added (present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present_attributes: Option<BTreeSet<String>>,
    /// For `modify`, the attributes that may be removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_attributes: Option<BTreeSet<String>>,
    pub explanation: Option<AuthorizationExplanation>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationExplanation {
    /// The access control profiles that apply to the caller. Only disclosed to members
    /// of `idm_access_control_admins`, empty otherwise.
    #[serde(default)]
    pub matched_rules: Vec<String>,
    pub denied_by: Option<String>,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct BatchAuthorizationRequest {
    pub requests: Vec<AuthorizationRequest>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct BatchAuthorizationResponse {
    pub responses: Vec<AuthorizationResponse>,
}

impl AuthorizationRequest {
    pub fn new(subject: Option<Uuid>, resource: Uuid, action: AuthorizationAction) -> Self {
        Self {
            subject,
            resource,
            action,
            attributes: None,
            include_explanation: false,
        }
    }

    pub fn with_attributes(mut self, attributes: BTreeSet<String>) -> Self {
        self.attributes = Some(attributes);
        self
    }

    pub fn with_explanation(mut self, include: bool) -> Self {
        self.include_explanation = include;
        self
    }
}

impl AuthorizationResponse {
    pub fn allow(resource: Uuid, action: AuthorizationAction) -> Self {
        Self {
            decision: AuthorizationDecision::Allow,
            resource,
            action,
            allowed_attributes: None,
            present_attributes: None,
            remove_attributes: None,
            explanation: None,
        }
    }

    pub fn allow_with_attributes(
        resource: Uuid,
        action: AuthorizationAction,
        attributes: BTreeSet<String>,
    ) -> Self {
        Self {
            decision: AuthorizationDecision::Allow,
            resource,
            action,
            allowed_attributes: Some(attributes),
            present_attributes: None,
            remove_attributes: None,
            explanation: None,
        }
    }

    pub fn deny(resource: Uuid, action: AuthorizationAction) -> Self {
        Self {
            decision: AuthorizationDecision::Deny,
            resource,
            action,
            allowed_attributes: None,
            present_attributes: None,
            remove_attributes: None,
            explanation: None,
        }
    }

    pub fn reauth_required(resource: Uuid, action: AuthorizationAction) -> Self {
        Self {
            decision: AuthorizationDecision::ReauthRequired,
            resource,
            action,
            allowed_attributes: None,
            present_attributes: None,
            remove_attributes: None,
            explanation: None,
        }
    }

    pub fn not_found(resource: Uuid, action: AuthorizationAction) -> Self {
        Self {
            decision: AuthorizationDecision::NotFound,
            resource,
            action,
            allowed_attributes: None,
            present_attributes: None,
            remove_attributes: None,
            explanation: None,
        }
    }

    pub fn with_explanation(mut self, explanation: AuthorizationExplanation) -> Self {
        self.explanation = Some(explanation);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_request_serialization() {
        let req =
            AuthorizationRequest::new(Some(Uuid::nil()), Uuid::nil(), AuthorizationAction::Search);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("search"));
    }

    #[test]
    fn test_authorization_response_decision() {
        let response = AuthorizationResponse::allow(Uuid::nil(), AuthorizationAction::Search);
        assert_eq!(response.decision, AuthorizationDecision::Allow);

        let response = AuthorizationResponse::deny(Uuid::nil(), AuthorizationAction::Delete);
        assert_eq!(response.decision, AuthorizationDecision::Deny);
    }

    #[test]
    fn test_authorization_request_with_attributes() {
        let attrs: BTreeSet<String> =
            BTreeSet::from(["name".to_string(), "displayname".to_string()]);
        let req =
            AuthorizationRequest::new(Some(Uuid::nil()), Uuid::nil(), AuthorizationAction::Modify)
                .with_attributes(attrs.clone());

        assert!(req.attributes.is_some());
        let req_attrs = req.attributes.unwrap();
        assert!(req_attrs.contains("name"));
        assert!(req_attrs.contains("displayname"));
    }

    #[test]
    fn test_authorization_request_with_explanation() {
        let req =
            AuthorizationRequest::new(Some(Uuid::nil()), Uuid::nil(), AuthorizationAction::Search)
                .with_explanation(true);

        assert!(req.include_explanation);

        let req_no_explanation =
            AuthorizationRequest::new(Some(Uuid::nil()), Uuid::nil(), AuthorizationAction::Search)
                .with_explanation(false);

        assert!(!req_no_explanation.include_explanation);
    }

    #[test]
    fn test_authorization_request_deserialization() {
        let json = r#"{
            "subject": "00000000-0000-0000-0000-000000000000",
            "resource": "00000000-0000-0000-0000-000000000001",
            "action": "modify",
            "attributes": ["name", "displayname"],
            "includeExplanation": true
        }"#;

        let req: AuthorizationRequest = serde_json::from_str(json).unwrap();
        assert!(req.subject.is_some());
        assert_eq!(req.action, AuthorizationAction::Modify);
        assert!(req.attributes.is_some());
        assert!(req.include_explanation);
    }

    #[test]
    fn test_authorization_request_deserialization_defaults() {
        let json = r#"{
            "resource": "00000000-0000-0000-0000-000000000000",
            "action": "search"
        }"#;

        let req: AuthorizationRequest = serde_json::from_str(json).unwrap();
        assert!(req.subject.is_none());
        assert!(req.attributes.is_none());
        assert!(!req.include_explanation);
    }

    #[test]
    fn test_authorization_response_with_explanation() {
        let explanation = AuthorizationExplanation {
            matched_rules: vec!["rule1".to_string(), "rule2".to_string()],
            denied_by: Some("policy_x".to_string()),
            reason: "Access denied due to security policy".to_string(),
        };

        let response = AuthorizationResponse::deny(Uuid::nil(), AuthorizationAction::Delete)
            .with_explanation(explanation.clone());

        assert!(response.explanation.is_some());
        let resp_explanation = response.explanation.unwrap();
        assert_eq!(resp_explanation.matched_rules.len(), 2);
        assert!(resp_explanation.denied_by.is_some());
        assert!(resp_explanation.reason.contains("denied"));
    }

    #[test]
    fn test_authorization_response_allow_with_attributes() {
        let attrs: BTreeSet<String> = BTreeSet::from(["name".to_string(), "mail".to_string()]);
        let response = AuthorizationResponse::allow_with_attributes(
            Uuid::nil(),
            AuthorizationAction::Search,
            attrs.clone(),
        );

        assert_eq!(response.decision, AuthorizationDecision::Allow);
        assert!(response.allowed_attributes.is_some());
        let resp_attrs = response.allowed_attributes.unwrap();
        assert_eq!(resp_attrs.len(), 2);
        assert!(resp_attrs.contains("name"));
        assert!(resp_attrs.contains("mail"));
    }

    #[test]
    fn test_authorization_decision_serde_roundtrip() {
        for decision in [
            AuthorizationDecision::Allow,
            AuthorizationDecision::Deny,
            AuthorizationDecision::ReauthRequired,
            AuthorizationDecision::NotFound,
        ] {
            let json = serde_json::to_string(&decision).unwrap();
            let parsed: AuthorizationDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, parsed);
        }
    }

    #[test]
    fn test_authorization_action_serde_roundtrip() {
        for action in [
            AuthorizationAction::Search,
            AuthorizationAction::Create,
            AuthorizationAction::Modify,
            AuthorizationAction::Delete,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: AuthorizationAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, parsed);
        }
    }

    #[test]
    fn test_authorization_response_full_serialization() {
        let response = AuthorizationResponse {
            decision: AuthorizationDecision::Allow,
            resource: Uuid::nil(),
            action: AuthorizationAction::Search,
            allowed_attributes: Some(BTreeSet::from(["name".to_string()])),
            present_attributes: None,
            remove_attributes: None,
            explanation: Some(AuthorizationExplanation {
                matched_rules: vec!["test_rule".to_string()],
                denied_by: None,
                reason: "Access granted".to_string(),
            }),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("allow"));
        assert!(json.contains("search"));
        assert!(json.contains("name"));
        assert!(json.contains("test_rule"));

        let parsed: AuthorizationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.decision, parsed.decision);
        assert_eq!(response.action, parsed.action);
    }

    #[test]
    fn test_authorization_request_missing_resource_fails() {
        let json = r#"{
            "subject": "00000000-0000-0000-0000-000000000000",
            "action": "search"
        }"#;

        let result: Result<AuthorizationRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorization_request_missing_action_fails() {
        let json = r#"{
            "subject": "00000000-0000-0000-0000-000000000000",
            "resource": "00000000-0000-0000-0000-000000000000"
        }"#;

        let result: Result<AuthorizationRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorization_request_invalid_uuid_fails() {
        let json = r#"{
            "subject": "not-a-uuid",
            "resource": "00000000-0000-0000-0000-000000000000",
            "action": "search"
        }"#;

        let result: Result<AuthorizationRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorization_request_invalid_action_fails() {
        let json = r#"{
            "resource": "00000000-0000-0000-0000-000000000000",
            "action": "invalid_action"
        }"#;

        let result: Result<AuthorizationRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_authorization_request() {
        let requests = vec![
            AuthorizationRequest::new(None, Uuid::nil(), AuthorizationAction::Search),
            AuthorizationRequest::new(None, Uuid::nil(), AuthorizationAction::Modify),
        ];

        let batch = BatchAuthorizationRequest { requests };
        assert_eq!(batch.requests.len(), 2);

        let json = serde_json::to_string(&batch).unwrap();
        assert!(json.contains("requests"));

        let parsed: BatchAuthorizationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.requests.len(), 2);
    }

    #[test]
    fn test_batch_authorization_response() {
        let responses = vec![
            AuthorizationResponse::allow(Uuid::nil(), AuthorizationAction::Search),
            AuthorizationResponse::deny(Uuid::nil(), AuthorizationAction::Delete),
        ];

        let batch = BatchAuthorizationResponse { responses };
        assert_eq!(batch.responses.len(), 2);

        let json = serde_json::to_string(&batch).unwrap();
        let parsed: BatchAuthorizationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.responses.len(), 2);
        assert_eq!(parsed.responses[0].decision, AuthorizationDecision::Allow);
        assert_eq!(parsed.responses[1].decision, AuthorizationDecision::Deny);
    }

    #[test]
    fn test_authorization_explanation_serialization() {
        let explanation = AuthorizationExplanation {
            matched_rules: vec![
                "rule_a".to_string(),
                "rule_b".to_string(),
                "rule_c".to_string(),
            ],
            denied_by: None,
            reason: "Access granted by access control profile".to_string(),
        };

        let json = serde_json::to_string(&explanation).unwrap();
        assert!(json.contains("matchedRules"));
        assert!(json.contains("rule_a"));
        assert!(json.contains("Access granted"));

        let parsed: AuthorizationExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.matched_rules.len(), 3);
        assert!(parsed.denied_by.is_none());
    }

    #[test]
    fn test_authorization_explanation_with_denied_by() {
        let explanation = AuthorizationExplanation {
            matched_rules: vec!["rule_x".to_string()],
            denied_by: Some("policy_y".to_string()),
            reason: "Access denied by security restrictions".to_string(),
        };

        let json = serde_json::to_string(&explanation).unwrap();
        let parsed: AuthorizationExplanation = serde_json::from_str(&json).unwrap();
        assert!(parsed.denied_by.is_some());
        assert_eq!(parsed.denied_by.unwrap(), "policy_y");
    }

    #[test]
    fn test_authorization_request_empty_attributes() {
        let attrs: BTreeSet<String> = BTreeSet::new();
        let req = AuthorizationRequest::new(None, Uuid::nil(), AuthorizationAction::Search)
            .with_attributes(attrs);

        assert!(req.attributes.is_some());
        assert!(req.attributes.unwrap().is_empty());
    }

    #[test]
    fn test_authorization_request_null_subject_json() {
        let json = r#"{
            "subject": null,
            "resource": "00000000-0000-0000-0000-000000000000",
            "action": "search"
        }"#;

        let req: AuthorizationRequest = serde_json::from_str(json).unwrap();
        assert!(req.subject.is_none());
    }

    #[test]
    fn test_authorization_request_unicode_attributes() {
        let attrs: BTreeSet<String> = BTreeSet::from([
            "日本語".to_string(),
            "属性名".to_string(),
            "émoji🎯".to_string(),
        ]);

        let req = AuthorizationRequest::new(None, Uuid::nil(), AuthorizationAction::Search)
            .with_attributes(attrs.clone());

        let json = serde_json::to_string(&req).unwrap();
        let parsed: AuthorizationRequest = serde_json::from_str(&json).unwrap();

        let parsed_attrs = parsed.attributes.unwrap();
        assert!(parsed_attrs.contains("日本語"));
        assert!(parsed_attrs.contains("属性名"));
        assert!(parsed_attrs.contains("émoji🎯"));
    }

    #[test]
    fn test_authorization_request_builder_chain() {
        let attrs: BTreeSet<String> = BTreeSet::from(["attr1".to_string()]);
        let req =
            AuthorizationRequest::new(Some(Uuid::nil()), Uuid::nil(), AuthorizationAction::Modify)
                .with_attributes(attrs.clone())
                .with_explanation(true);

        assert!(req.subject.is_some());
        assert_eq!(req.action, AuthorizationAction::Modify);
        assert!(req.attributes.is_some());
        assert!(req.include_explanation);
    }

    #[test]
    fn test_authorization_response_backward_compatible() {
        // A response from a server that does not know the modify attribute sets.
        let json = r#"{
            "decision": "allow",
            "resource": "00000000-0000-0000-0000-000000000000",
            "action": "search",
            "allowedAttributes": ["name"],
            "explanation": null
        }"#;
        let parsed: AuthorizationResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.present_attributes.is_none());
        assert!(parsed.remove_attributes.is_none());

        // And unset sets are not serialised.
        let json = serde_json::to_string(&AuthorizationResponse::allow(
            Uuid::nil(),
            AuthorizationAction::Search,
        ))
        .unwrap();
        assert!(!json.contains("presentAttributes"));
        assert!(!json.contains("removeAttributes"));
    }

    #[test]
    fn test_authorization_response_not_found() {
        let response = AuthorizationResponse::not_found(Uuid::nil(), AuthorizationAction::Search);
        assert_eq!(response.decision, AuthorizationDecision::NotFound);
        assert_eq!(
            serde_json::to_string(&AuthorizationDecision::NotFound).unwrap(),
            "\"notfound\""
        );
    }

    #[test]
    fn test_authorization_response_reauth_required() {
        let response =
            AuthorizationResponse::reauth_required(Uuid::nil(), AuthorizationAction::Modify);

        assert_eq!(response.decision, AuthorizationDecision::ReauthRequired);
        assert_eq!(response.action, AuthorizationAction::Modify);
        assert!(response.allowed_attributes.is_none());
        assert!(response.explanation.is_none());
    }
}
