use crate::prelude::*;
use crate::server::access::{
    apply_delete_access, apply_modify_access, apply_search_access, AccessControlsTransaction,
    DeleteResult, ModifyResult, SearchResult,
};
use crate::server::QueryServerReadTransaction;
use kubidm_proto::internal::{
    AuthorizationAction, AuthorizationDecision, AuthorizationExplanation, AuthorizationRequest,
    AuthorizationResponse,
};
use std::collections::BTreeSet;

pub fn make_authorization_decision(
    qs: &mut QueryServerReadTransaction<'_>,
    ident: &Identity,
    req: &AuthorizationRequest,
) -> Result<AuthorizationResponse, OperationError> {
    let resource_uuid = req.resource;
    let action = req.action;
    let include_explanation = req.include_explanation;

    let filter = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(resource_uuid)));
    let search_event =
        crate::event::SearchEvent::from_internal_message(ident.clone(), &filter, None, qs)?;

    let entries = qs.search(&search_event)?;

    let target_entry = entries
        .into_iter()
        .next()
        .ok_or(OperationError::NoMatchingEntries)?;

    let access_controls = qs.get_accesscontrols();

    let mut matched_rules = Vec::new();
    let mut denied_by: Option<String> = None;

    let decision = match action {
        AuthorizationAction::Search => {
            let related_acp = access_controls.search_related_acp(ident, None);

            if related_acp.is_empty() {
                denied_by = Some("No applicable access control profiles".to_string());
                AuthorizationDecision::Deny
            } else {
                for acp in &related_acp {
                    matched_rules.push(acp.acp.acp.name.clone());
                }

                match apply_search_access(
                    ident,
                    &related_acp,
                    &target_entry,
                    access_controls.get_curtime(),
                ) {
                    SearchResult::Deny => {
                        denied_by = Some("Access denied by policy".to_string());
                        AuthorizationDecision::Deny
                    }
                    SearchResult::Grant => AuthorizationDecision::Allow,
                    SearchResult::Allow(attrs) => {
                        let attr_names: BTreeSet<String> = attrs
                            .into_iter()
                            .map(|a: Attribute| a.to_string())
                            .collect();

                        if attr_names.is_empty() {
                            denied_by = Some("No attributes accessible".to_string());
                            AuthorizationDecision::Deny
                        } else {
                            let mut response = AuthorizationResponse::allow_with_attributes(
                                resource_uuid,
                                action,
                                attr_names,
                            );
                            if include_explanation {
                                response = response.with_explanation(AuthorizationExplanation {
                                    matched_rules: matched_rules.clone(),
                                    denied_by: None,
                                    reason: "Access granted by matching access control profile"
                                        .to_string(),
                                });
                            }
                            return Ok(response);
                        }
                    }
                    SearchResult::ReauthRequired { reason } => {
                        denied_by = Some(reason.clone());
                        AuthorizationDecision::ReauthRequired
                    }
                }
            }
        }
        AuthorizationAction::Delete => {
            let related_acp = access_controls.delete_related_acp(ident);

            if related_acp.is_empty() {
                denied_by = Some("No applicable access control profiles".to_string());
                AuthorizationDecision::Deny
            } else {
                for acp in &related_acp {
                    matched_rules.push(acp.acp.acp.name.clone());
                }

                match apply_delete_access(
                    ident,
                    &related_acp,
                    &target_entry,
                    access_controls.get_curtime(),
                ) {
                    DeleteResult::Deny => {
                        denied_by = Some("Access denied by policy".to_string());
                        AuthorizationDecision::Deny
                    }
                    DeleteResult::Grant => AuthorizationDecision::Allow,
                    DeleteResult::ReauthRequired { reason } => {
                        denied_by = Some(reason.clone());
                        AuthorizationDecision::ReauthRequired
                    }
                }
            }
        }
        AuthorizationAction::Modify => {
            let related_acp = access_controls.modify_related_acp(ident);

            if related_acp.is_empty() {
                denied_by = Some("No applicable access control profiles".to_string());
                AuthorizationDecision::Deny
            } else {
                for acp in &related_acp {
                    matched_rules.push(acp.acp.acp.name.clone());
                }

                let sync_agmts = access_controls.get_sync_agreements();
                match apply_modify_access(
                    ident,
                    &related_acp,
                    sync_agmts,
                    &target_entry,
                    access_controls.get_curtime(),
                ) {
                    ModifyResult::Deny => {
                        denied_by = Some("Access denied by policy".to_string());
                        AuthorizationDecision::Deny
                    }
                    ModifyResult::Grant => AuthorizationDecision::Allow,
                    ModifyResult::Allow { pres, rem, .. } => {
                        let mut all_attrs: BTreeSet<String> = BTreeSet::new();
                        for attr in pres.into_iter().chain(rem) {
                            all_attrs.insert(attr.to_string());
                        }

                        if all_attrs.is_empty() {
                            denied_by = Some("No attributes modifiable".to_string());
                            AuthorizationDecision::Deny
                        } else {
                            let mut response = AuthorizationResponse::allow_with_attributes(
                                resource_uuid,
                                action,
                                all_attrs,
                            );
                            if include_explanation {
                                response = response.with_explanation(AuthorizationExplanation {
                                    matched_rules: matched_rules.clone(),
                                    denied_by: None,
                                    reason: "Access granted by matching access control profile"
                                        .to_string(),
                                });
                            }
                            return Ok(response);
                        }
                    }
                    ModifyResult::ReauthRequired { reason } => {
                        denied_by = Some(reason.clone());
                        AuthorizationDecision::ReauthRequired
                    }
                }
            }
        }
        AuthorizationAction::Create => {
            denied_by =
                Some("Create action not supported for single-resource authorization".to_string());
            AuthorizationDecision::Deny
        }
    };

    let mut response = match decision {
        AuthorizationDecision::Allow => AuthorizationResponse::allow(resource_uuid, action),
        AuthorizationDecision::Deny => AuthorizationResponse::deny(resource_uuid, action),
        AuthorizationDecision::ReauthRequired => {
            AuthorizationResponse::reauth_required(resource_uuid, action)
        }
    };

    if include_explanation {
        response = response.with_explanation(AuthorizationExplanation {
            matched_rules,
            denied_by,
            reason: match decision {
                AuthorizationDecision::Allow => "Access granted".to_string(),
                AuthorizationDecision::Deny => "Access denied".to_string(),
                AuthorizationDecision::ReauthRequired => {
                    "Re-authentication required for this operation".to_string()
                }
            },
        });
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use kubidm_proto::internal::{
        AuthorizationAction, AuthorizationDecision, AuthorizationExplanation, AuthorizationRequest,
        AuthorizationResponse,
    };
    use std::collections::BTreeSet;
    use uuid::Uuid;

    #[test]
    fn test_authorization_response_allow_construction() {
        let resource = Uuid::new_v4();
        let response = AuthorizationResponse::allow(resource, AuthorizationAction::Search);
        assert_eq!(response.decision, AuthorizationDecision::Allow);
        assert_eq!(response.resource, resource);
        assert_eq!(response.action, AuthorizationAction::Search);
        assert!(response.allowed_attributes.is_none());
        assert!(response.explanation.is_none());
    }

    #[test]
    fn test_authorization_response_deny_construction() {
        let resource = Uuid::new_v4();
        let response = AuthorizationResponse::deny(resource, AuthorizationAction::Delete);
        assert_eq!(response.decision, AuthorizationDecision::Deny);
        assert_eq!(response.resource, resource);
        assert_eq!(response.action, AuthorizationAction::Delete);
        assert!(response.allowed_attributes.is_none());
        assert!(response.explanation.is_none());
    }

    #[test]
    fn test_authorization_response_reauth_required_construction() {
        let resource = Uuid::new_v4();
        let response =
            AuthorizationResponse::reauth_required(resource, AuthorizationAction::Modify);
        assert_eq!(response.decision, AuthorizationDecision::ReauthRequired);
        assert_eq!(response.resource, resource);
        assert_eq!(response.action, AuthorizationAction::Modify);
        assert!(response.allowed_attributes.is_none());
        assert!(response.explanation.is_none());
    }

    #[test]
    fn test_authorization_response_allow_with_attributes() {
        let resource = Uuid::new_v4();
        let attrs: BTreeSet<String> = BTreeSet::from([
            "name".to_string(),
            "mail".to_string(),
            "displayname".to_string(),
        ]);
        let response = AuthorizationResponse::allow_with_attributes(
            resource,
            AuthorizationAction::Search,
            attrs.clone(),
        );
        assert_eq!(response.decision, AuthorizationDecision::Allow);
        assert_eq!(response.resource, resource);
        let resp_attrs = response.allowed_attributes.unwrap();
        assert_eq!(resp_attrs.len(), 3);
        assert!(resp_attrs.contains("name"));
        assert!(resp_attrs.contains("mail"));
        assert!(resp_attrs.contains("displayname"));
    }

    #[test]
    fn test_authorization_response_with_explanation_allow() {
        let resource = Uuid::new_v4();
        let explanation = AuthorizationExplanation {
            matched_rules: vec!["acp_read".to_string(), "acp_write".to_string()],
            denied_by: None,
            reason: "Access granted by matching access control profile".to_string(),
        };
        let response = AuthorizationResponse::allow(resource, AuthorizationAction::Search)
            .with_explanation(explanation);
        let exp = response.explanation.unwrap();
        assert_eq!(exp.matched_rules.len(), 2);
        assert!(exp.denied_by.is_none());
        assert!(exp.reason.contains("granted"));
    }

    #[test]
    fn test_authorization_response_with_explanation_deny() {
        let resource = Uuid::new_v4();
        let explanation = AuthorizationExplanation {
            matched_rules: vec![],
            denied_by: Some("No applicable access control profiles".to_string()),
            reason: "Access denied".to_string(),
        };
        let response = AuthorizationResponse::deny(resource, AuthorizationAction::Delete)
            .with_explanation(explanation);
        let exp = response.explanation.unwrap();
        assert!(exp.matched_rules.is_empty());
        assert!(exp.denied_by.unwrap().contains("No applicable"));
    }

    #[test]
    fn test_authorization_response_with_explanation_reauth() {
        let resource = Uuid::new_v4();
        let explanation = AuthorizationExplanation {
            matched_rules: vec!["acp_sensitive".to_string()],
            denied_by: Some("Re-authentication required".to_string()),
            reason: "Re-authentication required for this operation".to_string(),
        };
        let response =
            AuthorizationResponse::reauth_required(resource, AuthorizationAction::Modify)
                .with_explanation(explanation);
        let exp = response.explanation.unwrap();
        assert_eq!(exp.matched_rules.len(), 1);
        assert!(exp.denied_by.is_some());
    }

    #[test]
    fn test_authorization_request_construction() {
        let resource = Uuid::new_v4();
        let subject = Uuid::new_v4();
        let req = AuthorizationRequest::new(Some(subject), resource, AuthorizationAction::Search);
        assert_eq!(req.subject, Some(subject));
        assert_eq!(req.resource, resource);
        assert_eq!(req.action, AuthorizationAction::Search);
        assert!(req.attributes.is_none());
        assert!(!req.include_explanation);
    }

    #[test]
    fn test_authorization_request_builder() {
        let resource = Uuid::new_v4();
        let attrs: BTreeSet<String> = BTreeSet::from(["name".to_string()]);
        let req = AuthorizationRequest::new(None, resource, AuthorizationAction::Modify)
            .with_attributes(attrs)
            .with_explanation(true);
        assert!(req.attributes.is_some());
        assert!(req.include_explanation);
    }

    #[test]
    fn test_authorization_decision_equality() {
        assert_eq!(AuthorizationDecision::Allow, AuthorizationDecision::Allow);
        assert_eq!(AuthorizationDecision::Deny, AuthorizationDecision::Deny);
        assert_eq!(
            AuthorizationDecision::ReauthRequired,
            AuthorizationDecision::ReauthRequired
        );
        assert_ne!(AuthorizationDecision::Allow, AuthorizationDecision::Deny);
    }

    #[test]
    fn test_authorization_action_equality() {
        assert_eq!(AuthorizationAction::Search, AuthorizationAction::Search);
        assert_eq!(AuthorizationAction::Create, AuthorizationAction::Create);
        assert_eq!(AuthorizationAction::Modify, AuthorizationAction::Modify);
        assert_eq!(AuthorizationAction::Delete, AuthorizationAction::Delete);
        assert_ne!(AuthorizationAction::Search, AuthorizationAction::Delete);
    }

    #[test]
    fn test_authorization_decision_serde_roundtrip() {
        for decision in [
            AuthorizationDecision::Allow,
            AuthorizationDecision::Deny,
            AuthorizationDecision::ReauthRequired,
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
    fn test_authorization_request_serde_roundtrip() {
        let resource = Uuid::new_v4();
        let subject = Uuid::new_v4();
        let attrs: BTreeSet<String> = BTreeSet::from(["name".to_string(), "mail".to_string()]);
        let req = AuthorizationRequest::new(Some(subject), resource, AuthorizationAction::Search)
            .with_attributes(attrs)
            .with_explanation(true);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AuthorizationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.subject, parsed.subject);
        assert_eq!(req.resource, parsed.resource);
        assert_eq!(req.action, parsed.action);
        assert_eq!(req.include_explanation, parsed.include_explanation);
        assert_eq!(req.attributes, parsed.attributes);
    }

    #[test]
    fn test_authorization_response_serde_roundtrip() {
        let resource = Uuid::new_v4();
        let response = AuthorizationResponse {
            decision: AuthorizationDecision::Allow,
            resource,
            action: AuthorizationAction::Search,
            allowed_attributes: Some(BTreeSet::from(["name".to_string()])),
            explanation: Some(AuthorizationExplanation {
                matched_rules: vec!["test_rule".to_string()],
                denied_by: None,
                reason: "Access granted".to_string(),
            }),
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: AuthorizationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.decision, parsed.decision);
        assert_eq!(response.resource, parsed.resource);
        assert_eq!(response.action, parsed.action);
        assert_eq!(response.allowed_attributes, parsed.allowed_attributes);
    }

    #[test]
    fn test_authorization_explanation_serde_roundtrip() {
        let explanation = AuthorizationExplanation {
            matched_rules: vec!["rule_a".to_string(), "rule_b".to_string()],
            denied_by: Some("policy_x".to_string()),
            reason: "Access denied by policy".to_string(),
        };
        let json = serde_json::to_string(&explanation).unwrap();
        let parsed: AuthorizationExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(explanation.matched_rules, parsed.matched_rules);
        assert_eq!(explanation.denied_by, parsed.denied_by);
        assert_eq!(explanation.reason, parsed.reason);
    }

    #[test]
    fn test_authorization_response_allow_with_empty_attributes() {
        let resource = Uuid::new_v4();
        let response = AuthorizationResponse::allow_with_attributes(
            resource,
            AuthorizationAction::Search,
            BTreeSet::new(),
        );
        assert_eq!(response.decision, AuthorizationDecision::Allow);
        assert!(response.allowed_attributes.unwrap().is_empty());
    }

    #[test]
    fn test_authorization_decision_serialized_values() {
        assert_eq!(
            serde_json::to_string(&AuthorizationDecision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&AuthorizationDecision::Deny).unwrap(),
            "\"deny\""
        );
        assert_eq!(
            serde_json::to_string(&AuthorizationDecision::ReauthRequired).unwrap(),
            "\"reauthrequired\""
        );
    }

    #[test]
    fn test_authorization_action_serialized_values() {
        assert_eq!(
            serde_json::to_string(&AuthorizationAction::Search).unwrap(),
            "\"search\""
        );
        assert_eq!(
            serde_json::to_string(&AuthorizationAction::Create).unwrap(),
            "\"create\""
        );
        assert_eq!(
            serde_json::to_string(&AuthorizationAction::Modify).unwrap(),
            "\"modify\""
        );
        assert_eq!(
            serde_json::to_string(&AuthorizationAction::Delete).unwrap(),
            "\"delete\""
        );
    }
}
