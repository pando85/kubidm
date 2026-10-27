//! The policy decision point behind `/v1/authorize`.
//!
//! Decisions are **ACP-level only**: they are built on
//! [`AccessControlsTransaction::effective_permission_check`], the same evaluation the
//! server applies to real operations, but plugins (attribute uniqueness, referential
//! integrity, value deny lists, ...) may still deny an operation that is allowed here.

use crate::prelude::*;
use crate::schema::SchemaTransaction;
use crate::server::access::{Access, AccessControlsTransaction, AccessEffectivePermission};
use crate::server::QueryServerReadTransaction;
use crate::value::SessionScope;
use kubidm_proto::internal::{
    AuthorizationAction, AuthorizationDecision, AuthorizationExplanation, AuthorizationRequest,
    AuthorizationResponse, AUTHORIZATION_BATCH_MAX,
};
use std::collections::BTreeSet;

/// The outcome of evaluating a request for one identity, before it is turned into a
/// response.
struct Evaluation {
    decision: AuthorizationDecision,
    allowed: Option<BTreeSet<String>>,
    present: Option<BTreeSet<String>>,
    remove: Option<BTreeSet<String>>,
    matched_rules: Vec<String>,
    denied_by: Option<String>,
}

impl Evaluation {
    fn deny(denied_by: &str) -> Self {
        Evaluation {
            decision: AuthorizationDecision::Deny,
            allowed: None,
            present: None,
            remove: None,
            matched_rules: Vec::new(),
            denied_by: Some(denied_by.to_string()),
        }
    }

    fn into_response(self, req: &AuthorizationRequest) -> AuthorizationResponse {
        let explanation = req.include_explanation.then(|| AuthorizationExplanation {
            reason: match self.decision {
                AuthorizationDecision::Allow => "Access granted".to_string(),
                AuthorizationDecision::Deny => "Access denied".to_string(),
                AuthorizationDecision::ReauthRequired => {
                    "Re-authentication required for this operation".to_string()
                }
                AuthorizationDecision::NotFound => "Resource not found".to_string(),
            },
            matched_rules: self.matched_rules,
            denied_by: self.denied_by,
        });

        AuthorizationResponse {
            decision: self.decision,
            resource: req.resource,
            action: req.action,
            allowed_attributes: self.allowed,
            present_attributes: self.present,
            remove_attributes: self.remove,
            explanation,
        }
    }
}

/// Decide a single authorization request for `ident`.
///
/// Fails with `NoMatchingEntries` if the resource does not exist or is not visible to
/// the caller (even after re-authentication), and with `InvalidRequestState` if the
/// request names a subject other than the caller.
pub fn make_authorization_decision(
    qs: &mut QueryServerReadTransaction<'_>,
    ident: &Identity,
    req: &AuthorizationRequest,
) -> Result<AuthorizationResponse, OperationError> {
    // Only the caller's own permissions can be queried.
    if let Some(subject) = req.subject {
        if subject != ident.get_uuid() {
            security_access!(
                ?subject,
                caller = ?ident.get_uuid(),
                "authorization subject does not match the caller"
            );
            return Err(OperationError::InvalidRequestState);
        }
    }

    let evaluation = evaluate(qs, ident, req);

    // Step-up: a privilege capable session that is currently read-only may be allowed
    // once it re-authenticates. The elevated identity is only used for this check and
    // never leaves this function; nothing from its evaluation except the fact that it
    // would be allowed is disclosed.
    let needs_stepup = match &evaluation {
        Ok(eval) => eval.decision == AuthorizationDecision::Deny,
        Err(OperationError::NoMatchingEntries) => true,
        Err(_) => false,
    };

    if needs_stepup && can_elevate(ident) {
        let elevated = ident.project_with_scope(AccessScope::ReadWrite);
        if let Ok(elevated_eval) = evaluate(qs, &elevated, req) {
            if elevated_eval.decision == AuthorizationDecision::Allow {
                let matched_rules = match &evaluation {
                    Ok(eval) => eval.matched_rules.clone(),
                    Err(_) => Vec::new(),
                };
                return Ok(Evaluation {
                    decision: AuthorizationDecision::ReauthRequired,
                    allowed: None,
                    present: None,
                    remove: None,
                    matched_rules,
                    denied_by: Some(
                        "This operation requires a privileged session. Please re-authenticate."
                            .to_string(),
                    ),
                }
                .into_response(req));
            }
        }
    }

    evaluation.map(|eval| eval.into_response(req))
}

/// Decide a batch of authorization requests for `ident` within a single read
/// transaction. Resources that are not found are reported per item as `NotFound`
/// rather than failing the whole batch.
pub fn make_batch_authorization_decision(
    qs: &mut QueryServerReadTransaction<'_>,
    ident: &Identity,
    reqs: &[AuthorizationRequest],
) -> Result<Vec<AuthorizationResponse>, OperationError> {
    if reqs.len() > AUTHORIZATION_BATCH_MAX {
        request_error!(
            len = reqs.len(),
            max = AUTHORIZATION_BATCH_MAX,
            "batch authorization request is too large"
        );
        return Err(OperationError::InvalidRequestState);
    }

    reqs.iter()
        .map(|req| match make_authorization_decision(qs, ident, req) {
            Err(OperationError::NoMatchingEntries) => {
                Ok(AuthorizationResponse::not_found(req.resource, req.action))
            }
            res => res,
        })
        .collect()
}

/// A read-only identity can be elevated by re-authentication when its session is
/// privilege capable. Read-only API tokens and other sessions can not.
fn can_elevate(ident: &Identity) -> bool {
    ident.access_scope() == AccessScope::ReadOnly
        && ident
            .get_session()
            .is_some_and(|session| session.scope == SessionScope::PrivilegeCapable)
}

/// Evaluate the request for exactly this identity.
fn evaluate(
    qs: &mut QueryServerReadTransaction<'_>,
    ident: &Identity,
    req: &AuthorizationRequest,
) -> Result<Evaluation, OperationError> {
    // Fetch the resource with the access controls applied, so that an entry that is
    // not visible to the caller is indistinguishable from one that does not exist.
    let filter = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(req.resource)));
    let search_event =
        crate::event::SearchEvent::from_internal_message(ident.clone(), &filter, None, qs)?;

    let target_entry = qs
        .search(&search_event)?
        .into_iter()
        .next()
        .ok_or(OperationError::NoMatchingEntries)?;

    // Every requested attribute must exist in the schema.
    let requested: Option<BTreeSet<Attribute>> = match &req.attributes {
        Some(names) => {
            let mut attrs = BTreeSet::new();
            for name in names {
                match qs.get_schema().normalise_attr_if_exists(name.as_str()) {
                    Some(attr) => {
                        attrs.insert(attr);
                    }
                    None => {
                        debug!(?name, "authorization requested an unknown attribute");
                        return Ok(Evaluation::deny("Unknown attribute requested"));
                    }
                }
            }
            Some(attrs)
        }
        None => None,
    };

    let access_controls = qs.get_accesscontrols();

    // Which profiles apply to the caller is only disclosed to access control admins.
    let matched_rules: Vec<String> =
        if req.include_explanation && ident.is_memberof(UUID_IDM_ACCESS_CONTROL_ADMINS) {
            match req.action {
                AuthorizationAction::Search => access_controls
                    .search_related_acp(ident, None)
                    .iter()
                    .map(|acp| acp.acp.acp.name.clone())
                    .collect(),
                AuthorizationAction::Modify => access_controls
                    .modify_related_acp(ident)
                    .iter()
                    .map(|acp| acp.acp.acp.name.clone())
                    .collect(),
                AuthorizationAction::Delete => access_controls
                    .delete_related_acp(ident)
                    .iter()
                    .map(|acp| acp.acp.acp.name.clone())
                    .collect(),
                AuthorizationAction::Create => Vec::new(),
            }
        } else {
            Vec::new()
        };

    if req.action == AuthorizationAction::Create {
        return Ok(Evaluation {
            matched_rules,
            ..Evaluation::deny("Create action not supported for single-resource authorization")
        });
    }

    let effective = access_controls
        .effective_permission_check(ident, None, std::slice::from_ref(&target_entry))?
        .into_iter()
        .next()
        .ok_or(OperationError::InvalidState)?;

    let mut evaluation = decide(req.action, requested.as_ref(), &effective);
    evaluation.matched_rules = matched_rules;
    Ok(evaluation)
}

fn attr_names(attrs: &BTreeSet<Attribute>) -> BTreeSet<String> {
    attrs.iter().map(|a| a.to_string()).collect()
}

/// Turn the effective permissions of the caller over the resource into a decision.
fn decide(
    action: AuthorizationAction,
    requested: Option<&BTreeSet<Attribute>>,
    effective: &AccessEffectivePermission,
) -> Evaluation {
    match action {
        AuthorizationAction::Search => {
            let allowed = match &effective.search {
                Access::Allow(allowed) => allowed,
                // Access controls never grant an unbounded read to a user.
                Access::Grant | Access::Deny => {
                    return Evaluation::deny("Access denied by policy");
                }
            };

            let permitted = match requested {
                Some(requested) => requested.is_subset(allowed),
                None => !allowed.is_empty(),
            };

            if permitted {
                Evaluation {
                    decision: AuthorizationDecision::Allow,
                    allowed: Some(attr_names(allowed)),
                    present: None,
                    remove: None,
                    matched_rules: Vec::new(),
                    denied_by: None,
                }
            } else {
                Evaluation::deny("Requested attributes are not readable")
            }
        }
        AuthorizationAction::Modify => {
            let Some(requested) = requested else {
                return Evaluation::deny("Attributes are required for modify");
            };

            if requested.is_empty() {
                return Evaluation::deny("Attributes are required for modify");
            }

            // The request can not express which class values would change, so a class
            // modification can never be authorised here.
            if requested.contains(&Attribute::Class) {
                return Evaluation::deny("Class modifications can not be authorised");
            }

            // Access controls never grant an unbounded modify to a user.
            let (Access::Allow(present), Access::Allow(remove)) =
                (&effective.modify_pres, &effective.modify_rem)
            else {
                return Evaluation::deny("Access denied by policy");
            };

            if requested.is_subset(present) && requested.is_subset(remove) {
                let both: BTreeSet<Attribute> = present.intersection(remove).cloned().collect();
                Evaluation {
                    decision: AuthorizationDecision::Allow,
                    allowed: Some(attr_names(&both)),
                    present: Some(attr_names(present)),
                    remove: Some(attr_names(remove)),
                    matched_rules: Vec::new(),
                    denied_by: None,
                }
            } else {
                Evaluation::deny("Requested attributes are not modifiable")
            }
        }
        AuthorizationAction::Delete => {
            if effective.delete {
                Evaluation {
                    decision: AuthorizationDecision::Allow,
                    allowed: None,
                    present: None,
                    remove: None,
                    matched_rules: Vec::new(),
                    denied_by: None,
                }
            } else {
                Evaluation::deny("Access denied by policy")
            }
        }
        AuthorizationAction::Create => {
            Evaluation::deny("Create action not supported for single-resource authorization")
        }
    }
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
            present_attributes: None,
            remove_attributes: None,
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
#[cfg(test)]
mod pdp_tests {
    use super::{make_authorization_decision, make_batch_authorization_decision};
    use crate::be::Limits;
    use crate::prelude::*;
    use crate::server::identity::{IdentUser, IdentityId, Source};
    use crate::value::{AuthType, Session, SessionExtMetadata, SessionScope, SessionState};
    use kubidm_proto::internal::{
        AuthorizationAction, AuthorizationDecision, AuthorizationRequest, AUTHORIZATION_BATCH_MAX,
    };
    use std::collections::BTreeSet;
    use std::sync::Arc;

    struct Fixture {
        user: Uuid,
        group: Uuid,
        target: Uuid,
        hidden: Uuid,
    }

    async fn setup(qs: &QueryServer) -> Fixture {
        let fx = Fixture {
            user: Uuid::new_v4(),
            group: Uuid::new_v4(),
            target: Uuid::new_v4(),
            hidden: Uuid::new_v4(),
        };

        let person = |name: &str, uuid: Uuid| {
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname(name)),
                (Attribute::DisplayName, Value::new_utf8s(name)),
                (Attribute::Uuid, Value::Uuid(uuid))
            )
        };

        let mut acp = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (Attribute::Class, EntryClass::AccessControlModify.to_value()),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (Attribute::Name, Value::new_iname("pdp_acp")),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::AcpReceiverGroup, Value::ReferN(fx.group)),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"eq\":[\"name\",\"pdp_target\"]}").expect("filter")
            )
        );
        for attr in [
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Class,
            Attribute::DisplayName,
        ] {
            acp.add_ava(Attribute::AcpSearchAttr, Value::new_iutf8n(attr.as_str()));
        }
        // displayname may be added and removed, legalname may only be added.
        for attr in [Attribute::DisplayName, Attribute::LegalName] {
            acp.add_ava(
                Attribute::AcpModifyPresentAttr,
                Value::new_iutf8n(attr.as_str()),
            );
        }
        acp.add_ava(
            Attribute::AcpModifyRemovedAttr,
            Value::new_iutf8n(Attribute::DisplayName.as_str()),
        );

        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();
        qs_write
            .internal_create(vec![
                person("pdp_user", fx.user),
                person("pdp_target", fx.target),
                person("pdp_hidden", fx.hidden),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Group.to_value()),
                    (Attribute::Name, Value::new_iname("pdp_group")),
                    (Attribute::Uuid, Value::Uuid(fx.group)),
                    (Attribute::Member, Value::ReferN(fx.user))
                ),
                acp,
            ])
            .expect("failed to create entries");
        qs_write.commit().expect("commit");

        fx
    }

    /// An in-memory identity entry for the user, with the given memberships and a
    /// session of the given scope.
    fn identity(
        fx: &Fixture,
        memberof: &[Uuid],
        session_scope: Option<SessionScope>,
        access_scope: AccessScope,
    ) -> Identity {
        let session_id = Uuid::new_v4();
        let mut entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("pdp_user")),
            (Attribute::Uuid, Value::Uuid(fx.user))
        );
        for group in memberof {
            entry.add_ava(Attribute::MemberOf, Value::ReferN(*group));
        }
        if let Some(scope) = session_scope {
            entry.add_ava(
                Attribute::UserAuthTokenSession,
                Value::Session(
                    session_id,
                    Session {
                        label: "test".to_string(),
                        state: SessionState::NeverExpires,
                        issued_at: time::OffsetDateTime::UNIX_EPOCH,
                        issued_by: IdentityId::User(fx.user),
                        cred_id: Uuid::new_v4(),
                        scope,
                        type_: AuthType::Passkey,
                        ext_metadata: SessionExtMetadata::None,
                    },
                ),
            );
        }

        Identity::new(
            IdentType::User(IdentUser {
                entry: Arc::new(entry.into_sealed_committed()),
            }),
            Source::Internal,
            session_id,
            access_scope,
            Limits::unlimited(),
            None,
        )
    }

    fn request(
        resource: Uuid,
        action: AuthorizationAction,
        attrs: Option<&[&str]>,
    ) -> AuthorizationRequest {
        let req = AuthorizationRequest::new(None, resource, action);
        match attrs {
            Some(attrs) => req.with_attributes(attrs.iter().map(|a| a.to_string()).collect()),
            None => req,
        }
    }

    fn names(attrs: &[&str]) -> Option<BTreeSet<String>> {
        Some(attrs.iter().map(|a| a.to_string()).collect())
    }

    #[qs_test]
    async fn test_pdp_attribute_decisions(qs: &QueryServer) {
        let fx = setup(qs).await;
        let ident = identity(&fx, &[fx.group], None, AccessScope::ReadWrite);
        let mut qs_read = qs.read().await.unwrap();

        let decide = |qs_read: &mut QueryServerReadTransaction<'_>, req: AuthorizationRequest| {
            make_authorization_decision(qs_read, &ident, &req).expect("decision")
        };

        // Search: allowed iff the requested attributes are readable.
        let res = decide(
            &mut qs_read,
            request(fx.target, AuthorizationAction::Search, None),
        );
        assert_eq!(res.decision, AuthorizationDecision::Allow);
        assert_eq!(
            res.allowed_attributes,
            names(&["class", "displayname", "name", "uuid"])
        );

        let res = decide(
            &mut qs_read,
            request(fx.target, AuthorizationAction::Search, Some(&["name"])),
        );
        assert_eq!(res.decision, AuthorizationDecision::Allow);

        for attrs in [
            &["legalname"][..],
            &["name", "legalname"],
            &["not_an_attribute"],
        ] {
            let res = decide(
                &mut qs_read,
                request(fx.target, AuthorizationAction::Search, Some(attrs)),
            );
            assert_eq!(res.decision, AuthorizationDecision::Deny, "{attrs:?}");
        }

        // Modify: allowed iff every attribute may be both added and removed.
        let res = decide(
            &mut qs_read,
            request(
                fx.target,
                AuthorizationAction::Modify,
                Some(&["displayname"]),
            ),
        );
        assert_eq!(res.decision, AuthorizationDecision::Allow);
        assert_eq!(res.present_attributes, names(&["displayname", "legalname"]));
        assert_eq!(res.remove_attributes, names(&["displayname"]));
        assert_eq!(res.allowed_attributes, names(&["displayname"]));

        for attrs in [
            None,
            Some(&[][..]),
            Some(&["legalname"][..]),
            Some(&["class"][..]),
            Some(&["displayname", "class"][..]),
            Some(&["not_an_attribute"][..]),
        ] {
            let res = decide(
                &mut qs_read,
                request(fx.target, AuthorizationAction::Modify, attrs),
            );
            assert_eq!(res.decision, AuthorizationDecision::Deny, "{attrs:?}");
            assert!(res.present_attributes.is_none());
        }

        // Delete.
        let res = decide(
            &mut qs_read,
            request(fx.target, AuthorizationAction::Delete, None),
        );
        assert_eq!(res.decision, AuthorizationDecision::Allow);

        // A resource that is not visible is indistinguishable from a missing one.
        for resource in [fx.hidden, Uuid::new_v4()] {
            let req = request(resource, AuthorizationAction::Search, None);
            assert_eq!(
                make_authorization_decision(&mut qs_read, &ident, &req).unwrap_err(),
                OperationError::NoMatchingEntries
            );
        }
    }

    #[qs_test]
    async fn test_pdp_subject_must_be_caller(qs: &QueryServer) {
        let fx = setup(qs).await;
        let ident = identity(&fx, &[fx.group], None, AccessScope::ReadWrite);
        let mut qs_read = qs.read().await.unwrap();

        let req =
            AuthorizationRequest::new(Some(Uuid::new_v4()), fx.target, AuthorizationAction::Search);
        assert_eq!(
            make_authorization_decision(&mut qs_read, &ident, &req).unwrap_err(),
            OperationError::InvalidRequestState
        );

        let req = AuthorizationRequest::new(Some(fx.user), fx.target, AuthorizationAction::Search);
        let res = make_authorization_decision(&mut qs_read, &ident, &req).expect("decision");
        assert_eq!(res.decision, AuthorizationDecision::Allow);
    }

    #[qs_test]
    async fn test_pdp_matched_rules_only_for_acp_admins(qs: &QueryServer) {
        let fx = setup(qs).await;
        let mut qs_read = qs.read().await.unwrap();
        let req = request(fx.target, AuthorizationAction::Search, None).with_explanation(true);

        let user = identity(&fx, &[fx.group], None, AccessScope::ReadWrite);
        let res = make_authorization_decision(&mut qs_read, &user, &req).expect("decision");
        let explanation = res.explanation.expect("explanation");
        assert!(explanation.matched_rules.is_empty());

        let admin = identity(
            &fx,
            &[fx.group, UUID_IDM_ACCESS_CONTROL_ADMINS],
            None,
            AccessScope::ReadWrite,
        );
        let res = make_authorization_decision(&mut qs_read, &admin, &req).expect("decision");
        let explanation = res.explanation.expect("explanation");
        assert!(explanation.matched_rules.contains(&"pdp_acp".to_string()));
    }

    #[qs_test]
    async fn test_pdp_stepup(qs: &QueryServer) {
        let fx = setup(qs).await;
        let mut qs_read = qs.read().await.unwrap();
        let modify = request(
            fx.target,
            AuthorizationAction::Modify,
            Some(&["displayname"]),
        );
        let delete = request(fx.target, AuthorizationAction::Delete, None);

        // A read-only, privilege capable session must re-authenticate, and learns
        // nothing about what it would be allowed.
        let privilege_capable = identity(
            &fx,
            &[fx.group],
            Some(SessionScope::PrivilegeCapable),
            AccessScope::ReadOnly,
        );
        for req in [&modify, &delete] {
            let res = make_authorization_decision(&mut qs_read, &privilege_capable, req)
                .expect("decision");
            assert_eq!(res.decision, AuthorizationDecision::ReauthRequired);
            assert!(res.allowed_attributes.is_none());
            assert!(res.present_attributes.is_none());
            assert!(res.remove_attributes.is_none());
        }

        // A request that is denied even after re-authentication stays denied.
        let res = make_authorization_decision(
            &mut qs_read,
            &privilege_capable,
            &request(fx.target, AuthorizationAction::Modify, Some(&["name"])),
        )
        .expect("decision");
        assert_eq!(res.decision, AuthorizationDecision::Deny);

        // An entry that is not visible even to a read-write session is not found.
        let req = request(
            fx.hidden,
            AuthorizationAction::Modify,
            Some(&["displayname"]),
        );
        assert_eq!(
            make_authorization_decision(&mut qs_read, &privilege_capable, &req).unwrap_err(),
            OperationError::NoMatchingEntries
        );

        // Sessions that can never be privileged (read-only api tokens, read-only
        // sessions) are simply denied.
        for ident in [
            identity(&fx, &[fx.group], None, AccessScope::ReadOnly),
            identity(
                &fx,
                &[fx.group],
                Some(SessionScope::ReadOnly),
                AccessScope::ReadOnly,
            ),
        ] {
            for req in [&modify, &delete] {
                let res = make_authorization_decision(&mut qs_read, &ident, req).expect("decision");
                assert_eq!(res.decision, AuthorizationDecision::Deny);
            }
        }
    }

    #[qs_test]
    async fn test_pdp_batch(qs: &QueryServer) {
        let fx = setup(qs).await;
        let ident = identity(&fx, &[fx.group], None, AccessScope::ReadWrite);
        let mut qs_read = qs.read().await.unwrap();

        let too_many: Vec<_> = (0..=AUTHORIZATION_BATCH_MAX)
            .map(|_| request(fx.target, AuthorizationAction::Search, None))
            .collect();
        assert_eq!(
            make_batch_authorization_decision(&mut qs_read, &ident, &too_many).unwrap_err(),
            OperationError::InvalidRequestState
        );

        let at_max = &too_many[..AUTHORIZATION_BATCH_MAX];
        assert_eq!(
            make_batch_authorization_decision(&mut qs_read, &ident, at_max)
                .expect("batch")
                .len(),
            AUTHORIZATION_BATCH_MAX
        );

        let missing = Uuid::new_v4();
        let mixed = vec![
            request(fx.target, AuthorizationAction::Search, None),
            request(fx.hidden, AuthorizationAction::Search, None),
            request(missing, AuthorizationAction::Delete, None),
            request(fx.target, AuthorizationAction::Modify, Some(&["legalname"])),
        ];
        let res = make_batch_authorization_decision(&mut qs_read, &ident, &mixed).expect("batch");
        let decisions: Vec<_> = res.iter().map(|r| (r.resource, r.decision)).collect();
        assert_eq!(
            decisions,
            vec![
                (fx.target, AuthorizationDecision::Allow),
                (fx.hidden, AuthorizationDecision::NotFound),
                (missing, AuthorizationDecision::NotFound),
                (fx.target, AuthorizationDecision::Deny),
            ]
        );
    }
}
