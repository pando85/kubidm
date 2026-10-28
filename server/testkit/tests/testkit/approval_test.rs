//! End to end tests for creating approval requests over HTTP.
//!
//! No operation is gated on approvals yet, so these exercise the full policy, request and
//! decision cycle through the API only.
#![deny(warnings)]
use std::collections::BTreeMap;

use kubidm_client::{ClientError, KubidmClient};
use kubidm_proto::internal::OperationError;
use kubidm_proto::v1::{
    ApprovalOperationType, ApprovalPattern, ApprovalPolicyCreateRequest,
    ApprovalRequestCreateRequest, ApprovalRequestState,
};
use kubidmd_testkit::{IDM_ADMIN_TEST_PASSWORD, IDM_ADMIN_TEST_USER, NOT_ADMIN_TEST_PASSWORD};
use reqwest::StatusCode;
use uuid::Uuid;

const REQUESTER: &str = "appr_requester";
const APPROVER_A: &str = "appr_approver_a";
const APPROVER_B: &str = "appr_approver_b";
const TARGET_GROUP: &str = "appr_target_group";

/// The uuid of a person account, as seen by the current session.
async fn person_uuid(rsclient: &KubidmClient, id: &str) -> Uuid {
    rsclient
        .idm_person_account_get(id)
        .await
        .expect("Unable to get person")
        .expect("Person not found")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse person uuid")
}

async fn login_idm_admin(rsclient: &KubidmClient) {
    let _ = rsclient.logout().await;
    rsclient
        .auth_simple_password(IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as idm_admin");
}

/// Log in as a person with an interactive, privileged (read-write) session.
async fn login_person(rsclient: &KubidmClient, id: &str) {
    let _ = rsclient.logout().await;
    rsclient
        .auth_simple_password(id, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as person");
    rsclient
        .reauth_simple_password(NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to reauth as person");
}

/// As idm_admin (an approval admin), create the people and the target group. Leaves the
/// client logged in as idm_admin.
async fn setup_directory(rsclient: &KubidmClient) {
    login_idm_admin(rsclient).await;

    for name in [REQUESTER, APPROVER_A, APPROVER_B] {
        rsclient
            .idm_person_account_create(name, name)
            .await
            .expect("Failed to create person");
        rsclient
            .idm_person_account_primary_credential_set_password(name, NOT_ADMIN_TEST_PASSWORD)
            .await
            .expect("Failed to set person password");
    }
    rsclient
        .idm_group_create(TARGET_GROUP, None)
        .await
        .expect("Failed to create target group");
}

fn policy_request(
    name: &str,
    pattern: ApprovalPattern,
    approvers: Vec<Uuid>,
) -> ApprovalPolicyCreateRequest {
    ApprovalPolicyCreateRequest {
        name: name.to_string(),
        description: None,
        operation_types: vec![ApprovalOperationType::PrivilegeGrant],
        approvers,
        backup_approvers: vec![],
        pattern,
        timeout_seconds: 3600,
        escalation_timeout_seconds: None,
    }
}

fn create_request(policy: &str) -> ApprovalRequestCreateRequest {
    ApprovalRequestCreateRequest {
        policy_name: policy.to_string(),
        operation_type: ApprovalOperationType::PrivilegeGrant,
        // By name, to cover resolving the target. A person can read their own entry, but
        // not the target group.
        target: REQUESTER.to_string(),
        operation_details: BTreeMap::from([("group".to_string(), "idm_admins".to_string())]),
    }
}

#[kubidmd_testkit::test]
async fn test_approval_request_create_and_approve(rsclient: &KubidmClient) {
    setup_directory(rsclient).await;
    let approver_a = person_uuid(rsclient, APPROVER_A).await;
    let approver_b = person_uuid(rsclient, APPROVER_B).await;
    let requester = person_uuid(rsclient, REQUESTER).await;
    // An approval admin creates a policy that needs both approvers.
    rsclient
        .approval_policy_create(&policy_request(
            "appr_all_policy",
            ApprovalPattern::All,
            vec![approver_a, approver_b],
        ))
        .await
        .expect("Failed to create approval policy");

    // A person creates a request.
    login_person(rsclient, REQUESTER).await;
    let request_uuid = rsclient
        .approval_request_create(&create_request("appr_all_policy"))
        .await
        .expect("Failed to create approval request");

    // The first decision leaves it pending, the second reaches the quorum.
    login_person(rsclient, APPROVER_A).await;
    rsclient
        .approval_request_approve(&request_uuid.to_string(), Some("ok"))
        .await
        .expect("Approver A failed to approve");

    login_idm_admin(rsclient).await;
    let request = rsclient
        .approval_request_get(&request_uuid.to_string())
        .await
        .expect("Failed to get approval request");
    assert_eq!(request.state, ApprovalRequestState::Pending);

    login_person(rsclient, APPROVER_B).await;
    rsclient
        .approval_request_approve(&request_uuid.to_string(), None)
        .await
        .expect("Approver B failed to approve");

    login_idm_admin(rsclient).await;
    let request = rsclient
        .approval_request_get(&request_uuid.to_string())
        .await
        .expect("Failed to get approval request");
    assert_eq!(request.uuid, request_uuid);
    assert_eq!(request.state, ApprovalRequestState::Approved);
    assert_eq!(request.policy_name.as_deref(), Some("appr_all_policy"));
    assert_eq!(
        request.operation_type,
        ApprovalOperationType::PrivilegeGrant
    );
    assert_eq!(request.target_uuid, Some(requester));
    assert_eq!(request.requestor_uuid, Some(requester));
    assert_eq!(
        request.operation_details.get("group").map(String::as_str),
        Some("idm_admins")
    );
    assert_eq!(request.decisions.len(), 2);
}

#[kubidmd_testkit::test]
async fn test_approval_request_create_unknown_policy(rsclient: &KubidmClient) {
    setup_directory(rsclient).await;

    login_person(rsclient, REQUESTER).await;
    let err = rsclient
        .approval_request_create(&create_request("appr_no_such_policy"))
        .await
        .expect_err("A request under an unknown policy must be rejected");
    assert!(
        matches!(
            err,
            ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::NoMatchingEntries),
                _
            )
        ),
        "unexpected error: {err:?}"
    );
}

#[kubidmd_testkit::test]
async fn test_approval_request_create_quorum_unreachable(rsclient: &KubidmClient) {
    setup_directory(rsclient).await;
    let requester = person_uuid(rsclient, REQUESTER).await;
    let approver_a = person_uuid(rsclient, APPROVER_A).await;

    // The requester is the only approver, and never counts as one of their own request.
    rsclient
        .approval_policy_create(&policy_request(
            "appr_self_policy",
            ApprovalPattern::AnyOne,
            vec![requester],
        ))
        .await
        .expect("Failed to create approval policy");
    rsclient
        .approval_policy_create(&policy_request(
            "appr_other_policy",
            ApprovalPattern::AnyOne,
            vec![requester, approver_a],
        ))
        .await
        .expect("Failed to create approval policy");

    login_person(rsclient, REQUESTER).await;
    let err = rsclient
        .approval_request_create(&create_request("appr_self_policy"))
        .await
        .expect_err("An unreachable quorum must be rejected");
    assert!(
        matches!(
            err,
            ClientError::Http(
                StatusCode::UNPROCESSABLE_ENTITY,
                Some(OperationError::AP0001ApprovalQuorumUnreachable),
                _
            )
        ),
        "unexpected error: {err:?}"
    );

    // With another approver the same requester can file.
    rsclient
        .approval_request_create(&create_request("appr_other_policy"))
        .await
        .expect("A reachable quorum must be accepted");
}

/// The failure a request for `target` gets, which must be an error.
async fn create_target_error(rsclient: &KubidmClient, policy: &str, target: &str) -> ClientError {
    let mut request = create_request(policy);
    request.target = target.to_string();
    rsclient
        .approval_request_create(&request)
        .await
        .expect_err("A request for a target the requester can not see must be rejected")
}

/// A requester can not tell an entry they may not read from one that does not exist.
#[kubidmd_testkit::test]
async fn test_approval_request_create_target_not_visible(rsclient: &KubidmClient) {
    setup_directory(rsclient).await;
    let requester = person_uuid(rsclient, REQUESTER).await;
    let approver_a = person_uuid(rsclient, APPROVER_A).await;

    // idm_admin is a service account the person can not read, and it exists.
    let hidden_uuid = rsclient
        .idm_service_account_get(IDM_ADMIN_TEST_USER)
        .await
        .expect("Failed to get idm_admin")
        .and_then(|e| e.attrs.get("uuid").and_then(|v| v.first().cloned()))
        .expect("Unable to read the idm_admin uuid");

    rsclient
        .approval_policy_create(&policy_request(
            "appr_target_policy",
            ApprovalPattern::AnyOne,
            vec![approver_a],
        ))
        .await
        .expect("Failed to create approval policy");

    login_person(rsclient, REQUESTER).await;
    assert!(
        rsclient
            .idm_service_account_get(IDM_ADMIN_TEST_USER)
            .await
            .map(|e| e.is_none())
            .unwrap_or(true),
        "the requester must not be able to read the hidden entry"
    );

    // Hidden entries by name, spn and uuid, against names and uuids that do not exist.
    let hidden = [
        IDM_ADMIN_TEST_USER.to_string(),
        format!("{IDM_ADMIN_TEST_USER}@localhost"),
        hidden_uuid,
        // A group is not readable by a person either.
        TARGET_GROUP.to_string(),
    ];
    let missing = [
        "appr_no_such_entry".to_string(),
        "appr_no_such_entry@localhost".to_string(),
        Uuid::new_v4().to_string(),
    ];
    let missing_error = create_target_error(rsclient, "appr_target_policy", &missing[0]).await;
    let ClientError::Http(missing_status, missing_op, _) = missing_error else {
        panic!("unexpected error: {missing_error:?}");
    };
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(missing_op, Some(OperationError::NoMatchingEntries));

    for target in hidden.iter().chain(missing.iter()) {
        let error = create_target_error(rsclient, "appr_target_policy", target).await;
        let ClientError::Http(status, op, body) = error else {
            panic!("unexpected error for {target}: {error:?}");
        };
        assert_eq!(status, missing_status, "{target}");
        assert_eq!(op, missing_op, "{target}");
        // The body is only the id of the request, which differs on every call.
        assert!(Uuid::parse_str(&body).is_ok(), "{target}: {body}");
    }

    // A visible target, the requester themselves, still works.
    let mut request = create_request("appr_target_policy");
    request.target = requester.to_string();
    rsclient
        .approval_request_create(&request)
        .await
        .expect("A visible target must be accepted");
}
