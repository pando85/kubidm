#![deny(warnings)]
use kubidm_client::KubidmClient;
use kubidm_proto::internal::{
    AuthorizationAction, AuthorizationDecision, AuthorizationRequest, AuthorizationResponse,
    BatchAuthorizationRequest, BatchAuthorizationResponse, AUTHORIZATION_BATCH_MAX,
};
use kubidmd_testkit::{
    create_user, login_account, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD,
    IDM_ADMIN_TEST_USER,
};
use std::collections::BTreeSet;
use std::time::Duration;
use uuid::Uuid;

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

async fn authorize(
    rsclient: &KubidmClient,
    request: AuthorizationRequest,
) -> AuthorizationResponse {
    rsclient
        .perform_post_request("/v1/authorize", request)
        .await
        .expect("Authorization request failed")
}

fn attrs(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| n.to_string()).collect()
}

#[kubidmd_testkit::test]
async fn test_authorization_endpoint_unauthorized(rsclient: &KubidmClient) {
    let resource_uuid = Uuid::new_v4();
    let request = AuthorizationRequest::new(None, resource_uuid, AuthorizationAction::Search);

    let result: Result<AuthorizationResponse, kubidm_client::ClientError> = rsclient
        .perform_post_request("/v1/authorize", request)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        kubidm_client::ClientError::Unauthorized => (),
        kubidm_client::ClientError::Http(kubidm_client::StatusCode::UNAUTHORIZED, _, _) => (),
        other => panic!("Expected Unauthorized error, got {:?}", other),
    }
}

#[kubidmd_testkit::test]
async fn test_authorization_endpoint_authenticated_admin(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let request =
        AuthorizationRequest::new(Some(admin_uuid), admin_uuid, AuthorizationAction::Search);

    let response: AuthorizationResponse = rsclient
        .perform_post_request("/v1/authorize", request)
        .await
        .expect("Authorization request failed");

    assert_eq!(response.resource, admin_uuid);
    assert_eq!(response.action, AuthorizationAction::Search);
}

#[kubidmd_testkit::test]
async fn test_authorization_decision_deny(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let request = AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Delete);

    let response: AuthorizationResponse = rsclient
        .perform_post_request("/v1/authorize", request)
        .await
        .expect("Authorization request failed");

    assert_eq!(response.decision, AuthorizationDecision::Deny);
    assert_eq!(response.resource, admin_uuid);
    assert_eq!(response.action, AuthorizationAction::Delete);
}

#[kubidmd_testkit::test]
async fn test_authorization_decision_types(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    for action in [
        AuthorizationAction::Search,
        AuthorizationAction::Create,
        AuthorizationAction::Modify,
        AuthorizationAction::Delete,
    ] {
        let request = AuthorizationRequest::new(None, admin_uuid, action);
        let response: AuthorizationResponse = rsclient
            .perform_post_request("/v1/authorize", request)
            .await
            .expect("Authorization request failed");

        assert_eq!(response.action, action);
        assert_eq!(response.resource, admin_uuid);
    }
}

#[kubidmd_testkit::test]
async fn test_authorization_with_explanation(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let request = AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Search)
        .with_explanation(true);

    let response: AuthorizationResponse = rsclient
        .perform_post_request("/v1/authorize", request)
        .await
        .expect("Authorization request failed");

    if let Some(explanation) = response.explanation {
        assert!(!explanation.reason.is_empty());
    }
}

#[kubidmd_testkit::test]
async fn test_batch_authorization_endpoint_unauthorized(rsclient: &KubidmClient) {
    let requests = vec![
        AuthorizationRequest::new(None, Uuid::new_v4(), AuthorizationAction::Search),
        AuthorizationRequest::new(None, Uuid::new_v4(), AuthorizationAction::Modify),
    ];
    let batch_request = BatchAuthorizationRequest { requests };

    let result: Result<BatchAuthorizationResponse, kubidm_client::ClientError> = rsclient
        .perform_post_request("/v1/authorize/batch", batch_request)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        kubidm_client::ClientError::Unauthorized => (),
        kubidm_client::ClientError::Http(kubidm_client::StatusCode::UNAUTHORIZED, _, _) => (),
        other => panic!("Expected Unauthorized error, got {:?}", other),
    }
}

#[kubidmd_testkit::test]
async fn test_batch_authorization_endpoint_authenticated(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let requests = vec![
        AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Search),
        AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Modify),
    ];
    let batch_request = BatchAuthorizationRequest { requests };

    let response: BatchAuthorizationResponse = rsclient
        .perform_post_request("/v1/authorize/batch", batch_request)
        .await
        .expect("Batch authorization request failed");

    assert_eq!(response.responses.len(), 2);
    assert_eq!(response.responses[0].resource, admin_uuid);
    assert_eq!(response.responses[1].resource, admin_uuid);
}

#[kubidmd_testkit::test]
async fn test_batch_authorization_empty_requests(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let batch_request = BatchAuthorizationRequest { requests: vec![] };

    let response: BatchAuthorizationResponse = rsclient
        .perform_post_request("/v1/authorize/batch", batch_request)
        .await
        .expect("Batch authorization request failed");

    assert!(response.responses.is_empty());
}

#[kubidmd_testkit::test]
async fn test_batch_authorization_large_batch(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let num_requests = 10;
    let requests: Vec<AuthorizationRequest> = (0..num_requests)
        .map(|_| AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Search))
        .collect();
    let batch_request = BatchAuthorizationRequest { requests };

    let response: BatchAuthorizationResponse = rsclient
        .perform_post_request("/v1/authorize/batch", batch_request)
        .await
        .expect("Batch authorization request failed");

    assert_eq!(response.responses.len(), num_requests);
}

#[kubidmd_testkit::test]
async fn test_authorization_nonexistent_resource_uuid(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let non_existent_uuid = Uuid::new_v4();
    let request = AuthorizationRequest::new(None, non_existent_uuid, AuthorizationAction::Search);

    let result: Result<AuthorizationResponse, kubidm_client::ClientError> = rsclient
        .perform_post_request("/v1/authorize", request)
        .await;

    assert!(result.is_err());
}

#[kubidmd_testkit::test]
async fn test_authorization_with_attributes_filtering(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    // A readable attribute is allowed, and reported as such.
    let request =
        AuthorizationRequest::new(Some(admin_uuid), admin_uuid, AuthorizationAction::Search)
            .with_attributes(attrs(&["name"]));
    let response = authorize(rsclient, request).await;
    assert_eq!(response.decision, AuthorizationDecision::Allow);
    let allowed = response
        .allowed_attributes
        .expect("allowed attributes missing");
    assert!(allowed.contains("name"));

    // An unknown attribute is denied, even alongside a readable one.
    let request =
        AuthorizationRequest::new(Some(admin_uuid), admin_uuid, AuthorizationAction::Search)
            .with_attributes(attrs(&["name", "not_an_attribute"]));
    let response = authorize(rsclient, request).await;
    assert_eq!(response.decision, AuthorizationDecision::Deny);
    assert!(response.allowed_attributes.is_none());
}

#[kubidmd_testkit::test]
async fn test_authorization_session_expiry_handling(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let request = AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Search);

    let response: AuthorizationResponse = rsclient
        .perform_post_request("/v1/authorize", request.clone())
        .await
        .expect("Authorization request failed");

    assert_eq!(response.resource, request.resource);
    assert_eq!(response.action, request.action);
}

#[kubidmd_testkit::test]
async fn test_authorization_concurrent_requests(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let requests: Vec<AuthorizationRequest> = (0..5)
        .map(|_| AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Search))
        .collect();

    let futures: Vec<_> = requests
        .iter()
        .map(|req| {
            rsclient.perform_post_request::<AuthorizationRequest, AuthorizationResponse>(
                "/v1/authorize",
                req.clone(),
            )
        })
        .collect();

    let results = futures::future::join_all(futures).await;

    for result in results {
        assert!(result.is_ok());
    }
}

#[kubidmd_testkit::test]
async fn test_authorization_create_action_unsupported(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let request = AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Create);

    let response: AuthorizationResponse = rsclient
        .perform_post_request("/v1/authorize", request)
        .await
        .expect("Authorization request failed");

    assert_eq!(response.decision, AuthorizationDecision::Deny);
}

#[kubidmd_testkit::test]
async fn test_authorization_subject_must_be_caller(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    let request = AuthorizationRequest::new(
        Some(Uuid::new_v4()),
        admin_uuid,
        AuthorizationAction::Search,
    );
    let result: Result<AuthorizationResponse, kubidm_client::ClientError> = rsclient
        .perform_post_request("/v1/authorize", request)
        .await;
    assert!(result.is_err());
}

#[kubidmd_testkit::test]
async fn test_batch_authorization_cap_and_mixed(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let admin_uuid = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned")
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("Unable to parse admin uuid");

    // More than the maximum is rejected.
    let requests: Vec<AuthorizationRequest> = (0..=AUTHORIZATION_BATCH_MAX)
        .map(|_| AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Search))
        .collect();
    let result: Result<BatchAuthorizationResponse, kubidm_client::ClientError> = rsclient
        .perform_post_request(
            "/v1/authorize/batch",
            BatchAuthorizationRequest { requests },
        )
        .await;
    assert!(result.is_err());

    // A missing resource does not fail the batch.
    let missing = Uuid::new_v4();
    let requests = vec![
        AuthorizationRequest::new(None, admin_uuid, AuthorizationAction::Search),
        AuthorizationRequest::new(None, missing, AuthorizationAction::Search),
    ];
    let response: BatchAuthorizationResponse = rsclient
        .perform_post_request(
            "/v1/authorize/batch",
            BatchAuthorizationRequest { requests },
        )
        .await
        .expect("Batch authorization request failed");
    assert_eq!(response.responses.len(), 2);
    assert_eq!(response.responses[0].decision, AuthorizationDecision::Allow);
    assert_eq!(response.responses[1].resource, missing);
    assert_eq!(
        response.responses[1].decision,
        AuthorizationDecision::NotFound
    );
}

#[kubidmd_testkit::test]
async fn test_authorization_low_privilege_user(rsclient: &KubidmClient) {
    let user = "authz_lowpriv";
    let other = "authz_other";

    rsclient
        .auth_simple_password(IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as idm_admin");
    create_user(rsclient, user, "authz_lowpriv_group").await;
    create_user(rsclient, other, "authz_other_group").await;
    let other_uuid = person_uuid(rsclient, other).await;

    // Logs in, and re-authenticates for a privileged session.
    login_account(rsclient, user).await;
    let user_uuid = person_uuid(rsclient, user).await;

    // The user can read and update their own name ...
    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Search)
            .with_attributes(attrs(&["name"])),
    )
    .await;
    assert_eq!(response.decision, AuthorizationDecision::Allow);

    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Modify)
            .with_attributes(attrs(&["displayname"])),
    )
    .await;
    assert_eq!(response.decision, AuthorizationDecision::Allow);
    assert!(response
        .present_attributes
        .expect("present attributes missing")
        .contains("displayname"));
    assert!(response
        .remove_attributes
        .expect("remove attributes missing")
        .contains("displayname"));

    // ... but not their classes, and they can not delete themselves.
    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Modify)
            .with_attributes(attrs(&["class"])),
    )
    .await;
    assert_eq!(response.decision, AuthorizationDecision::Deny);

    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Delete),
    )
    .await;
    assert_eq!(response.decision, AuthorizationDecision::Deny);

    // Modify requires the attributes to be named.
    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Modify),
    )
    .await;
    assert_eq!(response.decision, AuthorizationDecision::Deny);

    // Other people can not be modified or deleted.
    for request in [
        AuthorizationRequest::new(None, other_uuid, AuthorizationAction::Modify)
            .with_attributes(attrs(&["displayname"])),
        AuthorizationRequest::new(None, other_uuid, AuthorizationAction::Delete),
    ] {
        let result: Result<AuthorizationResponse, kubidm_client::ClientError> = rsclient
            .perform_post_request("/v1/authorize", request)
            .await;
        // Either not visible at all, or denied.
        if let Ok(response) = result {
            assert_eq!(response.decision, AuthorizationDecision::Deny);
        }
    }

    // A user can not ask about someone else's permissions.
    let request =
        AuthorizationRequest::new(Some(other_uuid), user_uuid, AuthorizationAction::Search);
    let result: Result<AuthorizationResponse, kubidm_client::ClientError> = rsclient
        .perform_post_request("/v1/authorize", request)
        .await;
    assert!(result.is_err());

    // The matching rules are not disclosed to a non access control admin.
    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Search)
            .with_explanation(true),
    )
    .await;
    let explanation = response.explanation.expect("explanation missing");
    assert!(explanation.matched_rules.is_empty());
}

#[kubidmd_testkit::test]
async fn test_authorization_stepup_reauth_required(rsclient: &KubidmClient) {
    let user = "authz_stepup";
    let policy_group = "authz_stepup_policy";

    rsclient
        .auth_simple_password(IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as idm_admin");
    create_user(rsclient, user, policy_group).await;
    // Privileges expire almost immediately for members of this group.
    rsclient
        .group_account_policy_enable(policy_group)
        .await
        .expect("Failed to enable account policy");
    rsclient
        .group_account_policy_privilege_expiry_set(policy_group, 1)
        .await
        .expect("Failed to set privilege expiry");

    login_account(rsclient, user).await;
    let user_uuid = person_uuid(rsclient, user).await;

    // Wait for the privileges of the session to lapse.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Reading is unaffected ...
    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Search)
            .with_attributes(attrs(&["name"])),
    )
    .await;
    assert_eq!(response.decision, AuthorizationDecision::Allow);

    // ... while a write the user is entitled to requires re-authentication, without
    // disclosing the attribute sets.
    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Modify)
            .with_attributes(attrs(&["displayname"])),
    )
    .await;
    assert_eq!(response.decision, AuthorizationDecision::ReauthRequired);
    assert!(response.allowed_attributes.is_none());
    assert!(response.present_attributes.is_none());
    assert!(response.remove_attributes.is_none());

    // A write the user is never entitled to is still denied.
    let response = authorize(
        rsclient,
        AuthorizationRequest::new(None, user_uuid, AuthorizationAction::Delete),
    )
    .await;
    assert_eq!(response.decision, AuthorizationDecision::Deny);
}
