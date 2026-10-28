//! End to end tests for template driven delegated administration over HTTP: grant a
//! template, use it as a member of the receiver group, and revoke it.
#![deny(warnings)]

use kubidm_client::{ClientError, KubidmClient};
use kubidm_proto::internal::OperationError;
use kubidmd_testkit::{
    ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD, IDM_ADMIN_TEST_USER,
    NOT_ADMIN_TEST_PASSWORD,
};
use reqwest::StatusCode;

const HELPER: &str = "dlg_helper";
const TARGET: &str = "dlg_target";
const OUTSIDER: &str = "dlg_outsider";
const RECEIVERS: &str = "dlg_receivers";
const SCOPE: &str = "dlg_scope";

async fn login(rsclient: &KubidmClient, id: &str, password: &str) {
    let _ = rsclient.logout().await;
    rsclient
        .auth_simple_password(id, password)
        .await
        .expect("Failed to login");
}

/// Log in as a person with a privileged (read-write) session.
async fn login_person(rsclient: &KubidmClient, id: &str) {
    login(rsclient, id, NOT_ADMIN_TEST_PASSWORD).await;
    rsclient
        .reauth_simple_password(NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to reauth as person");
}

/// Can the logged in account start a credential reset of `id`?
async fn can_reset(rsclient: &KubidmClient, id: &str) -> bool {
    rsclient
        .idm_person_account_credential_update_intent(id, None)
        .await
        .is_ok()
}

#[kubidmd_testkit::test]
async fn test_delegation_grant_use_revoke(rsclient: &KubidmClient) {
    // idm_admin sets up the people and the groups.
    login(rsclient, IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD).await;
    for name in [HELPER, TARGET, OUTSIDER] {
        rsclient
            .idm_person_account_create(name, name)
            .await
            .expect("Failed to create person");
        rsclient
            .idm_person_account_primary_credential_set_password(name, NOT_ADMIN_TEST_PASSWORD)
            .await
            .expect("Failed to set password");
    }
    for (group, member) in [(RECEIVERS, HELPER), (SCOPE, TARGET)] {
        rsclient
            .idm_group_create(group, None)
            .await
            .expect("Failed to create group");
        rsclient
            .idm_group_add_members(group, &[member])
            .await
            .expect("Failed to add member");
    }

    // idm_admin is not an access control admin, so it can not grant.
    assert!(matches!(
        rsclient
            .delegation_grant("helpdesk", RECEIVERS, SCOPE, None)
            .await,
        Err(ClientError::Http(StatusCode::FORBIDDEN, _, _))
    ));

    // Before the delegation, the helper can not reset the target.
    login_person(rsclient, HELPER).await;
    assert!(!can_reset(rsclient, TARGET).await);

    // admin (an access control admin) grants the help desk template.
    login(rsclient, ADMIN_TEST_USER, ADMIN_TEST_PASSWORD).await;
    let grant = rsclient
        .delegation_grant("helpdesk", RECEIVERS, SCOPE, None)
        .await
        .expect("Failed to grant");
    assert!(grant.name.starts_with("delegation_helpdesk_"));
    assert_eq!(grant.template.as_deref(), Some("helpdesk"));
    assert!(grant.drift.is_empty());
    assert!(grant
        .scope
        .as_ref()
        .and_then(|scope| scope.spn.as_deref())
        .is_some_and(|spn| spn.starts_with(SCOPE)));
    assert_eq!(grant.receivers.len(), 1);
    assert!(grant.receivers[0]
        .spn
        .as_deref()
        .is_some_and(|spn| spn.starts_with(RECEIVERS)));

    // A high privilege scope is refused, and so is the same delegation again.
    match rsclient
        .delegation_grant("helpdesk", RECEIVERS, "idm_admins", None)
        .await
    {
        Err(ClientError::Http(status, error, _)) => {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                error,
                Some(OperationError::DG0002DelegationHighPrivilegeGroup)
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(matches!(
        rsclient
            .delegation_grant("helpdesk", RECEIVERS, SCOPE, None)
            .await,
        Err(ClientError::Http(StatusCode::CONFLICT, _, _))
    ));

    let listed = rsclient.delegation_list().await.expect("Failed to list");
    assert_eq!(listed, vec![grant.clone()]);
    assert_eq!(
        rsclient
            .delegation_get(&grant.name)
            .await
            .expect("Failed to get"),
        grant
    );

    // The helper resets the credentials of the person in scope only, and can not see the
    // delegations.
    login_person(rsclient, HELPER).await;
    assert!(can_reset(rsclient, TARGET).await);
    assert!(!can_reset(rsclient, OUTSIDER).await);
    assert!(matches!(
        rsclient.delegation_list().await,
        Err(ClientError::Http(StatusCode::FORBIDDEN, _, _))
    ));
    assert!(rsclient.delegation_revoke(&grant.name).await.is_err());

    // admin revokes the delegation, which removes the access.
    login(rsclient, ADMIN_TEST_USER, ADMIN_TEST_PASSWORD).await;
    rsclient
        .delegation_revoke(&grant.name)
        .await
        .expect("Failed to revoke");
    assert_eq!(
        rsclient.delegation_list().await.expect("Failed to list"),
        Vec::new()
    );
    assert!(matches!(
        rsclient.delegation_get(&grant.name).await,
        Err(ClientError::Http(StatusCode::NOT_FOUND, _, _))
    ));

    login_person(rsclient, HELPER).await;
    assert!(!can_reset(rsclient, TARGET).await);
}
