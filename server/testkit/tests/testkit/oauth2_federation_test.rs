#![deny(warnings)]
use kubidm_client::{ClientError, KubidmClient, StatusCode};
use kubidm_proto::{
    constants::uri::{
        OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_PERMIT, OAUTH2_TOKEN_ENDPOINT,
        OAUTH2_TOKEN_INTROSPECT_ENDPOINT,
    },
    internal::{Filter, Modify, ModifyList},
    oauth2::AuthorisationResponse,
    v1::Entry,
};
use kubidmd_core::config::ServerRole;
use kubidmd_testkit::{
    ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD, IDM_ADMIN_TEST_USER,
    NOT_ADMIN_TEST_PASSWORD,
};
use std::collections::BTreeMap;
use url::Url;

/// The federation (upstream identity provider) management routes.
const FEDERATION_PATH: &str = "/v1/federation/oauth2";

fn get_federation_test_idp_name() -> String {
    "test_federation_idp".to_string()
}

fn get_federation_test_client_id() -> String {
    "test_federation_client_id".to_string()
}

fn get_federation_test_issuer() -> Url {
    Url::parse("https://idp.example.com").expect("Invalid issuer URL")
}

/// A valid federation entry: the required attributes plus the explicit authorisation,
/// token and introspection endpoints.
fn federation_entry(idp_name: &str, client_id: &str, client_secret: &str, issuer: &Url) -> Entry {
    let endpoint = |path: &str| issuer.join(path).expect("Invalid endpoint URL").to_string();
    Entry {
        attrs: BTreeMap::from([
            (
                "class".to_string(),
                vec!["oauth2_federation".to_string(), "object".to_string()],
            ),
            ("name".to_string(), vec![idp_name.to_string()]),
            ("oauth2_client_id".to_string(), vec![client_id.to_string()]),
            (
                "oauth2_client_secret".to_string(),
                vec![client_secret.to_string()],
            ),
            ("oauth2_issuer".to_string(), vec![issuer.to_string()]),
            (
                "oauth2_authorisation_endpoint".to_string(),
                vec![endpoint("/oauth2/authorise")],
            ),
            (
                "oauth2_token_endpoint".to_string(),
                vec![endpoint("/oauth2/token")],
            ),
            (
                "oauth2_token_introspect_endpoint".to_string(),
                vec![endpoint("/oauth2/token/introspect")],
            ),
        ]),
    }
}

/// [federation_entry] with the default test client and issuer.
fn default_federation_entry(idp_name: &str) -> Entry {
    federation_entry(
        idp_name,
        &get_federation_test_client_id(),
        "test_secret",
        &get_federation_test_issuer(),
    )
}

fn with_attr(mut entry: Entry, attr: &str, values: &[&str]) -> Entry {
    entry.attrs.insert(
        attr.to_string(),
        values.iter().map(|v| v.to_string()).collect(),
    );
    entry
}

fn without_attr(mut entry: Entry, attr: &str) -> Entry {
    entry.attrs.remove(attr);
    entry
}

async fn post_federation(rsclient: &KubidmClient, entry: Entry) -> Result<(), ClientError> {
    rsclient
        .perform_post_request::<_, ()>(FEDERATION_PATH, entry)
        .await
}

async fn create_federation_idp(
    rsclient: &KubidmClient,
    idp_name: &str,
    client_id: &str,
    client_secret: &str,
    issuer: &Url,
) -> Result<(), ClientError> {
    post_federation(
        rsclient,
        federation_entry(idp_name, client_id, client_secret, issuer),
    )
    .await
}

async fn get_federation_idp(rsclient: &KubidmClient, idp_name: &str) -> Result<Entry, ClientError> {
    rsclient
        .perform_get_request(&format!("{FEDERATION_PATH}/{idp_name}"))
        .await
}

async fn patch_federation_idp(
    rsclient: &KubidmClient,
    idp_name: &str,
    attrs: &[(&str, &[&str])],
) -> Result<(), ClientError> {
    let entry = Entry {
        attrs: attrs
            .iter()
            .map(|(attr, values)| {
                (
                    attr.to_string(),
                    values.iter().map(|v| v.to_string()).collect(),
                )
            })
            .collect(),
    };
    rsclient
        .perform_patch_request::<_, ()>(&format!("{FEDERATION_PATH}/{idp_name}"), entry)
        .await
}

/// DELETE a federation through the management route, returning the HTTP status.
async fn delete_federation_idp(rsclient: &KubidmClient, idp_name: &str) -> StatusCode {
    let token = rsclient.get_token().await.unwrap_or_default();
    api_client()
        .delete(rsclient.make_url(&format!("{FEDERATION_PATH}/{idp_name}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to send delete request")
        .status()
}

/// A client for direct HTTP requests, never following redirects.
fn api_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create client.")
}

async fn login_admin(rsclient: &KubidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
}

/// Assert that creating `entry` is rejected.
async fn assert_create_rejected(rsclient: &KubidmClient, entry: Entry, reason: &str) {
    let name = entry
        .attrs
        .get("name")
        .and_then(|n| n.first())
        .cloned()
        .unwrap_or_default();
    let result = post_federation(rsclient, entry).await;
    assert!(result.is_err(), "{reason} should fail");
    if !name.is_empty() {
        assert!(
            matches!(
                get_federation_idp(rsclient, &name).await,
                Err(ClientError::Http(StatusCode::NOT_FOUND, _, _))
            ),
            "{reason}: nothing must be stored"
        );
    }
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_create(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = get_federation_test_idp_name();
    let client_id = get_federation_test_client_id();
    let issuer = get_federation_test_issuer();

    let result =
        create_federation_idp(rsclient, &idp_name, &client_id, "test_secret", &issuer).await;

    assert!(result.is_ok(), "Federation IdP creation should succeed");
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_create_with_all_attributes(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_full", get_federation_test_idp_name());

    let entry = default_federation_entry(&idp_name);
    let entry = with_attr(entry, "oauth2_display_name", &["Full Federation IdP"]);
    let entry = with_attr(
        entry,
        "oauth2_jwks_uri",
        &["https://idp.example.com/oauth2/jwks"],
    );
    let entry = with_attr(
        entry,
        "oauth2_userinfo_endpoint",
        &["https://idp.example.com/oauth2/userinfo"],
    );
    let entry = with_attr(entry, "oauth2_email_domain", &["example.com", "test.com"]);
    let entry = with_attr(entry, "oauth2_link_policy", &["manual"]);
    let entry = with_attr(entry, "oauth2_idp_initiated_enabled", &["false"]);
    let entry = with_attr(entry, "oauth2_auto_discovery", &["false"]);
    let entry = with_attr(entry, "oauth2_federation_id", &["full_federation"]);
    let entry = with_attr(
        entry,
        "oauth2_request_scopes",
        &["openid", "email", "profile"],
    );

    let result = post_federation(rsclient, entry).await;
    assert!(
        result.is_ok(),
        "Federation IdP with all attributes should succeed: {result:?}"
    );

    let entry = get_federation_idp(rsclient, &idp_name)
        .await
        .expect("Failed to get federation");
    assert_eq!(
        entry.attrs.get("oauth2_token_introspect_endpoint"),
        Some(&vec![
            "https://idp.example.com/oauth2/token/introspect".to_string()
        ])
    );
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_get_list(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = get_federation_test_idp_name();
    let client_id = get_federation_test_client_id();
    let issuer = get_federation_test_issuer();

    let result =
        create_federation_idp(rsclient, &idp_name, &client_id, "test_secret", &issuer).await;
    assert!(result.is_ok());

    let entries: Vec<Entry> = rsclient
        .perform_get_request(FEDERATION_PATH)
        .await
        .expect("Failed to list federations");

    let found = entries.iter().any(|e| {
        e.attrs
            .get("name")
            .map(|names| names.contains(&idp_name))
            .unwrap_or(false)
    });
    assert!(found, "Created IdP should be in list");
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_get_by_name(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = get_federation_test_idp_name();
    let client_id = get_federation_test_client_id();
    let issuer = get_federation_test_issuer();

    let result =
        create_federation_idp(rsclient, &idp_name, &client_id, "test_secret", &issuer).await;
    assert!(result.is_ok());

    let entry = get_federation_idp(rsclient, &idp_name)
        .await
        .expect("Failed to get federation");
    let name = entry.attrs.get("name").and_then(|n| n.first());
    assert_eq!(name, Some(&idp_name), "IdP name should match");
}

/// Kubidm: create, read, update and delete over `/v1/federation/oauth2`.
#[kubidmd_testkit::test]
async fn test_oauth2_federation_crud(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_crud", get_federation_test_idp_name());

    // Create
    post_federation(rsclient, default_federation_entry(&idp_name))
        .await
        .expect("Failed to create federation");

    // Read
    let entry = get_federation_idp(rsclient, &idp_name)
        .await
        .expect("Failed to get federation");
    assert_eq!(
        entry.attrs.get("oauth2_client_secret"),
        Some(&vec!["test_secret".to_string()]),
        "the client secret is readable by federation admins"
    );

    // Update: rotate the secret and set a display name.
    patch_federation_idp(
        rsclient,
        &idp_name,
        &[
            ("oauth2_client_secret", &["rotated_secret"]),
            ("oauth2_display_name", &["Patched IdP"]),
        ],
    )
    .await
    .expect("Failed to patch federation");

    let entry = get_federation_idp(rsclient, &idp_name)
        .await
        .expect("Failed to get federation");
    assert_eq!(
        entry.attrs.get("oauth2_client_secret"),
        Some(&vec!["rotated_secret".to_string()])
    );
    assert_eq!(
        entry.attrs.get("oauth2_display_name"),
        Some(&vec!["Patched IdP".to_string()])
    );

    // An update that makes the provider invalid is rejected, and nothing changes.
    let result =
        patch_federation_idp(rsclient, &idp_name, &[("oauth2_link_policy", &["auto"])]).await;
    assert!(result.is_err(), "An invalid patch should fail");
    let entry = get_federation_idp(rsclient, &idp_name)
        .await
        .expect("Failed to get federation");
    assert!(!entry.attrs.contains_key("oauth2_link_policy"));

    // Patching a federation that does not exist fails.
    let result = patch_federation_idp(
        rsclient,
        "nonexistent_idp",
        &[("oauth2_display_name", &["Nope"])],
    )
    .await;
    assert!(result.is_err(), "Patching a missing federation should fail");

    // Delete
    assert_eq!(
        delete_federation_idp(rsclient, &idp_name).await,
        StatusCode::OK
    );
    assert!(
        matches!(
            get_federation_idp(rsclient, &idp_name).await,
            Err(ClientError::Http(StatusCode::NOT_FOUND, _, _))
        ),
        "Deleted IdP should not be found"
    );
    assert_ne!(
        delete_federation_idp(rsclient, &idp_name).await,
        StatusCode::OK,
        "Deleting a missing federation should fail"
    );
}

/// Kubidm: the delete route only deletes federation entries.
#[kubidmd_testkit::test]
async fn test_oauth2_federation_delete_only_federations(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    rsclient
        .idm_oauth2_rs_basic_create(
            "not_a_federation",
            "Not A Federation",
            "https://demo.example.com",
        )
        .await
        .expect("Failed to create oauth2 resource server");

    assert_ne!(
        delete_federation_idp(rsclient, "not_a_federation").await,
        StatusCode::OK
    );
    assert!(rsclient
        .idm_oauth2_rs_get("not_a_federation")
        .await
        .expect("Failed to get oauth2 resource server")
        .is_some());
}

/// Kubidm: an OAuth2 resource server named "federation" is still reachable at
/// `/v1/oauth2/federation` (the federation routes do not shadow it).
#[kubidmd_testkit::test]
async fn test_oauth2_rs_named_federation(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    // A federation exists too, so a shadowing route would have something to return.
    post_federation(rsclient, default_federation_entry("some_federation"))
        .await
        .expect("Failed to create federation");

    rsclient
        .idm_oauth2_rs_basic_create("federation", "Federation RS", "https://demo.example.com")
        .await
        .expect("Failed to create oauth2 resource server named federation");

    // GET
    let entry: Entry = rsclient
        .perform_get_request("/v1/oauth2/federation")
        .await
        .expect("Failed to get the oauth2 resource server named federation");
    assert_eq!(
        entry.attrs.get("name").and_then(|n| n.first()),
        Some(&"federation".to_string())
    );
    assert!(entry
        .attrs
        .get("class")
        .is_some_and(|c| c.contains(&"oauth2_resource_server".to_string())));

    // PATCH
    rsclient
        .idm_oauth2_rs_update(
            "federation",
            None,
            Some("Renamed Federation RS"),
            None,
            false,
        )
        .await
        .expect("Failed to patch the oauth2 resource server named federation");
    let entry = rsclient
        .idm_oauth2_rs_get("federation")
        .await
        .expect("Failed to get the oauth2 resource server named federation")
        .expect("oauth2 resource server named federation missing");
    assert_eq!(
        entry.attrs.get("displayname"),
        Some(&vec!["Renamed Federation RS".to_string()])
    );

    // DELETE
    rsclient
        .idm_oauth2_rs_delete("federation")
        .await
        .expect("Failed to delete the oauth2 resource server named federation");
    let result: Result<Entry, ClientError> =
        rsclient.perform_get_request("/v1/oauth2/federation").await;
    assert!(
        result.is_err(),
        "The deleted oauth2 resource server must be gone"
    );

    // The federation is untouched.
    get_federation_idp(rsclient, "some_federation")
        .await
        .expect("The federation must not be affected");
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_missing_required_fields(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    for (attr, reason) in [
        ("oauth2_client_id", "Missing client_id"),
        ("oauth2_client_secret", "Missing client_secret"),
        ("oauth2_issuer", "Missing issuer"),
        // Kubidm: the endpoints are never derived from the issuer.
        (
            "oauth2_authorisation_endpoint",
            "Missing authorisation endpoint",
        ),
        ("oauth2_token_endpoint", "Missing token endpoint"),
        // Kubidm: without introspection every login would be denied.
        (
            "oauth2_token_introspect_endpoint",
            "Missing introspection endpoint",
        ),
    ] {
        let entry = without_attr(default_federation_entry(&format!("missing_{attr}")), attr);
        assert_create_rejected(rsclient, entry, reason).await;
    }

    let entry = default_federation_entry("issuer_only");
    let entry = without_attr(entry, "oauth2_authorisation_endpoint");
    let entry = without_attr(entry, "oauth2_token_endpoint");
    assert_create_rejected(rsclient, entry, "Only an issuer").await;
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_empty_client_id(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let entry = with_attr(
        default_federation_entry("empty_client_id"),
        "oauth2_client_id",
        &[""],
    );
    assert_create_rejected(rsclient, entry, "Empty client_id").await;
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_empty_client_secret(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let entry = with_attr(
        default_federation_entry("empty_secret"),
        "oauth2_client_secret",
        &[""],
    );
    assert_create_rejected(rsclient, entry, "Empty client_secret").await;
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_invalid_issuer_url(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let entry = with_attr(
        default_federation_entry("invalid_issuer"),
        "oauth2_issuer",
        &["not-a-valid-url"],
    );
    assert_create_rejected(rsclient, entry, "Invalid issuer URL").await;
}

/// Kubidm: the authorisation, token and introspection endpoints must use https, except
/// on loopback, and must not carry credentials.
#[kubidmd_testkit::test]
async fn test_oauth2_federation_backchannel_requires_https(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    for attr in [
        "oauth2_authorisation_endpoint",
        "oauth2_token_endpoint",
        "oauth2_token_introspect_endpoint",
    ] {
        let entry = with_attr(
            default_federation_entry(&format!("http_{attr}")),
            attr,
            &["http://idp.example.com/endpoint"],
        );
        assert_create_rejected(rsclient, entry, &format!("Non loopback http {attr}")).await;

        let entry = with_attr(
            default_federation_entry(&format!("userinfo_{attr}")),
            attr,
            &["https://user:password@idp.example.com/endpoint"],
        );
        assert_create_rejected(rsclient, entry, &format!("Credentials in {attr}")).await;
    }

    let entry = default_federation_entry("loopback_http");
    let entry = with_attr(
        entry,
        "oauth2_authorisation_endpoint",
        &["http://[::1]:8443/oauth2/authorise"],
    );
    let entry = with_attr(
        entry,
        "oauth2_token_endpoint",
        &["http://localhost:8443/oauth2/token"],
    );
    let entry = with_attr(
        entry,
        "oauth2_token_introspect_endpoint",
        &["http://127.0.0.1:8443/oauth2/token/introspect"],
    );
    post_federation(rsclient, entry)
        .await
        .expect("Loopback http endpoints should be valid");
}

/// Kubidm: only the `manual` link policy is implemented.
#[kubidmd_testkit::test]
async fn test_oauth2_federation_link_policy_values(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_manual", get_federation_test_idp_name());
    let entry = with_attr(
        default_federation_entry(&idp_name),
        "oauth2_link_policy",
        &["manual"],
    );
    post_federation(rsclient, entry)
        .await
        .expect("Link policy 'manual' should be valid");

    for policy in ["auto", "admin_approval"] {
        let entry = with_attr(
            default_federation_entry(&format!("{}_{}", get_federation_test_idp_name(), policy)),
            "oauth2_link_policy",
            &[policy],
        );
        assert_create_rejected(
            rsclient,
            entry,
            &format!("Unimplemented link policy '{policy}'"),
        )
        .await;
    }
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_invalid_link_policy(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let entry = with_attr(
        default_federation_entry("invalid_policy_idp"),
        "oauth2_link_policy",
        &["invalid_policy_value"],
    );
    assert_create_rejected(rsclient, entry, "Invalid link policy").await;
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_multiple_email_domains(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_multidomain", get_federation_test_idp_name());
    let entry = with_attr(
        default_federation_entry(&idp_name),
        "oauth2_email_domain",
        &["example.com", "test.org", "company.net"],
    );

    let result = post_federation(rsclient, entry).await;
    assert!(result.is_ok(), "Multiple email domains should be valid");
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_multiple_request_scopes(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_scopes", get_federation_test_idp_name());
    let entry = with_attr(
        default_federation_entry(&idp_name),
        "oauth2_request_scopes",
        &["openid", "email", "profile", "groups"],
    );

    let result = post_federation(rsclient, entry).await;
    assert!(result.is_ok(), "Multiple request scopes should be valid");
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_duplicate_name(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_duplicate", get_federation_test_idp_name());
    let client_id = get_federation_test_client_id();
    let issuer = get_federation_test_issuer();

    let result =
        create_federation_idp(rsclient, &idp_name, &client_id, "test_secret", &issuer).await;
    assert!(result.is_ok());

    let result = create_federation_idp(
        rsclient,
        &idp_name,
        &format!("{client_id}_2"),
        "test_secret_2",
        &Url::parse("https://idp2.example.com").expect("Invalid URL"),
    )
    .await;

    assert!(result.is_err(), "Duplicate name should fail");
}

/// Kubidm: IdP initiated login is not implemented, enabling it is rejected.
#[kubidmd_testkit::test]
async fn test_oauth2_federation_idp_initiated_enabled(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let entry = with_attr(
        default_federation_entry("idp_init_false"),
        "oauth2_idp_initiated_enabled",
        &["false"],
    );
    post_federation(rsclient, entry)
        .await
        .expect("IdP initiated disabled should be valid");

    let entry = with_attr(
        default_federation_entry("idp_init_true"),
        "oauth2_idp_initiated_enabled",
        &["true"],
    );
    assert_create_rejected(rsclient, entry, "IdP initiated enabled").await;
}

/// Kubidm: OIDC auto discovery is not implemented, enabling it is rejected.
#[kubidmd_testkit::test]
async fn test_oauth2_federation_auto_discovery(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let entry = with_attr(
        default_federation_entry("auto_disc_false"),
        "oauth2_auto_discovery",
        &["false"],
    );
    post_federation(rsclient, entry)
        .await
        .expect("Auto discovery disabled should be valid");

    let entry = with_attr(
        default_federation_entry("auto_disc_true"),
        "oauth2_auto_discovery",
        &["true"],
    );
    assert_create_rejected(rsclient, entry, "Auto discovery enabled").await;
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_unauthorized_access(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    post_federation(rsclient, default_federation_entry("existing_idp"))
        .await
        .expect("Failed to create federation");

    rsclient
        .idm_person_account_create("test_federation_user", "test_federation_user")
        .await
        .expect("Failed to create account");

    rsclient
        .idm_person_account_primary_credential_set_password(
            "test_federation_user",
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("Failed to set password");

    let res = rsclient
        .auth_simple_password("test_federation_user", NOT_ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let result = post_federation(rsclient, default_federation_entry("unauthorized_idp")).await;
    assert!(
        matches!(result, Err(ClientError::Http(StatusCode::FORBIDDEN, _, _))),
        "Non-admin user should not be able to create federation IdP"
    );

    let result = patch_federation_idp(
        rsclient,
        "existing_idp",
        &[("oauth2_client_secret", &["stolen"])],
    )
    .await;
    assert!(
        result.is_err(),
        "Non-admin user should not be able to modify a federation IdP"
    );

    assert_ne!(
        delete_federation_idp(rsclient, "existing_idp").await,
        StatusCode::OK,
        "Non-admin user should not be able to delete a federation IdP"
    );

    login_admin(rsclient).await;

    let entry = get_federation_idp(rsclient, "existing_idp")
        .await
        .expect("The federation must still exist");
    assert_eq!(
        entry.attrs.get("oauth2_client_secret"),
        Some(&vec!["test_secret".to_string()])
    );
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_federation_id_unique(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let federation_id = "unique_federation_id_12345";

    let entry1 = with_attr(
        default_federation_entry(&format!("{}_fed1", get_federation_test_idp_name())),
        "oauth2_federation_id",
        &[federation_id],
    );
    let result = post_federation(rsclient, entry1).await;
    assert!(
        result.is_ok(),
        "First federation IdP with federation_id should succeed"
    );

    let entry2 = federation_entry(
        &format!("{}_fed2", get_federation_test_idp_name()),
        &format!("{}_2", get_federation_test_client_id()),
        "test_secret_2",
        &Url::parse("https://idp2.example.com").expect("Invalid URL"),
    );
    let entry2 = with_attr(entry2, "oauth2_federation_id", &[federation_id]);
    let result = post_federation(rsclient, entry2).await;
    assert!(result.is_err(), "Duplicate federation_id should fail");
}

/// Kubidm: explicit endpoints are stored as given, including an issuer path.
#[kubidmd_testkit::test]
async fn test_oauth2_federation_custom_endpoints(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_custom_ep", get_federation_test_idp_name());

    let entry = default_federation_entry(&idp_name);
    let entry = with_attr(
        entry,
        "oauth2_issuer",
        &["https://custom.idp.example.com/realms/main"],
    );
    let entry = with_attr(
        entry,
        "oauth2_authorisation_endpoint",
        &["https://custom.idp.example.com/realms/main/protocol/openid-connect/auth"],
    );
    let entry = with_attr(
        entry,
        "oauth2_token_endpoint",
        &["https://custom.idp.example.com/realms/main/protocol/openid-connect/token"],
    );
    let entry = with_attr(
        entry,
        "oauth2_token_introspect_endpoint",
        &["https://custom.idp.example.com/realms/main/protocol/openid-connect/token/introspect"],
    );
    let entry = with_attr(
        entry,
        "oauth2_jwks_uri",
        &["https://custom.idp.example.com/realms/main/protocol/openid-connect/certs"],
    );

    let result = post_federation(rsclient, entry).await;
    assert!(result.is_ok(), "Custom endpoints should be valid");

    let entry = get_federation_idp(rsclient, &idp_name)
        .await
        .expect("Failed to get federation");
    assert_eq!(
        entry.attrs.get("oauth2_token_endpoint"),
        Some(&vec![
            "https://custom.idp.example.com/realms/main/protocol/openid-connect/token".to_string()
        ])
    );
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_concurrent_idps(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_count = 5;

    for i in 0..idp_count {
        let idp_name = format!("{}_concurrent_{}", get_federation_test_idp_name(), i);

        let result = create_federation_idp(
            rsclient,
            &idp_name,
            &format!("{}_{}", get_federation_test_client_id(), i),
            &format!("secret_{i}"),
            &Url::parse(&format!("https://idp{i}.example.com")).expect("Invalid URL"),
        )
        .await;

        assert!(
            result.is_ok(),
            "Concurrent IdP {i} should be created successfully"
        );
    }

    let entries: Vec<Entry> = rsclient
        .perform_get_request(FEDERATION_PATH)
        .await
        .expect("Failed to list federations");
    assert!(
        entries.len() >= idp_count,
        "Should have at least {idp_count} IdPs"
    );
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_get_nonexistent(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let result = get_federation_idp(rsclient, "nonexistent_idp").await;

    assert!(
        matches!(result, Err(ClientError::Http(StatusCode::NOT_FOUND, _, _))),
        "Nonexistent IdP should return NOT_FOUND"
    );
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_with_display_name(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_display", get_federation_test_idp_name());
    let entry = with_attr(
        default_federation_entry(&idp_name),
        "oauth2_display_name",
        &["My Custom IdP Display Name"],
    );

    let result = post_federation(rsclient, entry).await;
    assert!(result.is_ok(), "Display name should be valid");
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_with_description(rsclient: &KubidmClient) {
    login_admin(rsclient).await;

    let idp_name = format!("{}_desc", get_federation_test_idp_name());
    let entry = with_attr(
        default_federation_entry(&idp_name),
        "description",
        &["This is a test federation IdP description"],
    );

    let result = post_federation(rsclient, entry).await;
    assert!(result.is_ok(), "Description should be valid");
}

#[kubidmd_testkit::test]
async fn test_oauth2_federation_invalid_auth_method(rsclient: &KubidmClient) {
    let _ = rsclient.logout().await;

    let result = post_federation(rsclient, default_federation_entry("unauthorized")).await;

    assert!(result.is_err(), "Unauthenticated request should fail");
}

// =========================================
// Kubidm: a full federation login, with this kubidm instance acting as the upstream
// identity provider for itself.

const SELF_IDP_RS_NAME: &str = "self_idp_rs";
const SELF_IDP_FEDERATION_NAME: &str = "self_federation";
const SELF_IDP_USER: &str = "self_idp_user";

/// Configure this instance as its own upstream IdP: an OAuth2 resource server for the
/// federation, an IdP side user, and a federation that points at this instance over
/// (loopback) http. Returns the IdP side user's uuid, which introspection reports as
/// the subject.
async fn setup_self_federation(rsclient: &KubidmClient) -> String {
    login_admin(rsclient).await;

    let landing_url = rsclient.make_url("/ui/login/oauth2_landing");

    rsclient
        .idm_oauth2_rs_basic_create(
            SELF_IDP_RS_NAME,
            "Self IdP",
            rsclient.make_url("/").as_str(),
        )
        .await
        .expect("Failed to create oauth2 resource server");
    rsclient
        .idm_oauth2_client_add_origin(SELF_IDP_RS_NAME, &landing_url)
        .await
        .expect("Failed to add the landing redirect url");
    rsclient
        .idm_oauth2_rs_update_scope_map(SELF_IDP_RS_NAME, "idm_all_accounts", vec!["openid"])
        .await
        .expect("Failed to update the scope map");
    let client_secret = rsclient
        .idm_oauth2_rs_get_basic_secret(SELF_IDP_RS_NAME)
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve the basic secret");

    rsclient
        .idm_person_account_create(SELF_IDP_USER, "Self IdP User")
        .await
        .expect("Failed to create the IdP user");
    rsclient
        .idm_person_account_primary_credential_set_password(SELF_IDP_USER, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to set the IdP user password");
    let idp_user_uuid = rsclient
        .idm_person_account_get(SELF_IDP_USER)
        .await
        .expect("Failed to get the IdP user")
        .and_then(|e| e.attrs.get("uuid").and_then(|u| u.first()).cloned())
        .expect("IdP user has no uuid");

    let entry = federation_entry(
        SELF_IDP_FEDERATION_NAME,
        SELF_IDP_RS_NAME,
        &client_secret,
        &rsclient.make_url(&format!("/oauth2/openid/{SELF_IDP_RS_NAME}")),
    );
    let entry = with_attr(
        entry,
        "oauth2_authorisation_endpoint",
        &[rsclient.make_url("/ui/oauth2").as_str()],
    );
    let entry = with_attr(
        entry,
        "oauth2_token_endpoint",
        &[rsclient.make_url(OAUTH2_TOKEN_ENDPOINT).as_str()],
    );
    let entry = with_attr(
        entry,
        "oauth2_token_introspect_endpoint",
        &[rsclient.make_url(OAUTH2_TOKEN_INTROSPECT_ENDPOINT).as_str()],
    );
    let entry = with_attr(entry, "oauth2_request_scopes", &["openid"]);
    post_federation(rsclient, entry)
        .await
        .expect("Failed to create the self federation");

    idp_user_uuid
}

/// Create a local account, linked by an admin to the IdP side user with `user_sub`.
async fn create_linked_account(rsclient: &KubidmClient, name: &str, user_sub: &str) {
    login_admin(rsclient).await;
    let federation_uuid = get_federation_idp(rsclient, SELF_IDP_FEDERATION_NAME)
        .await
        .expect("Failed to get the self federation")
        .attrs
        .get("uuid")
        .and_then(|u| u.first())
        .cloned()
        .expect("federation has no uuid");

    rsclient
        .idm_person_account_create(name, name)
        .await
        .expect("Failed to create the local account");

    // Enrolling an account to an OAuth2 provider is an oauth2 account admin right.
    let res = rsclient
        .auth_simple_password(IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let modlist = ModifyList::new_list(vec![
        Modify::Present("class".to_string(), "oauth2_account".to_string()),
        Modify::Present("oauth2_account_provider".to_string(), federation_uuid),
        Modify::Present(
            "oauth2_account_unique_user_id".to_string(),
            SELF_IDP_USER.to_string(),
        ),
        Modify::Present(
            "oauth2_account_unique_user_sub".to_string(),
            user_sub.to_string(),
        ),
        Modify::Present(
            "oauth2_account_credential_uuid".to_string(),
            uuid::Uuid::new_v4().to_string(),
        ),
    ]);
    rsclient
        .modify(Filter::Eq("name".to_string(), name.to_string()), modlist)
        .await
        .expect("Failed to link the local account to the federation");
}

fn location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|hv| hv.to_str().ok())
        .map(str::to_string)
        .expect("response has no location")
}

/// Run a federation login for `local_user` in a browser like client, with the IdP side
/// login and consent done by `SELF_IDP_USER` through the API. Returns the browser client
/// and the response of the landing page, where the server exchanges the code and
/// introspects the access token.
async fn self_federation_login(
    rsclient: &KubidmClient,
    local_user: &str,
) -> (reqwest::Client, reqwest::Response) {
    let browser = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // The only credential of the local account is the federation, so it is selected
    // and the browser is sent to the upstream authorisation endpoint.
    let response = browser
        .post(rsclient.make_url("/ui/login/begin"))
        .form(&[("username", local_user)])
        .send()
        .await
        .expect("Failed to begin the login");
    assert!(
        response.status().is_redirection(),
        "expected a redirect to the IdP, got {}",
        response.status()
    );
    let authorise_url = Url::parse(&location(&response)).expect("Invalid authorise url");
    assert_eq!(authorise_url.path(), "/ui/oauth2");
    let authorise_query: Vec<(String, String)> = authorise_url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert!(authorise_query
        .iter()
        .any(|(k, v)| k == "code_challenge_method" && v == "S256"));

    // The IdP side user authorises the request and consents.
    let res = rsclient
        .auth_simple_password(SELF_IDP_USER, NOT_ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    let idp_token = rsclient.get_token().await.expect("No IdP user token");

    let api = api_client();
    let response = api
        .get(rsclient.make_url(OAUTH2_AUTHORISE))
        .bearer_auth(&idp_token)
        .query(&authorise_query)
        .send()
        .await
        .expect("Failed to send the authorisation request");

    let response = if response.status() == StatusCode::OK {
        let consent: AuthorisationResponse = response
            .json()
            .await
            .expect("Invalid authorisation response");
        let AuthorisationResponse::ConsentRequested { consent_token, .. } = consent else {
            panic!("expected a consent request");
        };
        api.get(rsclient.make_url(OAUTH2_AUTHORISE_PERMIT))
            .bearer_auth(&idp_token)
            .query(&[("token", consent_token.as_str())])
            .send()
            .await
            .expect("Failed to send the consent")
    } else {
        response
    };
    assert_eq!(response.status(), StatusCode::FOUND);

    // The IdP redirects the browser back to the landing page with the code and state.
    let landing_url = Url::parse(&location(&response)).expect("Invalid landing url");
    assert_eq!(landing_url.path(), "/ui/login/oauth2_landing");

    let response = browser
        .get(landing_url)
        .send()
        .await
        .expect("Failed to send the landing request");
    (browser, response)
}

/// Kubidm: a full federation login against this instance as the upstream IdP. The token
/// exchange and introspection run through the shared outbound client, and the account
/// is only logged in when the introspected subject matches the admin linked one.
#[kubidmd_testkit::test(role = ServerRole::WriteReplica)]
async fn test_oauth2_federation_login_self_idp(rsclient: &KubidmClient) {
    let idp_user_uuid = setup_self_federation(rsclient).await;

    // Correctly linked: the login succeeds.
    create_linked_account(rsclient, "fed_linked_user", &idp_user_uuid).await;
    let (browser, response) = self_federation_login(rsclient, "fed_linked_user").await;
    assert!(
        response.status().is_redirection(),
        "expected a successful login redirect, got {}: {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );
    assert_eq!(location(&response), "/ui/apps");

    // The browser now holds a session.
    let response = browser
        .get(rsclient.make_url("/ui/apps"))
        .send()
        .await
        .expect("Failed to get apps");
    assert_eq!(response.status(), StatusCode::OK);

    // Linked to a different subject: the introspected subject does not match, denied.
    create_linked_account(
        rsclient,
        "fed_wrong_user",
        &uuid::Uuid::new_v4().to_string(),
    )
    .await;
    let (browser, response) = self_federation_login(rsclient, "fed_wrong_user").await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "expected the login denied page"
    );
    let response = browser
        .get(rsclient.make_url("/ui/apps"))
        .send()
        .await
        .expect("Failed to get apps");
    assert!(
        response.status().is_redirection(),
        "a denied login must not create a session"
    );
}
