//! Kubidm: types for OAuth2 client providers (`OAuth2Client` and `OAuth2Federation`),
//! where Kubidm is the OAuth2 client of an upstream identity provider.

use serde::{Deserialize, Serialize};
use serde_with::{
    formats::{PreferMany, SpaceSeparator},
    serde_as, DefaultOnNull, OneOrMany, StringWithSeparator,
};
use std::collections::BTreeSet;

/// An RFC 7662 token introspection response from an upstream identity provider.
///
/// This is deliberately more lenient than
/// [crate::oauth2::AccessTokenIntrospectResponse], which is what Kubidm's own
/// introspection endpoint returns. Only `active` is required (an inactive token is
/// often just `{"active":false}`), `aud` may be a string or an array (Keycloak), `jti`
/// is any string, and unknown fields are ignored.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct OAuth2ClientIntrospectResponse {
    pub active: bool,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    #[serde_as(as = "DefaultOnNull<OneOrMany<_, PreferMany>>")]
    pub aud: Vec<String>,
    #[serde(default)]
    #[serde_as(as = "DefaultOnNull<StringWithSeparator::<SpaceSeparator, String>>")]
    pub scope: BTreeSet<String>,
    #[serde(default)]
    pub jti: Option<String>,
    #[serde(default)]
    pub exp: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::OAuth2ClientIntrospectResponse;

    fn parse(json: &str) -> OAuth2ClientIntrospectResponse {
        match serde_json::from_str(json) {
            Ok(response) => response,
            Err(err) => panic!("{json} must parse: {err}"),
        }
    }

    #[test]
    fn test_oauth2_client_introspect_response_inactive() {
        let response = parse(r#"{"active":false}"#);
        assert_eq!(response, OAuth2ClientIntrospectResponse::default());
    }

    #[test]
    fn test_oauth2_client_introspect_response_keycloak() {
        // Abridged Keycloak response: `aud` is an array, `jti` is not a UUID, and there
        // are many fields this type does not know.
        let response = parse(
            r#"{
                "exp": 1761650000, "iat": 1761649700, "jti": "onrtac:3f5c-not-a-uuid",
                "iss": "https://idp.example.com/realms/main",
                "aud": ["kubidm", "account"],
                "sub": "6b0f8f1e-1f43-4a0c-9c43-7b8f6d1c2a10",
                "typ": "Bearer", "azp": "kubidm", "sid": "abc",
                "realm_access": {"roles": ["offline_access"]},
                "scope": "openid profile email",
                "email_verified": true, "client_id": "kubidm",
                "username": "alice", "token_type": "Bearer", "active": true
            }"#,
        );
        assert!(response.active);
        assert_eq!(
            response.sub.as_deref(),
            Some("6b0f8f1e-1f43-4a0c-9c43-7b8f6d1c2a10")
        );
        assert_eq!(response.client_id.as_deref(), Some("kubidm"));
        assert_eq!(
            response.iss.as_deref(),
            Some("https://idp.example.com/realms/main")
        );
        assert_eq!(response.aud, vec!["kubidm", "account"]);
        assert_eq!(
            response
                .scope
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["email", "openid", "profile"]
        );
        assert_eq!(response.jti.as_deref(), Some("onrtac:3f5c-not-a-uuid"));
        assert_eq!(response.exp, Some(1761650000));
    }

    #[test]
    fn test_oauth2_client_introspect_response_lenient_fields() {
        // `aud` as a single string, no `scope` or `jti`.
        let response = parse(r#"{"active":true,"sub":"subject","aud":"kubidm"}"#);
        assert_eq!(response.aud, vec!["kubidm"]);
        assert!(response.scope.is_empty());
        assert_eq!(response.jti, None);

        // Explicit nulls are treated as absent.
        let response = parse(r#"{"active":true,"aud":null,"scope":null,"jti":null,"exp":null}"#);
        assert!(response.aud.is_empty());
        assert!(response.scope.is_empty());
        assert_eq!(response.exp, None);

        // `active` is the one required field.
        assert!(serde_json::from_str::<OAuth2ClientIntrospectResponse>(r#"{"sub":"x"}"#).is_err());
    }
}
