use super::{
    CredState, BAD_AUTH_TYPE_MSG, BAD_OAUTH2_CSRF_STATE_MSG, BAD_OAUTH2_ID_TOKEN_MSG,
    BAD_OAUTH2_SESSION_MSG, BAD_OAUTH2_SUBJECT_MSG,
};
use crate::{
    idm::{
        account::OAuth2AccountCredential,
        authentication::{AuthCredential, AuthExternal},
        oauth2::PkceS256Secret,
        oauth2_client::{OAuth2ClientProvider, OAuth2SubjectVerifier},
        oauth2_client_id_token::{
            parse_id_token, verify_id_token, IdTokenError, IdTokenExpectations,
        },
    },
    prelude::*,
    utils,
    value::{AuthType, SessionExtMetadata},
};
use compact_jwt::{Jwk, JwsCompact};
use kubidm_proto::{
    oauth2::{
        AccessTokenIntrospectRequest, AccessTokenRequest, AccessTokenResponse,
        AuthorisationRequest, AuthorisationRequestOidc, GrantTypeReq, ResponseType,
    },
    oauth2_federation::OAuth2ClientIntrospectResponse,
};
use std::{collections::BTreeSet, fmt};

#[derive(Clone)]
enum SessionState {
    Init,
    AccessTokenRequested,
    /// Kubidm: waiting for the provider's JWKS to verify the `id_token`.
    /// `jwks_refreshed` is set once a refresh of the JWKS was requested.
    IdTokenUnverified {
        id_token: Box<JwsCompact>,
        access_expires_at: Duration,
        access_token: String,
        refresh_token: Option<String>,
        jwks_refreshed: bool,
    },
    AccessTokenUnverified {
        access_expires_at: Duration,
        access_token: String,
        refresh_token: Option<String>,
    },
    Finished,
}

#[derive(Clone)]
pub struct CredHandlerOAuth2Client {
    // For logging - this is the trust provider we are using.
    provider_id: Uuid,
    provider_name: String,

    // The users ID as the remote trust provider knows them.
    user_id: String,
    user_sub: String,
    user_cred_id: Uuid,

    user_sub_verifier: OAuth2SubjectVerifier,

    request_scopes: BTreeSet<String>,
    client_id: String,
    client_basic_secret: String,
    client_redirect_url: Url,
    authorisation_endpoint: Url,
    token_endpoint: Url,
    issuer: Option<Url>,
    pkce_secret: PkceS256Secret,
    csrf_state: String,
    // Kubidm: the OIDC nonce, which the id_token must carry.
    nonce: String,

    session_state: SessionState,
}

impl fmt::Debug for CredHandlerOAuth2Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredHandlerOauth2Trust")
            .field("provider_id", &self.provider_id)
            .field("provider_name", &self.provider_name)
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("authorisation_endpoint", &self.authorisation_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .finish()
    }
}

impl CredHandlerOAuth2Client {
    pub fn new(
        client_provider: &OAuth2ClientProvider,
        client_user_cred: &OAuth2AccountCredential,
    ) -> Self {
        let pkce_secret = PkceS256Secret::default();
        let csrf_state = utils::password_from_random();
        let nonce = utils::password_from_random();

        // Kubidm: an id_token is only issued for the `openid` scope.
        let mut request_scopes = client_provider.request_scopes.clone();
        if matches!(
            client_provider.user_sub_verifier,
            OAuth2SubjectVerifier::OidcIdToken { .. }
        ) {
            request_scopes.insert("openid".to_string());
        }

        CredHandlerOAuth2Client {
            provider_id: client_provider.uuid,
            provider_name: client_provider.name.clone(),
            request_scopes,
            user_id: client_user_cred.user_id.to_string(),
            user_sub: client_user_cred.user_sub.to_string(),
            user_cred_id: client_user_cred.cred_id,
            client_id: client_provider.client_id.clone(),
            client_basic_secret: client_provider.client_basic_secret.clone(),
            client_redirect_url: client_provider.client_redirect_uri.clone(),
            authorisation_endpoint: client_provider.authorisation_endpoint.clone(),
            token_endpoint: client_provider.token_endpoint.clone(),
            issuer: client_provider.issuer.clone(),
            pkce_secret,
            csrf_state,
            nonce,
            user_sub_verifier: client_provider.user_sub_verifier.clone(),
            session_state: SessionState::Init,
        }
    }

    pub fn start_auth_request(&self) -> (Url, AuthorisationRequest) {
        let pkce_request = self.pkce_secret.to_request();

        (
            self.authorisation_endpoint.clone(),
            AuthorisationRequest {
                redirect_uri: self.client_redirect_url.clone(),
                response_type: ResponseType::Code,
                response_mode: None,
                client_id: self.client_id.clone(),
                state: Some(self.csrf_state.clone()),
                pkce_request: Some(pkce_request),
                scope: self.request_scopes.clone(),
                // Kubidm: bind the id_token to this auth session.
                nonce: self.uses_id_token().then(|| self.nonce.clone()),
                oidc_ext: AuthorisationRequestOidc {
                    login_hint: Some(self.user_id.clone()),
                    ..Default::default()
                },
                max_age: None,
                prompt: Vec::new(),
                ui_locales: Vec::new(),
                unknown_keys: Default::default(),
            },
        )
    }

    pub fn validate(&mut self, cred: &AuthCredential, current_time: Duration) -> CredState {
        let (next_state, response) = match (self.session_state.clone(), cred) {
            (SessionState::Init, AuthCredential::OAuth2AuthorisationResponse { code, state }) => {
                self.validate_authorisation_response(code, state.as_deref())
            }

            (
                SessionState::AccessTokenRequested,
                AuthCredential::OAuth2AccessTokenResponse { response },
            ) => self.validate_access_token_response(response, current_time),

            (
                SessionState::IdTokenUnverified {
                    id_token,
                    access_expires_at,
                    access_token,
                    refresh_token,
                    jwks_refreshed,
                },
                AuthCredential::OAuth2JwksResponse { keys },
            ) => self.validate_id_token(
                keys,
                id_token,
                access_token,
                refresh_token,
                access_expires_at,
                jwks_refreshed,
                current_time,
            ),

            (
                SessionState::AccessTokenUnverified {
                    access_token,
                    refresh_token,
                    access_expires_at,
                },
                AuthCredential::OAuth2AccessTokenIntrospectResponse { response },
            ) => self.validate_access_token_introspection_response(
                response,
                access_token,
                refresh_token,
                access_expires_at,
                current_time,
            ),
            _ => (SessionState::Finished, CredState::Denied(BAD_AUTH_TYPE_MSG)),
        };

        self.session_state = next_state;
        response
    }

    fn validate_authorisation_response(
        &self,
        code: &str,
        state: Option<&str>,
    ) -> (SessionState, CredState) {
        // Validate our csrf state

        let csrf_valid = state.map(|s| s == self.csrf_state).unwrap_or_default();

        if !csrf_valid {
            return (
                SessionState::Finished,
                CredState::Denied(BAD_OAUTH2_CSRF_STATE_MSG),
            );
        }

        let code_verifier = Some(self.pkce_secret.verifier().to_string());

        let grant_type_req = GrantTypeReq::AuthorizationCode {
            code: code.into(),
            redirect_uri: self.client_redirect_url.clone(),
            code_verifier,
        };

        let request = AccessTokenRequest::from(grant_type_req);

        (
            SessionState::AccessTokenRequested,
            CredState::External(AuthExternal::OAuth2AccessTokenRequest {
                token_url: self.token_endpoint.clone(),
                client_id: self.client_id.clone(),
                client_secret: self.client_basic_secret.clone(),
                request,
            }),
        )
    }

    fn validate_access_token_response(
        &self,
        response: &AccessTokenResponse,
        current_time: Duration,
    ) -> (SessionState, CredState) {
        // We have a positive response and now have the access and refresh tokens. However
        // now we need to assert the token belongs to our subject.

        let access_expires_at = current_time + Duration::from_secs(response.expires_in as u64);

        match &self.user_sub_verifier {
            OAuth2SubjectVerifier::None => {
                (SessionState::Finished, CredState::Denied(BAD_AUTH_TYPE_MSG))
            }
            OAuth2SubjectVerifier::Rfc7662TokenIntrospection { endpoint } => self
                .introspection_request(
                    endpoint,
                    response.access_token.clone(),
                    response.refresh_token.clone(),
                    access_expires_at,
                ),
            // Kubidm: verify the id_token first. Its signature needs the JWKS, which
            // the caller fetches.
            OAuth2SubjectVerifier::OidcIdToken { jwks_uri, .. } => {
                let id_token = match response.id_token.as_deref().map(parse_id_token) {
                    Some(Ok(id_token)) => id_token,
                    Some(Err(reason)) => {
                        error!(provider = %self.provider_name, "id_token {reason}, refusing to proceed");
                        return (
                            SessionState::Finished,
                            CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG),
                        );
                    }
                    None => {
                        error!(provider = %self.provider_name, "token response has no id_token, refusing to proceed");
                        return (
                            SessionState::Finished,
                            CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG),
                        );
                    }
                };

                (
                    SessionState::IdTokenUnverified {
                        id_token: Box::new(id_token),
                        access_expires_at,
                        access_token: response.access_token.clone(),
                        refresh_token: response.refresh_token.clone(),
                        jwks_refreshed: false,
                    },
                    CredState::External(AuthExternal::OAuth2JwksRequest {
                        provider_id: self.provider_id,
                        jwks_uri: jwks_uri.clone(),
                        refresh: false,
                    }),
                )
            }
        }
    }

    fn uses_id_token(&self) -> bool {
        matches!(
            self.user_sub_verifier,
            OAuth2SubjectVerifier::OidcIdToken { .. }
        )
    }

    fn introspection_request(
        &self,
        endpoint: &Url,
        access_token: String,
        refresh_token: Option<String>,
        access_expires_at: Duration,
    ) -> (SessionState, CredState) {
        let request = AccessTokenIntrospectRequest::from(access_token.clone());

        (
            SessionState::AccessTokenUnverified {
                access_token,
                refresh_token,
                access_expires_at,
            },
            CredState::External(AuthExternal::OAuth2AccessTokenIntrospectionRequest {
                introspection_url: endpoint.clone(),
                client_id: self.client_id.clone(),
                client_secret: self.client_basic_secret.clone(),
                request,
            }),
        )
    }

    /// Kubidm: verify the id_token with the keys of the provider's JWKS. When no key
    /// matches, the JWKS is refreshed once (the IdP may have rotated its keys) before the
    /// login is denied.
    #[allow(clippy::too_many_arguments)]
    fn validate_id_token(
        &self,
        keys: &[Jwk],
        id_token: Box<JwsCompact>,
        access_token: String,
        refresh_token: Option<String>,
        access_expires_at: Duration,
        jwks_refreshed: bool,
        current_time: Duration,
    ) -> (SessionState, CredState) {
        let OAuth2SubjectVerifier::OidcIdToken {
            jwks_uri,
            issuer,
            introspection_endpoint,
        } = &self.user_sub_verifier
        else {
            return (SessionState::Finished, CredState::Denied(BAD_AUTH_TYPE_MSG));
        };

        let expect = IdTokenExpectations {
            issuer,
            client_id: &self.client_id,
            nonce: &self.nonce,
            subject: &self.user_sub,
        };

        let denied = match verify_id_token(&id_token, keys, &expect, current_time) {
            Ok(_) => None,
            Err(IdTokenError::UnknownKey) if !jwks_refreshed => {
                debug!(provider = %self.provider_name, "id_token key not in the JWKS, refreshing it");
                return (
                    SessionState::IdTokenUnverified {
                        id_token,
                        access_expires_at,
                        access_token,
                        refresh_token,
                        jwks_refreshed: true,
                    },
                    CredState::External(AuthExternal::OAuth2JwksRequest {
                        provider_id: self.provider_id,
                        jwks_uri: jwks_uri.clone(),
                        refresh: true,
                    }),
                );
            }
            Err(IdTokenError::UnknownKey) => Some((
                "is signed by a key that is not in the JWKS",
                BAD_OAUTH2_ID_TOKEN_MSG,
            )),
            Err(IdTokenError::Signature) => {
                Some(("has an invalid signature", BAD_OAUTH2_ID_TOKEN_MSG))
            }
            Err(IdTokenError::Claims(reason)) => Some((reason, BAD_OAUTH2_ID_TOKEN_MSG)),
            Err(IdTokenError::Subject) => Some((
                "has a different subject than expected",
                BAD_OAUTH2_SUBJECT_MSG,
            )),
        };

        if let Some((reason, msg)) = denied {
            error!(provider = %self.provider_name, "id_token {reason}, refusing to proceed");
            return (SessionState::Finished, CredState::Denied(msg));
        }

        // Both verifiers are configured: the access token must pass introspection too.
        if let Some(endpoint) = introspection_endpoint {
            return self.introspection_request(
                endpoint,
                access_token,
                refresh_token,
                access_expires_at,
            );
        }

        self.success(access_token, refresh_token, access_expires_at)
    }

    fn success(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        access_expires_at: Duration,
    ) -> (SessionState, CredState) {
        // What is the credential id here? The provider id?
        // How do we make sure that session plugin doesn't kill us?
        let cred_id = self.user_cred_id;

        // We need a way to bubble up extra session metadata now.
        // Need to pass up the expiry, token, refresh token.
        let ext_session_metadata = SessionExtMetadata::OAuth2 {
            access_token,
            refresh_token,
            access_expires_at,
        };

        (
            SessionState::Finished,
            CredState::Success {
                auth_type: AuthType::OAuth2Trust,
                cred_id,
                ext_session_metadata,
            },
        )
    }

    fn validate_access_token_introspection_response(
        &self,
        response: &OAuth2ClientIntrospectResponse,
        access_token: String,
        refresh_token: Option<String>,
        access_expires_at: Duration,
        current_time: Duration,
    ) -> (SessionState, CredState) {
        // Process the response!!!

        // The session must be active.

        if !response.active {
            error!(
                "access token introspection indicates the token is not active, refusing to proceed"
            );
            return (
                SessionState::Finished,
                CredState::Denied(BAD_OAUTH2_SESSION_MSG),
            );
        }

        // Kubidm: defence in depth. The optional claims, when present, must agree with
        // this provider and the token must not have expired.
        if let Err(reason) = self.check_introspection_claims(response, current_time) {
            error!(
                provider = %self.provider_name,
                "access token introspection {reason}, refusing to proceed"
            );
            return (
                SessionState::Finished,
                CredState::Denied(BAD_OAUTH2_SESSION_MSG),
            );
        }

        if let Some(response_sub) = response.sub.as_deref() {
            if response_sub == self.user_sub {
                // It's all good!
            } else {
                error!("access token introspection returned a different subject than expected, refusing to proceed with authentication.");
                return (
                    SessionState::Finished,
                    CredState::Denied(BAD_OAUTH2_SUBJECT_MSG),
                );
            }
        } else {
            warn!("access token introspection has no subject field, unable to proceed with authentication.");
            return (
                SessionState::Finished,
                CredState::Denied(BAD_OAUTH2_SUBJECT_MSG),
            );
        }

        self.success(access_token, refresh_token, access_expires_at)
    }

    /// Kubidm: check the optional claims of an introspection response. Each is only
    /// checked when the provider sent it: `client_id` must be ours, `iss` must be the
    /// configured issuer (ignoring a trailing `/`) and `exp` must be in the future.
    fn check_introspection_claims(
        &self,
        response: &OAuth2ClientIntrospectResponse,
        current_time: Duration,
    ) -> Result<(), &'static str> {
        if response
            .client_id
            .as_deref()
            .is_some_and(|client_id| client_id != self.client_id)
        {
            return Err("returned a different client_id");
        }

        if let (Some(response_iss), Some(issuer)) = (response.iss.as_deref(), &self.issuer) {
            if response_iss.trim_end_matches('/') != issuer.as_str().trim_end_matches('/') {
                return Err("returned a different issuer");
            }
        }

        if let Some(exp) = response.exp {
            let now = i64::try_from(current_time.as_secs()).unwrap_or(i64::MAX);
            if exp <= now {
                return Err("indicates the token has expired");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_ID: &str = "test_client_id";
    const USER_SUB: &str = "test_user_sub";
    const ISSUER: &str = "https://idp.example.com/realms/main";
    /// The time the introspection response is validated at, in seconds since the epoch.
    const NOW: u64 = 1_800_000_000;

    fn handler(issuer: Option<&str>) -> CredHandlerOAuth2Client {
        let mut provider = OAuth2ClientProvider::new_test(
            CLIENT_ID,
            "https://idp.example.com",
            ["openid"],
            "https://idp.example.com/introspect",
        );
        provider.issuer = issuer.map(|iss| Url::parse(iss).expect("invalid test issuer"));
        let cred = OAuth2AccountCredential {
            provider: provider.uuid,
            cred_id: Uuid::new_v4(),
            user_id: "user".to_string(),
            user_sub: USER_SUB.to_string(),
        };
        CredHandlerOAuth2Client::new(&provider, &cred)
    }

    /// An active response for our client and subject, with every optional claim valid.
    fn valid_response() -> OAuth2ClientIntrospectResponse {
        OAuth2ClientIntrospectResponse {
            active: true,
            sub: Some(USER_SUB.to_string()),
            client_id: Some(CLIENT_ID.to_string()),
            iss: Some(ISSUER.to_string()),
            aud: vec![CLIENT_ID.to_string(), "account".to_string()],
            scope: BTreeSet::from(["openid".to_string()]),
            jti: Some("not-a-uuid".to_string()),
            exp: Some(NOW as i64 + 300),
        }
    }

    fn introspect(
        handler: &CredHandlerOAuth2Client,
        response: &OAuth2ClientIntrospectResponse,
    ) -> CredState {
        let (state, cred_state) = handler.validate_access_token_introspection_response(
            response,
            "access_token".to_string(),
            None,
            Duration::from_secs(NOW + 300),
            Duration::from_secs(NOW),
        );
        assert!(matches!(state, SessionState::Finished));
        cred_state
    }

    fn assert_success(
        handler: &CredHandlerOAuth2Client,
        response: &OAuth2ClientIntrospectResponse,
    ) {
        assert!(
            matches!(introspect(handler, response), CredState::Success { .. }),
            "{response:?} must be accepted"
        );
    }

    fn assert_denied(
        handler: &CredHandlerOAuth2Client,
        response: &OAuth2ClientIntrospectResponse,
        msg: &str,
    ) {
        assert!(
            matches!(introspect(handler, response), CredState::Denied(m) if m == msg),
            "{response:?} must be denied with {msg:?}"
        );
    }

    #[test]
    fn test_oauth2_client_introspection_valid() {
        let handler = handler(Some(ISSUER));
        assert_success(&handler, &valid_response());

        // Only `active` and `sub` are required, every other claim is optional.
        let minimal = OAuth2ClientIntrospectResponse {
            active: true,
            sub: Some(USER_SUB.to_string()),
            ..Default::default()
        };
        assert_success(&handler, &minimal);
    }

    #[test]
    fn test_oauth2_client_introspection_inactive_denied() {
        let handler = handler(Some(ISSUER));
        let response = OAuth2ClientIntrospectResponse {
            active: false,
            ..valid_response()
        };
        assert_denied(&handler, &response, BAD_OAUTH2_SESSION_MSG);
        assert_denied(
            &handler,
            &OAuth2ClientIntrospectResponse::default(),
            BAD_OAUTH2_SESSION_MSG,
        );
    }

    #[test]
    fn test_oauth2_client_introspection_subject() {
        let handler = handler(Some(ISSUER));
        let response = OAuth2ClientIntrospectResponse {
            sub: Some("another_subject".to_string()),
            ..valid_response()
        };
        assert_denied(&handler, &response, BAD_OAUTH2_SUBJECT_MSG);

        let response = OAuth2ClientIntrospectResponse {
            sub: None,
            ..valid_response()
        };
        assert_denied(&handler, &response, BAD_OAUTH2_SUBJECT_MSG);
    }

    #[test]
    fn test_oauth2_client_introspection_client_id() {
        let handler = handler(Some(ISSUER));
        for client_id in ["another_client", "", "TEST_CLIENT_ID"] {
            let response = OAuth2ClientIntrospectResponse {
                client_id: Some(client_id.to_string()),
                ..valid_response()
            };
            assert_denied(&handler, &response, BAD_OAUTH2_SESSION_MSG);
        }
    }

    #[test]
    fn test_oauth2_client_introspection_issuer() {
        // The configured issuer is a Url, so "https://idp.example.com" is stored with a
        // trailing "/". A trailing "/" on either side is ignored.
        for (configured, sent) in [
            (ISSUER, ISSUER),
            (ISSUER, "https://idp.example.com/realms/main/"),
            ("https://idp.example.com/realms/main/", ISSUER),
            ("https://idp.example.com", "https://idp.example.com"),
            ("https://idp.example.com", "https://idp.example.com/"),
        ] {
            let response = OAuth2ClientIntrospectResponse {
                iss: Some(sent.to_string()),
                ..valid_response()
            };
            assert_success(&handler(Some(configured)), &response);
        }

        let handler_with_issuer = handler(Some(ISSUER));
        for sent in [
            "https://idp.example.com/realms/other",
            "https://idp.example.com/realms/main/extra",
            "https://evil.example.com/realms/main",
            "http://idp.example.com/realms/main",
            "",
        ] {
            let response = OAuth2ClientIntrospectResponse {
                iss: Some(sent.to_string()),
                ..valid_response()
            };
            assert_denied(&handler_with_issuer, &response, BAD_OAUTH2_SESSION_MSG);
        }

        // Without a configured issuer (an upstream OAuth2Client may have none), `iss`
        // can not be checked.
        let response = OAuth2ClientIntrospectResponse {
            iss: Some("https://anything.example.com".to_string()),
            ..valid_response()
        };
        assert_success(&handler(None), &response);
    }

    #[test]
    fn test_oauth2_client_introspection_expiry() {
        let handler = handler(Some(ISSUER));
        for exp in [NOW as i64 - 300, NOW as i64, 0, i64::MIN] {
            let response = OAuth2ClientIntrospectResponse {
                exp: Some(exp),
                ..valid_response()
            };
            assert_denied(&handler, &response, BAD_OAUTH2_SESSION_MSG);
        }

        let response = OAuth2ClientIntrospectResponse {
            exp: Some(NOW as i64 + 1),
            ..valid_response()
        };
        assert_success(&handler, &response);
    }

    /// The session's current time is used, not the wall clock: a token that is valid at
    /// the session time is accepted even if it expired long ago in real time.
    #[test]
    fn test_oauth2_client_introspection_expiry_uses_session_time() {
        let handler = handler(Some(ISSUER));
        let response = OAuth2ClientIntrospectResponse {
            exp: Some(1_000),
            ..valid_response()
        };
        let (_, cred_state) = handler.validate_access_token_introspection_response(
            &response,
            "access_token".to_string(),
            None,
            Duration::from_secs(1_300),
            Duration::from_secs(999),
        );
        assert!(matches!(cred_state, CredState::Success { .. }));
    }

    // =========================================
    // Kubidm: the id_token verifier.

    mod id_token {
        use super::super::*;
        use crate::idm::oauth2_client_id_token::test_idp::{
            self, claims_with, Signer, CLIENT_ID, ISSUER, NOW, SUBJECT,
        };
        use kubidm_proto::oauth2::{AccessTokenType, IssuedTokenType};
        use serde_json::json;

        const INTROSPECT_URL: &str = "https://idp.example.com/introspect";
        const JWKS_URI: &str = "https://idp.example.com/jwks";

        fn now() -> Duration {
            Duration::from_secs(NOW)
        }

        /// A handler for an id_token federation, optionally also with introspection.
        fn handler(introspection: bool) -> CredHandlerOAuth2Client {
            let mut provider = OAuth2ClientProvider::new_test(
                CLIENT_ID,
                "https://idp.example.com",
                ["email"],
                INTROSPECT_URL,
            );
            let issuer = Url::parse(ISSUER).expect("invalid test issuer");
            provider.issuer = Some(issuer.clone());
            provider.user_sub_verifier = OAuth2SubjectVerifier::OidcIdToken {
                jwks_uri: Url::parse(JWKS_URI).expect("invalid test url"),
                issuer,
                introspection_endpoint: introspection
                    .then(|| Url::parse(INTROSPECT_URL).expect("invalid test url")),
            };
            let cred = OAuth2AccountCredential {
                provider: provider.uuid,
                cred_id: Uuid::new_v4(),
                user_id: "user".to_string(),
                user_sub: SUBJECT.to_string(),
            };
            CredHandlerOAuth2Client::new(&provider, &cred)
        }

        fn token_response(id_token: Option<String>) -> AccessTokenResponse {
            AccessTokenResponse {
                access_token: "access_token".to_string(),
                token_type: AccessTokenType::Bearer,
                issued_token_type: Some(IssuedTokenType::AccessToken),
                expires_in: 300,
                refresh_token: None,
                scope: BTreeSet::new(),
                id_token,
            }
        }

        /// Run the flow up to the token response, which carries `id_token`.
        fn submit_id_token(
            handler: &mut CredHandlerOAuth2Client,
            id_token: Option<String>,
        ) -> CredState {
            let state = handler.csrf_state.clone();
            let cred = AuthCredential::OAuth2AuthorisationResponse {
                code: "code".to_string(),
                state: Some(state),
            };
            assert!(matches!(
                handler.validate(&cred, now()),
                CredState::External(AuthExternal::OAuth2AccessTokenRequest { .. })
            ));
            let cred = AuthCredential::OAuth2AccessTokenResponse {
                response: token_response(id_token),
            };
            handler.validate(&cred, now())
        }

        fn jwks(handler: &mut CredHandlerOAuth2Client, keys: Vec<Jwk>) -> CredState {
            handler.validate(&AuthCredential::OAuth2JwksResponse { keys }, now())
        }

        fn is_jwks_request(state: &CredState, expect_refresh: bool) -> bool {
            matches!(
                state,
                CredState::External(AuthExternal::OAuth2JwksRequest { jwks_uri, refresh, .. })
                    if jwks_uri.as_str() == JWKS_URI && *refresh == expect_refresh
            )
        }

        /// Claims valid for this handler's nonce.
        fn claims(handler: &CredHandlerOAuth2Client) -> serde_json::Value {
            claims_with(&json!({ "nonce": handler.nonce }))
        }

        /// The authorisation request asks for `openid` and carries the session nonce.
        /// An introspection federation sends no nonce and keeps its scopes.
        #[test]
        fn test_oauth2_client_id_token_auth_request() {
            let handler = handler(false);
            let (_, request) = handler.start_auth_request();
            assert_eq!(request.nonce.as_deref(), Some(handler.nonce.as_str()));
            assert!(!handler.nonce.is_empty());
            assert!(request.scope.contains("openid"));
            assert!(request.scope.contains("email"));

            // Every session has its own nonce.
            assert_ne!(handler.nonce, self::handler(false).nonce);

            let introspection = super::handler(Some(ISSUER));
            let (_, request) = introspection.start_auth_request();
            assert_eq!(request.nonce, None);
            assert_eq!(
                request.scope,
                BTreeSet::from(["openid".to_string()]),
                "the configured scopes are sent unchanged"
            );
        }

        #[test]
        fn test_oauth2_client_id_token_success() {
            let mut handler = handler(false);
            let signer = Signer::es256("key");
            let id_token = signer.sign_with_kid(&claims(&handler));

            let state = submit_id_token(&mut handler, Some(id_token));
            assert!(is_jwks_request(&state, false));
            assert!(matches!(
                jwks(&mut handler, vec![signer.jwk()]),
                CredState::Success { .. }
            ));
        }

        /// The token response must carry a valid id_token.
        #[test]
        fn test_oauth2_client_id_token_missing_or_malformed() {
            let hs256 = Signer::hs256().sign_with_kid(&test_idp::valid_claims());
            for id_token in [None, Some("not-a-jwt".to_string()), Some(hs256)] {
                let mut handler = handler(false);
                assert!(matches!(
                    submit_id_token(&mut handler, id_token),
                    CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG)
                ));
                assert!(matches!(handler.session_state, SessionState::Finished));
            }
        }

        /// An unknown key refreshes the JWKS once. Still unknown after the refresh: denied.
        #[test]
        fn test_oauth2_client_id_token_unknown_kid() {
            let signer = Signer::es256("new-key");
            let stale = Signer::es256("old-key");

            let mut handler = handler(false);
            let id_token = signer.sign_with_kid(&claims(&handler));
            assert!(is_jwks_request(
                &submit_id_token(&mut handler, Some(id_token)),
                false
            ));
            assert!(is_jwks_request(
                &jwks(&mut handler, vec![stale.jwk()]),
                true
            ));
            assert!(matches!(
                jwks(&mut handler, vec![stale.jwk()]),
                CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG)
            ));
            assert!(matches!(handler.session_state, SessionState::Finished));

            // The refreshed JWKS has the rotated key: accepted.
            let mut handler = self::handler(false);
            let id_token = signer.sign_with_kid(&claims(&handler));
            submit_id_token(&mut handler, Some(id_token));
            assert!(is_jwks_request(
                &jwks(&mut handler, vec![stale.jwk()]),
                true
            ));
            assert!(matches!(
                jwks(&mut handler, vec![stale.jwk(), signer.jwk()]),
                CredState::Success { .. }
            ));
        }

        /// A bad signature is not retried with a refreshed JWKS.
        #[test]
        fn test_oauth2_client_id_token_bad_signature() {
            let signer = Signer::es256("key");
            let impostor = Signer::es256("key");
            let mut handler = handler(false);
            let id_token = impostor.sign_with_kid(&claims(&handler));
            submit_id_token(&mut handler, Some(id_token));
            assert!(matches!(
                jwks(&mut handler, vec![signer.jwk()]),
                CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG)
            ));
        }

        /// The id_token must carry this session's nonce: one from another session (a
        /// replayed token) is denied.
        #[test]
        fn test_oauth2_client_id_token_nonce_mismatch() {
            let signer = Signer::es256("key");
            let other_session = handler(false);
            let mut handler = handler(false);
            let id_token = signer.sign_with_kid(&claims(&other_session));
            submit_id_token(&mut handler, Some(id_token));
            assert!(matches!(
                jwks(&mut handler, vec![signer.jwk()]),
                CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG)
            ));
        }

        #[test]
        fn test_oauth2_client_id_token_claims_denied() {
            let signer = Signer::es256("key");
            for (changes, msg) in [
                (json!({"sub": "attacker"}), BAD_OAUTH2_SUBJECT_MSG),
                (
                    json!({"iss": "https://evil.example.com"}),
                    BAD_OAUTH2_ID_TOKEN_MSG,
                ),
                (json!({"aud": "other"}), BAD_OAUTH2_ID_TOKEN_MSG),
                (json!({"exp": NOW - 3600}), BAD_OAUTH2_ID_TOKEN_MSG),
            ] {
                let mut handler = handler(false);
                let mut claims = claims(&handler);
                if let (Some(claims), Some(changes)) = (claims.as_object_mut(), changes.as_object())
                {
                    claims.extend(changes.clone());
                }
                submit_id_token(&mut handler, Some(signer.sign_with_kid(&claims)));
                assert!(
                    matches!(jwks(&mut handler, vec![signer.jwk()]), CredState::Denied(m) if m == msg),
                    "{changes} must be denied with {msg:?}"
                );
            }
        }

        /// With introspection configured too, both must pass.
        #[test]
        fn test_oauth2_client_id_token_and_introspection() {
            let signer = Signer::es256("key");
            let valid_introspection = OAuth2ClientIntrospectResponse {
                active: true,
                sub: Some(SUBJECT.to_string()),
                ..Default::default()
            };

            let mut handler = handler(true);
            let id_token = signer.sign_with_kid(&claims(&handler));
            submit_id_token(&mut handler, Some(id_token));
            assert!(matches!(
                jwks(&mut handler, vec![signer.jwk()]),
                CredState::External(AuthExternal::OAuth2AccessTokenIntrospectionRequest {
                    introspection_url,
                    ..
                }) if introspection_url.as_str() == INTROSPECT_URL
            ));
            let mut failed = handler.clone();
            assert!(matches!(
                handler.validate(
                    &AuthCredential::OAuth2AccessTokenIntrospectResponse {
                        response: valid_introspection.clone()
                    },
                    now()
                ),
                CredState::Success { .. }
            ));
            assert!(matches!(
                failed.validate(
                    &AuthCredential::OAuth2AccessTokenIntrospectResponse {
                        response: OAuth2ClientIntrospectResponse {
                            sub: Some("attacker".to_string()),
                            ..valid_introspection.clone()
                        }
                    },
                    now()
                ),
                CredState::Denied(BAD_OAUTH2_SUBJECT_MSG)
            ));

            // A bad id_token is denied before introspection.
            let mut handler = self::handler(true);
            let id_token = signer.sign_with_kid(&claims_with(&json!({"nonce": "wrong"})));
            submit_id_token(&mut handler, Some(id_token));
            assert!(matches!(
                jwks(&mut handler, vec![signer.jwk()]),
                CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG)
            ));
        }

        /// The longest flow: an unknown key, a JWKS refresh that has it, then
        /// introspection. Four external steps before the result (the login view allows
        /// for them).
        #[test]
        fn test_oauth2_client_id_token_refresh_then_introspection() {
            let signer = Signer::es256("rotated");
            let stale = Signer::es256("old");
            let mut handler = handler(true);
            let id_token = signer.sign_with_kid(&claims(&handler));

            assert!(is_jwks_request(
                &submit_id_token(&mut handler, Some(id_token)),
                false
            ));
            assert!(is_jwks_request(
                &jwks(&mut handler, vec![stale.jwk()]),
                true
            ));
            assert!(matches!(
                jwks(&mut handler, vec![stale.jwk(), signer.jwk()]),
                CredState::External(AuthExternal::OAuth2AccessTokenIntrospectionRequest { .. })
            ));
            assert!(matches!(
                handler.validate(
                    &AuthCredential::OAuth2AccessTokenIntrospectResponse {
                        response: OAuth2ClientIntrospectResponse {
                            active: true,
                            sub: Some(SUBJECT.to_string()),
                            ..Default::default()
                        }
                    },
                    now()
                ),
                CredState::Success { .. }
            ));
        }

        /// A token signed by provider A's key is never accepted by a session of provider
        /// B: B asks for its own JWKS, and A's key is not in it, whatever the `kid`.
        #[test]
        fn test_oauth2_client_id_token_other_provider_key() {
            let key_a = Signer::es256("key-a");
            let key_b = Signer::es256("key-b");
            let colliding_a = Signer::es256("key-b");

            let mut handler_b = handler(false);
            let provider_b = handler_b.provider_id;
            assert_ne!(provider_b, handler(false).provider_id);

            // A's kid: unknown to B, refreshed once, then denied.
            let id_token = key_a.sign_with_kid(&claims(&handler_b));
            let state = submit_id_token(&mut handler_b, Some(id_token));
            assert!(matches!(
                state,
                CredState::External(AuthExternal::OAuth2JwksRequest { provider_id, .. })
                    if provider_id == provider_b
            ));
            assert!(is_jwks_request(
                &jwks(&mut handler_b, vec![key_b.jwk()]),
                true
            ));
            assert!(matches!(
                jwks(&mut handler_b, vec![key_b.jwk()]),
                CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG)
            ));

            // A's key with B's kid: B's key is tried, and the signature fails.
            let mut handler_b = handler(false);
            let id_token = colliding_a.sign_with_kid(&claims(&handler_b));
            submit_id_token(&mut handler_b, Some(id_token));
            assert!(matches!(
                jwks(&mut handler_b, vec![key_b.jwk()]),
                CredState::Denied(BAD_OAUTH2_ID_TOKEN_MSG)
            ));
        }

        /// The JWKS can not be submitted out of order, and an introspection federation
        /// ignores an id_token entirely.
        #[test]
        fn test_oauth2_client_id_token_out_of_order() {
            let signer = Signer::es256("key");
            let mut handler = handler(false);
            assert!(matches!(
                jwks(&mut handler, vec![signer.jwk()]),
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            ));

            let mut introspection = super::handler(Some(ISSUER));
            let id_token = signer.sign_with_kid(&test_idp::valid_claims());
            assert!(matches!(
                submit_id_token(&mut introspection, Some(id_token)),
                CredState::External(AuthExternal::OAuth2AccessTokenIntrospectionRequest { .. })
            ));
        }
    }
}
