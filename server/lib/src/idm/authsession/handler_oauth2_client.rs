use super::{
    CredState, BAD_AUTH_TYPE_MSG, BAD_OAUTH2_CSRF_STATE_MSG, BAD_OAUTH2_SESSION_MSG,
    BAD_OAUTH2_SUBJECT_MSG,
};
use crate::{
    idm::{
        account::OAuth2AccountCredential,
        authentication::{AuthCredential, AuthExternal},
        oauth2::PkceS256Secret,
        oauth2_client::{OAuth2ClientProvider, OAuth2SubjectVerifier},
    },
    prelude::*,
    utils,
    value::{AuthType, SessionExtMetadata},
};
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

        CredHandlerOAuth2Client {
            provider_id: client_provider.uuid,
            provider_name: client_provider.name.clone(),
            request_scopes: client_provider.request_scopes.clone(),
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
                nonce: None,
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

        match &self.user_sub_verifier {
            OAuth2SubjectVerifier::None => {
                (SessionState::Finished, CredState::Denied(BAD_AUTH_TYPE_MSG))
            }
            OAuth2SubjectVerifier::Rfc7662TokenIntrospection { endpoint } => {
                let request = AccessTokenIntrospectRequest::from(response.access_token.clone());

                let access_expires_at =
                    current_time + Duration::from_secs(response.expires_in as u64);

                (
                    SessionState::AccessTokenUnverified {
                        access_token: response.access_token.clone(),
                        refresh_token: response.refresh_token.clone(),
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
        }
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
}
