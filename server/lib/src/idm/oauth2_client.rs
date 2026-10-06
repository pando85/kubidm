use crate::{idm::server::IdmServerProxyWriteTransaction, prelude::*};
use kubidm_proto::oauth2::OidcDiscoveryResponse;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};
use tokio::sync::RwLock;

pub const OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH: &str = "/ui/login/oauth2_landing";

pub const OIDC_DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountLinkPolicy {
    Auto,
    Manual,
    AdminApproval,
}

impl std::str::FromStr for AccountLinkPolicy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(AccountLinkPolicy::Auto),
            "manual" => Ok(AccountLinkPolicy::Manual),
            "admin_approval" => Ok(AccountLinkPolicy::AdminApproval),
            _ => Err(()),
        }
    }
}

impl fmt::Display for AccountLinkPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountLinkPolicy::Auto => write!(f, "auto"),
            AccountLinkPolicy::Manual => write!(f, "manual"),
            AccountLinkPolicy::AdminApproval => write!(f, "admin_approval"),
        }
    }
}

#[derive(Clone)]
pub enum OAuth2SubjectVerifier {
    None,
    Rfc7662TokenIntrospection { endpoint: Url },
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct OAuth2ClientProvider {
    pub(crate) name: String,
    pub(crate) uuid: Uuid,
    pub(crate) client_id: String,
    pub(crate) client_basic_secret: String,
    pub(crate) client_redirect_uri: Url,
    pub(crate) request_scopes: BTreeSet<String>,
    pub(crate) authorisation_endpoint: Url,
    pub(crate) token_endpoint: Url,
    pub(crate) user_sub_verifier: OAuth2SubjectVerifier,
    pub(crate) issuer: Option<Url>,
    pub(crate) jwks_uri: Option<Url>,
    pub(crate) userinfo_endpoint: Option<Url>,
    pub(crate) display_name: Option<String>,
    pub(crate) email_domains: BTreeSet<String>,
    pub(crate) link_policy: AccountLinkPolicy,
    pub(crate) idp_initiated_enabled: bool,
    pub(crate) federation_id: Option<String>,
    pub(crate) auto_discovery: bool,
}

impl fmt::Debug for OAuth2ClientProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2ClientProvider")
            .field("name", &self.name)
            .field("uuid", &self.uuid)
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("email_domains", &self.email_domains)
            .field("display_name", &self.display_name)
            .finish()
    }
}

impl OAuth2ClientProvider {
    #[cfg(test)]
    pub fn new_test<'a, I: IntoIterator<Item = &'a str>>(
        client_id: &str,
        domain: &str,
        request_scopes: I,
        introspect_url: &str,
    ) -> Self {
        let mut client_redirect_uri =
            Url::parse("https://idm.example.com").expect("invalid test data");
        client_redirect_uri.set_path(OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH);

        let mut domain = Url::parse(domain).expect("invalid test data");

        domain.set_path("/oauth2/authorise");
        let authorisation_endpoint = domain.clone();

        domain.set_path("/oauth2/token");
        let token_endpoint = domain.clone();

        let client_basic_secret = crate::utils::password_from_random();

        let request_scopes = request_scopes.into_iter().map(String::from).collect();

        let endpoint = Url::parse(introspect_url).expect("invalid test data");
        let user_sub_verifier = OAuth2SubjectVerifier::Rfc7662TokenIntrospection { endpoint };

        Self {
            name: "test_client_provider".to_string(),
            uuid: Uuid::new_v4(),
            client_id: client_id.to_string(),
            client_basic_secret,
            client_redirect_uri,
            request_scopes,
            authorisation_endpoint,
            token_endpoint,
            user_sub_verifier,
            issuer: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            display_name: None,
            email_domains: BTreeSet::new(),
            link_policy: AccountLinkPolicy::Manual,
            idp_initiated_enabled: false,
            federation_id: None,
            auto_discovery: false,
        }
    }

    #[allow(dead_code)]
    pub fn matches_email_domain(&self, email: &str) -> bool {
        if self.email_domains.is_empty() {
            return false;
        }
        email
            .split('@')
            .nth(1)
            .map(|domain| {
                self.email_domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(domain))
            })
            .unwrap_or(false)
    }
}

#[allow(dead_code)]
pub struct FederationDiscoveryCache {
    cache: Arc<RwLock<BTreeMap<String, OidcDiscoveryResponse>>>,
}

impl Default for FederationDiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl FederationDiscoveryCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub async fn get(&self, issuer: &str) -> Option<OidcDiscoveryResponse> {
        let cache = self.cache.read().await;
        cache.get(issuer).cloned()
    }

    pub async fn insert(&self, issuer: String, response: OidcDiscoveryResponse) {
        let mut cache = self.cache.write().await;
        cache.insert(issuer, response);
    }

    pub async fn remove(&self, issuer: &str) {
        let mut cache = self.cache.write().await;
        cache.remove(issuer);
    }
}

#[allow(dead_code)]
pub async fn discover_oidc_provider(
    issuer_url: &Url,
) -> Result<OidcDiscoveryResponse, OperationError> {
    let discovery_url = format!(
        "{}{}",
        issuer_url.as_str().trim_end_matches('/'),
        OIDC_DISCOVERY_PATH
    );

    let url = Url::parse(&discovery_url).map_err(|e| {
        error!(?e, "Failed to parse discovery URL");
        OperationError::InvalidState
    })?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            error!(?e, "Failed to create HTTP client for discovery");
            OperationError::InvalidState
        })?;

    let response = client.get(url.clone()).send().await.map_err(|e| {
        error!(?e, "Failed to fetch OIDC discovery document");
        OperationError::InvalidState
    })?;

    if !response.status().is_success() {
        error!(status = ?response.status(), "OIDC discovery request failed");
        return Err(OperationError::InvalidValueState);
    }

    let discovery = response
        .json::<OidcDiscoveryResponse>()
        .await
        .map_err(|e| {
            error!(?e, "Failed to parse OIDC discovery response");
            OperationError::SerdeJsonError
        })?;

    if discovery.issuer.as_str().trim_end_matches('/') != issuer_url.as_str().trim_end_matches('/')
    {
        error!(
            expected = ?issuer_url,
            actual = ?discovery.issuer,
            "OIDC discovery issuer mismatch"
        );
        return Err(OperationError::InvalidValueState);
    }

    Ok(discovery)
}

impl IdmServerProxyWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_oauth2_client_providers(&mut self) -> Result<(), OperationError> {
        let oauth2_client_entries = self.qs_write.internal_search(filter!(f_or!([
            f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
            f_eq(Attribute::Class, EntryClass::OAuth2Federation.into())
        ])))?;

        let mut oauth2_client_provider_structs = Vec::with_capacity(oauth2_client_entries.len());

        let mut client_redirect_uri = self.origin.clone();
        client_redirect_uri.set_path(OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH);

        for provider_entry in oauth2_client_entries {
            let uuid = provider_entry.get_uuid();
            trace!(?uuid, "Checking OAuth2 Provider configuration");

            let name = provider_entry
                .get_ava_single_iname(Attribute::Name)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let client_id = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClientId)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let client_basic_secret = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let issuer = provider_entry
                .get_ava_single_url(Attribute::OAuth2Issuer)
                .cloned();

            let authorisation_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2AuthorisationEndpoint)
                .cloned();

            let token_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2TokenEndpoint)
                .cloned();

            let request_scopes = provider_entry
                .get_ava_as_oauthscopes(Attribute::OAuth2RequestScopes)
                .map(|s| s.map(str::to_string).collect())
                .unwrap_or_default();

            let jwks_uri = provider_entry
                .get_ava_single_url(Attribute::OAuth2JwksUri)
                .cloned();

            let userinfo_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2UserinfoEndpoint)
                .cloned();

            let display_name = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2DisplayName)
                .map(str::to_string);

            let email_domains: BTreeSet<String> = provider_entry
                .get_ava_iter_iutf8(Attribute::OAuth2EmailDomain)
                .map(|s| s.map(str::to_string).collect())
                .unwrap_or_default();

            let link_policy = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2LinkPolicy)
                .and_then(|s| s.parse().ok())
                .unwrap_or(AccountLinkPolicy::Manual);

            let idp_initiated_enabled = provider_entry
                .get_ava_single_bool(Attribute::OAuth2IdpInitiatedEnabled)
                .unwrap_or(false);

            let federation_id = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2FederationId)
                .map(str::to_string);

            let auto_discovery = provider_entry
                .get_ava_single_bool(Attribute::OAuth2AutoDiscovery)
                .unwrap_or(false);

            let (authorisation_endpoint, token_endpoint) =
                match (authorisation_endpoint, token_endpoint, issuer.as_ref()) {
                    (Some(auth), Some(token), _) => (auth, token),
                    (None, None, Some(issuer_url)) => {
                        let mut auth = issuer_url.clone();
                        auth.set_path("/oauth2/authorize");

                        let mut token = issuer_url.clone();
                        token.set_path("/oauth2/token");

                        (auth, token)
                    }
                    _ => {
                        error!(?uuid, "OAuth2 provider missing required endpoints");
                        return Err(OperationError::InvalidValueState);
                    }
                };

            let maybe_rfc7662_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2TokenIntrospectEndpoint)
                .cloned();

            let user_sub_verifier = match maybe_rfc7662_endpoint {
                Some(endpoint) => OAuth2SubjectVerifier::Rfc7662TokenIntrospection { endpoint },
                None => OAuth2SubjectVerifier::None,
            };

            let provider = OAuth2ClientProvider {
                name,
                uuid,
                client_id,
                client_basic_secret,
                client_redirect_uri: client_redirect_uri.clone(),
                request_scopes,
                authorisation_endpoint,
                token_endpoint,
                user_sub_verifier,
                issuer,
                jwks_uri,
                userinfo_endpoint,
                display_name,
                email_domains,
                link_policy,
                idp_initiated_enabled,
                federation_id,
                auto_discovery,
            };

            oauth2_client_provider_structs.push((uuid, provider));
        }

        self.oauth2_client_providers.clear();
        self.oauth2_client_providers
            .extend(oauth2_client_provider_structs);

        Ok(())
    }
}
