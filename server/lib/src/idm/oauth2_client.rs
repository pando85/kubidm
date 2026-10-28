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

/// A loaded `OAuth2Client` (upstream) or `OAuth2Federation` (Kubidm) provider.
///
/// Kubidm: `jwks_uri`, `userinfo_endpoint`, `display_name`, `email_domains` and
/// `federation_id` are reserved. They are stored and loaded but not used by the login
/// flow, which only trusts the RFC 7662 introspection of the access token against a
/// pre-linked account. `link_policy` is always `Manual`, and `idp_initiated_enabled` and
/// `auto_discovery` are always false, because any other value is rejected at load.
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
    /// Reload the OAuth2 client providers (`OAuth2Client` and `OAuth2Federation` entries).
    /// This runs on commit when a provider entry changed. A provider that was changed in
    /// this transaction and is invalid fails the reload, so the change is rejected. Invalid
    /// providers that were not changed are logged and skipped, so a pre-existing bad entry
    /// never blocks unrelated writes.
    ///
    /// A transaction that applies replicated changes is always lenient: the content was
    /// already accepted by the supplier, and failing here would block replication (a
    /// refresh marks every entry as changed) until the entry is fixed on the supplier.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_oauth2_client_providers(&mut self) -> Result<(), OperationError> {
        let strict_for_changed = !self.qs_write.is_replication_apply();
        self.reload_oauth2_client_providers_inner(strict_for_changed)
    }

    /// As [Self::reload_oauth2_client_providers], but every invalid provider entry is
    /// logged and skipped. Used at startup, so a bad entry does not stop the server.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_oauth2_client_providers_lenient(&mut self) -> Result<(), OperationError> {
        self.reload_oauth2_client_providers_inner(false)
    }

    /// `strict_for_changed`: fail on an invalid provider that was changed in this txn.
    fn reload_oauth2_client_providers_inner(
        &mut self,
        strict_for_changed: bool,
    ) -> Result<(), OperationError> {
        let oauth2_client_entries = self.qs_write.internal_search(filter!(f_or!([
            f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
            f_eq(Attribute::Class, EntryClass::OAuth2Federation.into())
        ])))?;

        let mut oauth2_client_provider_structs = Vec::with_capacity(oauth2_client_entries.len());

        let mut client_redirect_uri = self.origin.clone();
        client_redirect_uri.set_path(OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH);

        for provider_entry in oauth2_client_entries {
            let uuid = provider_entry.get_uuid();
            match oauth2_client_provider_from_entry(&provider_entry, &client_redirect_uri) {
                Ok(provider) => oauth2_client_provider_structs.push((uuid, provider)),
                // Kubidm: only the providers changed in this transaction are validated
                // strictly, so the offending change is rejected. Any other invalid
                // provider (including all of them at startup) is skipped.
                Err(err) if !(strict_for_changed && self.qs_write.is_changed_uuid(&uuid)) => {
                    error!(
                        ?err,
                        ?uuid,
                        "Skipping invalid OAuth2 client provider configuration"
                    );
                }
                Err(err) => {
                    error!(?err, ?uuid, "Invalid OAuth2 client provider configuration");
                    return Err(err);
                }
            }
        }

        self.oauth2_client_providers.clear();
        self.oauth2_client_providers
            .extend(oauth2_client_provider_structs);

        Ok(())
    }
}

/// Kubidm: the server itself sends the client secret and the access token to the token
/// and introspection endpoints, and a federation's users type their IdP password at its
/// authorisation endpoint, so they must use https. Plain http is only accepted when the
/// host is a loopback address (`localhost`, `127.0.0.0/8` or `::1`), for local
/// development and tests. Credentials in the URL (`user:password@`) are never accepted.
fn require_secure_endpoint_url(
    uuid: Uuid,
    endpoint_name: &str,
    url: &Url,
) -> Result<(), OperationError> {
    if !url.username().is_empty() || url.password().is_some() {
        error!(
            ?uuid,
            "OAuth2 provider {endpoint_name} endpoint must not contain credentials (user:password@)"
        );
        return Err(OperationError::InvalidValueState);
    }

    if url.scheme() == "https" {
        return Ok(());
    }

    let is_loopback = match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };

    if url.scheme() == "http" && is_loopback {
        return Ok(());
    }

    error!(
        ?uuid,
        %url,
        "OAuth2 provider {endpoint_name} endpoint must use https (http is only allowed on loopback addresses)"
    );
    Err(OperationError::InvalidValueState)
}

fn oauth2_client_provider_from_entry(
    provider_entry: &EntrySealedCommitted,
    client_redirect_uri: &Url,
) -> Result<OAuth2ClientProvider, OperationError> {
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

    let is_federation =
        provider_entry.attribute_equality(Attribute::Class, &EntryClass::OAuth2Federation.into());

    // OAuth2LinkPolicy is Utf8StringInsensitive and OAuth2FederationId is
    // Utf8StringIname, so they must be read with the matching accessors.
    //
    // Kubidm: only admin linked accounts (`manual`) are implemented. Absent means manual.
    // Anything else, including the reserved `auto` and `admin_approval`, is rejected
    // rather than silently treated as manual.
    let link_policy = match provider_entry.get_ava_single_iutf8(Attribute::OAuth2LinkPolicy) {
        None => AccountLinkPolicy::Manual,
        Some(value) => match value.parse::<AccountLinkPolicy>() {
            Ok(AccountLinkPolicy::Manual) => AccountLinkPolicy::Manual,
            Ok(policy) => {
                error!(?uuid, %policy, "OAuth2 provider link policy is not implemented, only 'manual' is supported");
                return Err(OperationError::InvalidValueState);
            }
            Err(()) => {
                error!(?uuid, %value, "OAuth2 provider link policy is invalid, only 'manual' is supported");
                return Err(OperationError::InvalidValueState);
            }
        },
    };

    // Kubidm: IdP initiated login and OIDC auto discovery are not implemented. Enabling
    // them is rejected so that a configuration never appears to do something it does not.
    let idp_initiated_enabled = provider_entry
        .get_ava_single_bool(Attribute::OAuth2IdpInitiatedEnabled)
        .unwrap_or(false);

    if idp_initiated_enabled {
        error!(
            ?uuid,
            "OAuth2 provider enables IdP initiated login, which is not implemented"
        );
        return Err(OperationError::InvalidValueState);
    }

    let federation_id = provider_entry
        .get_ava_single_iname(Attribute::OAuth2FederationId)
        .map(str::to_string);

    let auto_discovery = provider_entry
        .get_ava_single_bool(Attribute::OAuth2AutoDiscovery)
        .unwrap_or(false);

    if auto_discovery {
        error!(
            ?uuid,
            "OAuth2 provider enables OIDC auto discovery, which is not implemented"
        );
        return Err(OperationError::InvalidValueState);
    }

    let (authorisation_endpoint, token_endpoint) =
        match (authorisation_endpoint, token_endpoint, issuer.as_ref()) {
            (Some(auth), Some(token), _) => (auth, token),
            // Kubidm: a federation must set both endpoints explicitly. Deriving them from
            // the issuer guesses a provider specific layout and drops any issuer path.
            (None, None, Some(issuer_url)) if !is_federation => {
                let mut auth = issuer_url.clone();
                auth.set_path("/oauth2/authorize");

                let mut token = issuer_url.clone();
                token.set_path("/oauth2/token");

                (auth, token)
            }
            _ => {
                error!(
                    ?uuid,
                    "OAuth2 provider missing required authorisation or token endpoint"
                );
                return Err(OperationError::InvalidValueState);
            }
        };

    let maybe_rfc7662_endpoint = provider_entry
        .get_ava_single_url(Attribute::OAuth2TokenIntrospectEndpoint)
        .cloned();

    // Kubidm: the client secret and the access token are sent to these endpoints by the
    // server, so they must use https. Plain http is only accepted on loopback addresses.
    require_secure_endpoint_url(uuid, "token", &token_endpoint)?;
    if let Some(endpoint) = maybe_rfc7662_endpoint.as_ref() {
        require_secure_endpoint_url(uuid, "token introspection", endpoint)?;
    }

    if is_federation {
        // Kubidm: users of a federation type their IdP password at the authorisation
        // endpoint, so it must not be plain http either. Upstream `OAuth2Client`
        // providers keep their behaviour.
        require_secure_endpoint_url(uuid, "authorisation", &authorisation_endpoint)?;

        // Kubidm: a login is only accepted once the access token is introspected, so a
        // federation without an introspection endpoint would deny every user after they
        // signed in at the IdP.
        if maybe_rfc7662_endpoint.is_none() {
            error!(
                ?uuid,
                "OAuth2 federation is missing the token introspection endpoint, which is required to verify logins"
            );
            return Err(OperationError::InvalidValueState);
        }
    }

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

    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::{require_secure_endpoint_url, AccountLinkPolicy, OAuth2SubjectVerifier};
    use crate::prelude::*;

    /// Kubidm: OAuth2 federation entries are valid at the target domain level, and every
    /// federation attribute is parsed by `reload_oauth2_client_providers` with the
    /// accessor matching its syntax.
    #[idm_test]
    async fn test_idm_oauth2_federation_provider_reload(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let fed_uuid = Uuid::new_v4();
        let e_fed: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::OAuth2Federation.to_value()),
            (Attribute::Uuid, Value::Uuid(fed_uuid)),
            (Attribute::Name, Value::new_iname("test_federation")),
            (Attribute::OAuth2ClientId, Value::new_utf8s("client_id")),
            (Attribute::OAuth2ClientSecret, Value::new_utf8s("secret")),
            (
                Attribute::OAuth2Issuer,
                Value::Url(Url::parse("https://idp.example.com/realms/main").unwrap())
            ),
            (
                Attribute::OAuth2AuthorisationEndpoint,
                Value::Url(Url::parse("https://idp.example.com/realms/main/auth").unwrap())
            ),
            (
                Attribute::OAuth2TokenEndpoint,
                Value::Url(Url::parse("https://idp.example.com/realms/main/token").unwrap())
            ),
            (
                Attribute::OAuth2TokenIntrospectEndpoint,
                Value::Url(Url::parse("https://idp.example.com/realms/main/introspect").unwrap())
            ),
            (
                Attribute::OAuth2JwksUri,
                Value::Url(Url::parse("https://idp.example.com/jwks").unwrap())
            ),
            (
                Attribute::OAuth2UserinfoEndpoint,
                Value::Url(Url::parse("https://idp.example.com/userinfo").unwrap())
            ),
            (
                Attribute::OAuth2EmailDomain,
                Value::new_iutf8n("example.com")
            ),
            (
                Attribute::OAuth2EmailDomain,
                Value::new_iutf8n("example.org")
            ),
            (
                Attribute::OAuth2DisplayName,
                Value::new_utf8s("Example IdP")
            ),
            (Attribute::OAuth2LinkPolicy, Value::new_iutf8("manual")),
            (
                Attribute::OAuth2FederationId,
                Value::new_iname("example_fed")
            ),
            (Attribute::OAuth2IdpInitiatedEnabled, Value::Bool(false)),
            (Attribute::OAuth2AutoDiscovery, Value::Bool(false))
        );

        idms_prox_write
            .qs_write
            .internal_create(vec![e_fed])
            .expect("failed to create oauth2 federation entry");

        idms_prox_write
            .reload_oauth2_client_providers()
            .expect("failed to reload oauth2 client providers");

        let provider = idms_prox_write
            .oauth2_client_providers
            .get(&fed_uuid)
            .expect("federation provider not loaded");

        assert_eq!(provider.name, "test_federation");
        assert_eq!(
            provider.issuer.as_ref().map(Url::as_str),
            Some("https://idp.example.com/realms/main")
        );
        assert_eq!(
            provider.jwks_uri.as_ref().map(Url::as_str),
            Some("https://idp.example.com/jwks")
        );
        assert_eq!(provider.email_domains.len(), 2);
        assert_eq!(provider.display_name.as_deref(), Some("Example IdP"));
        assert_eq!(provider.link_policy, AccountLinkPolicy::Manual);
        assert_eq!(provider.federation_id.as_deref(), Some("example_fed"));
        assert!(!provider.idp_initiated_enabled);
        assert!(!provider.auto_discovery);
        // The explicit endpoints are used as is, keeping the issuer path.
        assert_eq!(
            provider.authorisation_endpoint.as_str(),
            "https://idp.example.com/realms/main/auth"
        );
        assert_eq!(
            provider.token_endpoint.as_str(),
            "https://idp.example.com/realms/main/token"
        );
        // The introspection endpoint is in the federation schema and becomes the subject
        // verifier. Without it every federation login is denied.
        match &provider.user_sub_verifier {
            OAuth2SubjectVerifier::Rfc7662TokenIntrospection { endpoint } => assert_eq!(
                endpoint.as_str(),
                "https://idp.example.com/realms/main/introspect"
            ),
            OAuth2SubjectVerifier::None => panic!("federation loaded without a verifier"),
        }

        idms_prox_write.commit().expect("failed to commit");
    }

    fn federation_entry(uuid: Uuid, name: &str) -> EntryInitNew {
        entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::OAuth2Federation.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::OAuth2ClientId, Value::new_utf8s("client_id")),
            (Attribute::OAuth2ClientSecret, Value::new_utf8s("secret")),
            (
                Attribute::OAuth2Issuer,
                Value::Url(Url::parse("https://idp.example.com").unwrap())
            ),
            (
                Attribute::OAuth2AuthorisationEndpoint,
                Value::Url(Url::parse("https://idp.example.com/authorise").unwrap())
            ),
            (
                Attribute::OAuth2TokenEndpoint,
                Value::Url(Url::parse("https://idp.example.com/token").unwrap())
            ),
            (
                Attribute::OAuth2TokenIntrospectEndpoint,
                Value::Url(Url::parse("https://idp.example.com/introspect").unwrap())
            )
        )
    }

    /// Kubidm: creating, modifying and deleting a federation at runtime reloads the
    /// provider list on commit, without a restart or an explicit reload.
    #[idm_test]
    async fn test_idm_oauth2_federation_reload_on_change(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let fed_uuid = Uuid::new_v4();

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_create(vec![federation_entry(fed_uuid, "runtime_federation")])
            .expect("failed to create oauth2 federation entry");
        idms_prox_write.commit().expect("failed to commit");

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let provider = idms_prox_write
            .oauth2_client_providers
            .get(&fed_uuid)
            .expect("federation provider not loaded after create");
        assert_eq!(provider.display_name, None);
        idms_prox_write
            .qs_write
            .internal_modify_uuid(
                fed_uuid,
                &ModifyList::new_purge_and_set(
                    Attribute::OAuth2DisplayName,
                    Value::new_utf8s("Runtime IdP"),
                ),
            )
            .expect("failed to modify oauth2 federation entry");
        idms_prox_write.commit().expect("failed to commit");

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let provider = idms_prox_write
            .oauth2_client_providers
            .get(&fed_uuid)
            .expect("federation provider missing after modify");
        assert_eq!(provider.display_name.as_deref(), Some("Runtime IdP"));
        idms_prox_write
            .qs_write
            .internal_delete_uuid(fed_uuid)
            .expect("failed to delete oauth2 federation entry");
        idms_prox_write.commit().expect("failed to commit");

        let idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(idms_prox_write
            .oauth2_client_providers
            .get(&fed_uuid)
            .is_none());
    }

    /// An unimplemented link policy: the provider configuration is invalid (the entry
    /// itself is schema valid).
    fn invalid_federation_entry(uuid: Uuid, name: &str) -> EntryInitNew {
        let mut bad = federation_entry(uuid, name);
        bad.add_ava(Attribute::OAuth2LinkPolicy, Value::new_iutf8("auto"));
        bad
    }

    fn set_display_name(txn: &mut QueryServerWriteTransaction<'_>, uuid: Uuid, name: &str) {
        txn.internal_modify_uuid(
            uuid,
            &ModifyList::new_purge_and_set(Attribute::OAuth2DisplayName, Value::new_utf8s(name)),
        )
        .expect("failed to modify oauth2 federation entry");
    }

    /// Kubidm: creating an invalid federation, or modifying a federation so that it becomes
    /// invalid, is rejected at commit.
    #[idm_test]
    async fn test_idm_oauth2_federation_invalid_change_rejected(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let good_uuid = Uuid::new_v4();
        let bad_uuid = Uuid::new_v4();

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_create(vec![federation_entry(good_uuid, "good_federation")])
            .expect("failed to create oauth2 federation entry");
        idms_prox_write.commit().expect("failed to commit");

        // Create an invalid provider.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_create(vec![invalid_federation_entry(bad_uuid, "bad_federation")])
            .expect("the entry itself is schema valid");
        assert_eq!(
            idms_prox_write.commit(),
            Err(OperationError::InvalidValueState)
        );

        // Make a valid provider invalid.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(idms_prox_write
            .qs_write
            .internal_search_uuid(bad_uuid)
            .is_err());
        idms_prox_write
            .qs_write
            .internal_modify_uuid(
                good_uuid,
                &ModifyList::new_append(Attribute::OAuth2LinkPolicy, Value::new_iutf8("auto")),
            )
            .expect("the entry itself is schema valid");
        assert_eq!(
            idms_prox_write.commit(),
            Err(OperationError::InvalidValueState)
        );

        // Nothing was committed: the provider is still valid and loaded.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(!idms_prox_write
            .qs_write
            .internal_search_uuid(good_uuid)
            .unwrap()
            .attribute_pres(Attribute::OAuth2LinkPolicy));
        assert!(idms_prox_write
            .oauth2_client_providers
            .get(&good_uuid)
            .is_some());
    }

    /// Kubidm: an invalid provider that is already stored (for example written by an older
    /// version, or replicated) does not block writes to other providers; it is skipped.
    #[idm_test]
    async fn test_idm_oauth2_federation_invalid_existing_does_not_block(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let good_uuid = Uuid::new_v4();
        let bad_uuid = Uuid::new_v4();

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_create(vec![federation_entry(good_uuid, "good_federation")])
            .expect("failed to create oauth2 federation entry");
        idms_prox_write.commit().expect("failed to commit");

        // Store the invalid provider bypassing the IDM layer reload, as an older version
        // would have. The block drops the rest of the IDM transaction (and its locks).
        {
            let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
            idms_prox_write
                .qs_write
                .internal_create(vec![invalid_federation_entry(bad_uuid, "bad_federation")])
                .expect("the entry itself is schema valid");
            idms_prox_write.qs_write.commit().expect("failed to commit");
        }

        // A modify of a different, valid provider succeeds and reloads the providers.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        set_display_name(&mut idms_prox_write.qs_write, good_uuid, "Good IdP");
        idms_prox_write
            .commit()
            .expect("an unrelated invalid provider must not block the write");

        let idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert_eq!(
            idms_prox_write
                .oauth2_client_providers
                .get(&good_uuid)
                .and_then(|p| p.display_name.as_deref()),
            Some("Good IdP")
        );
        assert!(idms_prox_write
            .oauth2_client_providers
            .get(&bad_uuid)
            .is_none());
    }

    /// Kubidm: the server starts with an invalid provider stored, skipping it and serving
    /// the valid ones.
    #[qs_test]
    async fn test_idm_oauth2_federation_invalid_startup(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let good_uuid = Uuid::new_v4();
        let bad_uuid = Uuid::new_v4();

        let mut qs_write = server.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![
                federation_entry(good_uuid, "good_federation"),
                invalid_federation_entry(bad_uuid, "bad_federation"),
            ])
            .expect("the entries are schema valid");
        qs_write.commit().expect("failed to commit");

        let (idms, _idms_delayed, _idms_audit) = IdmServer::new(
            server.clone(),
            &Url::parse("https://idm.example.com").unwrap(),
            true,
            ct,
        )
        .await
        .expect("an invalid provider must not prevent startup");

        let idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(idms_prox_write
            .oauth2_client_providers
            .get(&good_uuid)
            .is_some());
        assert!(idms_prox_write
            .oauth2_client_providers
            .get(&bad_uuid)
            .is_none());
    }

    /// Create `entry` and commit, returning the commit result. A failed commit leaves
    /// nothing behind.
    async fn commit_provider(idms: &IdmServer, entry: EntryInitNew) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_create(vec![entry])
            .expect("the entry itself is schema valid");
        idms_prox_write.commit()
    }

    /// As [federation_entry], with `attr` replaced by `values` (removed when empty).
    fn federation_entry_with(uuid: Uuid, attr: &Attribute, values: Vec<Value>) -> EntryInitNew {
        let mut entry = federation_entry(uuid, "variant_federation");
        entry.remove_ava(attr);
        for value in values {
            entry.add_ava(attr.clone(), value);
        }
        entry
    }

    fn replace_ava(entry: &mut EntryInitNew, attr: Attribute, value: Value) {
        entry.remove_ava(&attr);
        entry.add_ava(attr, value);
    }

    fn url_value(url: &str) -> Value {
        Value::Url(Url::parse(url).unwrap())
    }

    /// Kubidm: a federation must set both the authorisation and the token endpoint, they
    /// are never derived from the issuer.
    #[idm_test]
    async fn test_idm_oauth2_federation_requires_explicit_endpoints(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        for attr in [
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
        ] {
            let entry = federation_entry_with(Uuid::new_v4(), &attr, vec![]);
            assert_eq!(
                commit_provider(idms, entry).await,
                Err(OperationError::InvalidValueState),
                "a federation without {attr} must be rejected"
            );
        }

        let mut entry = federation_entry(Uuid::new_v4(), "issuer_only");
        entry.remove_ava(Attribute::OAuth2AuthorisationEndpoint);
        entry.remove_ava(Attribute::OAuth2TokenEndpoint);
        assert_eq!(
            commit_provider(idms, entry).await,
            Err(OperationError::InvalidValueState),
            "a federation with only an issuer must be rejected"
        );
    }

    /// Kubidm: only the `manual` link policy (or none) is accepted.
    #[idm_test]
    async fn test_idm_oauth2_federation_link_policy(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        for policy in ["auto", "admin_approval", "Auto", "garbage"] {
            let entry = federation_entry_with(
                Uuid::new_v4(),
                &Attribute::OAuth2LinkPolicy,
                vec![Value::new_iutf8(policy)],
            );
            assert_eq!(
                commit_provider(idms, entry).await,
                Err(OperationError::InvalidValueState),
                "link policy {policy:?} must be rejected"
            );
        }

        for (name, values) in [
            ("manual_federation", vec![Value::new_iutf8("manual")]),
            ("upper_manual_federation", vec![Value::new_iutf8("MANUAL")]),
            ("unset_federation", vec![]),
        ] {
            let uuid = Uuid::new_v4();
            let mut entry = federation_entry_with(uuid, &Attribute::OAuth2LinkPolicy, values);
            replace_ava(&mut entry, Attribute::Name, Value::new_iname(name));
            commit_provider(idms, entry)
                .await
                .expect("a manual link policy must be accepted");

            let idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
            assert_eq!(
                idms_prox_write
                    .oauth2_client_providers
                    .get(&uuid)
                    .map(|p| p.link_policy),
                Some(AccountLinkPolicy::Manual)
            );
        }
    }

    /// Kubidm: OIDC auto discovery and IdP initiated login are not implemented, so
    /// enabling them is rejected. Explicitly disabling them is fine.
    #[idm_test]
    async fn test_idm_oauth2_federation_unimplemented_features(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        for attr in [
            Attribute::OAuth2AutoDiscovery,
            Attribute::OAuth2IdpInitiatedEnabled,
        ] {
            let entry = federation_entry_with(Uuid::new_v4(), &attr, vec![Value::Bool(true)]);
            assert_eq!(
                commit_provider(idms, entry).await,
                Err(OperationError::InvalidValueState),
                "{attr}=true must be rejected"
            );

            let mut entry = federation_entry_with(Uuid::new_v4(), &attr, vec![Value::Bool(false)]);
            replace_ava(
                &mut entry,
                Attribute::Name,
                Value::new_iname(&format!("{attr}_off")),
            );
            commit_provider(idms, entry)
                .await
                .unwrap_or_else(|err| panic!("{attr}=false must be accepted: {err:?}"));
        }
    }

    /// Kubidm: the authorisation, token and introspection endpoints of a federation must
    /// use https, except on loopback, and must not carry credentials.
    #[idm_test]
    async fn test_idm_oauth2_federation_backchannel_https(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        for attr in [
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2TokenIntrospectEndpoint,
        ] {
            for url in [
                "http://idp.example.com/endpoint",
                "https://user:password@idp.example.com/endpoint",
                "https://user@idp.example.com/endpoint",
                "http://user:password@127.0.0.1/endpoint",
            ] {
                let entry = federation_entry_with(Uuid::new_v4(), &attr, vec![url_value(url)]);
                assert_eq!(
                    commit_provider(idms, entry).await,
                    Err(OperationError::InvalidValueState),
                    "{attr} {url} must be rejected"
                );
            }
        }

        // Loopback http is accepted, for the testkit and local development.
        let uuid = Uuid::new_v4();
        let mut entry = federation_entry(uuid, "loopback_federation");
        replace_ava(
            &mut entry,
            Attribute::OAuth2AuthorisationEndpoint,
            url_value("http://[::1]:8443/authorise"),
        );
        replace_ava(
            &mut entry,
            Attribute::OAuth2TokenEndpoint,
            url_value("http://localhost:8443/token"),
        );
        replace_ava(
            &mut entry,
            Attribute::OAuth2TokenIntrospectEndpoint,
            url_value("http://127.0.0.1:8443/introspect"),
        );
        commit_provider(idms, entry)
            .await
            .expect("loopback http endpoints must be accepted");
    }

    /// Kubidm: a federation without an introspection endpoint is rejected when it is
    /// created or modified, since every login through it would be denied. One already
    /// stored is skipped at startup.
    #[idm_test]
    async fn test_idm_oauth2_federation_requires_introspection(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let entry = federation_entry_with(
            Uuid::new_v4(),
            &Attribute::OAuth2TokenIntrospectEndpoint,
            vec![],
        );
        assert_eq!(
            commit_provider(idms, entry).await,
            Err(OperationError::InvalidValueState),
        );

        // Removing it from a valid federation is rejected too, and nothing changes.
        let ct = duration_from_epoch_now();
        let uuid = Uuid::new_v4();
        commit_provider(idms, federation_entry(uuid, "introspected_federation"))
            .await
            .expect("a federation with an introspection endpoint must be accepted");
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_modify_uuid(
                uuid,
                &ModifyList::new_purge(Attribute::OAuth2TokenIntrospectEndpoint),
            )
            .expect("the entry itself is schema valid");
        assert_eq!(
            idms_prox_write.commit(),
            Err(OperationError::InvalidValueState)
        );
        let idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(matches!(
            idms_prox_write
                .oauth2_client_providers
                .get(&uuid)
                .map(|p| &p.user_sub_verifier),
            Some(OAuth2SubjectVerifier::Rfc7662TokenIntrospection { .. })
        ));
    }

    #[qs_test]
    async fn test_idm_oauth2_federation_without_introspection_skipped_at_startup(
        server: &QueryServer,
    ) {
        let ct = duration_from_epoch_now();
        let good_uuid = Uuid::new_v4();
        let bad_uuid = Uuid::new_v4();

        let mut bad = federation_entry(bad_uuid, "unverified_federation");
        bad.remove_ava(&Attribute::OAuth2TokenIntrospectEndpoint);
        let mut qs_write = server.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![federation_entry(good_uuid, "good_federation"), bad])
            .expect("the entries are schema valid");
        qs_write.commit().expect("failed to commit");

        let (idms, _idms_delayed, _idms_audit) = IdmServer::new(
            server.clone(),
            &Url::parse("https://idm.example.com").unwrap(),
            true,
            ct,
        )
        .await
        .expect("a federation without introspection must not prevent startup");

        let idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(idms_prox_write
            .oauth2_client_providers
            .get(&good_uuid)
            .is_some());
        assert!(idms_prox_write
            .oauth2_client_providers
            .get(&bad_uuid)
            .is_none());
    }

    /// The federation only rules (introspection required, https authorisation endpoint)
    /// do not apply to an upstream `OAuth2Client` provider.
    #[idm_test]
    async fn test_idm_oauth2_client_upstream_rules_unchanged(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let uuid = Uuid::new_v4();
        let entry: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::OAuth2Client.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::Name, Value::new_iname("upstream_client")),
            (Attribute::OAuth2ClientId, Value::new_utf8s("client_id")),
            (Attribute::OAuth2ClientSecret, Value::new_utf8s("secret")),
            (
                Attribute::OAuth2AuthorisationEndpoint,
                url_value("http://idp.example.com/authorise")
            ),
            (
                Attribute::OAuth2TokenEndpoint,
                url_value("https://idp.example.com/token")
            ),
            (
                Attribute::OAuth2RequestScopes,
                Value::new_oauthscope("openid").unwrap()
            )
        );
        commit_provider(idms, entry)
            .await
            .expect("an upstream OAuth2Client provider must be accepted");

        let idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
        assert!(matches!(
            idms_prox_write
                .oauth2_client_providers
                .get(&uuid)
                .map(|p| &p.user_sub_verifier),
            Some(OAuth2SubjectVerifier::None)
        ));
    }

    #[test]
    fn test_require_secure_endpoint_url() {
        let check =
            |url: &str| require_secure_endpoint_url(Uuid::nil(), "test", &Url::parse(url).unwrap());

        for good in [
            "https://idp.example.com/token",
            "https://127.0.0.1/token",
            "http://localhost/token",
            "http://LOCALHOST:8080/token",
            "http://127.0.0.1:8080/token",
            "http://127.1.2.3/token",
            "http://[::1]:8080/token",
        ] {
            assert!(check(good).is_ok(), "{good} must be accepted");
        }

        for bad in [
            "http://idp.example.com/token",
            "http://10.0.0.1/token",
            "http://[::2]/token",
            "http://localhost.example.com/token",
            "http://0.0.0.0/token",
            "ftp://localhost/token",
            "https://user:password@idp.example.com/token",
            "https://user@idp.example.com/token",
            "https://:password@idp.example.com/token",
            "http://user:password@localhost/token",
        ] {
            assert_eq!(
                check(bad),
                Err(OperationError::InvalidValueState),
                "{bad} must be rejected"
            );
        }
    }
}
