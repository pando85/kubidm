# OAuth2 Federation (Upstream Identity Providers)

Kubidm can let an account log in through an upstream OAuth2 / OpenID Connect identity provider (IdP). Kubidm acts as a
confidential OAuth2 client of the IdP: it runs the authorisation code flow with PKCE and `state`, exchanges the code for
tokens, and then verifies the login in one of two ways:

- **OpenID Connect `id_token`**: the signed `id_token` of the token response is verified with the IdP's published keys
  (JWKS). This works with most IdPs (Google, Microsoft Entra ID, Okta, Keycloak, Kubidm).
- **[RFC 7662 token introspection](https://www.rfc-editor.org/rfc/rfc7662)** of the access token. Most public IdPs do
  not offer introspection to relying parties, but Keycloak and Kubidm do.

## The model

- **Admin linked accounts only.** Federation never creates or links accounts by itself. An administrator links an
  existing person to the IdP by recording which IdP subject it belongs to. An account that is not linked can not use the
  federation.
- **A verifier is required.** A federation must set `oauth2_jwks_uri` (to verify the `id_token`, see below), or
  `oauth2_token_introspect_endpoint` (to introspect the access token), or both. A federation with neither is rejected.
- **Explicit endpoints.** The authorisation and token endpoints (and the JWKS and introspection endpoints) must be
  configured explicitly. They are never derived from the issuer or discovered.
- **https.** The token and introspection endpoints receive the client secret and the access token, the JWKS decides
  which tokens are trusted, and users type their IdP password at the authorisation endpoint, so all of them must use
  `https`. Plain `http` is accepted only for loopback hosts (`localhost`, `127.0.0.0/8`, `::1`), for development and
  tests. Endpoint URLs must not contain credentials (`user:password@`).
- **Outbound requests.** Kubidm calls the token, introspection and JWKS endpoints itself. The system proxy settings
  (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) apply, except to loopback endpoints, which are always called
  directly. Redirects are never followed, requests time out after 10 seconds (5 seconds to connect), and responses
  larger than 64 KiB (after decompression) are rejected.
- **`oauth2_link_policy` is `manual` only.** It may be unset (meaning `manual`) or `manual`. The values `auto` and
  `admin_approval` are reserved and rejected, as is any other value.
- **Not implemented.** `oauth2_auto_discovery` and `oauth2_idp_initiated_enabled` must be unset or `false`. Setting
  either to `true` is rejected.

### Verifying the `id_token`

When `oauth2_jwks_uri` is set, the federation verifies the OpenID Connect `id_token`:

- Kubidm always requests the `openid` scope (in addition to `oauth2_request_scopes`) and sends a random `nonce`, bound
  to the login session.
- The token response must contain an `id_token`. Without one the login is denied.
- The signature is verified with a key from the JWKS at `oauth2_jwks_uri`. Only `RS256` (RSA keys of at least 2048 bits)
  and `ES256` (P-256) are accepted. `none`, `HS256` and every other algorithm are rejected. When the token header names
  a key (`kid`), only that key is used. Keys marked for encryption (`"use": "enc"`) or for another algorithm are never
  used, and keys or key URLs embedded in the token header are ignored. Keys of kinds Kubidm can not use (for example
  `OKP` or `P-384`) are skipped, but a JWKS with no usable key fails the login.
- The claims must all be valid: `iss` must be the configured `oauth2_issuer` (one trailing `/` is ignored), `aud` must
  contain the federation's client id (and with several audiences, `azp` must be the client id; `azp` is checked whenever
  it is present), `exp` must be in the future and `iat` (which is required) not in the future, `nbf` (if present) must
  have passed, `nonce` must be the nonce of the login session, and `sub` must be the subject linked to the account. A
  clock difference with the IdP of up to 60 seconds is allowed for `exp`, `iat` and `nbf`.
- Extra values in `aud` are accepted when `azp` is the federation's client id: the token was issued to Kubidm, and is
  also meant for other audiences.

The JWKS of each federation is cached for 10 minutes. If a token names a key that the cached JWKS does not have (the IdP
rotated its keys), the JWKS is fetched again once. If the key is still unknown, the login is denied. The JWKS of a
federation is never fetched more than once every 30 seconds, counting failed attempts, and logins at the same time share
one fetch, which completes even if the login that started it is abandoned.

If the cache has expired and the IdP is unavailable (it can not be reached, the request times out, or it answers with a
`5xx` status), the last JWKS is used (and a warning logged) for up to 1 hour. Any other answer of the IdP replaces the
cached JWKS and is never bridged: a JWKS that is empty or has no usable key, a `4xx` status, a redirect, or a body that
is not a JWKS denies every login until the IdP publishes a usable JWKS again. So when an IdP withdraws a key (for
example after a compromise), Kubidm stops accepting it as soon as its cached JWKS expires. Any other error (a bad
signature, an invalid claim) denies the login.

### Introspecting the access token

When `oauth2_token_introspect_endpoint` is set, Kubidm introspects the access token at the IdP. The login succeeds only
if the token is `active` and its `sub` is the subject linked to the account. When the response also carries these
fields, they must agree: `client_id` must be the federation's client id, `iss` must be the configured `oauth2_issuer` (a
trailing `/` is ignored), and `exp` must be in the future.

### Both

When both `oauth2_jwks_uri` and `oauth2_token_introspect_endpoint` are set, the `id_token` is verified first, and then
the access token is introspected. Both must pass. A federation that only had an introspection endpoint and gains a
`oauth2_jwks_uri` therefore also requires a valid `id_token` from then on.

### Invalid federations

An invalid federation is rejected when it is created or modified. A stored federation that is invalid (for example
written by an older version, or received through replication) is skipped and logged, and does not block other changes.

The same https and no credentials rules apply to the token and introspection endpoints of upstream `OAuth2Client`
providers. Such a provider that uses plain `http` on a host that is not loopback is now skipped at startup (and logged),
and changing one to such an endpoint is rejected. Use `https`, or a loopback address.

### `localhost`

`localhost` is accepted as a loopback host so that a development IdP on the same machine works. Kubidm's own requests
never resolve it through DNS: it is always `127.0.0.1` or `::1`. The authorisation endpoint, however, is opened by the
user's browser, which resolves `localhost` itself (on the user's machine). Prefer an IP literal (`127.0.0.1`, `[::1]`)
when testing, and `https` everywhere else.

## Security considerations

- **Federation administrators can log in as linked accounts.** Members of `idm_oauth2_client_admins` can change a
  federation's endpoints. Pointing them at an IdP they control lets them answer introspection with any subject, and so
  log in as any account linked to that federation. A federation session is read-only, but it can read everything the
  account can read. Treat `idm_oauth2_client_admins` as at least as trusted as the accounts linked to its federations.
- **Federation administrators can also replace the JWKS.** Pointing `oauth2_jwks_uri` at keys they control lets them
  sign an `id_token` for any subject, with the same effect.
- **The IdP is trusted for the linked accounts.** Anyone who can obtain an access token (or an `id_token` for this
  client) for a linked subject from the IdP can log in as the linked account.

## Attributes

| Attribute                          | Required | Meaning                                          |
| ---------------------------------- | -------- | ------------------------------------------------ |
| `name`                             | yes      | Name of the federation                           |
| `oauth2_client_id`                 | yes      | Client id registered at the IdP                  |
| `oauth2_client_secret`             | yes      | Client secret registered at the IdP              |
| `oauth2_issuer`                    | yes      | Issuer of the IdP                                |
| `oauth2_authorisation_endpoint`    | yes      | Authorisation endpoint (https, or loopback http) |
| `oauth2_token_endpoint`            | yes      | Token endpoint (https, or loopback http)         |
| `oauth2_jwks_uri`                  | see (1)  | JWKS of the IdP (https, or loopback http)        |
| `oauth2_token_introspect_endpoint` | see (1)  | Introspection endpoint (https, or loopback http) |
| `oauth2_request_scopes`            | no       | Scopes requested from the IdP                    |
| `oauth2_link_policy`               | no       | `manual` only                                    |
| `description`                      | no       | Free text                                        |

(1) At least one of `oauth2_jwks_uri` and `oauth2_token_introspect_endpoint` is required. See [The model](#the-model).

The client secret is readable by federation administrators (members of `idm_oauth2_client_admins`). See
[Security considerations](#security-considerations).

The redirect URL to register at the IdP is `https://<your kubidm origin>/ui/login/oauth2_landing`.

### Reserved attributes

These attributes are stored but not used by the login flow. They are reserved for future features:

- `oauth2_email_domain`
- `oauth2_display_name`
- `oauth2_userinfo_endpoint`
- `oauth2_federation_id`

## Linking an account

A member of `idm_oauth2_account_admins` links a person by adding the `oauth2_account` class and these attributes:

| Attribute                        | Value                                                                  |
| -------------------------------- | ---------------------------------------------------------------------- |
| `oauth2_account_provider`        | The federation                                                         |
| `oauth2_account_unique_user_id`  | The user's login name at the IdP (sent as `login_hint`)                |
| `oauth2_account_unique_user_sub` | The user's subject at the IdP (`sub` of the id_token or introspection) |
| `oauth2_account_credential_uuid` | A new random UUID                                                      |

The link is required with both verifiers: Kubidm never links an account from the claims of an `id_token` (for example
its `email`). A valid `id_token` for a subject that is not the one linked to the account logging in is denied.

## API

Federations are managed under `/v1/federation/oauth2`:

| Method   | Path                           | Action              |
| -------- | ------------------------------ | ------------------- |
| `GET`    | `/v1/federation/oauth2`        | List federations    |
| `POST`   | `/v1/federation/oauth2`        | Create a federation |
| `GET`    | `/v1/federation/oauth2/{name}` | Get a federation    |
| `PATCH`  | `/v1/federation/oauth2/{name}` | Modify a federation |
| `DELETE` | `/v1/federation/oauth2/{name}` | Delete a federation |

`/v1/oauth2/{name}` always refers to an OAuth2 resource server, including one named `federation`.

For example, to create a federation that verifies the `id_token` (Google):

```bash
curl -X POST "https://idm.example.com/v1/federation/oauth2" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"attrs": {
    "name": ["google"],
    "oauth2_client_id": ["....apps.googleusercontent.com"],
    "oauth2_client_secret": ["..."],
    "oauth2_issuer": ["https://accounts.google.com"],
    "oauth2_authorisation_endpoint": ["https://accounts.google.com/o/oauth2/v2/auth"],
    "oauth2_token_endpoint": ["https://oauth2.googleapis.com/token"],
    "oauth2_jwks_uri": ["https://www.googleapis.com/oauth2/v3/certs"]
  }}'
```

The issuer and endpoints of an IdP are listed in its discovery document, at `<issuer>/.well-known/openid-configuration`.
Kubidm does not read it, so copy `issuer`, `authorization_endpoint`, `token_endpoint` and `jwks_uri` from it.

Or to create a federation that uses introspection (Keycloak):

```bash
curl -X POST "https://idm.example.com/v1/federation/oauth2" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"attrs": {
    "name": ["corporate_idp"],
    "oauth2_client_id": ["kubidm"],
    "oauth2_client_secret": ["..."],
    "oauth2_issuer": ["https://idp.example.com/realms/main"],
    "oauth2_authorisation_endpoint": ["https://idp.example.com/realms/main/protocol/openid-connect/auth"],
    "oauth2_token_endpoint": ["https://idp.example.com/realms/main/protocol/openid-connect/token"],
    "oauth2_token_introspect_endpoint": ["https://idp.example.com/realms/main/protocol/openid-connect/token/introspect"],
    "oauth2_request_scopes": ["openid"]
  }}'
```

## IdP compatibility

The `id_token` claims are parsed leniently too: `aud` may be a string or an array, and unknown claims are ignored.

The introspection response is parsed as [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) describes it: only `active`
is required, and an inactive token may be just `{"active": false}`. `sub` is required for a login to succeed. `aud` may
be a string or an array, `jti` may be any string, `scope` may be absent, and unknown fields are ignored. This works with
Keycloak (which returns `aud` as an array and many extra fields) and with Kubidm itself as the IdP.
