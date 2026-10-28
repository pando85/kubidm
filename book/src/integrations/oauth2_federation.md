# OAuth2 Federation (Upstream Identity Providers)

Kubidm can let an account log in through an upstream OAuth2 / OpenID Connect identity provider (IdP). Kubidm acts as a
confidential OAuth2 client of the IdP: it runs the authorisation code flow with PKCE and `state`, exchanges the code for
an access token, and then verifies the token with
[RFC 7662 token introspection](https://www.rfc-editor.org/rfc/rfc7662).

## The model

- **Admin linked accounts only.** Federation never creates or links accounts by itself. An administrator links an
  existing person to the IdP by recording which IdP subject it belongs to. An account that is not linked can not use the
  federation.
- **Introspection is required.** After the code exchange, Kubidm introspects the access token at the IdP. The login
  succeeds only if the token is `active` and its `sub` is the subject linked to the account. When the response also
  carries these fields, they must agree: `client_id` must be the federation's client id, `iss` must be the configured
  `oauth2_issuer` (a trailing `/` is ignored), and `exp` must be in the future. A federation without an introspection
  endpoint is rejected.
- **Explicit endpoints.** The authorisation, token and introspection endpoints must be configured explicitly. They are
  never derived from the issuer. A federation without an authorisation, token or introspection endpoint is rejected.
- **https.** The token and introspection endpoints receive the client secret and the access token, and users type their
  IdP password at the authorisation endpoint, so all three must use `https`. Plain `http` is accepted only for loopback
  hosts (`localhost`, `127.0.0.0/8`, `::1`), for development and tests. Endpoint URLs must not contain credentials
  (`user:password@`).
- **Outbound requests.** Kubidm calls the token and introspection endpoints itself. The system proxy settings
  (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) apply, except to loopback endpoints, which are always called
  directly. Redirects are never followed, requests time out after 10 seconds (5 seconds to connect), and responses
  larger than 64 KiB (after decompression) are rejected.
- **`oauth2_link_policy` is `manual` only.** It may be unset (meaning `manual`) or `manual`. The values `auto` and
  `admin_approval` are reserved and rejected, as is any other value.
- **Not implemented.** `oauth2_auto_discovery` and `oauth2_idp_initiated_enabled` must be unset or `false`. Setting
  either to `true` is rejected.

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
- **The IdP is trusted for the linked accounts.** Anyone who can obtain an access token for a linked subject from the
  IdP can log in as the linked account.

## Attributes

| Attribute                          | Required | Meaning                                          |
| ---------------------------------- | -------- | ------------------------------------------------ |
| `name`                             | yes      | Name of the federation                           |
| `oauth2_client_id`                 | yes      | Client id registered at the IdP                  |
| `oauth2_client_secret`             | yes      | Client secret registered at the IdP              |
| `oauth2_issuer`                    | yes      | Issuer of the IdP                                |
| `oauth2_authorisation_endpoint`    | yes      | Authorisation endpoint (https, or loopback http) |
| `oauth2_token_endpoint`            | yes      | Token endpoint (https, or loopback http)         |
| `oauth2_token_introspect_endpoint` | yes      | Introspection endpoint (https, or loopback http) |
| `oauth2_request_scopes`            | no       | Scopes requested from the IdP                    |
| `oauth2_link_policy`               | no       | `manual` only                                    |
| `description`                      | no       | Free text                                        |

The client secret is readable by federation administrators (members of `idm_oauth2_client_admins`). See
[Security considerations](#security-considerations).

The redirect URL to register at the IdP is `https://<your kubidm origin>/ui/login/oauth2_landing`.

### Reserved attributes

These attributes are stored but not used by the login flow. They are reserved for future features:

- `oauth2_email_domain`
- `oauth2_display_name`
- `oauth2_jwks_uri`
- `oauth2_userinfo_endpoint`
- `oauth2_federation_id`

## Linking an account

A member of `idm_oauth2_account_admins` links a person by adding the `oauth2_account` class and these attributes:

| Attribute                        | Value                                                       |
| -------------------------------- | ----------------------------------------------------------- |
| `oauth2_account_provider`        | The federation                                              |
| `oauth2_account_unique_user_id`  | The user's login name at the IdP (sent as `login_hint`)     |
| `oauth2_account_unique_user_sub` | The user's subject at the IdP, as returned by introspection |
| `oauth2_account_credential_uuid` | A new random UUID                                           |

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

For example, to create a federation:

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

The introspection response is parsed as [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) describes it: only `active`
is required, and an inactive token may be just `{"active": false}`. `sub` is required for a login to succeed. `aud` may
be a string or an array, `jti` may be any string, `scope` may be absent, and unknown fields are ignored. This works with
Keycloak (which returns `aud` as an array and many extra fields) and with Kubidm itself as the IdP.
