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
  succeeds only if the token is `active` and its `sub` is the subject linked to the account. A federation without an
  introspection endpoint loads, but every login through it is denied.
- **Explicit endpoints.** The authorisation, token and introspection endpoints must be configured explicitly. They are
  never derived from the issuer. A federation without an authorisation or token endpoint is rejected.
- **https.** The token and introspection endpoints receive the client secret and the access token, so they must use
  `https`. Plain `http` is accepted only for loopback hosts (`localhost`, `127.0.0.0/8`, `::1`). Redirects from these
  endpoints are never followed, requests time out after 10 seconds (5 seconds to connect), and responses larger than 64
  KiB are rejected.
- **`oauth2_link_policy` is `manual` only.** It may be unset (meaning `manual`) or `manual`. The values `auto` and
  `admin_approval` are reserved and rejected, as is any other value.
- **Not implemented.** `oauth2_auto_discovery` and `oauth2_idp_initiated_enabled` must be unset or `false`. Setting
  either to `true` is rejected.

An invalid federation is rejected when it is created or modified. A stored federation that is invalid (for example
written by an older version, or received through replication) is skipped and logged, and does not block other changes.

## Attributes

| Attribute                          | Required  | Meaning                                          |
| ---------------------------------- | --------- | ------------------------------------------------ |
| `name`                             | yes       | Name of the federation                           |
| `oauth2_client_id`                 | yes       | Client id registered at the IdP                  |
| `oauth2_client_secret`             | yes       | Client secret registered at the IdP              |
| `oauth2_issuer`                    | yes       | Issuer of the IdP                                |
| `oauth2_authorisation_endpoint`    | yes       | Authorisation endpoint (browser redirect)        |
| `oauth2_token_endpoint`            | yes       | Token endpoint (https, or loopback http)         |
| `oauth2_token_introspect_endpoint` | for login | Introspection endpoint (https, or loopback http) |
| `oauth2_request_scopes`            | no        | Scopes requested from the IdP                    |
| `oauth2_link_policy`               | no        | `manual` only                                    |
| `description`                      | no        | Free text                                        |

The client secret is readable by federation administrators (members of `idm_oauth2_client_admins`).

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

## Limitations

The introspection response must include the `scope` and `jti` fields, in addition to `active` and `sub`.
