# External Attributes (PIP)

A Policy Information Point (PIP) lets access control profiles depend on attributes that live outside of Kubidm, such as
the department in an HR system or a risk level from a security tool. A profile with a PIP condition only applies to a
receiver whose external attributes satisfy the condition.

PIP conditions are opt-in. Without `pip_config`, or without a profile that uses a PIP condition, nothing is fetched and
access decisions are unchanged.

## Sources

Sources are configured in the server configuration under `pip_config`. Each source has an `id`, which is used in
conditions as `pip:<id>:<attribute>`. Ids may only use ASCII letters, digits, `_`, `-` and `.`, and must be unique
(ignoring case).

```toml
[pip_config]
# The time budget for fetching the attributes of one request (default: 2000).
prefetch_timeout_ms = 1000

[[pip_config.sources]]
type = "http"
id = "hr"
base_url = "https://hr.example.com/api"
endpoint_path = "/employees/{username}"
auth = { type = "bearer", token = "..." }
timeout_secs = 1
cache_ttl_secs = 300
fallback_behavior = "deny"

[[pip_config.sources]]
type = "ldap"
id = "corp"
url = "ldaps://ldap.example.com"
base_dn = "ou=people,dc=example,dc=com"
bind_dn = "cn=kubidm,ou=services,dc=example,dc=com"
bind_password = "..."
search_filter = "(uid={username})"
attributes = ["employeeType"]
timeout_secs = 1
```

- An `http` source sends a request to `base_url` + `endpoint_path` and expects a JSON object: each key of the object is
  an attribute of the source. An `ldap` source searches for exactly one entry with `search_filter`, and each returned
  attribute (renamed by `attribute_mapping`, if set) is an attribute of the source.
- `endpoint_path` and `search_filter` may use `{uuid}`, `{username}` and `{email}`. They are taken from the
  authenticated account: its uuid, its `name`, and its primary `mail`. If the account has no value for a placeholder,
  the source has no answer for that request (see [Fail Closed](#fail-closed)).
- Substituted values can not change the request. In `endpoint_path` they are percent-encoded, so they can not add path
  segments, a query or a fragment, and the values `.` and `..` are refused. In `search_filter` they are placed into the
  already parsed filter, so characters such as `*`, `(` and `)` are matched literally; when the assertion value is a DN
  (for example `uid={username},ou=people,dc=example,dc=com` in a `member` assertion), the substituted value is also
  escaped as a DN value.
- Plain-text `http://` and `ldap://` sources are refused unless `tls.allow_insecure` is set, which is only meant for
  development.
- The server refuses to start when a source is invalid, rather than ignoring it. Set `enabled = false` under
  `pip_config` to turn the PIP off without removing its configuration.

## Conditions

A condition is set on an access control profile with the multi-valued attribute `acp_receiver_pip_condition`. Each value
has the form `pip:<source>:<attribute>=<value>`, and all values must hold: the account must have the external attribute,
and the attribute must contain the value. Source ids, attribute names and values are all compared ignoring case, so
`pip:hr:department=engineering` matches an attribute `Department` with the value `Engineering`. Several values for the
same attribute must all be present.

External values are compared as text: numbers and booleans use their plain form (`5`, `true`), and each element of a
list is a value of the attribute. JSON objects and `null` never match.

A malformed condition (for example, a missing `pip:` prefix, an empty value, or a source id with spaces) is rejected
when the profile is created or changed.

The condition is checked in addition to the receiver of the profile, so the account must still be a receiver (for
example, a member of the receiver group). It applies to every kind of profile (search, create, modify and delete) and to
the decisions of `/v1/authorize`.

## Fail Closed

A PIP condition is only satisfied by attributes that were fetched for this request. It is never satisfied when:

- no PIP is configured, or the source in the condition does not exist;
- the source fails or times out. With `fallback_behavior = "deny"` (the default) or `"ignore"` the source contributes no
  attributes. With `"usefallback"`, see below;
- the source has no answer for the request: it does not know the account (an HTTP `404`, or no LDAP entry), it rejects
  the request (any other HTTP `4xx`, including `408 Request Timeout` and `429 Too Many Requests`, which a user can
  provoke, for example by flooding requests until the source rate limits), the LDAP search matches more than one entry,
  or the request can not be built for the account (for example `{email}` for an account without `mail`). This is not a
  source failure, so `fallback_values` are never used for it;
- the account does not have the attribute, or not with that value;
- the request is not made by an authenticated account (anonymous, internal, synchronisation), or is made to an endpoint
  that does not fetch PIP attributes: the OAuth2 and OpenID Connect endpoints (authorisation, consent, token, userinfo
  and device authorisation), and LDAP operations other than search and compare.

A failure only affects the profiles with a PIP condition on that source. Every other profile still applies.

### `usefallback` Fails Open

With `fallback_behavior = "usefallback"`, while a source is down (unreachable, timing out, unhealthy, or answering with
a server error `5xx` or an unusable response), every account is given that source's `fallback_values` as if the source
had returned them. **A profile whose conditions match the fallback values then grants its access to all of its receivers
for as long as the source is down.** Only use it when the fallback values are safe to grant on, for example values that
no condition grants on, or that only narrow access. The fallback values are never used when the source works but has no
answer for an account (see above), and the server logs a warning at startup for every source that uses `usefallback`.

## Caching and Timeouts

For every request made by an authenticated account, while at least one enabled profile has a PIP condition, Kubidm
fetches the attributes that the conditions reference, from all sources at once, before the request is processed. The
access decisions themselves never wait on a source. A request without valid credentials never causes a fetch.

- Each source caches the attributes of an account for its own `cache_ttl_secs` (default 300 seconds, up to 1000 accounts
  per source). A change in the external system, including a revocation, can therefore take up to that long to be seen:
  lower `cache_ttl_secs` for attributes that revoke access. Failures are not cached.
- `prefetch_timeout_ms` (default 2000) bounds the time a request spends fetching attributes, across all sources. A
  source that has not answered in time contributes no attributes to that request, and this counts as a failure of the
  source.
- Each source's own `timeout_secs` (default 1) must not exceed `prefetch_timeout_ms`, otherwise the server refuses to
  start. With sources configured, `prefetch_timeout_ms` is therefore at least 1000.
- A source that keeps failing (`health_check.failure_threshold` consecutive failures, default 3, including timeouts) is
  marked unhealthy, and then only tried again every `health_check.interval_secs` (default 60 seconds). Until then,
  requests fail closed without waiting on it, so a hanging source does not slow every request down.

## LDAP

PIP conditions apply to LDAP searches and compares of a bound session (an account or an api token). The attributes are
fetched for each operation, in the same way as for HTTP requests. Operations without a bind run as anonymous, so PIP
conditions never match them.

## Downgrading

A Kubidm version without PIP support ignores `acp_receiver_pip_condition`, so a profile with a PIP condition applies to
all of its receivers, without the condition: **rolling back widens access.** Before downgrading to such a version,
disable (`acp_enable`) or delete every profile that has a PIP condition.

## Example

Members of `idm_access_control_admins` manage PIP conditions with a privileged session, through the built-in
`idm_acp_acp_manage`: they can read them, and add them to and remove them from access control profiles. Here, an
existing profile `acp_hr_engineering_read` lets the members of `hr_viewers` read the names and email addresses of
persons. Restrict it to the members that are active in the engineering department of the HR system, through the raw API:

```bash
curl -X POST https://idm.example.com/v1/raw/modify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data '{
    "filter": {"eq": ["name", "acp_hr_engineering_read"]},
    "modlist": {"mods": [
      {"present": ["acp_receiver_pip_condition", "pip:hr:department=engineering"]},
      {"present": ["acp_receiver_pip_condition", "pip:hr:active=true"]}
    ]}
  }'
```

To remove the conditions again, use the modification `{"purged": "acp_receiver_pip_condition"}`.

`idm_acp_acp_manage` does not grant the `access_control_receiver_group` and `access_control_target_scope` classes when
creating a profile (an inherited limitation), so a new profile with a receiver group and a target scope can not be
created in band; conditions can be set on the profiles that exist.

With the `hr` source above, a member of `hr_viewers` named `alice` is granted the access when
`https://hr.example.com/api/employees/alice` answers, for example, `{"department": "engineering", "active": true}`. If
the HR system answers `{"department": "sales", "active": true}`, is unreachable, or does not answer within the timeout,
`alice` does not get this access, and keeps any access granted by other profiles.
