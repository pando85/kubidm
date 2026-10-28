# Delegated Administration

Delegated administration lets the members of one group (the _receivers_) administer the members of another group (the
_scope_), with a fixed set of rights chosen from a built-in _template_. For example, the members of `helpdesk_emea` may
reset the credentials of the members of `staff_emea`, and of nobody else.

Delegations are granted from templates only. The server builds the access control profile that implements a delegation
from the template, checks it, and creates it: administrators never write the profile themselves, and can not change what
a template grants.

## Who Can Grant Delegations

Delegations are granted, listed and revoked by members of `idm_access_control_admins` (by default the members of
`system_admins`), the group that already administers access control profiles. Granting and revoking need a privileged
(read-write) session. `idm_access_control_admins` is a member of `idm_high_privilege`, so the people who grant a
delegation can never be its targets.

Members of `idm_access_control_admins` can also read the templates, which are the `delegated_role` entries
`idm_delegated_helpdesk`, `idm_delegated_user_admin` and `idm_delegated_group_admin`.

## Templates

Every template applies only to the targets in its scope (see below), and only grants the rights listed here.

| template      | targets | read                                                                                                                                                                                | modify                                                                                                                   | delete |
| ------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------ |
| `helpdesk`    | persons | `class`, `name`, `spn`, `uuid`, `displayname`, `memberof`, `account_expire`, `account_valid_from`, `primary_credential`, `passkeys`, `attested_passkeys`, `account_softlock_expire` | `primary_credential`, `passkeys`, `attested_passkeys`, `account_expire`, `account_valid_from`, `account_softlock_expire` | no     |
| `user_admin`  | persons | `class`, `name`, `spn`, `uuid`, `displayname`, `legalname`, `mail`, `memberof`, `account_expire`, `account_valid_from`                                                              | `displayname`, `legalname`, `account_expire`, `account_valid_from`                                                       | yes    |
| `group_admin` | groups  | `class`, `name`, `uuid`, `spn`, `description`, `mail`, `member`, `memberof`, `dynmember`, `entry_managed_by`                                                                        | nothing (read only)                                                                                                      | no     |

- `helpdesk` grants what `idm_service_desk` has over persons: the receivers can find the persons in scope and reset
  their credentials (`kubidm person credential create-reset-token`), and lock or unlock their accounts.
- `user_admin` manages the profile of the persons in scope and can delete them. It does not include credential resets:
  grant `helpdesk` as well for those. It can not rename them, since that changes how they log in, and it can read but
  **not change their mail address**. The mail address is effectively a credential: Kubidm sends account recovery links
  to it, and OAuth2 clients receive it as a verified address, so whoever can change it can take over the account.
- `group_admin` is **read only**: the receivers can find the groups in scope and see their members. Managing members is
  not delegated, see the warning below.

> [!WARNING]
>
> A member added to a group in the scope becomes a nested member of the scope group, and so a target of every delegation
> over that scope. Delegating member management would let the receivers pull any entry into their scope: the receiver
> group of another delegation (taking over its administrators and their rights), OAuth2 scope map groups, POSIX and sudo
> groups, or their own receiver group. Doing it safely needs a constraint on the values that may be added, which access
> controls can not express yet, so `group_admin` does not grant it. Group membership is managed by `idm_group_admins` or
> a group's entry managers.

No template can create entries. A new entry is not a member of any group yet, so it is never in a scope: a create right
could never be used. Persons and groups are created by `idm_people_admins`, `idm_people_on_boarding` or
`idm_group_admins`, and enter a scope once they are added to the scope group.

## Scope

The targets of a delegation are the entries that are:

- members of the scope group, directly or through nested groups,
- of the template's kind (persons for `helpdesk` and `user_admin`, groups for `group_admin`),
- matching the optional scope filter given when granting, and
- **not** high privilege (members of `idm_high_privilege`, directly or nested), recycled or deleted, and
- **not** a receiver of this or any other delegation (see below), and
- **not** one of the privileged built-in groups `idm_account_mail_read`, `idm_unix_authentication_read`,
  `idm_mail_servers` or `idm_people_self_mail_write`, nor a member of one of them.

The filter can only narrow the scope: a target always is a member of the scope group, and never high privilege or a
receiver, whatever the filter says. A filter that does not match the schema is refused, and so is a filter that uses
`self` or refers to an entry that does not exist. References to entries in the filter (for example
`{"andnot":{"eq":["memberof","contractors"]}}`) are stored as the UUID of the entry when the delegation is granted, so
renaming `contractors`, or giving its name to another group, never changes the scope.

High privilege accounts are never targets. A member of the scope group who is also a member of `idm_high_privilege` (for
example an administrator) can not be administered through any delegation, in the same way that `idm_service_desk` can
not reset the credentials of administrators.

The receiver group and the scope group must be groups that are:

- not high privilege: neither `idm_high_privilege` nor nested in it;
- not built-in: groups such as `idm_all_persons` or `idm_all_accounts` would make everybody a receiver or a target;
- not the same group, and the receiver group can not be nested in the scope group;
- the scope group can not be the receiver group of any delegation, nor nested in one (its members are never targets);
- neither group, nor any group nested in them, can be a dynamic group: its members follow a filter on attributes that a
  delegation may be able to write;
- neither group, nor any group nested in them, can have an entry manager (`entry_managed_by`) that is not high privilege
  (see below).

Membership of the scope group decides who is administered, so whoever can change it extends the delegation. Keep the
scope group (and the groups nested in it) managed by people you trust with what the delegations over it grant.

> [!WARNING]
>
> The entry managers of a group can change its members, so the entry managers of the scope group, of a group nested in
> it, or of the receiver group **bypass the scope**: they can add anyone to it (and then administer them), or add
> themselves to the receivers. A grant is refused while any of these groups has an entry manager that is not high
> privilege, and an entry manager set after the grant is reported under `drift`. Do not set entry managers on these
> groups.

Taking over a person through `helpdesk` means taking over everything that person can do, including the sudo, POSIX and
OAuth2 scope map groups they are a member of: only grant `helpdesk` over persons whose rights the receivers may hold.
`user_admin` can set and clear `account_expire` and `account_valid_from`, so it can re-enable an expired account in its
scope.

### Receivers Are Never Targets

The receivers of a delegation are never its targets, even if their group is nested into the scope group after the
delegation was granted. The receivers of a delegation are not the targets of any other delegation either: whenever the
access controls are loaded, the server collects the receiver groups of all delegations, and excludes them and their
members from every delegated scope. This set is derived from the delegations themselves, so it follows every grant and
revoke (including on other replicas) without anything to maintain.

## Granting, Listing and Revoking

```bash
kubidm login --name admin

# Members of helpdesk_emea may reset the credentials of the persons in staff_emea.
kubidm delegation grant --template helpdesk --receiver helpdesk_emea --scope staff_emea

# Members of hr_emea manage the persons in staff_emea that have a mail address.
kubidm delegation grant --template user_admin --receiver hr_emea --scope staff_emea \
  --filter '{"pres":"mail"}'

kubidm delegation list
kubidm delegation get delegation_helpdesk_9f2c4e1a5b7d3c08_1a2b3c4d5e6f7a8b
kubidm delegation revoke delegation_helpdesk_9f2c4e1a5b7d3c08_1a2b3c4d5e6f7a8b
```

The receiver and the scope are group names, SPNs or UUIDs. The `--filter` is a JSON filter, as used by `kubidm raw`.

A delegation is named `delegation_<template>_<scope>_<receiver>`, where `<scope>` and `<receiver>` are the last 16 hex
digits of the UUIDs of the groups, so that a name never depends on group names that may change. `kubidm delegation list`
shows the groups by name. The same template can be granted once for a receiver and a scope: to change the filter, revoke
the delegation and grant it again. Revoking takes the name or the UUID of the delegation.

`list` and `get` show every receiver group of a delegation and, under `drift`, any way in which its access control
profile differs from what its template grants (for example a delegation granted by an older version of a template), and
any entry manager or dynamic group that would refuse the grant now. Whatever is stored, a delegation only ever grants
what its template grants: its attributes, classes and target kinds are rebuilt from the template when the access
controls are loaded. Revoke and grant such a delegation again to bring it in line with its template.

The same operations are available over HTTP:

| method   | path                  | operation                                  |
| -------- | --------------------- | ------------------------------------------ |
| `GET`    | `/v1/delegation`      | list the delegations                       |
| `POST`   | `/v1/delegation`      | grant a delegation, returns the delegation |
| `GET`    | `/v1/delegation/{id}` | get a delegation by name or UUID           |
| `DELETE` | `/v1/delegation/{id}` | revoke a delegation by name or UUID        |

## Deleting Groups

The scope group and the receiver group of a delegation can not be deleted while the delegation exists: the delete is
refused, because it would leave the delegation's access control profile invalid. Revoke the delegation first, then
delete the group.

If the delete of a scope group arrives through replication, the delegation is not widened: its access control profile is
skipped, and grants nothing, until it is revoked.

## Under the Hood

A delegation is one access control profile with the classes `access_control_receiver_group` and
`access_control_target_delegated_scope`. It records the scope group (`delegated_scope_group`), the template's class
terms and the filter (`delegated_scope_filter`), the template (`delegated_role_template`) and who granted it
(`delegated_by`). When access controls are loaded, its target becomes

```text
memberof=<scope> AND <template classes> AND <filter> AND NOT (
  memberof=idm_high_privilege OR recycled OR tombstone
  OR uuid=<R> OR memberof=<R>  (for every receiver group R of any delegation)
  OR uuid=<B> OR memberof=<B>  (for every excluded privileged built-in group B)
)
```

The profile can not be created, changed or deleted through the generic access control operations: they do not allow the
delegation attributes, and `idm_acp_acp_manage` does not target profiles with the
`access_control_target_delegated_scope` class. Delegations are only granted and revoked as described above.
