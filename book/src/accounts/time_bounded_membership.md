# Temporary Group Membership

A group can hold _temporary_ (time-bounded) memberships. A temporary membership makes an entry a member of the group
from a start time (or immediately) until an end time, after which the membership is removed again without anyone having
to remember to do it. This suits break-glass access, on-call rotations, and access for contractors or audits.

## The Model

- A group must first be enabled for temporary memberships, which adds the `time_bounded_grant` class to it.
- Each temporary membership is a _grant_ of `(member, valid_from, valid_until)`. The member may be a person, a group or
  a service account. A member has at most one grant per group: a new grant replaces the existing one.
- While a grant is valid the member is shown in `memberof` like any other member, including through nested groups. A
  temporary membership and a permanent one (through `member`) can coexist: when the grant ends, the permanent membership
  stays.
- `valid_until` is exclusive and must be in the future. When `valid_from` is absent, the grant starts immediately.
- When a member is deleted, its grants are removed.

## Who Can Grant

Granting, revoking and listing temporary memberships of a group are allowed to whoever may change (or, for listing,
read) the members of the group under the normal access controls. For example, the entry managers of a group can grant
temporary memberships of it, as can members of `idm_group_admins` for groups that are not high privilege. Replacing a
grant that is active or has not started yet also needs the right to remove members, since it takes that grant away;
replacing an expired grant only needs the right to add members.

Anyone who may read the members of a group can also list its temporary memberships, including their start and end times.

Temporary memberships of high privilege groups (`idm_high_privilege` and the groups that are members of it, directly or
through nesting) are refused, even when the group was enabled before it became high privilege.

A group can become high privilege after grants were written on it, for example when it is nested into a high privilege
group. Its grants then do **not** make their members members of the group while it is high privilege, including grants
that were already active and grants that start later: they are listed with the state `suppressed`. They can still be
listed and revoked. If the group stops being high privilege, the grants that have not ended apply again.

Enabling temporary memberships and setting the maximum grant duration is allowed to members of `idm_group_admins`, for
groups that are not high privilege. The entry managers of a group can not change its maximum grant duration.

## Maximum Grant Duration

A grant may cover at most the group's maximum grant duration (the `max_grant_duration` attribute, in seconds), counted
from the later of now and `valid_from` until `valid_until`. When the group does not set one, a default cap of 90 days
applies. Grants that would exceed the cap are rejected. A grant may also start at most that long from now, so that a
grant can not be scheduled to begin long after the person who granted it has lost the right to do so. Setting the
maximum on an existing group does not change the grants it already holds.

Setting a maximum of 0 is rejected. Older versions accepted it, so a group may still hold a stored maximum of 0 (written
then, or replicated from such a version): it blocks all new grants on the group until it is changed to a positive number
of seconds or removed. The grants the group already holds are left as they are, and can be revoked.

## Refresh Lag

Grants are applied at once when they are written, revoked or replaced. A grant that _starts_ or _ends_ between writes is
applied by a periodic refresh, which runs every 10 minutes in release builds (the server's `PURGE_FREQUENCY`). So a
membership can start, or remain, up to 10 minutes after the time in its grant. Do not rely on the end time for access
that must stop at an exact moment: revoke it instead, which takes effect immediately.

## Commands

```bash
# Allow temporary memberships, with a maximum of 7 days per grant.
kubidm group enable-temporary demo_group --max 7d --name idm_admin

# Grant demo_user membership for 8 hours from now.
kubidm group grant-temporary demo_group demo_user --for 8h --name idm_admin

# Grant membership for a fixed window. --until and --from take RFC 3339 datetimes.
kubidm group grant-temporary demo_group demo_user \
    --from 2026-11-02T08:00:00Z --until 2026-11-02T18:00:00Z --name idm_admin

# Show the temporary memberships of the group, with the state of each one.
kubidm group list-temporary demo_group --name idm_admin

# Remove a temporary membership before it ends.
kubidm group revoke-temporary demo_group demo_user --name idm_admin
```

Durations for `--for` and `--max` are a number of seconds, or a number followed by `s`, `m`, `h`, `d` or `w`. `--for`
counts from `--from`, or from the current time of the machine running the command.

`list-temporary` shows the state of each grant at the time of the request, by the same rules that decide the membership:

| State        | Meaning                                                                                                 |
| ------------ | ------------------------------------------------------------------------------------------------------- |
| `active`     | Within its window: the member is a member of the group                                                  |
| `pending`    | `valid_from` is in the future                                                                           |
| `expired`    | `valid_until` is past                                                                                   |
| `suppressed` | Not ended, but grants nothing because the group is high privilege (see [Who Can Grant](#who-can-grant)) |

The membership itself follows a grant's start and end with the [refresh lag](#refresh-lag), so around those times the
state can be ahead of `memberof` by up to one refresh interval.

The same operations are available over HTTP as `POST`, `GET` and `DELETE` on `/v1/group/{id}/_time_bounded_member` (the
`DELETE` takes the member as `/v1/group/{id}/_time_bounded_member/{member}`). Each grant returned by `GET` has a `state`
field with one of the states above.
