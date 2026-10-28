# Approval Workflows

Approval workflows let a group of approvers authorise a sensitive operation before it is carried out. An approval policy
says who may approve and how many of them must agree; a request asks for approval of one operation on one entry;
approvers then approve or reject the request.

Approvals are opt-in. One operation can be gated today: adding a member to a high privilege group (see
[Gated operations](#gated-operations)). It is only gated while an enabled policy covers it; for every other operation
type a request records intent and collects decisions, but does not cause or block anything.

## Policies

Policies are managed by members of `idm_approval_admins` (by default the members of `idm_admins`), using a privileged
session.

```bash
kubidm approval policy create high_priv_grants \
  --operation-type privilege_grant \
  --approver <person uuid> --approver <group uuid> \
  --backup-approver <person uuid> --escalation-timeout 1800 \
  --pattern majority --timeout 3600
kubidm approval policy list
kubidm approval policy get high_priv_grants
kubidm approval policy disable high_priv_grants
kubidm approval policy enable high_priv_grants
kubidm approval policy delete high_priv_grants
```

- Every approver is one approver slot, naming a person or a group. A member of a group may fill that group's slot.
- `--pattern` is `any_one` (one slot), `majority` (more than half of the slots) or `all`.
- After the escalation timeout, backup approvers may fill slots that are still open.
- `--timeout` is the number of seconds before a request expires.
- The requester never counts as an approver of their own request.

## Requests

Any account with a read-write session may create a request. The requester is the logged in account.

```bash
kubidm approval request create --policy high_priv_grants --operation privilege_grant \
  --target <name or uuid> --details '{"group": "idm_admins"}'
```

- `--policy` is the policy the request is filed under. It must be enabled and cover the operation type.
- `--operation` is one of the operation types of the policy, such as `privilege_grant`.
- `--target` is the entry the operation applies to, as a name, spn or uuid. It must be an entry the requester may read:
  an entry they may not read is reported exactly like one that does not exist.
- `--details` is optional, a JSON object whose values are all strings.

The command prints the uuid of the new request. It fails with HTTP 404 if the policy or target does not exist, and with
HTTP 422 if the policy can never be satisfied for this requester, for example because there are too few approvers other
than the requester.

The approvers and pattern of the policy are copied onto the request when it is created, so later changes to the policy
do not alter a request that already exists.

## Decisions

Only people may decide, using a privileged session; service accounts and API tokens may not. A person may decide on a
request if they fill an approver slot of it.

```bash
kubidm approval request list --state pending
kubidm approval request get <request uuid>
kubidm approval request approve <request uuid> --comment "ok"
kubidm approval request reject <request uuid> --comment "no"
kubidm approval request cancel <request uuid>
```

Approval admins can list and read every request. A requester can read their own request with
`kubidm approval request get`, for example to see whether it was approved. For a `group_membership_high_privilege`
request, approval admins also see the member it would add: its name, its classes and, for a group, its number of direct
members, the nested members (direct and indirect) it had when the request was created (`approved_members`), and whether
those have changed since (`members_changed`).

A request moves from `pending` to `approved` once enough slots have approved, to `rejected` once the open slots can no
longer reach that, to `expired` once its timeout passes, or to `cancelled` when the requester (or an approval admin)
cancels it. An approved request that has been used to authorise an operation becomes `consumed` and can not be used
again.

Disabling a policy, with `kubidm approval policy disable` or the [break-glass](#break-glass), cancels its `pending` and
`approved` requests. Enabling it again does not bring them back: file new requests.

Operations on a request or policy in the wrong state (creating a request under a disabled policy or one that does not
cover the operation, deciding a request that is no longer pending or whose policy is disabled, filling a slot that has
already decided, cancelling a request that is no longer pending) fail with HTTP 409 and `AP0003ApprovalNotUsable`.

## Gated operations

### `group_membership_high_privilege`

A high privilege group is `idm_high_privilege` itself, or any group that is a direct or nested member of it (such as
`idm_admins`, `idm_people_admins` or `idm_approval_admins`, or a group of your own nested into one of them).

While at least one **enabled** policy covers `group_membership_high_privilege`, adding a member to a high privilege
group is refused, even to someone the access controls allow to add it, with HTTP 403 and the error
`AP0002ApprovalRequired`. This applies to every write path (`kubidm group add-members`, `group set-members`, SCIM, and
the raw modify API). Without such a policy nothing changes.

Also gated, because they add members too:

- reviving an entry from the recycle bin, which restores its direct memberships: it is refused if one of them is a high
  privilege group;
- a SCIM sync (for example from FreeIPA or LDAP) that adds a member to a synced group nested in a high privilege group:
  the whole sync is refused with `AP0002ApprovalRequired` until the group is no longer nested or the gate is turned off.

Not gated:

- removing members;
- writes made internally by the server (migrations, referential integrity, `memberof`);
- changes arriving by replication; the gate applies on the server where the change is made;
- members that a dynamic group gains because entries come to match its filter. A dynamic group that is already nested in
  a high privilege group (from before the gate was enabled) is therefore outside the gate: remove such nesting before
  relying on it. Creating or enabling a policy that covers `group_membership_high_privilege` logs a warning on the
  server for each dynamic group, or group owned by a sync agreement, that is nested in a high privilege group.

Time-bounded grants are not routed through approvals: they are refused on high privilege groups whether or not the gate
is enabled.

The flow:

1. An approval admin enables the gate by creating a policy that covers the operation:

   ```bash
   kubidm approval policy create high_priv_members \
     --operation-type group_membership_high_privilege \
     --approver <person or group uuid> --pattern any_one --timeout 86400
   ```

2. A direct add is now refused:

   ```bash
   kubidm group add-members idm_admins alice
   # refused: HTTP 403, AP0002ApprovalRequired
   ```

3. The person who wants to make the change files a request. The target is the group, and the details are exactly
   `{"member": "<uuid>"}`, the uuid of the entry to add:

   ```bash
   kubidm approval request create --policy high_priv_members \
     --operation group_membership_high_privilege \
     --target idm_admins --details '{"member": "<uuid of alice>"}'
   ```

   The target must be a high privilege group, and the details must have exactly that form, or the request is refused
   with HTTP 400. The member must exist, and must not be a dynamic group, an entry owned by a sync agreement, or a group
   containing either: their members are decided by a filter or by the sync connector, so approving them would hand
   control over high privilege membership to that filter or connector.

   When the member is a group, the server records its nested members (direct and indirect) on the request, in the
   operation details as `member_contents`, and shows them to the approvers. That is what is approved: the request can
   only be executed while the group still contains exactly these entries. Adding anyone to the group (or to a group
   nested in it) after the request was created makes the request unusable; file a new one.

4. The approvers decide, as for any request (`kubidm approval request approve <request uuid>`).

5. Once the request is approved, the requester executes it:

   ```bash
   kubidm approval request execute <request uuid>
   ```

   This adds the member and consumes the approval in a single transaction, so a request adds its member once; executing
   it again fails.

Execution rules:

- Only the requester may execute their request, with a privileged session.
- The requester must still be allowed to add members to the group by the access controls at the time of execution. An
  approval lifts the gate, it does not grant any rights.
- The server chooses the policy, not the requester: the request must have been filed under an enabled policy that covers
  `group_membership_high_privilege`. If several enabled policies cover it, a request under any one of them is accepted,
  so each of them is enough on its own: keep a single covering policy unless that is what you want. A request whose
  policy has since been disabled or deleted, or no longer covers the operation, can not be executed.
- The request must not have expired, and the approval is recounted when it is executed (see [Decisions](#decisions)).
- The target must still be a high privilege group, and the member must still exist and still meet the conditions above.
  A group member must still have exactly the nested members recorded when the request was created.

An execute that is refused because of the state of the request (not approved yet, already executed, expired, cancelled,
its policy disabled, its target or member changed, or the nested members of a group member changed) fails with HTTP 409
and `AP0003ApprovalNotUsable`; one made by someone other than the requester fails with HTTP 403.

If an enabled policy covering `group_membership_high_privilege` is malformed (for example edited by hand into an invalid
state), the gate stays on, but requests filed under it can not be executed: disable or delete it.

Creating or enabling a policy that covers an operation type another enabled policy already covers logs a warning on the
server, and `kubidm approval policy create` and `enable` print it.

### Break-glass

An approval admin can always turn the gate off, since managing approval policies is never gated:

```bash
kubidm approval policy disable high_priv_members
```

Direct adds work again as soon as no enabled policy covers the operation. Re-enable the policy afterwards.

This is not enough on its own. `idm_approval_admins` is itself a high privilege group, and so is `idm_admins`, which it
contains by default. Removing members is not gated, so the last approval admin can remove themselves (for example
`idm_admin` leaving `idm_admins`), after which no one may disable the policy and adding anyone back is gated.
`kubidmd recover-account` only resets credentials, so it does not help.

The break-glass is on the server: it disables policies through the admin socket of the running server, as the server
itself, with no approval admin needed:

```bash
# disable one policy
kubidmd approval-policy disable high_priv_members
# or every enabled policy
kubidmd approval-policy disable --all
```

It prints the policies it disabled, and cancels their pending and approved requests, as any disable does. Run it as a
user that can reach the admin socket (the same as for `kubidmd recover-account`); the server logs the uid of the
connecting user. With the gate off, have an approval admin re-enable the policy with `kubidm approval policy enable`
once the situation is resolved.

The break-glass only turns the gate off; it does not add anyone to a group. In particular `idm_admins` manages its own
members, so if its last member leaves it, no one can add members to it again, with or without approvals. Keep more than
one member in `idm_admins` (and in `idm_approval_admins`).
