# Approval Workflows

Approval workflows let a group of approvers authorise a sensitive operation before it is carried out. An approval policy
says who may approve and how many of them must agree; a request asks for approval of one operation on one entry;
approvers then approve or reject the request.

> [!WARNING]
>
> No operation is gated on approvals yet. Creating a request currently records intent and collects decisions only: an
> approved request does not cause anything to happen, and an operation is not blocked when it has no approved request.
> Server operations that need approval will check for an approved request under a policy they choose themselves.

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

A request moves from `pending` to `approved` once enough slots have approved, to `rejected` once the open slots can no
longer reach that, to `expired` once its timeout passes, or to `cancelled` when the requester (or an approval admin)
cancels it. An approved request that has been used to authorise an operation becomes `consumed` and can not be used
again.
