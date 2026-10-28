# Maintenance Control Protocol

This document is the operator-facing protocol reference for the implementation described in
[Node Drain, Replication Fences, and Maintenance Control Plane](node_drain_replication_fences_maintenance.md).

## Read-only HTTP surface

`GET /maintenance` returns the node-local maintenance state and capability set. It is unauthenticated and intended for
capability discovery, so it deliberately omits the active operation ID and last error; those are only returned by the
privileged `MaintenanceStatus` admin socket request. `GET /readyz` remains the normal serving-readiness endpoint and
returns `503` whenever maintenance state is not `serving`; its message names the maintenance state but not the operation
ID.

Neither endpoint mutates directory or database state.

## Privileged local control surface

Mutating operations use the existing Unix admin socket, protected by its root/server-UID peer-credential check. The
version-1 request set is:

- `MaintenanceCapabilities`
- `MaintenanceStatus`
- `MaintenanceDrain { operation_id }`
- `MaintenanceRun { operation_id, operation }`
- `ReplicationFence`
- `ReplicationSyncUntil { operation_id, fence, timeout_seconds }`
- `MaintenanceResume { operation_id }`

The `kubidmd maintenance` command sends these requests, see
[Draining a Node for Maintenance](../../integrations/kubernetes_probes.md#draining-a-node-for-maintenance).

Supported native maintenance operations are `reindex` and `verify`. `vacuum` and `restore` are intentionally reported as
unsupported because they require stronger backend/recovery lifecycle semantics.

## Concurrency and failure semantics

Steps of one operation are serialized. While a drain, run, sync-until or resume of the active operation is still
executing, every other step for it, including a retry of the same drain and a resume, returns a `busy` error. A `busy`
error never changes any state and is always safe to retry: repeat the same request, with the same operation ID, until
the step in progress has completed. A completed drain is idempotent: repeating it with the same operation ID returns the
fence it captured.

A drain that fails before it fenced anything, on a node that had no active operation, rolls the node back to `serving`
and clears the operation, so writes are not left gated. The operation counts as resumed: resuming it afterwards is an
idempotent success. A failed drain retry or re-fence of an operation that was already in progress leaves the node
`failed`; retry the drain to fence it again, or resume the operation. If a step stops before recording its outcome (for
example its handler panics), the node becomes `failed` in the same way and is recovered by a drain retry or a resume.

`ReplicationSyncUntil` waits at most `timeout_seconds` (60 when omitted), bounded to between 1 second and 1 hour per
request. Repeat the request to wait longer.

Orchestrators must read the active operation ID and the last error from `MaintenanceStatus` on the admin socket. The
unauthenticated HTTP endpoints do not expose them.

## Rolling handoff

For replicas A and B, the safe maintenance sequence for B is:

1. drain B and persist the returned fence `F_B`;
2. require A to satisfy `F_B`;
3. run the maintenance operation on B;
4. capture a fresh fence `F_A` from A;
5. require B to satisfy `F_A` while B remains non-serving;
6. resume B only after fence satisfaction succeeds.

The fence is replication state, not wall-clock time and not Kubernetes readiness. Domain or replication-generation
mismatches are hard failures.

## Transport stability

The Unix admin transport is the initial privileged control path. The maintenance semantics and request/result model are
intentionally transport-independent so a future dedicated mTLS operator endpoint can expose the same operations without
moving orchestration logic into Kubidm.
