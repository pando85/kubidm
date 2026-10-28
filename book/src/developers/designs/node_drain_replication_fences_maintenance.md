# Node Drain, Replication Fences, and Maintenance Control Plane

Status: **Accepted for implementation in this branch**

Related:

- Kubidm replication-aware readiness: #361
- Kubidm recovery/generation design: #363
- Kaniop maintenance request: pando85/kaniop#950
- Upstream Kanidm database-maintenance model

## Context

Kubidm inherits Kanidm's decentralised, eventually-consistent multi-master replication model. That model is intentionally not quorum/leader based, but the upstream operational interface assumes that database maintenance such as reindex, verify, and vacuum is performed while the server is offline.

That assumption is awkward for Kubernetes operators. An operator can remove a Pod from service and stop it, but Kubernetes readiness does not prove that a surviving replica has received every write known to the Pod that is about to be made unavailable. `Pod Ready` and Kubidm's normal replication-aware readiness answer an availability question, not a handoff/convergence question.

Kubidm already exposes replication-aware `/readyz`, tracks replication state, and has access to the replication update vector (RUV). It also already performs reindex and verification through in-process backend/query-server primitives. We can therefore expose a small node-local control plane that lets an external orchestrator perform safe rolling maintenance without turning Kubidm into a Kubernetes controller and without adding leader election, quorum, or a coordinator.

## Decision

Kubidm will provide three related primitives:

1. **Drain/fence** — stop accepting new local mutations, wait for in-flight local writes to complete, pause replication-consumer application, and capture an immutable replication fence representing the local RUV.
2. **Replication handoff** — allow an orchestrator to ask a node to synchronise until a supplied fence is satisfied, so another replica can be removed from service without losing acknowledged history.
3. **Exclusive in-process maintenance** — execute supported database operations while the node is fenced and no ordinary query-server transaction can overlap the maintenance operation.

The feature is deliberately node-local. Kaniop or another orchestrator decides which node to drain first, obtains/copies fences between nodes, and sequences a rolling operation.

## Goals

- Make reindex and verify Kubernetes-native without attaching the same SQLite database to a second process.
- Give operators a machine-readable proof that a peer has received a drained node's history before the drained node is taken into exclusive maintenance.
- Make maintenance operations idempotent and observable.
- Keep normal Kubidm availability/readiness semantics unchanged.
- Preserve eventual-consistency multi-master replication; do not introduce a leader, write quorum, witness, or continuously available coordinator.
- Ensure all local mutation paths, including background and replication writes, participate in the drain/exclusive-maintenance safety model.
- Fail closed if a maintenance attempt cannot prove the required local invariants.

## Non-goals

- Cluster-wide orchestration inside Kubidm.
- Historical rollback/PITR semantics; those remain governed by replication generations.
- Automatic maintenance based on log parsing.
- Treating a replication fence as a total-order commit index.
- Making normal readiness require full global convergence.
- In-process restore. Restore remains a recovery operation with stronger topology semantics.
- In-process vacuum in this first implementation. Vacuum requires a separate backend/pool lifecycle refactor and is exposed as unsupported by capabilities until that work lands.

## Terminology

### Serving readiness

Whether a node is safe enough to receive normal production traffic. Only the `healthy` and `degraded` replication states are serving-ready, see [Kubernetes probes](../../integrations/kubernetes_probes.md#readiness-decision-matrix).

### Drain

A local administrative state in which Kubidm stops accepting operations that can create local durable mutations and waits for existing local mutations to finish.

### Replication fence

An opaque, versioned snapshot of the local RUV plus domain identity and, when available, replication generation. A fence means "this node knew at least this replication history when the fence was captured".

A fence is not a timestamp and must not be reduced to `last_replication_success`.

### Fence satisfaction

A local node satisfies a fence when its current RUV contains every range represented by that fence in the same domain/generation. Fence comparison must use replication-range semantics rather than only `ts_max`.

### Fenced node

A drained node whose mutation sources and replication consumer are paused and whose final local RUV has been captured. A fenced node may continue acting as a replication supplier until exclusive maintenance begins, allowing peers to pull its final state.

## Node operation state machine

```text
Serving
  |
  | drain(operation_id)
  v
Draining
  |
  | local/background writes drained
  | replication consumer paused
  | RUV captured
  v
Fenced
  | \
  |  \ resume
  |   ------------------------> Serving
  |
  | maintenance(operation_id)
  v
Maintenance
  |
  | complete/fail
  v
Fenced
  |
  | catch up to peer fence if required by orchestrator
  | resume
  v
Serving
```

Failures during maintenance leave the node fenced and not serving-ready. An explicit resume is required after the caller has inspected/recovered the node.

The control state is intentionally independent from `ReplicationState`. Normal replication health describes data-plane health; maintenance state describes administrative serving/mutation policy.

## Mutation classes

All durable mutations must pass through a common gate.

Conceptually:

```rust
pub enum MutationOrigin {
    Client,
    Internal,
    Replication,
    Maintenance,
}
```

The first implementation does not require every caller to carry this enum if a lower-level gate can enforce the same invariant. The invariant is what matters:

- `Serving`: ordinary reads/writes and replication work normally.
- `Draining`: new ordinary writes fail fast; in-flight ordinary writes are allowed to finish; replication consumer is allowed to finish its current application and then pauses.
- `Fenced`: ordinary/background writes and replication-consumer writes are rejected/paused; read-only control/status and replication-supplier activity may continue.
- `Maintenance`: an exclusive query-server/database guard prevents ordinary reads or writes from overlapping the maintenance operation.

## QueryServer exclusivity

The gate MUST live at or below `QueryServer`, not only in HTTP middleware, because delayed/background actions and replication can call `IdmServer::proxy_write()` without traversing HTTP.

`QueryServer` will own a maintenance transaction gate. Ordinary read/write transactions acquire shared access for their lifetime; an exclusive maintenance operation acquires exclusive access only after all ordinary transactions have drained.

The implementation may use a Tokio read/write lock or an equivalent semaphore/permit design, but must preserve these properties:

1. once drain starts, no new ordinary write transaction can begin;
2. fence capture happens only after previously-started ordinary writes and replication apply transactions have finished;
3. exclusive maintenance starts only when no ordinary QueryServer transaction remains;
4. control/status endpoints remain reachable while the database gate is exclusive.

## Replication consumer pause

`ReplCtrl` will gain explicit controls to pause and resume consumer application and to request an immediate incremental synchronisation.

The pause acknowledgement is emitted only after any in-flight incremental/refresh application has completed. Supplier handling can stay active while fenced so a healthy peer can consume the final fence.

## ReplicationFence v1

The wire/control representation is versioned from the beginning:

```rust
pub enum ReplicationFence {
    V1 {
        domain_uuid: Uuid,
        ranges: ReplRuvRange,
        generation: Option<Uuid>,
    },
}
```

If replication-generation support is not implemented yet, `generation` is `None`. Once generations exist, a supplied fence from a different generation is rejected rather than merged.

Fence objects are administrative/control-plane data and are not replicated directory entries.

## Fence comparison

`ReplRuvRange` will expose a comparison helper that determines whether a current RUV satisfies another RUV. The comparison is per supplier/server UUID and range. The implementation must not compare only a single maximum timestamp.

For v1 ranges, a current range satisfies a fence range only if the current range covers the fenced interval required for that supplier identity. Missing supplier ranges fail satisfaction.

If the local history has been trimmed such that satisfaction cannot be proven, the result is not guessed; the caller receives a refresh-required/unsatisfied result.

## Control interface

The canonical internal implementation is a `MaintenanceController`/actor shared by both the local Unix admin socket and HTTP control handlers.

The first implementation exposes authenticated-local administration through the existing Unix socket and exposes read-only capability/status data over normal HTTP. A future dedicated mTLS operator listener can call the same controller without changing semantics.

This avoids coupling the correctness implementation to a particular Kubernetes certificate/bootstrap design in the first PR while ensuring Kaniop does not need to parse logs or invoke offline database commands.

### Requests

The admin protocol gains idempotent operations conceptually equivalent to:

```text
MaintenanceCapabilities
MaintenanceStatus
MaintenanceDrain { operation_id }
MaintenanceRun { operation_id, operation }
MaintenanceResume { operation_id }
ReplicationFence
ReplicationSyncUntil { operation_id, fence }
```

### Supported operations

```rust
pub enum MaintenanceOperation {
    Reindex,
    Verify,
}
```

`Vacuum` is reported as unsupported by capabilities in this implementation rather than pretending it has safe in-process semantics.

### Idempotency

Every mutating control request carries a caller-generated UUID.

- Repeating the same operation id and request returns the existing result/status.
- Reusing an operation id for an incompatible request fails.
- Only one exclusive node operation may run at a time.

This lets a Kubernetes reconciler restart and replay requests safely.

## Status/readiness integration

`/healthz` remains process liveness.

`/readyz` becomes not-ready whenever maintenance state is not `Serving`, regardless of raw replication health. The readiness message names the maintenance state. It never includes the active operation id: `/readyz` is unauthenticated, so orchestrators must read operation ids from the admin socket `MaintenanceStatus` request.

This ensures a drain removes the node from Kubernetes Service endpoints, but correctness never relies solely on EndpointSlice propagation because the write gate independently rejects new mutations.

A new public read-only endpoint (`GET /maintenance`) exposes maintenance capabilities and state so probes/operators can inspect the node without database authentication. Because it is unauthenticated it omits the active operation id and the last error; both are only available from the admin socket `MaintenanceStatus` request. Mutating operations remain restricted to the local admin control path in the first implementation.

## Reindex implementation

Kubidm already exposes reindex on `QueryServerWriteTransaction`, delegating to the backend transaction. The maintenance path will execute reindex in-process while holding the exclusive maintenance guard, then perform verification before reporting success.

The node remains fenced after the operation. The orchestrator decides when it has caught up to an appropriate peer fence and explicitly resumes it.

## Verify implementation

Verification executes against the already-open QueryServer/backend while the maintenance guard is held. The result is returned as structured success/failure rather than terminating the process as the CLI helper does.

Verification does not automatically repair data.

## Failure semantics

- Drain timeout/failure: return failure. If nothing was fenced and no operation was active before the drain, the node rolls back to `Serving` (nothing needs protecting) and the operation counts as resumed, so a subsequent resume of it is an idempotent success. A failed drain retry for an operation that was already in progress leaves the node `Failed` and non-serving until the drain is retried successfully or the caller explicitly resumes.
- Interrupted step (a handler stops before recording its outcome): the step's claim is released and the node becomes `Failed`, so a drain retry or a resume recovers it without a restart.
- Fence mismatch/domain mismatch: fail without modifying data.
- Sync-until refresh required: return `RefreshRequired`; do not claim the fence is satisfied.
- Maintenance operation error or failed verification: report state `Failed` while keeping the write fence held, set last operation failure, and keep `/readyz` false.
- Process restart during an in-memory maintenance operation: startup begins in normal `Serving` state in this first implementation because no destructive external-process operation is used. Persistent maintenance journaling is deferred until an operation requiring crash-sticky recovery semantics (for example future vacuum) is introduced.

## Security

- Mutating maintenance operations are privileged local administrative operations.
- Existing Unix peer-credential checks (root or the Kubidm UID) protect the initial control transport.
- The ordinary identity database must not be required to authenticate recovery/maintenance control requests; otherwise an index/authentication failure could prevent the operation needed to repair it.
- The future remote operator transport should be a dedicated mTLS listener/CA, not a normal user bearer token.
- Fences contain replication metadata, not user attributes or credentials.

## Orchestrator protocol

For two serving replicas A and B, rolling maintenance of B is:

1. Kaniop calls `drain(B)`.
2. B becomes not-ready, rejects new local writes, pauses its consumer after in-flight work, and returns fence `F_B`.
3. Kaniop asks A to `sync_until(F_B)`.
4. Only after A reports `Satisfied` may Kaniop run exclusive maintenance on B.
5. Kaniop runs `maintenance(B, Reindex)` (or Verify).
6. Kaniop captures a current fence `F_A` from A.
7. Kaniop asks B to `sync_until(F_A)` while B remains unavailable to clients.
8. After B satisfies `F_A`, Kaniop resumes B and waits for serving readiness.
9. Repeat in the opposite direction for A if the operation targets the whole topology.

This protocol proves handoff at explicit points without requiring global zero-lag readiness.

## Compatibility

- Existing deployments that never use maintenance controls preserve current behaviour.
- Existing `/healthz` semantics remain unchanged.
- **Breaking:** `/readyz` `peers` changed from a list of peer objects (URL, connection flag, timestamps) to counts `{ total, healthy, stale }`, so that the unauthenticated endpoint does not disclose replication topology. Apart from that and the intentional not-ready state during drain/maintenance, `/readyz` is unchanged.
- **Breaking:** `/maintenance` no longer returns `active_operation_id` or `last_error`. Orchestrators must use the admin socket `MaintenanceStatus` request for both.
- Upstream-style offline CLI commands remain available.
- Kaniop can feature-detect native maintenance support and retain its scale-to-zero/offline Job fallback for Kanidm.

## Detailed implementation plan

The implementation following this ADR will land in the same branch, with this ADR/plan as the first commit.

### Phase 1 — replication fence primitives

1. Add a versioned `ReplicationFence` type to internal protocol types.
2. Add RUV fence-satisfaction helpers with unit tests covering:
   - identical ranges;
   - local range ahead of fence;
   - missing supplier range;
   - insufficient local maximum;
   - domain mismatch;
   - multiple supplier identities.
3. Add a QueryServer helper to capture the local replication fence without mutating data.

### Phase 2 — maintenance state and transaction gate

4. Add `MaintenanceState`, `MaintenanceOperation`, and structured operation/status/result types.
5. Add a shared `MaintenanceStateTracker` used by readiness and control operations.
6. Add a QueryServer maintenance gate so new writes are rejected during drain/fence and an exclusive maintenance guard can wait for ordinary transactions to leave.
7. Integrate maintenance state into readiness; add tests that non-serving maintenance states force readiness false independently of replication health.

### Phase 3 — replication control

8. Extend `ReplCtrl` with pause/resume and immediate sync-until controls.
9. Ensure pause acknowledgement occurs only after any current consumer-apply transaction returns.
10. Implement `sync_until(fence)` using immediate incremental replication plus local fence comparison; return structured `Satisfied`, `Unsatisfied`, `RefreshRequired`, or mismatch/error outcomes.
11. Add replication tests for fence handoff and pause semantics.

### Phase 4 — maintenance controller

12. Add a node-local controller coordinating drain, fence capture, maintenance execution, and resume.
13. Implement operation-id idempotency and single-active-operation exclusion.
14. Implement in-process `Reindex` under the exclusive gate and run verification afterward.
15. Implement in-process `Verify` with structured consistency results.
16. Leave the node fenced after maintenance success/failure until explicit resume.

### Phase 5 — admin/status API

17. Extend the existing Unix admin request/response protocol with maintenance capability/status/drain/run/resume/fence/sync-until operations.
18. Add read-only HTTP maintenance capability/status output and OpenAPI schema.
19. Document example control flow and Kubernetes/operator expectations.

### Phase 6 — validation

20. Add unit tests for state transitions, idempotency, readiness interaction, RUV fence comparison, and maintenance operation preconditions.
21. Add/extend integration tests proving:
   - drain prevents new writes;
   - a fence is stable after drain;
   - another replica can satisfy the fence;
   - reindex completes without starting a second process against the DB;
   - the node remains not-ready until resume;
   - normal writes work after resume.
22. Run formatting, clippy/lints, unit/integration tests, and repository CI; fix all failures before marking the PR ready.

## Follow-up work intentionally outside this PR

- Dedicated mTLS operator-control listener and certificate rotation/bootstrap.
- Persistent crash-sticky maintenance journal if future operations require it.
- Safe in-process SQLite vacuum/backend pool reopen lifecycle.
- Native restore/DR control operations; these must obey replication-generation recovery semantics rather than this ordinary rolling-maintenance protocol.
- Kaniop `KanidmMaintenance` CRD/controller and scheduling policy, documented separately in the companion Kaniop design proposal.


## Implementation refinement

The implementation keeps the safety invariants above but deliberately uses a smaller
lock/control surface than the initial plan described.

- `QueryServer::write` is the hard admission boundary. It rejects ordinary writes in every
  non-`Serving` maintenance state, both before waiting for and after acquiring the writer
  permit. The second check closes the race with writers that entered the semaphore queue just
  before a drain began.
- Privileged maintenance work uses a Tokio task-local bypass. Because the bypass is scoped to
  one directly-awaited future, it cannot admit unrelated client/background writers in another
  task.
- The replication consumer is idle while a node is `Draining`, `Fenced`, `Maintenance`, or
  `Failed`. In `Recovering` only replication apply receives the task-local bypass; ordinary
  writes remain rejected while the node catches up to the supplied fence.
- This makes explicit `ReplCtrl` pause/resume messages unnecessary for the first implementation:
  write admission itself provides the pause acknowledgement once the maintenance fence owns the
  writer permit.
- `sync-until` currently observes the existing periodic incremental replication loop instead of
  forcing a new replication tick. This can add up to one configured replication interval of
  latency but does not weaken the fence proof. An immediate-sync control is an optimisation, not
  a correctness requirement.

The original plan remains in the first commit for design history; this section records the final
mechanism implemented by the branch.
