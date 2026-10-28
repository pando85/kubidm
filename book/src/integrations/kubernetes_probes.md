# Kubernetes Health and Readiness Probes

Kubidm provides separate endpoints for liveness and readiness checks, designed for Kubernetes-style health monitoring in
multi-master replication deployments.

## Endpoints

### `/healthz` - Liveness Probe

Returns whether the process is alive and responding to requests.

**Response:**

```json
{
  "alive": true
}
```

**HTTP Status:** Always 200 OK if the endpoint responds.

**Use for:** Kubernetes `livenessProbe`

### `/readyz` - Readiness Probe

Returns whether the replica is ready to serve production traffic. This endpoint considers:

- Server initialization phase (must be `running`)
- Local database health
- Replication state
- Node maintenance state (must be `serving`, see [`/maintenance`](#maintenance---maintenance-state))

The endpoint is unauthenticated, so it only reports peer counts, never peer addresses or replication timestamps. `peers`
is `null` when replication is not configured. The peers counted are the _supplier_ peers, the nodes this node pulls from
(`pull` and `mutual-pull`); `allow-pull` nodes only pull from this node and report their own health.

**Response (200 OK - Ready):**

```json
{
  "serving_ready": "ready",
  "replication_state": "healthy",
  "database_health": "healthy",
  "server_phase": "running",
  "peers": {
    "total": 2,
    "healthy": 2,
    "stale": 0
  },
  "message": "Ready to serve traffic"
}
```

| Field           | Description                                                                |
| --------------- | -------------------------------------------------------------------------- |
| `peers.total`   | Number of configured supplier peers                                        |
| `peers.healthy` | Supplier peers whose last connection succeeded and that are not stale      |
| `peers.stale`   | Supplier peers with no successful sync within the stale window (see below) |

**Response (503 Service Unavailable - Not Ready):**

```json
{
  "serving_ready": "not_ready",
  "replication_state": "refresh_required",
  "database_health": "healthy",
  "server_phase": "running",
  "peers": {
    "total": 2,
    "healthy": 2,
    "stale": 0
  },
  "message": "Replication state 'refresh_required' does not allow serving"
}
```

**Response (503 Service Unavailable - Maintenance):**

```json
{
  "serving_ready": "not_ready",
  "replication_state": "healthy",
  "database_health": "healthy",
  "server_phase": "running",
  "peers": null,
  "message": "Node is unavailable for maintenance (state: Fenced)"
}
```

While a node is drained for maintenance it reports not ready even though its replication and database are healthy, so
that it is removed from the Service endpoints until the maintenance operation is resumed.

**Use for:** Kubernetes `readinessProbe`

### `/maintenance` - Maintenance State

Returns the node-local maintenance state and the maintenance capabilities of this server version. It is read-only and
intended for capability discovery by an orchestrator.

**Response:**

```json
{
  "state": "serving",
  "capabilities": {
    "api_version": "v1",
    "drain": true,
    "replication_fence": true,
    "sync_until": true,
    "reindex": true,
    "verify": true,
    "vacuum": false,
    "restore": false
  }
}
```

**HTTP Status:** Always 200 OK if the endpoint responds.

| State         | Meaning                                                         | Ready? |
| ------------- | --------------------------------------------------------------- | ------ |
| `serving`     | Normal operation                                                | Yes    |
| `draining`    | Waiting for in-flight writes to finish before fencing the node  | No     |
| `fenced`      | Writes are fenced, the node is waiting for a maintenance step   | No     |
| `maintenance` | A maintenance operation (reindex, verify) is running            | No     |
| `recovering`  | The node is applying replication changes from peers             | No     |
| `failed`      | A maintenance step failed, the operator must retry or resume it | No     |

This endpoint is unauthenticated, so it does not include the active operation ID or the last error. Those are only
available through the privileged admin socket (`MaintenanceStatus`), see the
[maintenance control protocol](../developers/designs/maintenance_control_protocol.md).

**Use for:** Diagnostics and orchestration. Do not use it as a probe: `/readyz` already accounts for the maintenance
state.

### `/status` - Legacy Endpoint

Returns a simple boolean for backward compatibility. Returns `true` when the server is up.

**Response:**

```json
true
```

**Note:** For new deployments, use `/healthz` and `/readyz` instead.

## Replication States

The `replication_state` field is derived from what the replication consumer tasks observe each time they sync with a
supplier peer (every `task_poll_interval`, 15 seconds by default). It is evaluated when `/readyz` is requested, so a
peer becomes stale even if its replication task stops reporting. Elapsed times are measured on the monotonic clock, so
wall clock adjustments neither hide nor fake a stale peer. The states are checked in this order, the first match wins:

| State              | Set when                                                                                                                                                         | Ready? |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| `refreshing`       | A full refresh from a supplier is being applied                                                                                                                  | No     |
| `refresh_required` | A supplier answered that this node must be refreshed: this node is older than the supplier's changelog, or a domain mismatch this node can not blame on the peer | No     |
| `catching_up`      | A supplier is configured with `automatic_refresh`, but this node has never completed a refresh or incremental from a supplier (a fresh replica)                  | No     |
| `failed`           | Applying what the suppliers send has kept failing for 20 replication intervals (5 minutes by default), and the last failure is within the stale window           | No     |
| `degraded`         | At least one supplier peer had no successful sync for 4 replication intervals (1 minute by default), or answered from another domain (see below)                 | Yes    |
| `healthy`          | Every supplier peer synced within the stale window, or replication is not configured, or this node has no supplier peers                                         | Yes    |

The stale and failed windows scale with `task_poll_interval`: a peer is stale after `4 × task_poll_interval` without a
successful sync. Replication is failed after `20 × task_poll_interval` of local apply failures that are still ongoing: a
run of failures ends when no new failure happens for the stale window, and a later failure starts a new run.

### Transitions

- **Successful incremental from a peer:** the peer is fresh again, its `refresh_required` and other domain flags are
  cleared, the node counts as synced, and any run of apply failures ends.
- **Supplier reports that this node is behind its changelog:** the node is `refresh_required` until that supplier
  answers an incremental normally again or a refresh succeeds. With `automatic_refresh` the refresh starts immediately.
- **Supplier answers from another domain:** a refresh would replace all of this node's content with the peer's, so it is
  only done automatically when this node has nothing to lose. See
  [The Domain Mismatch Guard](#the-domain-mismatch-guard).
- **Refresh:** `refreshing` while it runs. On success every `refresh_required` flag is cleared, the node is synced, and
  a failed verification is cleared because the content was replaced. A refresh is applied in a single transaction, so a
  failed refresh leaves the content unchanged and the state returns to what it was before (`refresh_required`,
  `catching_up`, or `healthy` for an operator requested refresh of a synced node).
- **Connection failure or failed exchange** (timeout, protocol or decode error, the supplier closed the connection): the
  peer keeps its last successful sync time and goes stale once the stale window passes, making the node `degraded`.
- **Local apply failure** (this node could not read its replication state, or could not apply or commit what the
  supplier sent): the node becomes `failed` if such failures keep happening for the failed window. A successful sync
  with any supplier, or the stale window passing without a new failure, ends the run.

`failed` deliberately only covers ongoing failures to apply changes locally. Suppliers that are unreachable, however
long, only make the node `degraded`, even after an earlier apply failure: in a partition, or in a two node topology that
lost one node, turning every survivor not ready would turn a replication problem into a full outage. Alert on `degraded`
instead (see below).

### Startup

When the server starts with replication configured, it decides whether it must wait for a supplier before serving:

- A node with no supplier configured with `automatic_refresh` holds the domain's content by configuration and starts
  `healthy` (ready). This covers the node that created the domain (for example pod-0 of a StatefulSet, whose peers do
  not exist yet when it starts), a lone survivor whose peers are gone, and replication configured without supplier peers
  (an empty peer list, or only `allow-pull` consumers).
- A node with a supplier configured with `automatic_refresh` expects to receive its content from a supplier. It starts
  `healthy` if its database shows that it has synced before, and `catching_up` (not ready) otherwise, until its first
  successful refresh or incremental. A fresh replica's first incremental is answered with a domain mismatch, so it moves
  to `refresh_required` and is refreshed automatically.

A node without an `automatic_refresh` supplier is ready as soon as it starts, before it has talked to any peer. If such
a node was replaced by an empty one (for example pod-0 re-created with a new volume), it creates a new domain and is
ready for up to one `task_poll_interval`, until its first incremental with a peer is answered with a domain mismatch. It
then reports `refresh_required` (not ready). The replicas that pull from it never refresh from it automatically, see
[The Domain Mismatch Guard](#the-domain-mismatch-guard).

The database shows that a node has synced before when either:

- its domain info entry was created by another server. A fresh server creates its own domain; a refresh replaces the
  whole content, including the domain entry and its creation record, with the supplier's, in the same transaction. Entry
  creation records are never trimmed, so this survives restarts, changelog trimming and backups. A server outside the
  supplier's domain can only sync through a refresh, so for a fresh replica this is the complete answer; or
- its replication update vector (RUV) records changes that originated on another server, i.e. it applied an incremental.
  This covers a domain creator configured with `automatic_refresh` towards a peer, until every peer has been gone longer
  than the changelog (7 days).

If the database can not be read at startup, a node with an `automatic_refresh` supplier is treated as never synced and
stays not ready until its first successful sync; an error is logged.

Supplier peers must be configured by DNS name: replication refuses addresses because the TLS check needs a name. A peer
configured by address is logged at startup, tracked under its address, and reported stale.

### The Domain Mismatch Guard

A supplier answers with a domain mismatch when it and this node are not in the same domain. Either side may be the one
out of the domain, and an automatic refresh would replace all of this node's content with the supplier's. The node
decides as follows:

- **This node has evidence that it holds replicated content, and a supplier configured with `automatic_refresh`:** it is
  never refreshed automatically from a mismatched peer, whatever the other peers do. The evidence is the one used at
  startup (its database shows that it synced before), or any successful refresh or incremental since it started. The
  peer is reported stale, the node is `degraded` and keeps serving, and an error is logged on every replication
  interval. This protects a synced replica from an empty, re-created supplier: such a node has no `automatic_refresh`
  supplier, so it is ready at once and would otherwise wipe every replica that refreshes from it (in a two replica
  StatefulSet, or after a full restart of a larger one, where no other peer is in sync yet).
- **This node has no such evidence (a fresh replica):** it is the one out of the domain. It reports `refresh_required`
  and, with `automatic_refresh`, is refreshed from the peer.
- **This node has no supplier configured with `automatic_refresh` (the origin, pod-0):** it is never refreshed
  automatically. If another supplier synced within the stale window, the mismatched peer is reported stale (`degraded`,
  still ready); otherwise the node can not tell which side is out of the domain and reports `refresh_required` (not
  ready).

A supplier that reports that this node fell behind its changelog, in the same domain, is not a domain mismatch: with
`automatic_refresh` the node is refreshed as before.

When a new replica joins an existing topology, the existing nodes that pull from it are answered with a domain mismatch
until it has been refreshed. They report it as a stale peer (`degraded`, still ready) and are never refreshed from it.
An existing node without `automatic_refresh` whose only supplier is the new replica reports `refresh_required` until the
new replica has been refreshed: refresh the new replica before adding it as the only supplier of an existing node.

#### Recovering From a Mismatch

The guard never decides which domain is the right one, an operator does. Check the error logged on the degraded node,
which names the supplier, and compare the domain of both sides (`kubidmd domain show`).

- **The supplier is the one out of the domain** (an empty or re-created node, for example pod-0 after its volume was
  lost): refresh the supplier from a node that holds the content. On the supplier, run:

  ```bash
  kubidmd refresh-replication-consumer --i-want-to-refresh-this-servers-database
  ```

  A node without `automatic_refresh` refreshes from one of its suppliers, so it needs a supplier that holds the content
  (in a Kaniop StatefulSet every pod pulls from every other pod).
- **The cluster was intentionally rebuilt in a new domain** (for example restored from a backup of another cluster, or
  re-initialised on purpose): the nodes that still hold the old domain refuse the automatic refresh. Run the same
  command on each of them to replace their content with the new domain's. The manual refresh does not go through the
  guard, and on success the node is synced and healthy again.

## Database Health

The `database_health` field is `unhealthy` (not ready) when either of these checks last failed:

| Check  | Fails when                                                                                       | Recovers when                                                                                                       |
| ------ | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| Commit | The backend commit of a write transaction fails (database or IO error, for example a full disk)  | The next write transaction commits                                                                                  |
| Verify | The online consistency verification that ends every admin socket `MaintenanceRun` reports errors | The next verification reports none, the operator resumes a maintenance operation, or a replication refresh succeeds |

Changes rejected by schema, access control or plugin validation never reach the backend commit and do not affect the
database health. Search errors do not affect it either. The two checks recover independently: a successful write does
not clear a corruption found by a verification. A `resume` clears any failed verification, not only one found by the
operation it ends: resuming is the operator's decision that the node is fit to serve. Both results are kept in memory
only, so a restart of the server also clears them.

## Readiness Decision Matrix

A replica is considered **ready** when ALL of the following are true:

- `server_phase` is `"running"`
- `database_health` is `"healthy"`
- `replication_state` is `healthy` or `degraded`
- The maintenance state is `serving`

A replica is **not ready** when ANY of the following are true:

- Server is still initializing (phase is `bootstrap`, `schema_ready`, or `domain_info_ready`)
- The last backend commit failed, or the last online verification found errors
- Replication state is `catching_up`, `refresh_required`, `refreshing`, or `failed`
- The node is drained for maintenance (maintenance state is not `serving`)

## Kubernetes Configuration

### Example Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubidm
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kubidm
  template:
    metadata:
      labels:
        app: kubidm
    spec:
      containers:
        - name: kubidmd
          image: ghcr.io/pando85/kubidm/server:latest
          ports:
            - containerPort: 8443
              name: https
            - containerPort: 8080
              name: repl
            # Startup runs database migrations (and, after an upgrade, possibly a full
            # reindex) before the HTTPS listener is bound. Allow plenty of time here so
            # that the liveness probe does not kill the pod in the middle of it.
          startupProbe:
            httpGet:
              path: /healthz
              port: https
              scheme: HTTPS
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 180
          livenessProbe:
            httpGet:
              path: /healthz
              port: https
              scheme: HTTPS
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: https
              scheme: HTTPS
            initialDelaySeconds: 10
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 2
            successThreshold: 1
```

### Probe Configuration Guidance

#### Startup Probe (`/healthz`)

- **Purpose:** Give the server time to finish startup before liveness checks begin
- **Period:** 10 seconds
- **Timeout:** 3-5 seconds
- **Failure threshold:** large, e.g. 180 (30 minutes at a 10 second period)

On startup the server opens the database and runs any pending schema and domain migrations before it binds the HTTPS
listener. On a large database, or after an upgrade that requires a reindex, this can take far longer than a liveness
probe tolerates: without a startup probe the kubelet would restart the container in the middle of the migration, which
then starts over. Kubernetes holds the liveness and readiness probes back until the startup probe succeeds once, so size
`periodSeconds * failureThreshold` above your longest expected startup.

#### Liveness Probe (`/healthz`)

- **Purpose:** Detect if the process is stuck or dead
- **Initial delay:** 5-10 seconds (not needed with a startup probe)
- **Period:** 10-30 seconds
- **Timeout:** 3-5 seconds
- **Failure threshold:** 3-5

The liveness probe should be lenient. It only checks if the process is alive, not if it's ready to serve traffic.

#### Readiness Probe (`/readyz`)

- **Purpose:** Determine if the replica should receive traffic
- **Initial delay:** 10-30 seconds (allow time for initialization)
- **Period:** 5-10 seconds
- **Timeout:** 3-5 seconds
- **Failure threshold:** 2-3
- **Success threshold:** 1

The readiness probe should be more aggressive than liveness. A replica that fails readiness should be removed from the
Service endpoints immediately.

### Multi-Master Considerations

In a multi-master replication setup:

1. **Synced replicas serve traffic** in the `healthy` and `degraded` states
2. **Disconnections are tolerated** - a synced replica remains ready while its suppliers are unreachable, it only
   becomes `degraded`
3. **Fresh replicas wait for their first sync** - a new replica configured with `automatic_refresh` is not ready until
   it has received the domain's content; a node without `automatic_refresh` holds the content by configuration
4. **Refresh operations take replicas offline** - when a replica needs or is performing a refresh, it reports as not
   ready
5. **No quorum or leader election** - each replica makes independent readiness decisions based on local state

This design prioritizes availability while ensuring a replica never serves content it is still waiting to receive.

## Draining a Node for Maintenance

The maintenance control plane is driven with `kubidmd maintenance` on the node itself. It talks to the root-only admin
socket (`admin_bind_path` of the server configuration), so run it as root or as the server user, for example through
`kubectl exec`. The commands are the building blocks an external orchestrator uses; Kubidm does not choose the replica
to maintain or sequence the nodes itself. See the
[maintenance control protocol](../developers/designs/maintenance_control_protocol.md) for the semantics.

| Command                                                                                     | Effect                                                                         |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `kubidmd maintenance capabilities`                                                          | Show what this server version supports                                         |
| `kubidmd maintenance status`                                                                | State, active operation ID and last error                                      |
| `kubidmd maintenance drain --operation-id <uuid>`                                           | Stop serving, wait for in-flight writes and print the node's replication fence |
| `kubidmd maintenance run --operation-id <uuid> <reindex\|verify>`                           | Run a maintenance operation on the drained node                                |
| `kubidmd maintenance fence`                                                                 | Capture a fresh replication fence of this node                                 |
| `kubidmd maintenance sync-until --operation-id <uuid> --fence <json> [--timeout-seconds N]` | Wait until this node has received the state of a fence from a peer             |
| `kubidmd maintenance resume --operation-id <uuid>`                                          | Serve again and end the operation                                              |

The operation ID is a UUID chosen by the caller, and every step of one operation uses the same one. Add `-o json` to
print a single JSON object on stdout instead of text. Every command exits non-zero when the step did not succeed.

A rolling maintenance of replica `B` with peer `A` looks like this:

```bash
OP=$(uuidgen)

# On B: drain and keep the fence it prints.
kubectl exec pod-b -- kubidmd maintenance -o json drain --operation-id "$OP" > drain.json
FENCE_B=$(jq -c .output.fence drain.json)

# On A: require A to have received everything B had when it was fenced.
kubectl exec pod-a -- kubidmd maintenance sync-until --operation-id "$OP" --fence "$FENCE_B"

# On B: run the operation, then wait for what A has now.
kubectl exec pod-b -- kubidmd maintenance run --operation-id "$OP" reindex
FENCE_A=$(kubectl exec pod-a -- kubidmd maintenance -o json fence | jq -c .output.fence)
kubectl exec pod-b -- kubidmd maintenance sync-until --operation-id "$OP" --fence "$FENCE_A"

# On B: only now let it serve again.
kubectl exec pod-b -- kubidmd maintenance resume --operation-id "$OP"
```

Use `--fence-file <path>` instead of `--fence` to read the fence from a file.

Handling failures:

- **`busy`** means another step of the operation is still executing. It never changes any state and is always safe to
  retry: repeat the same command with the same operation ID until it succeeds. In JSON output the error has
  `"retryable": true`.
- **`timed_out`** from `sync-until` means the fence was not satisfied within `--timeout-seconds` (60 by default, at most
  one hour). Repeat the command to keep waiting.
- **`domain_mismatch` and `generation_mismatch`** are hard failures: the fence belongs to another domain or replication
  generation.
- A `failed` state is recovered by repeating the `drain` or by `resume` with the same operation ID.

## Monitoring and Alerting

The `/readyz` endpoint exposes state that can be monitored by polling the endpoint and parsing the JSON response.

### Recommended Alerts

1. **Replication Failed:** Alert immediately when `replication_state` is `failed`. The state itself already requires 20
   replication intervals of failures to apply changes.
2. **Replication Degraded:** Alert when `replication_state` is `degraded` for more than 10 minutes, and page when
   `peers.healthy` is `0` while `peers.total` is greater than `0`: the node is serving but not receiving changes from
   any supplier.
3. **Refresh Required:** Alert when `replication_state` is `refresh_required` for more than 10 minutes
4. **Fresh Replica Not Synced:** Alert when `replication_state` is `catching_up` for more than 15 minutes
5. **Database Unhealthy:** Alert immediately when `database_health` is `unhealthy`
6. **Not Ready:** Alert when a replica has been `not_ready` for more than 15 minutes (excluding initialization)

### Example Blackbox Exporter Configuration

To monitor readiness with Prometheus, use the blackbox exporter to probe the `/readyz` endpoint and alert on non-200
responses or specific JSON field values.

## Troubleshooting

### Replica Shows Not Ready

Check the `/readyz` endpoint response to determine the cause:

1. **`server_phase` not `running`:** Server is still initializing. Wait for initialization to complete.

2. **`database_health` is `unhealthy`:** A write transaction failed to commit in the backend, or the last online
   verification found consistency errors. Check the logs for `Database health check failed`. A commit failure clears
   with the next successful write (check disk space and permissions). A verification failure clears with the next clean
   verification, a successful refresh from a peer, or when the operator resumes the maintenance operation; repairing it
   may require a reindex, a refresh, or a restore from backup. A restart also clears both, as they are kept in memory.

3. **`replication_state` is `catching_up`:** The node expects its content from an `automatic_refresh` supplier and has
   never synced from one. Check that the supplier is reachable; the refresh then happens automatically (or run
   `kubidmd refresh-replication-consumer`).

4. **`replication_state` is `refresh_required`:** A supplier reported that this node's content must be refreshed: it is
   a new replica, it has fallen further behind than the changelog, or (on a node without `automatic_refresh`) a supplier
   is in another domain and no other supplier is in sync, for example an empty, re-created pod-0. See
   [Recovering From a Mismatch](#recovering-from-a-mismatch). With `automatic_refresh` a refresh of a new or lagging
   replica happens automatically; if it persists, check:
   - Network connectivity to peers
   - Peer availability
   - Replication configuration

5. **`replication_state` stays `degraded` with a domain mismatch error in the logs:** a supplier is in another domain,
   and this node holds replicated content, so it refuses to be refreshed from it automatically. See
   [Recovering From a Mismatch](#recovering-from-a-mismatch).

6. **`replication_state` is `failed`:** This node has been unable to apply the changes its suppliers send. Check the
   logs for `Consumer was not able to apply changes`; a refresh from a healthy peer usually resolves it.

7. **`replication_state` is `refreshing`:** Replica is currently performing a full refresh. This is normal and will
   complete automatically. If it takes too long, check:
   - Network bandwidth
   - Database size
   - Peer load

8. **`message` reports maintenance:** The node is drained for a maintenance operation. Check `/maintenance` for the
   state. A `failed` state needs the operator to retry or resume the operation; run `kubidmd maintenance status` on the
   node for the operation ID and the last error (see
   [Draining a Node for Maintenance](#draining-a-node-for-maintenance)).

### Replica Shows Ready But Not Serving Traffic

Check:

- Kubernetes Service endpoints include the pod
- Network policies allow traffic
- Load balancer health checks are configured correctly
- TLS certificates are valid

## Related Issues

- [Issue #361: Observability: expose replication state and serving readiness](https://github.com/pando85/kubidm/issues/361)
- [Issue #359: Related observability improvements](https://github.com/pando85/kubidm/issues/359)
