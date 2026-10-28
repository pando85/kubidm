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
peer becomes stale even if its replication task stops reporting. The states are checked in this order, the first match
wins:

| State              | Set when                                                                                                                                        | Ready? |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| `refreshing`       | A full refresh from a supplier is being applied                                                                                                 | No     |
| `refresh_required` | A supplier answered that this node must be refreshed (domain mismatch, or this node is older than the supplier's changelog)                     | No     |
| `catching_up`      | Replication has supplier peers, but this node has never completed a refresh or incremental from one (a fresh replica)                           | No     |
| `failed`           | Applying what the suppliers send has failed for 20 replication intervals (5 minutes by default) with no successful sync in between              | No     |
| `degraded`         | At least one supplier peer had no successful sync for 4 replication intervals (1 minute by default): unreachable, or the exchange keeps failing | Yes    |
| `healthy`          | Every supplier peer synced within the stale window, or replication is not configured, or this node has no supplier peers                        | Yes    |

The stale and failed windows scale with `task_poll_interval`: a peer is stale after `4 × task_poll_interval` without a
successful sync, and replication is failed after `20 × task_poll_interval` of continuous local apply failures.

### Transitions

- **Successful incremental from a peer:** the peer is fresh again, its `refresh_required` flag is cleared, the node
  counts as synced, and any `failed` condition is cleared.
- **Supplier reports a refresh is required:** the node is `refresh_required` until that supplier answers an incremental
  normally again or a refresh succeeds. With `automatic_refresh` the refresh starts immediately.
- **Refresh:** `refreshing` while it runs. On success every `refresh_required` flag is cleared and the node is synced. A
  refresh is applied in a single transaction, so a failed refresh leaves the content unchanged and the state returns to
  what it was before (`refresh_required`, `catching_up`, or `healthy` for an operator requested refresh of a synced
  node).
- **Connection failure or failed exchange** (timeout, protocol or decode error, the supplier closed the connection): the
  peer keeps its last successful sync time and goes stale once the stale window passes, making the node `degraded`.
- **Local apply failure** (this node could not read its replication state, or could not apply or commit what the
  supplier sent): the node becomes `failed` if this continues for the failed window. A successful sync with any supplier
  clears it.

`failed` deliberately only covers failures to apply changes locally. Suppliers that are unreachable, however long, only
make the node `degraded`: in a partition, or in a two node topology that lost one node, turning every survivor not ready
would turn a replication problem into a full outage. Alert on `degraded` instead (see below).

### Startup

When the server starts with replication configured, it decides whether it holds the domain's content from its
replication update vector (RUV):

- If the RUV records changes that originated on another server, the node has received a refresh or an incremental before
  and starts `healthy` (ready). Active servers write an anchor into the RUV every purge interval, so a synced node keeps
  its peers there.
- If the RUV only records this node's own changes, the node is a fresh replica and starts `catching_up` (not ready)
  until its first successful refresh or incremental. A fresh replica's first incremental is normally answered with a
  domain mismatch, so it moves to `refresh_required` until it is refreshed (automatically with `automatic_refresh`, or
  with `kubidmd refresh-replication-consumer`).
- If replication is configured without supplier peers (an empty peer list, or only `allow-pull` consumers), there is
  nothing to wait for: the node starts `healthy`.

A node whose RUV no longer names any other server because every peer has been gone for longer than the changelog (7
days) is treated as fresh too, and is not ready until a supplier is reachable again.

When a new replica joins an existing topology, the existing nodes that pull from it are answered with a domain mismatch
until the new replica has been refreshed, so they also report `refresh_required` for that window. To keep them serving,
configure the new replica as an `allow-pull` consumer on the existing nodes first, refresh it, and only then switch them
to `mutual-pull` (or `pull`) from it.

## Database Health

The `database_health` field is `unhealthy` (not ready) when either of these checks last failed:

| Check  | Fails when                                                                                       | Recovers when                      |
| ------ | ------------------------------------------------------------------------------------------------ | ---------------------------------- |
| Commit | The backend commit of a write transaction fails (database or IO error, for example a full disk)  | The next write transaction commits |
| Verify | The online consistency verification that ends every admin socket `MaintenanceRun` reports errors | The next verification reports none |

Changes rejected by schema, access control or plugin validation never reach the backend commit and do not affect the
database health. Search errors do not affect it either. The two checks recover independently: a successful write does
not clear a corruption found by a verification.

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
3. **Fresh replicas wait for their first sync** - a new replica is not ready until it has received the domain's content
4. **Refresh operations take replicas offline** - when a replica needs or is performing a refresh, it reports as not
   ready
5. **No quorum or leader election** - each replica makes independent readiness decisions based on local state

This design prioritizes availability while ensuring a node never serves content it has not received from the domain.

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
   with the next successful write (check disk space and permissions); a verification failure clears with the next clean
   verification, and may require a reindex, a refresh from a peer, or a restore from backup.

3. **`replication_state` is `catching_up`:** The node has never synced from a supplier. Check that a supplier is
   reachable, then refresh the node (automatically with `automatic_refresh`, or with
   `kubidmd refresh-replication-consumer`).

4. **`replication_state` is `refresh_required`:** A supplier reported that this node's content must be refreshed: it is
   a new replica, it has fallen further behind than the changelog, or a supplier is itself a new, not yet refreshed
   replica. With `automatic_refresh` this happens automatically; if it persists, check:
   - Network connectivity to peers
   - Peer availability
   - Replication configuration

5. **`replication_state` is `failed`:** This node has been unable to apply the changes its suppliers send. Check the
   logs for `Consumer was not able to apply changes`; a refresh from a healthy peer usually resolves it.

6. **`replication_state` is `refreshing`:** Replica is currently performing a full refresh. This is normal and will
   complete automatically. If it takes too long, check:
   - Network bandwidth
   - Database size
   - Peer load

7. **`message` reports maintenance:** The node is drained for a maintenance operation. Check `/maintenance` for the
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
