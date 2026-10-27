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
is `null` when replication is not configured.

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

| Field           | Description                                   |
| --------------- | --------------------------------------------- |
| `peers.total`   | Number of configured replication peers        |
| `peers.healthy` | Peers that are currently connected and fresh  |
| `peers.stale`   | Peers whose replication relationship is stale |

**Response (503 Service Unavailable - Not Ready):**

```json
{
  "serving_ready": "not_ready",
  "replication_state": "refresh_required",
  "database_health": "healthy",
  "server_phase": "running",
  "peers": null,
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

The `replication_state` field indicates the current replication health:

| State              | Description                                                       | Serving Safe? |
| ------------------ | ----------------------------------------------------------------- | ------------- |
| `healthy`          | Replication is healthy and up-to-date                             | Yes           |
| `catching_up`      | Replica is catching up within acceptable bounds                   | Yes           |
| `degraded`         | Replication is degraded (significant lag, some peers unreachable) | Yes           |
| `refresh_required` | Replica requires a full refresh from a peer                       | No            |
| `refreshing`       | Replica is currently performing a full refresh                    | No            |
| `failed`           | Replication has failed and requires operator intervention         | No            |

## Readiness Decision Matrix

A replica is considered **ready** when ALL of the following are true:

- `server_phase` is `"running"`
- `database_health` is `"healthy"`
- `replication_state` is one of: `healthy`, `catching_up`, or `degraded`
- The maintenance state is `serving`

A replica is **not ready** when ANY of the following are true:

- Server is still initializing (phase is `bootstrap`, `schema_ready`, or `domain_info_ready`)
- Database health check failed
- Replication state is `refresh_required`, `refreshing`, or `failed`
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

1. **All replicas can serve traffic** when in `healthy`, `catching_up`, or `degraded` states
2. **Temporary disconnections are tolerated** - a replica with valid local data remains ready even if peers are
   temporarily unreachable
3. **Refresh operations take replicas offline** - when a replica needs or is performing a refresh, it reports as not
   ready
4. **No quorum or leader election** - each replica makes independent readiness decisions based on local state

This design prioritizes availability while ensuring data consistency. A catching-up replica can still serve reads; it
will eventually converge with peers.

## Monitoring and Alerting

The `/readyz` endpoint exposes state that can be monitored by polling the endpoint and parsing the JSON response.

### Recommended Alerts

1. **Replication Failed:** Alert when `replication_state` is `failed` for more than 5 minutes
2. **Refresh Required:** Alert when `replication_state` is `refresh_required` for more than 10 minutes
3. **Database Unhealthy:** Alert immediately when `database_health` is `unhealthy`
4. **Not Ready:** Alert when a replica has been `not_ready` for more than 15 minutes (excluding initialization)

### Example Blackbox Exporter Configuration

To monitor readiness with Prometheus, use the blackbox exporter to probe the `/readyz` endpoint and alert on non-200
responses or specific JSON field values.

## Troubleshooting

### Replica Shows Not Ready

Check the `/readyz` endpoint response to determine the cause:

1. **`server_phase` not `running`:** Server is still initializing. Wait for initialization to complete.

2. **`database_health` is `unhealthy`:** Database backend has encountered a failure. Check logs for database errors. May
   require database repair or restore from backup.

3. **`replication_state` is `refresh_required`:** Replica has fallen too far behind and needs a full refresh. This
   happens automatically, but if it persists, check:
   - Network connectivity to peers
   - Peer availability
   - Replication configuration

4. **`replication_state` is `refreshing`:** Replica is currently performing a full refresh. This is normal and will
   complete automatically. If it takes too long, check:
   - Network bandwidth
   - Database size
   - Peer load

5. **`message` reports maintenance:** The node is drained for a maintenance operation. Check `/maintenance` for the
   state. A `failed` state needs the operator to retry or resume the operation; use the admin socket `MaintenanceStatus`
   request for the operation ID and the last error.

### Replica Shows Ready But Not Serving Traffic

Check:

- Kubernetes Service endpoints include the pod
- Network policies allow traffic
- Load balancer health checks are configured correctly
- TLS certificates are valid

## Related Issues

- [Issue #361: Observability: expose replication state and serving readiness](https://github.com/pando85/kubidm/issues/361)
- [Issue #359: Related observability improvements](https://github.com/pando85/kubidm/issues/359)
