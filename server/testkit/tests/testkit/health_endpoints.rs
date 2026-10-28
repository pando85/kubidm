//! Tests for health and readiness endpoints.

use std::time::Duration;

use kubidmd_lib::status::{
    DatabaseCheck, DatabaseHealth, ReplicationStartup, ReplicationState, ReplicationStateTracker,
    ServingReadiness,
};
use serde_json::json;

#[kubidmd_testkit::test]
async fn test_healthz_endpoint(rsclient: &kubidm_client::KubidmClient) {
    let client = rsclient.client();

    let res = client
        .get(rsclient.make_url("/healthz"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.expect("Failed to parse JSON");
    assert_eq!(body["alive"], true);
}

#[kubidmd_testkit::test]
async fn test_maintenance_endpoint_after_startup(rsclient: &kubidm_client::KubidmClient) {
    let client = rsclient.client();

    let res = client
        .get(rsclient.make_url("/maintenance"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.expect("Failed to parse JSON");
    assert_eq!(body["state"], "serving");
    // The unauthenticated endpoint never exposes the operation id or internal errors.
    assert!(body.get("active_operation_id").is_none());
    assert!(body.get("last_error").is_none());
    assert_eq!(body["capabilities"]["api_version"], "v1");
    assert_eq!(body["capabilities"]["drain"], true);
    assert_eq!(body["capabilities"]["replication_fence"], true);
    assert_eq!(body["capabilities"]["sync_until"], true);
    assert_eq!(body["capabilities"]["reindex"], true);
    assert_eq!(body["capabilities"]["verify"], true);
    assert_eq!(body["capabilities"]["vacuum"], false);
    assert_eq!(body["capabilities"]["restore"], false);
}

#[kubidmd_testkit::test]
async fn test_readyz_endpoint_after_startup(rsclient: &kubidm_client::KubidmClient) {
    let client = rsclient.client();

    let res = client
        .get(rsclient.make_url("/readyz"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.expect("Failed to parse JSON");

    assert_eq!(body["serving_ready"], "ready");
    assert_eq!(body["server_phase"], "running");
    assert_eq!(body["database_health"], "healthy");
    assert_eq!(body["message"], "Ready to serve traffic");
    assert_eq!(body["replication_state"], "healthy");
    // Without replication there is no peer summary.
    assert!(body["peers"].is_null());
}

/// A self-signed test certificate, encoded as the replication config expects it.
const TEST_REPL_CERT: &str = "MIICeDCCAh6gAwIBAgIBAjAKBggqhkjOPQQDAjCBhDELMAkGA1UEBhMCQVUxDDAKBgNVBAgMA1FMRDEPMA0GA1UECgwGS2FuaWRtMRwwGgYDVQQDDBNLYW5pZG0gR2VuZXJhdGVkIENBMTgwNgYDVQQLDC9EZXZlbG9wbWVudCBhbmQgRXZhbHVhdGlvbiAtIE5PVCBGT1IgUFJPRFVDVElPTjAeFw0yNTA3MjkwMzMxMDNaFw0yNTA4MDMwMzMxMDNaMHoxCzAJBgNVBAYTAkFVMQwwCgYDVQQIDANRTEQxDzANBgNVBAoMBkthbmlkbTESMBAGA1UEAwwJbG9jYWxob3N0MTgwNgYDVQQLDC9EZXZlbG9wbWVudCBhbmQgRXZhbHVhdGlvbiAtIE5PVCBGT1IgUFJPRFVDVElPTjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPFkpVzFH-feItm9JFFm_noge-BlZLpdGWOuSUvfoivAzCgPr7KrnGd8kUzIyJermePzu2SVQLaEt_7GY8Ha-2ujgYkwgYYwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFOjucEtXmj_wQ7npVaMOyDtLU6dUMB8GA1UdIwQYMBaAFNo5o-5ea0sNMlW_75VgGJCv2AcJMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNIADBFAiEA1TACf4eSg07LRiKhlMgA-6xxztxiZCuV6LakRp7FZdECIFp0rFSiFJdkLEO9IyqYc-zPW770ta41VMU3u9UQfHxF";

/// A `[replication]` section with the given peers, as the server config holds it. The
/// integration test servers never start the replication listener, only the tracker.
fn replication_section(peers: serde_json::Value) -> serde_json::Value {
    let mut section = json!({
        "origin": "repl://localhost:8444",
        "bindaddress": "127.0.0.1:8444",
    });
    if let (Some(section), Some(peers)) = (section.as_object_mut(), peers.as_object()) {
        section.extend(peers.clone());
    }
    section
}

async fn get_readyz(rsclient: &kubidm_client::KubidmClient) -> (u16, serde_json::Value) {
    let res = rsclient
        .client()
        .get(rsclient.make_url("/readyz"))
        .send()
        .await
        .expect("Failed to send request");
    let status = res.status().as_u16();
    let body = res.json().await.expect("Failed to parse JSON");
    (status, body)
}

// Replication is configured, but there is nobody to pull from (an empty peer map, or only
// allow-pull consumers): the node does not wait for a sync that can never happen.
fn consumer_only_replication() -> serde_json::Value {
    replication_section(json!({
        "repl://consumer.example.com:8444": {
            "type": "allow-pull",
            "consumer_cert": TEST_REPL_CERT,
        },
    }))
}

#[kubidmd_testkit::test(repl_config = serde_json::from_value(consumer_only_replication()).ok())]
async fn test_readyz_replication_without_suppliers_is_ready(
    rsclient: &kubidm_client::KubidmClient,
) {
    let (status, body) = get_readyz(rsclient).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["serving_ready"], "ready");
    assert_eq!(body["replication_state"], "healthy");
    assert_eq!(body["peers"]["total"], 0);
}

// A freshly created node configured to pull from a supplier has never received the
// domain's content: it must not take traffic before its first successful sync.
fn pull_replication() -> serde_json::Value {
    replication_section(json!({
        "repl://supplier.example.com:8444": {
            "type": "pull",
            "supplier_cert": TEST_REPL_CERT,
            "automatic_refresh": true,
        },
    }))
}

#[kubidmd_testkit::test(repl_config = serde_json::from_value(pull_replication()).ok())]
async fn test_readyz_fresh_replica_is_not_ready(rsclient: &kubidm_client::KubidmClient) {
    let (status, body) = get_readyz(rsclient).await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["serving_ready"], "not_ready");
    assert_eq!(body["replication_state"], "catching_up");
    assert_eq!(body["database_health"], "healthy");
    assert_eq!(body["server_phase"], "running");
    assert_eq!(body["peers"]["total"], 1);
    assert_eq!(body["peers"]["healthy"], 0);
    assert_eq!(
        body["message"],
        "Replication state 'catching_up' does not allow serving"
    );
}

#[kubidmd_testkit::test]
async fn test_status_endpoint_legacy(rsclient: &kubidm_client::KubidmClient) {
    let client = rsclient.client();

    let res = client
        .get(rsclient.make_url("/status"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), 200);

    let body: bool = res.json().await.expect("Failed to parse JSON");
    assert!(body);
}

#[test]
fn test_replication_state_serialization() {
    let state = ReplicationState::Healthy;
    let json = serde_json::to_string(&state).expect("Failed to serialize");
    assert_eq!(json, "\"healthy\"");

    let state: ReplicationState =
        serde_json::from_str("\"catching_up\"").expect("Failed to deserialize");
    assert_eq!(state, ReplicationState::CatchingUp);
}

#[test]
fn test_serving_readiness_serialization() {
    let readiness = ServingReadiness::Ready;
    let json = serde_json::to_string(&readiness).expect("Failed to serialize");
    assert_eq!(json, "\"ready\"");

    let readiness: ServingReadiness =
        serde_json::from_str("\"not_ready\"").expect("Failed to deserialize");
    assert_eq!(readiness, ServingReadiness::NotReady);
}

#[test]
fn test_database_health_serialization() {
    let health = DatabaseHealth::Healthy;
    let json = serde_json::to_string(&health).expect("Failed to serialize");
    assert_eq!(json, "\"healthy\"");

    let health: DatabaseHealth =
        serde_json::from_str("\"unhealthy\"").expect("Failed to deserialize");
    assert_eq!(health, DatabaseHealth::Unhealthy);
}

const T0: u64 = 1_000_000;
const PEER: &str = "repl://peer1.example.com:8444";

fn replicated_tracker(has_peer_changes: bool) -> ReplicationStateTracker {
    let tracker = ReplicationStateTracker::new();
    tracker.mark_startup_complete(
        Some(ReplicationStartup {
            supplier_peers: vec![PEER.to_string()],
            poll_interval: Duration::from_secs(15),
            has_peer_changes,
        }),
        T0,
    );
    tracker
}

#[test]
fn test_tracker_lifecycle_transitions() {
    let tracker = ReplicationStateTracker::new();

    assert_eq!(tracker.get_server_phase(), "bootstrap");
    assert_eq!(
        tracker.compute_serving_readiness(T0),
        ServingReadiness::NotReady
    );

    tracker.mark_startup_complete(None, T0);

    assert_eq!(tracker.get_server_phase(), "running");
    assert_eq!(tracker.get_database_health(), DatabaseHealth::Healthy);
    assert_eq!(tracker.get_replication_state(T0), ReplicationState::Healthy);
    assert_eq!(
        tracker.compute_serving_readiness(T0),
        ServingReadiness::Ready
    );
}

#[test]
fn test_tracker_database_failure_makes_not_ready() {
    let tracker = ReplicationStateTracker::new();
    tracker.mark_startup_complete(None, T0);
    assert_eq!(
        tracker.compute_serving_readiness(T0),
        ServingReadiness::Ready
    );

    tracker.mark_database_failure(DatabaseCheck::Commit);
    assert_eq!(tracker.get_database_health(), DatabaseHealth::Unhealthy);
    assert_eq!(
        tracker.compute_serving_readiness(T0),
        ServingReadiness::NotReady
    );

    tracker.mark_database_healthy(DatabaseCheck::Commit);
    assert_eq!(
        tracker.compute_serving_readiness(T0),
        ServingReadiness::Ready
    );
}

#[test]
fn test_tracker_fresh_replica_refresh_cycle() {
    let tracker = replicated_tracker(false);
    assert_eq!(
        tracker.get_replication_state(T0),
        ReplicationState::CatchingUp
    );
    assert_eq!(
        tracker.compute_serving_readiness(T0),
        ServingReadiness::NotReady
    );

    tracker.notify_replication_connected(PEER);
    tracker.notify_replication_refresh_required(PEER);
    assert_eq!(
        tracker.get_replication_state(T0),
        ReplicationState::RefreshRequired
    );

    tracker.notify_replication_refresh_started();
    assert_eq!(
        tracker.get_replication_state(T0),
        ReplicationState::Refreshing
    );
    assert_eq!(
        tracker.compute_serving_readiness(T0),
        ServingReadiness::NotReady
    );

    tracker.notify_replication_refresh_failed(T0 + 1);
    assert_eq!(
        tracker.get_replication_state(T0 + 1),
        ReplicationState::RefreshRequired
    );

    tracker.notify_replication_refresh_started();
    tracker.notify_replication_refresh_success(PEER, T0 + 2);
    assert_eq!(
        tracker.get_replication_state(T0 + 2),
        ReplicationState::Healthy
    );
    assert_eq!(
        tracker.compute_serving_readiness(T0 + 2),
        ServingReadiness::Ready
    );

    tracker.notify_replication_incremental_success(PEER, T0 + 17);
    assert_eq!(
        tracker.get_replication_state(T0 + 17),
        ReplicationState::Healthy
    );
}

#[test]
fn test_tracker_unreachable_supplier_degrades_but_stays_ready() {
    let tracker = replicated_tracker(true);
    assert_eq!(
        tracker.compute_serving_readiness(T0),
        ServingReadiness::Ready
    );

    // Four 15 second intervals without a sync make the peer stale.
    tracker.notify_replication_connect_failure(PEER, T0 + 60);
    assert_eq!(
        tracker.get_replication_state(T0 + 60),
        ReplicationState::Degraded
    );
    assert_eq!(
        tracker.compute_serving_readiness(T0 + 60),
        ServingReadiness::Ready
    );
    assert!(tracker.get_last_replication_failure().is_some());
    let peers = tracker.get_peers(T0 + 60).expect("peers are tracked");
    assert!(peers[0].stale);
    assert!(!peers[0].connected);

    tracker.notify_replication_connected(PEER);
    tracker.notify_replication_incremental_success(PEER, T0 + 75);
    assert_eq!(
        tracker.get_replication_state(T0 + 75),
        ReplicationState::Healthy
    );
}

#[test]
fn test_tracker_apply_failures_fail_replication() {
    let tracker = replicated_tracker(true);
    tracker.notify_replication_apply_failure(T0);
    // Twenty 15 second intervals of failing to apply changes fail replication.
    assert_eq!(
        tracker.get_replication_state(T0 + 299),
        ReplicationState::Degraded
    );
    assert_eq!(
        tracker.get_replication_state(T0 + 300),
        ReplicationState::Failed
    );
    assert_eq!(
        tracker.compute_serving_readiness(T0 + 300),
        ServingReadiness::NotReady
    );

    tracker.notify_replication_incremental_success(PEER, T0 + 301);
    assert_eq!(
        tracker.compute_serving_readiness(T0 + 301),
        ServingReadiness::Ready
    );
}
