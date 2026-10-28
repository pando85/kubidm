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
    assert_eq!(body["peers"]["foreign"], 0);
}

// A freshly created node configured to pull from a supplier has never received the
// domain's content: it must not take traffic before its first successful sync.
fn origin_replication() -> serde_json::Value {
    replication_section(json!({
        "repl://partner1.example.com:8444": {
            "type": "mutual-pull",
            "partner_cert": TEST_REPL_CERT,
        },
        "repl://partner2.example.com:8444": {
            "type": "mutual-pull",
            "partner_cert": TEST_REPL_CERT,
        },
    }))
}

// The first node of a new cluster created the domain and has never synced from its
// partners, which do not exist yet. Without automatic_refresh it holds the domain's content
// by configuration and must be ready, or an ordered rollout never starts the next node.
#[kubidmd_testkit::test(repl_config = serde_json::from_value(origin_replication()).ok())]
async fn test_readyz_domain_origin_is_ready(rsclient: &kubidm_client::KubidmClient) {
    let (status, body) = get_readyz(rsclient).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["serving_ready"], "ready");
    assert_eq!(body["replication_state"], "healthy");
    assert_eq!(body["peers"]["total"], 2);
}

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
    assert_eq!(body["peers"]["foreign"], 0);
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

/// A replica configured with `automatic_refresh` from `PEER`.
fn replicated_tracker(has_synced: bool) -> ReplicationStateTracker {
    let tracker = ReplicationStateTracker::new();
    tracker.mark_startup_complete(
        Some(ReplicationStartup {
            supplier_peers: vec![PEER.to_string()],
            automatic_refresh: true,
            poll_interval: Duration::from_secs(15),
            has_synced,
            sync_evidence: has_synced,
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
    assert!(!peers[0].foreign_domain);
    // An unreachable peer is not reported as being in another domain.
    let status = tracker.build_readiness_status(T0 + 60);
    assert_eq!(status.peers.map(|peers| peers.foreign), Some(0));
    assert_eq!(status.message, "Ready to serve traffic");

    tracker.notify_replication_connected(PEER);
    tracker.notify_replication_incremental_success(PEER, T0 + 75);
    assert_eq!(
        tracker.get_replication_state(T0 + 75),
        ReplicationState::Healthy
    );
}

#[test]
fn test_tracker_foreign_peer_needs_operator() {
    // A synced replica whose supplier answers from another domain is never refreshed from
    // it automatically. It keeps serving, and /readyz says that an operator must act.
    let tracker = replicated_tracker(true);
    assert!(!tracker.notify_replication_domain_mismatch(PEER, T0 + 15));
    let status = tracker.build_readiness_status(T0 + 15);
    assert_eq!(status.serving_ready, ServingReadiness::Ready);
    assert_eq!(status.replication_state, ReplicationState::Degraded);
    let json = serde_json::to_value(&status).expect("Failed to serialize");
    assert_eq!(json["peers"]["total"], 1);
    assert_eq!(json["peers"]["stale"], 1);
    assert_eq!(json["peers"]["foreign"], 1);
    assert_eq!(
        json["message"],
        "Degraded: 1 peer(s) in another domain; operator action required"
    );
}

#[test]
fn test_tracker_apply_failures_fail_replication() {
    let tracker = replicated_tracker(true);
    // Twenty 15 second intervals of ongoing failures to apply changes fail replication.
    let mut now = T0;
    while now < T0 + 300 {
        tracker.notify_replication_apply_failure(now);
        now += 15;
    }
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

#[test]
fn test_tracker_one_apply_failure_then_unreachable_is_not_failed() {
    let tracker = replicated_tracker(true);
    tracker.notify_replication_apply_failure(T0);
    let mut now = T0;
    while now < T0 + 3600 {
        now += 15;
        tracker.notify_replication_connect_failure(PEER, now);
    }
    assert_eq!(
        tracker.get_replication_state(now),
        ReplicationState::Degraded
    );
    assert_eq!(
        tracker.compute_serving_readiness(now),
        ServingReadiness::Ready
    );
}
