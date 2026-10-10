//! Tests for health and readiness endpoints.

use kubidmd_lib::status::{DatabaseHealth, ReplicationState, ServingReadiness};

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
    assert!(body["active_operation_id"].is_null());
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

#[test]
fn test_tracker_lifecycle_transitions() {
    use kubidmd_lib::status::ReplicationStateTracker;

    let tracker = ReplicationStateTracker::new();

    assert_eq!(tracker.get_server_phase(), "bootstrap");

    tracker.mark_startup_complete(false);

    assert_eq!(tracker.get_server_phase(), "running");
    assert_eq!(tracker.get_database_health(), DatabaseHealth::Healthy);
    assert_eq!(tracker.get_replication_state(), ReplicationState::Healthy);
    assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);
}

#[test]
fn test_tracker_database_failure_makes_not_ready() {
    use kubidmd_lib::status::ReplicationStateTracker;

    let tracker = ReplicationStateTracker::new();
    tracker.mark_startup_complete(false);
    assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);

    tracker.mark_database_failure();
    assert_eq!(tracker.get_database_health(), DatabaseHealth::Unhealthy);
    assert_eq!(
        tracker.compute_serving_readiness(),
        ServingReadiness::NotReady
    );
}

#[test]
fn test_tracker_replication_refresh_cycle() {
    use kubidmd_lib::status::ReplicationStateTracker;

    let tracker = ReplicationStateTracker::new();
    tracker.mark_startup_complete(true);

    tracker.notify_replication_refresh_required();
    assert_eq!(
        tracker.get_replication_state(),
        ReplicationState::RefreshRequired
    );
    assert_eq!(
        tracker.compute_serving_readiness(),
        ServingReadiness::NotReady
    );

    tracker.notify_replication_refresh_started();
    assert_eq!(
        tracker.get_replication_state(),
        ReplicationState::Refreshing
    );
    assert_eq!(
        tracker.compute_serving_readiness(),
        ServingReadiness::NotReady
    );

    tracker.notify_replication_refresh_success();
    assert_eq!(
        tracker.get_replication_state(),
        ReplicationState::CatchingUp
    );
    assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);

    tracker.notify_replication_incremental_success(12345);
    assert_eq!(tracker.get_replication_state(), ReplicationState::Healthy);
    assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);
}

#[test]
fn test_tracker_refresh_failure_returns_to_refresh_required() {
    use kubidmd_lib::status::ReplicationStateTracker;

    let tracker = ReplicationStateTracker::new();
    tracker.mark_startup_complete(true);

    tracker.notify_replication_refresh_required();
    tracker.notify_replication_refresh_started();
    assert_eq!(
        tracker.get_replication_state(),
        ReplicationState::Refreshing
    );

    tracker.notify_replication_refresh_failed();
    assert_eq!(
        tracker.get_replication_state(),
        ReplicationState::RefreshRequired
    );
    assert_eq!(
        tracker.compute_serving_readiness(),
        ServingReadiness::NotReady
    );
}

#[test]
fn test_tracker_peer_state_from_config() {
    use kubidmd_lib::status::ReplicationStateTracker;

    let tracker = ReplicationStateTracker::new();
    assert!(tracker.get_peers().is_none());

    tracker.init_peers_from_config(vec![
        "repl://peer1.example.com:8443".to_string(),
        "repl://peer2.example.com:8443".to_string(),
    ]);

    let peers = tracker.get_peers().expect("peers should be set");
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].url, "repl://peer1.example.com:8443");
    assert!(!peers[0].connected);

    tracker.update_peer_connected("repl://peer1.example.com:8443", 12345);
    let peers = tracker.get_peers().expect("peers should be set");
    assert!(peers[0].connected);
    assert_eq!(peers[0].last_success, Some(12345));

    tracker.update_peer_disconnected("repl://peer1.example.com:8443");
    let peers = tracker.get_peers().expect("peers should be set");
    assert!(!peers[0].connected);
}

#[test]
fn test_tracker_connect_failure_does_not_affect_readiness() {
    use kubidmd_lib::status::ReplicationStateTracker;

    let tracker = ReplicationStateTracker::new();
    tracker.mark_startup_complete(true);
    assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);

    tracker.notify_replication_connect_failure(12345);
    assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);
    assert!(tracker.get_last_replication_failure().is_some());
}

#[test]
fn test_tracker_degraded_recovery_on_connect() {
    use kubidmd_lib::status::ReplicationStateTracker;

    let tracker = ReplicationStateTracker::new();
    tracker.mark_startup_complete(true);

    tracker.set_replication_state(ReplicationState::Degraded);
    assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);

    tracker.notify_replication_connect_success();
    assert_eq!(
        tracker.get_replication_state(),
        ReplicationState::CatchingUp
    );
}
