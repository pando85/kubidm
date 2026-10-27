//! Replication-aware health and readiness tracking for Kubidm.
//!
//! This module provides separate liveness and readiness semantics for Kubernetes-style
//! health checks. Liveness indicates the process is running; readiness indicates whether
//! the replica is safe to serve production traffic.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

/// Replication state machine for a Kubidm replica.
///
/// This represents the health of replication from the perspective of this node,
/// independent of whether it can serve traffic (see `ServingReadiness`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationState {
    /// Replication is healthy and up-to-date (or within acceptable lag window).
    Healthy,
    /// Replica is catching up to peers but within acceptable bounds.
    CatchingUp,
    /// Replication is degraded (e.g., significant lag, some peers unreachable).
    Degraded,
    /// Replica requires a full refresh from a peer.
    RefreshRequired,
    /// Replica is currently performing a full refresh.
    Refreshing,
    /// Replication has failed and requires operator intervention.
    Failed,
}

impl ReplicationState {
    /// Returns true if this state indicates the replica can safely serve traffic.
    pub fn is_serving_safe(&self) -> bool {
        matches!(
            self,
            ReplicationState::Healthy | ReplicationState::CatchingUp | ReplicationState::Degraded
        )
    }
}

impl std::fmt::Display for ReplicationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplicationState::Healthy => write!(f, "healthy"),
            ReplicationState::CatchingUp => write!(f, "catching_up"),
            ReplicationState::Degraded => write!(f, "degraded"),
            ReplicationState::RefreshRequired => write!(f, "refresh_required"),
            ReplicationState::Refreshing => write!(f, "refreshing"),
            ReplicationState::Failed => write!(f, "failed"),
        }
    }
}

/// Readiness state for serving traffic, independent of raw replication state.
///
/// This is what Kubernetes readiness probes should check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServingReadiness {
    /// Ready to serve traffic.
    Ready,
    /// Not ready to serve traffic (e.g., initial sync, refresh failed, DB error).
    NotReady,
}

impl ServingReadiness {
    pub fn is_ready(&self) -> bool {
        matches!(self, ServingReadiness::Ready)
    }
}

impl std::fmt::Display for ServingReadiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServingReadiness::Ready => write!(f, "ready"),
            ServingReadiness::NotReady => write!(f, "not_ready"),
        }
    }
}

/// Information about a replication peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PeerInfo {
    /// URL of the peer.
    pub url: String,
    /// Whether the peer connection is currently active.
    pub connected: bool,
    /// Timestamp of last successful replication/heartbeat (seconds since epoch).
    pub last_success: Option<u64>,
    /// Whether the peer relationship is considered stale.
    pub stale: bool,
}

/// Aggregate counts of replication peers.
///
/// This is what the unauthenticated readiness endpoint exposes: peer URLs and
/// replication timestamps are internal topology details and are not published there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub struct PeerSummary {
    /// Number of configured replication peers.
    pub total: usize,
    /// Peers that are currently connected and not stale.
    pub healthy: usize,
    /// Peers whose relationship is considered stale.
    pub stale: usize,
}

impl PeerSummary {
    pub fn from_peers(peers: &[PeerInfo]) -> Self {
        Self {
            total: peers.len(),
            healthy: peers.iter().filter(|p| p.connected && !p.stale).count(),
            stale: peers.iter().filter(|p| p.stale).count(),
        }
    }
}

/// Local database health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseHealth {
    /// Database is healthy and consistent.
    Healthy,
    /// Database has consistency issues.
    Unhealthy,
}

/// Comprehensive status response for the readiness endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReadinessStatus {
    /// Overall serving readiness (what Kubernetes should check).
    pub serving_ready: ServingReadiness,
    /// Current replication state.
    pub replication_state: ReplicationState,
    /// Local database health.
    pub database_health: DatabaseHealth,
    /// Server phase (bootstrap, schema_ready, domain_info_ready, running).
    pub server_phase: String,
    /// Counts of replication peers (if replication is configured).
    pub peers: Option<PeerSummary>,
    /// Human-readable status message.
    pub message: String,
}

/// Simple liveness response (process is alive).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LivenessStatus {
    /// Always true if the endpoint responds.
    pub alive: bool,
}

/// Request event for status queries.
pub struct StatusRequestEvent {
    pub eventid: Uuid,
}

/// Shared replication state tracker.
///
/// This is updated by the replication subsystem and read by the status endpoints.
#[derive(Debug, Clone)]
pub struct ReplicationStateTracker {
    inner: Arc<ReplicationStateInner>,
}

#[derive(Debug)]
struct ReplicationStateInner {
    replication_state: std::sync::RwLock<ReplicationState>,
    database_health: std::sync::RwLock<DatabaseHealth>,
    server_phase: std::sync::RwLock<String>,
    peers: std::sync::RwLock<Option<Vec<PeerInfo>>>,
    last_replication_success: AtomicU64,
    last_replication_failure: AtomicU64,
}

impl ReplicationStateTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ReplicationStateInner {
                replication_state: std::sync::RwLock::new(ReplicationState::Healthy),
                database_health: std::sync::RwLock::new(DatabaseHealth::Healthy),
                server_phase: std::sync::RwLock::new("bootstrap".to_string()),
                peers: std::sync::RwLock::new(None),
                last_replication_success: AtomicU64::new(0),
                last_replication_failure: AtomicU64::new(0),
            }),
        }
    }

    pub fn mark_startup_complete(&self, replication_configured: bool) {
        self.set_server_phase("running".to_string());
        self.set_database_health(DatabaseHealth::Healthy);
        if !replication_configured {
            self.set_replication_state(ReplicationState::Healthy);
        }
    }

    pub fn mark_database_failure(&self) {
        self.set_database_health(DatabaseHealth::Unhealthy);
    }

    pub fn notify_replication_refresh_required(&self) {
        self.set_replication_state(ReplicationState::RefreshRequired);
    }

    pub fn notify_replication_refresh_started(&self) {
        self.set_replication_state(ReplicationState::Refreshing);
    }

    pub fn notify_replication_refresh_success(&self) {
        self.set_replication_state(ReplicationState::CatchingUp);
    }

    pub fn notify_replication_refresh_failed(&self) {
        let current = self.get_replication_state();
        if current == ReplicationState::Refreshing {
            self.set_replication_state(ReplicationState::RefreshRequired);
        }
    }

    pub fn notify_replication_incremental_success(&self, now: u64) {
        self.record_replication_success(now);
        let current = self.get_replication_state();
        if current == ReplicationState::CatchingUp || current == ReplicationState::Healthy {
            self.set_replication_state(ReplicationState::Healthy);
        }
    }

    pub fn notify_replication_connect_failure(&self, now: u64) {
        self.record_replication_failure(now);
    }

    pub fn notify_replication_connect_success(&self) {
        let current = self.get_replication_state();
        if current == ReplicationState::Degraded {
            self.set_replication_state(ReplicationState::CatchingUp);
        }
    }

    pub fn init_peers_from_config(&self, peer_urls: Vec<String>) {
        if peer_urls.is_empty() {
            return;
        }
        let peers: Vec<PeerInfo> = peer_urls
            .into_iter()
            .map(|url| PeerInfo {
                url,
                connected: false,
                last_success: None,
                stale: false,
            })
            .collect();
        self.set_peers(Some(peers));
    }

    pub fn update_peer_connected(&self, peer_url: &str, now: u64) {
        if let Ok(mut lock) = self.inner.peers.write() {
            if let Some(ref mut peers) = *lock {
                if let Some(peer) = peers.iter_mut().find(|p| p.url == peer_url) {
                    peer.connected = true;
                    peer.last_success = Some(now);
                    peer.stale = false;
                }
            }
        }
    }

    pub fn update_peer_disconnected(&self, peer_url: &str) {
        if let Ok(mut lock) = self.inner.peers.write() {
            if let Some(ref mut peers) = *lock {
                if let Some(peer) = peers.iter_mut().find(|p| p.url == peer_url) {
                    peer.connected = false;
                }
            }
        }
    }

    pub fn set_replication_state(&self, state: ReplicationState) {
        if let Ok(mut lock) = self.inner.replication_state.write() {
            *lock = state;
        }
    }

    pub fn get_replication_state(&self) -> ReplicationState {
        self.inner
            .replication_state
            .read()
            .map(|s| *s)
            .unwrap_or(ReplicationState::Failed)
    }

    pub fn set_database_health(&self, health: DatabaseHealth) {
        if let Ok(mut lock) = self.inner.database_health.write() {
            *lock = health;
        }
    }

    pub fn get_database_health(&self) -> DatabaseHealth {
        self.inner
            .database_health
            .read()
            .map(|h| *h)
            .unwrap_or(DatabaseHealth::Unhealthy)
    }

    pub fn set_server_phase(&self, phase: String) {
        if let Ok(mut lock) = self.inner.server_phase.write() {
            *lock = phase;
        }
    }

    pub fn get_server_phase(&self) -> String {
        self.inner
            .server_phase
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    pub fn set_peers(&self, peers: Option<Vec<PeerInfo>>) {
        if let Ok(mut lock) = self.inner.peers.write() {
            *lock = peers;
        }
    }

    pub fn get_peers(&self) -> Option<Vec<PeerInfo>> {
        self.inner.peers.read().ok().and_then(|p| p.clone())
    }

    pub fn record_replication_success(&self, now: u64) {
        self.inner
            .last_replication_success
            .store(now, Ordering::SeqCst);
    }

    pub fn record_replication_failure(&self, now: u64) {
        self.inner
            .last_replication_failure
            .store(now, Ordering::SeqCst);
    }

    pub fn get_last_replication_success(&self) -> Option<u64> {
        let ts = self.inner.last_replication_success.load(Ordering::SeqCst);
        if ts == 0 {
            None
        } else {
            Some(ts)
        }
    }

    pub fn get_last_replication_failure(&self) -> Option<u64> {
        let ts = self.inner.last_replication_failure.load(Ordering::SeqCst);
        if ts == 0 {
            None
        } else {
            Some(ts)
        }
    }

    /// Compute serving readiness based on current state.
    pub fn compute_serving_readiness(&self) -> ServingReadiness {
        let repl_state = self.get_replication_state();
        let db_health = self.get_database_health();
        let phase = self.get_server_phase();

        // Not ready if database is unhealthy
        if db_health != DatabaseHealth::Healthy {
            return ServingReadiness::NotReady;
        }

        // Not ready if server is not in Running phase
        if phase != "running" {
            return ServingReadiness::NotReady;
        }

        // Ready if replication state allows serving
        if repl_state.is_serving_safe() {
            ServingReadiness::Ready
        } else {
            ServingReadiness::NotReady
        }
    }

    /// Build a comprehensive readiness status response.
    pub fn build_readiness_status(&self) -> ReadinessStatus {
        let serving_ready = self.compute_serving_readiness();
        let replication_state = self.get_replication_state();
        let database_health = self.get_database_health();
        let server_phase = self.get_server_phase();
        let peers = self
            .get_peers()
            .map(|peers| PeerSummary::from_peers(&peers));

        let message = match serving_ready {
            ServingReadiness::Ready => "Ready to serve traffic".to_string(),
            ServingReadiness::NotReady => {
                if database_health != DatabaseHealth::Healthy {
                    "Database health check failed".to_string()
                } else if server_phase != "running" {
                    format!("Server not yet ready (phase: {})", server_phase)
                } else {
                    format!(
                        "Replication state '{}' does not allow serving",
                        replication_state
                    )
                }
            }
        };

        ReadinessStatus {
            serving_ready,
            replication_state,
            database_health,
            server_phase,
            peers,
            message,
        }
    }
}

impl Default for ReplicationStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Status actor for handling status requests.
pub struct StatusActor {
    tracker: ReplicationStateTracker,
}

impl StatusActor {
    pub fn start() -> &'static Self {
        let tracker = ReplicationStateTracker::new();
        let x = Box::new(StatusActor { tracker });

        let x_ptr = Box::into_raw(x);
        unsafe { &(*x_ptr) }
    }

    pub fn start_with_tracker(tracker: ReplicationStateTracker) -> &'static Self {
        let x = Box::new(StatusActor { tracker });

        let x_ptr = Box::into_raw(x);
        unsafe { &(*x_ptr) }
    }

    pub async fn handle_request(&self, _event: StatusRequestEvent) -> bool {
        trace!("status handler complete");
        true
    }

    pub fn get_tracker(&self) -> &ReplicationStateTracker {
        &self.tracker
    }

    pub fn get_tracker_clone(&self) -> ReplicationStateTracker {
        self.tracker.clone()
    }

    pub fn get_readiness_status(&self) -> ReadinessStatus {
        self.tracker.build_readiness_status()
    }

    pub fn get_liveness_status(&self) -> LivenessStatus {
        LivenessStatus { alive: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replication_state_serving_safe() {
        assert!(ReplicationState::Healthy.is_serving_safe());
        assert!(ReplicationState::CatchingUp.is_serving_safe());
        assert!(ReplicationState::Degraded.is_serving_safe());
        assert!(!ReplicationState::RefreshRequired.is_serving_safe());
        assert!(!ReplicationState::Refreshing.is_serving_safe());
        assert!(!ReplicationState::Failed.is_serving_safe());
    }

    #[test]
    fn test_serving_readiness() {
        assert!(ServingReadiness::Ready.is_ready());
        assert!(!ServingReadiness::NotReady.is_ready());
    }

    #[test]
    fn test_replication_state_tracker_default() {
        let tracker = ReplicationStateTracker::new();
        assert_eq!(tracker.get_replication_state(), ReplicationState::Healthy);
        assert_eq!(tracker.get_database_health(), DatabaseHealth::Healthy);
        assert_eq!(tracker.get_server_phase(), "bootstrap");
        assert!(tracker.get_peers().is_none());
    }

    #[test]
    fn test_replication_state_tracker_setters() {
        let tracker = ReplicationStateTracker::new();

        tracker.set_replication_state(ReplicationState::CatchingUp);
        assert_eq!(
            tracker.get_replication_state(),
            ReplicationState::CatchingUp
        );

        tracker.set_database_health(DatabaseHealth::Unhealthy);
        assert_eq!(tracker.get_database_health(), DatabaseHealth::Unhealthy);

        tracker.set_server_phase("running".to_string());
        assert_eq!(tracker.get_server_phase(), "running");

        let peers = vec![PeerInfo {
            url: "https://peer1.example.com".to_string(),
            connected: true,
            last_success: Some(1234567890),
            stale: false,
        }];
        tracker.set_peers(Some(peers.clone()));
        assert_eq!(tracker.get_peers(), Some(peers));
    }

    #[test]
    fn test_compute_serving_readiness_ready() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("running".to_string());
        tracker.set_replication_state(ReplicationState::Healthy);
        tracker.set_database_health(DatabaseHealth::Healthy);

        assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);
    }

    #[test]
    fn test_compute_serving_readiness_not_ready_bootstrap() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("bootstrap".to_string());
        tracker.set_replication_state(ReplicationState::Healthy);
        tracker.set_database_health(DatabaseHealth::Healthy);

        assert_eq!(
            tracker.compute_serving_readiness(),
            ServingReadiness::NotReady
        );
    }

    #[test]
    fn test_compute_serving_readiness_not_ready_db_unhealthy() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("running".to_string());
        tracker.set_replication_state(ReplicationState::Healthy);
        tracker.set_database_health(DatabaseHealth::Unhealthy);

        assert_eq!(
            tracker.compute_serving_readiness(),
            ServingReadiness::NotReady
        );
    }

    #[test]
    fn test_compute_serving_readiness_not_ready_refresh_required() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("running".to_string());
        tracker.set_replication_state(ReplicationState::RefreshRequired);
        tracker.set_database_health(DatabaseHealth::Healthy);

        assert_eq!(
            tracker.compute_serving_readiness(),
            ServingReadiness::NotReady
        );
    }

    #[test]
    fn test_compute_serving_readiness_catching_up_is_ready() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("running".to_string());
        tracker.set_replication_state(ReplicationState::CatchingUp);
        tracker.set_database_health(DatabaseHealth::Healthy);

        assert_eq!(tracker.compute_serving_readiness(), ServingReadiness::Ready);
    }

    #[test]
    fn test_build_readiness_status() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("running".to_string());
        tracker.set_replication_state(ReplicationState::Healthy);
        tracker.set_database_health(DatabaseHealth::Healthy);

        let status = tracker.build_readiness_status();
        assert_eq!(status.serving_ready, ServingReadiness::Ready);
        assert_eq!(status.replication_state, ReplicationState::Healthy);
        assert_eq!(status.database_health, DatabaseHealth::Healthy);
        assert_eq!(status.server_phase, "running");
        assert_eq!(status.message, "Ready to serve traffic");
        assert!(status.peers.is_none());
    }

    #[test]
    fn test_build_readiness_status_summarises_peers() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("running".to_string());
        tracker.set_peers(Some(vec![
            PeerInfo {
                url: "repl://peer1.example.com:8444".to_string(),
                connected: true,
                last_success: Some(1234567890),
                stale: false,
            },
            PeerInfo {
                url: "repl://peer2.example.com:8444".to_string(),
                connected: false,
                last_success: None,
                stale: false,
            },
            PeerInfo {
                url: "repl://peer3.example.com:8444".to_string(),
                connected: true,
                last_success: Some(1234567000),
                stale: true,
            },
        ]));

        let status = tracker.build_readiness_status();
        assert_eq!(
            status.peers,
            Some(PeerSummary {
                total: 3,
                healthy: 1,
                stale: 1,
            })
        );

        // No peer URLs or timestamps are exposed in the serialised response.
        let json = serde_json::to_string(&status).expect("Failed to serialize");
        assert!(!json.contains("peer1.example.com"));
        assert!(!json.contains("1234567890"));
    }

    #[test]
    fn test_build_readiness_status_not_ready() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("bootstrap".to_string());

        let status = tracker.build_readiness_status();
        assert_eq!(status.serving_ready, ServingReadiness::NotReady);
        assert!(status.message.contains("not yet ready"));
    }

    #[test]
    fn test_replication_timestamps() {
        let tracker = ReplicationStateTracker::new();
        assert!(tracker.get_last_replication_success().is_none());
        assert!(tracker.get_last_replication_failure().is_none());

        tracker.record_replication_success(1234567890);
        assert_eq!(tracker.get_last_replication_success(), Some(1234567890));

        tracker.record_replication_failure(1234567900);
        assert_eq!(tracker.get_last_replication_failure(), Some(1234567900));
    }

    #[test]
    fn test_replication_state_display() {
        assert_eq!(format!("{}", ReplicationState::Healthy), "healthy");
        assert_eq!(format!("{}", ReplicationState::CatchingUp), "catching_up");
        assert_eq!(format!("{}", ReplicationState::Degraded), "degraded");
        assert_eq!(
            format!("{}", ReplicationState::RefreshRequired),
            "refresh_required"
        );
        assert_eq!(format!("{}", ReplicationState::Refreshing), "refreshing");
        assert_eq!(format!("{}", ReplicationState::Failed), "failed");
    }

    #[test]
    fn test_serving_readiness_display() {
        assert_eq!(format!("{}", ServingReadiness::Ready), "ready");
        assert_eq!(format!("{}", ServingReadiness::NotReady), "not_ready");
    }
}
