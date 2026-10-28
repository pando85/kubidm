//! Replication-aware health and readiness tracking for Kubidm.
//!
//! This module provides separate liveness and readiness semantics for Kubernetes-style
//! health checks. Liveness indicates the process is running; readiness indicates whether
//! the replica is safe to serve production traffic.
//!
//! The [`ReplicationStateTracker`] is fed by the replication consumer tasks (one event per
//! sync attempt with a supplier), by the query server write commit path and by the online
//! consistency verification. The replication state is *derived* from those observations
//! at the time it is read, so that a peer becomes stale even when no further replication
//! event arrives.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use utoipa::ToSchema;
use uuid::Uuid;

/// A supplier peer is stale when no sync with it has succeeded for this many replication
/// intervals (`task_poll_interval`, 15 seconds by default, so one minute by default).
pub const STALE_AFTER_INTERVALS: u64 = 4;

/// Replication is failed when this node has been unable to apply what its suppliers send
/// for this many replication intervals in a row (5 minutes by default).
pub const FAILED_AFTER_INTERVALS: u64 = 20;

/// Replication state machine for a Kubidm replica.
///
/// This represents the health of replication from the perspective of this node,
/// independent of whether it can serve traffic (see `ServingReadiness`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationState {
    /// The node has synced, and every supplier peer synced within the stale window (or
    /// replication is not configured, or the node has no supplier peers).
    Healthy,
    /// Replication is configured with supplier peers, but this node has never completed a
    /// refresh or incremental sync from one: it is a fresh replica whose content is not yet
    /// the domain's content.
    CatchingUp,
    /// The node is synced, but at least one supplier peer has not synced within the stale
    /// window (unreachable, or the exchange with it keeps failing).
    Degraded,
    /// A supplier reported that this node's content must be refreshed (domain mismatch or
    /// a replication update vector older than the supplier's changelog).
    RefreshRequired,
    /// Replica is currently performing a full refresh.
    Refreshing,
    /// This node has been unable to apply replication changes it received for the failed
    /// window, with no successful sync in between. Requires operator intervention.
    Failed,
}

impl ReplicationState {
    /// Returns true if this state indicates the replica can safely serve traffic.
    pub fn is_serving_safe(&self) -> bool {
        matches!(self, ReplicationState::Healthy | ReplicationState::Degraded)
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
    /// Whether the last connection attempt to the peer succeeded.
    pub connected: bool,
    /// Timestamp of the last successful sync (refresh or incremental) with the peer
    /// (seconds since epoch).
    pub last_success: Option<u64>,
    /// Whether no sync with the peer succeeded within the stale window.
    pub stale: bool,
}

/// Aggregate counts of replication peers.
///
/// This is what the unauthenticated readiness endpoint exposes: peer URLs and
/// replication timestamps are internal topology details and are not published there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub struct PeerSummary {
    /// Number of configured supplier peers (peers this node pulls from).
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
    /// The last write transaction commit failed in the backend, or the last online
    /// consistency verification found errors.
    Unhealthy,
}

/// The database checks whose results drive [`DatabaseHealth`]. Each one fails and
/// recovers independently: a successful commit does not prove a corruption found by a
/// verification is gone, only a clean verification does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseCheck {
    /// The backend commit of a write transaction.
    Commit,
    /// The online consistency verification (`maintenance verify`).
    Verify,
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

/// The thresholds, in seconds, after which the observations of the replication tasks
/// turn into the `degraded` and `failed` states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicationTimings {
    /// A supplier peer is stale once no sync with it succeeded for this long.
    pub stale_after: u64,
    /// Replication is failed once applying changes has failed for this long.
    pub failed_after: u64,
}

impl ReplicationTimings {
    /// The thresholds for a replication poll interval: [`STALE_AFTER_INTERVALS`] and
    /// [`FAILED_AFTER_INTERVALS`] intervals.
    pub fn from_poll_interval(poll_interval: Duration) -> Self {
        let interval = poll_interval.as_secs().max(1);
        Self {
            stale_after: interval.saturating_mul(STALE_AFTER_INTERVALS),
            failed_after: interval.saturating_mul(FAILED_AFTER_INTERVALS),
        }
    }
}

/// What the tracker needs to know about replication when the server finishes starting.
#[derive(Debug, Clone)]
pub struct ReplicationStartup {
    /// The peers this node pulls from (`pull` and `mutual-pull`). `allow-pull` peers only
    /// pull from this node, so their health is reported by themselves, not here.
    pub supplier_peers: Vec<String>,
    /// The replication poll interval, the unit of the stale and failed thresholds.
    pub poll_interval: Duration,
    /// Whether the replication update vector holds changes that originated on another
    /// server, i.e. this node has received a refresh or an incremental before.
    pub has_peer_changes: bool,
}

#[derive(Debug, Default)]
struct PeerRecord {
    connected: bool,
    last_success: Option<u64>,
    refresh_required: bool,
}

#[derive(Debug)]
struct ReplicationTracking {
    timings: ReplicationTimings,
    /// When tracking started: the reference for peers that never synced.
    started_at: u64,
    /// The node holds the domain's content: it has synced from a supplier, or it has no
    /// supplier to sync from.
    synced: bool,
    refreshing: bool,
    /// When applying replicated changes locally started failing, cleared by any success.
    apply_failing_since: Option<u64>,
    peers: BTreeMap<String, PeerRecord>,
}

impl ReplicationTracking {
    fn peer_stale(&self, peer: &PeerRecord, now: u64) -> bool {
        let since = peer.last_success.unwrap_or(self.started_at);
        now.saturating_sub(since) >= self.timings.stale_after
    }

    fn state(&self, now: u64) -> ReplicationState {
        if self.refreshing {
            ReplicationState::Refreshing
        } else if self.peers.values().any(|peer| peer.refresh_required) {
            ReplicationState::RefreshRequired
        } else if !self.synced {
            ReplicationState::CatchingUp
        } else if self
            .apply_failing_since
            .is_some_and(|since| now.saturating_sub(since) >= self.timings.failed_after)
        {
            ReplicationState::Failed
        } else if self.peers.values().any(|peer| self.peer_stale(peer, now)) {
            ReplicationState::Degraded
        } else {
            ReplicationState::Healthy
        }
    }

    fn peer_infos(&self, now: u64) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .map(|(url, peer)| PeerInfo {
                url: url.clone(),
                connected: peer.connected,
                last_success: peer.last_success,
                stale: self.peer_stale(peer, now),
            })
            .collect()
    }

    fn record_sync_success(&mut self, peer_url: &str, now: u64) {
        self.synced = true;
        self.apply_failing_since = None;
        if let Some(peer) = self.peers.get_mut(peer_url) {
            peer.connected = true;
            peer.last_success = Some(now);
            peer.refresh_required = false;
        }
    }
}

/// Shared replication state tracker.
///
/// This is updated by the replication subsystem and the query server, and read by the
/// status endpoints. All time arguments are seconds since the epoch.
#[derive(Debug, Clone)]
pub struct ReplicationStateTracker {
    inner: Arc<ReplicationStateInner>,
}

#[derive(Debug)]
struct ReplicationStateInner {
    /// `None` until startup completes, and when replication is not configured.
    replication: RwLock<Option<ReplicationTracking>>,
    commit_failed: AtomicBool,
    verify_failed: AtomicBool,
    server_phase: RwLock<String>,
    last_replication_success: AtomicU64,
    last_replication_failure: AtomicU64,
}

impl ReplicationStateTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ReplicationStateInner {
                replication: RwLock::new(None),
                commit_failed: AtomicBool::new(false),
                verify_failed: AtomicBool::new(false),
                server_phase: RwLock::new("bootstrap".to_string()),
                last_replication_success: AtomicU64::new(0),
                last_replication_failure: AtomicU64::new(0),
            }),
        }
    }

    /// The server finished starting. `replication` is `None` when replication is not
    /// configured.
    ///
    /// A node with supplier peers that has never received changes from another server
    /// starts in `catching_up` (not ready) until its first successful sync. A node without
    /// supplier peers has nothing to wait for and is ready.
    pub fn mark_startup_complete(&self, replication: Option<ReplicationStartup>, now: u64) {
        let tracking = replication.map(|startup| {
            let synced = startup.has_peer_changes || startup.supplier_peers.is_empty();
            if !synced {
                info!(
                    "This node has never synced from a replication supplier: it reports not \
                     ready until its first successful refresh or incremental replication."
                );
            }
            ReplicationTracking {
                timings: ReplicationTimings::from_poll_interval(startup.poll_interval),
                started_at: now,
                synced,
                refreshing: false,
                apply_failing_since: None,
                peers: startup
                    .supplier_peers
                    .into_iter()
                    .map(|url| (url, PeerRecord::default()))
                    .collect(),
            }
        });
        if let Ok(mut lock) = self.inner.replication.write() {
            *lock = tracking;
        }
        self.set_server_phase("running".to_string());
    }

    fn with_replication(&self, f: impl FnOnce(&mut ReplicationTracking)) {
        if let Ok(mut lock) = self.inner.replication.write() {
            if let Some(tracking) = lock.as_mut() {
                f(tracking);
            }
        }
    }

    fn with_peer(&self, peer_url: &str, f: impl FnOnce(&mut PeerRecord)) {
        self.with_replication(|tracking| {
            if let Some(peer) = tracking.peers.get_mut(peer_url) {
                f(peer);
            }
        });
    }

    /// A check of the database failed: the database is unhealthy until the same check
    /// succeeds again.
    pub fn mark_database_failure(&self, check: DatabaseCheck) {
        if !self.check_flag(check).swap(true, Ordering::SeqCst) {
            error!(
                ?check,
                "Database health check failed, the node reports not ready"
            );
        }
    }

    /// A check of the database succeeded, clearing an earlier failure of the same check.
    pub fn mark_database_healthy(&self, check: DatabaseCheck) {
        if self.check_flag(check).swap(false, Ordering::SeqCst) {
            info!(?check, "Database health check recovered");
        }
    }

    fn check_flag(&self, check: DatabaseCheck) -> &AtomicBool {
        match check {
            DatabaseCheck::Commit => &self.inner.commit_failed,
            DatabaseCheck::Verify => &self.inner.verify_failed,
        }
    }

    /// The connection to a supplier peer succeeded.
    pub fn notify_replication_connected(&self, peer_url: &str) {
        self.with_peer(peer_url, |peer| peer.connected = true);
    }

    /// The connection to a supplier peer could not be established.
    pub fn notify_replication_connect_failure(&self, peer_url: &str, now: u64) {
        self.record_replication_failure(now);
        self.with_peer(peer_url, |peer| peer.connected = false);
    }

    /// The exchange with a connected supplier peer failed (timeout, protocol or decode
    /// error, connection closed). The peer goes stale if this persists.
    pub fn notify_replication_exchange_failure(&self, now: u64) {
        self.record_replication_failure(now);
    }

    /// This node failed to apply what a supplier sent (or to read its own replication
    /// state). Replication fails if this persists for the failed window.
    pub fn notify_replication_apply_failure(&self, now: u64) {
        self.record_replication_failure(now);
        self.with_replication(|tracking| {
            tracking.apply_failing_since.get_or_insert(now);
        });
    }

    /// An incremental sync with a supplier peer succeeded.
    pub fn notify_replication_incremental_success(&self, peer_url: &str, now: u64) {
        self.record_replication_success(now);
        self.with_replication(|tracking| tracking.record_sync_success(peer_url, now));
    }

    /// A supplier peer reported that this node's content must be refreshed.
    pub fn notify_replication_refresh_required(&self, peer_url: &str) {
        self.with_peer(peer_url, |peer| {
            peer.connected = true;
            peer.refresh_required = true;
        });
    }

    pub fn notify_replication_refresh_started(&self) {
        self.with_replication(|tracking| tracking.refreshing = true);
    }

    /// A refresh from a supplier peer was applied: the node holds the domain's content.
    pub fn notify_replication_refresh_success(&self, peer_url: &str, now: u64) {
        self.record_replication_success(now);
        self.with_replication(|tracking| {
            tracking.refreshing = false;
            tracking
                .peers
                .values_mut()
                .for_each(|peer| peer.refresh_required = false);
            tracking.record_sync_success(peer_url, now);
        });
    }

    /// A refresh failed. The refresh is applied in a single transaction, so the content
    /// is unchanged and the state returns to what it was before the refresh started.
    pub fn notify_replication_refresh_failed(&self, now: u64) {
        self.record_replication_failure(now);
        self.with_replication(|tracking| tracking.refreshing = false);
    }

    /// The replication state at `now`.
    pub fn get_replication_state(&self, now: u64) -> ReplicationState {
        match self.inner.replication.read() {
            Ok(lock) => lock
                .as_ref()
                .map(|tracking| tracking.state(now))
                .unwrap_or(ReplicationState::Healthy),
            Err(_) => ReplicationState::Failed,
        }
    }

    pub fn get_database_health(&self) -> DatabaseHealth {
        if self.inner.commit_failed.load(Ordering::SeqCst)
            || self.inner.verify_failed.load(Ordering::SeqCst)
        {
            DatabaseHealth::Unhealthy
        } else {
            DatabaseHealth::Healthy
        }
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

    /// The supplier peers at `now`, `None` when replication is not configured.
    pub fn get_peers(&self, now: u64) -> Option<Vec<PeerInfo>> {
        self.inner
            .replication
            .read()
            .ok()
            .and_then(|lock| lock.as_ref().map(|tracking| tracking.peer_infos(now)))
    }

    fn record_replication_success(&self, now: u64) {
        self.inner
            .last_replication_success
            .store(now, Ordering::SeqCst);
    }

    fn record_replication_failure(&self, now: u64) {
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

    /// Compute serving readiness at `now`.
    pub fn compute_serving_readiness(&self, now: u64) -> ServingReadiness {
        // Not ready if database is unhealthy
        if self.get_database_health() != DatabaseHealth::Healthy {
            return ServingReadiness::NotReady;
        }

        // Not ready if server is not in Running phase
        if self.get_server_phase() != "running" {
            return ServingReadiness::NotReady;
        }

        // Ready if replication state allows serving
        if self.get_replication_state(now).is_serving_safe() {
            ServingReadiness::Ready
        } else {
            ServingReadiness::NotReady
        }
    }

    /// Build a comprehensive readiness status response at `now`.
    pub fn build_readiness_status(&self, now: u64) -> ReadinessStatus {
        let serving_ready = self.compute_serving_readiness(now);
        let replication_state = self.get_replication_state(now);
        let database_health = self.get_database_health();
        let server_phase = self.get_server_phase();
        let peers = self
            .get_peers(now)
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

    /// The readiness status at `now` (seconds since the epoch).
    pub fn get_readiness_status(&self, now: u64) -> ReadinessStatus {
        self.tracker.build_readiness_status(now)
    }

    pub fn get_liveness_status(&self) -> LivenessStatus {
        LivenessStatus { alive: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_1: &str = "repl://peer1.example.com:8444";
    const PEER_2: &str = "repl://peer2.example.com:8444";
    const T0: u64 = 1_000_000;
    // A 10 second poll interval: stale after 40 seconds, failed after 200 seconds.
    const INTERVAL: Duration = Duration::from_secs(10);
    const STALE: u64 = 10 * STALE_AFTER_INTERVALS;
    const FAILED: u64 = 10 * FAILED_AFTER_INTERVALS;

    fn replicated(peers: &[&str], has_peer_changes: bool) -> ReplicationStateTracker {
        let tracker = ReplicationStateTracker::new();
        tracker.mark_startup_complete(
            Some(ReplicationStartup {
                supplier_peers: peers.iter().map(|peer| peer.to_string()).collect(),
                poll_interval: INTERVAL,
                has_peer_changes,
            }),
            T0,
        );
        tracker
    }

    fn assert_state(
        tracker: &ReplicationStateTracker,
        now: u64,
        state: ReplicationState,
        readiness: ServingReadiness,
    ) {
        assert_eq!(tracker.get_replication_state(now), state);
        assert_eq!(tracker.compute_serving_readiness(now), readiness);
    }

    #[test]
    fn test_replication_state_serving_safe() {
        assert!(ReplicationState::Healthy.is_serving_safe());
        assert!(ReplicationState::Degraded.is_serving_safe());
        assert!(!ReplicationState::CatchingUp.is_serving_safe());
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
    fn test_replication_timings_from_poll_interval() {
        assert_eq!(
            ReplicationTimings::from_poll_interval(Duration::from_secs(15)),
            ReplicationTimings {
                stale_after: 60,
                failed_after: 300,
            }
        );
        // A zero interval still gives non zero thresholds.
        assert_eq!(
            ReplicationTimings::from_poll_interval(Duration::ZERO),
            ReplicationTimings {
                stale_after: STALE_AFTER_INTERVALS,
                failed_after: FAILED_AFTER_INTERVALS,
            }
        );
    }

    #[test]
    fn test_replication_state_tracker_default() {
        let tracker = ReplicationStateTracker::new();
        assert_eq!(tracker.get_replication_state(T0), ReplicationState::Healthy);
        assert_eq!(tracker.get_database_health(), DatabaseHealth::Healthy);
        assert_eq!(tracker.get_server_phase(), "bootstrap");
        assert!(tracker.get_peers(T0).is_none());
        assert_eq!(
            tracker.compute_serving_readiness(T0),
            ServingReadiness::NotReady
        );
    }

    #[test]
    fn test_startup_without_replication_is_ready() {
        let tracker = ReplicationStateTracker::new();
        tracker.mark_startup_complete(None, T0);
        assert_state(
            &tracker,
            T0,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
        // Without replication nothing ever goes stale.
        assert_state(
            &tracker,
            T0 + 10 * FAILED,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
        assert!(tracker.build_readiness_status(T0).peers.is_none());
    }

    #[test]
    fn test_startup_with_no_supplier_peers_is_ready() {
        // Replication is configured, but this node has no supplier (no peers at all, or
        // only allow-pull consumers): there is nothing to wait for.
        let tracker = replicated(&[], false);
        assert_state(
            &tracker,
            T0,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
        assert_state(
            &tracker,
            T0 + 10 * FAILED,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
        assert_eq!(
            tracker.build_readiness_status(T0).peers,
            Some(PeerSummary::default())
        );
    }

    #[test]
    fn test_fresh_replica_not_ready_until_first_incremental() {
        let tracker = replicated(&[PEER_1], false);
        assert_state(
            &tracker,
            T0,
            ReplicationState::CatchingUp,
            ServingReadiness::NotReady,
        );

        // Failing to reach the supplier keeps it not ready, however long it lasts.
        tracker.notify_replication_connect_failure(PEER_1, T0 + 10);
        assert_state(
            &tracker,
            T0 + 10 * FAILED,
            ReplicationState::CatchingUp,
            ServingReadiness::NotReady,
        );

        tracker.notify_replication_connected(PEER_1);
        tracker.notify_replication_incremental_success(PEER_1, T0 + 20);
        assert_state(
            &tracker,
            T0 + 20,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_fresh_replica_refresh_lifecycle() {
        let tracker = replicated(&[PEER_1, PEER_2], false);
        tracker.notify_replication_connected(PEER_1);
        // The supplier is in another domain: the fresh replica must be refreshed.
        tracker.notify_replication_refresh_required(PEER_1);
        assert_state(
            &tracker,
            T0 + 1,
            ReplicationState::RefreshRequired,
            ServingReadiness::NotReady,
        );

        tracker.notify_replication_refresh_started();
        assert_state(
            &tracker,
            T0 + 2,
            ReplicationState::Refreshing,
            ServingReadiness::NotReady,
        );

        // A failed refresh leaves the content untouched: back to refresh required.
        tracker.notify_replication_refresh_failed(T0 + 3);
        assert_state(
            &tracker,
            T0 + 3,
            ReplicationState::RefreshRequired,
            ServingReadiness::NotReady,
        );

        tracker.notify_replication_refresh_started();
        tracker.notify_replication_refresh_success(PEER_1, T0 + 4);
        assert_state(
            &tracker,
            T0 + 4,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
        assert_eq!(tracker.get_last_replication_success(), Some(T0 + 4));
    }

    #[test]
    fn test_refresh_failure_on_synced_node_keeps_it_ready() {
        // An operator requested refresh on a synced node that fails is rolled back.
        let tracker = replicated(&[PEER_1], true);
        tracker.notify_replication_refresh_started();
        assert_state(
            &tracker,
            T0,
            ReplicationState::Refreshing,
            ServingReadiness::NotReady,
        );
        tracker.notify_replication_refresh_failed(T0 + 1);
        assert_state(
            &tracker,
            T0 + 1,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_refresh_required_clears_on_incremental_success() {
        // A synced node told by a (new, not yet refreshed) peer that the domains differ
        // recovers as soon as that peer answers normally.
        let tracker = replicated(&[PEER_1], true);
        tracker.notify_replication_refresh_required(PEER_1);
        assert_state(
            &tracker,
            T0,
            ReplicationState::RefreshRequired,
            ServingReadiness::NotReady,
        );
        tracker.notify_replication_incremental_success(PEER_1, T0 + 5);
        assert_state(
            &tracker,
            T0 + 5,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_synced_node_starts_ready() {
        let tracker = replicated(&[PEER_1], true);
        assert_state(
            &tracker,
            T0,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_stale_peer_degrades_and_recovers() {
        let tracker = replicated(&[PEER_1, PEER_2], true);
        tracker.notify_replication_incremental_success(PEER_1, T0 + 10);
        tracker.notify_replication_incremental_success(PEER_2, T0 + 10);
        assert_state(
            &tracker,
            T0 + 10,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );

        // Peer 2 becomes unreachable, peer 1 keeps syncing.
        let mut now = T0 + 10;
        while now < T0 + 10 + STALE {
            now += 10;
            tracker.notify_replication_incremental_success(PEER_1, now);
            tracker.notify_replication_connect_failure(PEER_2, now);
        }
        assert_state(
            &tracker,
            now,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );
        let status = tracker.build_readiness_status(now);
        assert_eq!(
            status.peers,
            Some(PeerSummary {
                total: 2,
                healthy: 1,
                stale: 1,
            })
        );
        assert_eq!(tracker.get_last_replication_failure(), Some(now));

        // Much later every peer is stale. Without local failures to apply changes the node
        // stays degraded and ready: unreachable suppliers alone never fail replication.
        assert_state(
            &tracker,
            now + 10 * FAILED,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );

        // Peer 2 is back.
        tracker.notify_replication_connected(PEER_2);
        tracker.notify_replication_incremental_success(PEER_2, now + 1);
        tracker.notify_replication_incremental_success(PEER_1, now + 1);
        assert_state(
            &tracker,
            now + 1,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_peer_that_never_synced_goes_stale_after_startup() {
        let tracker = replicated(&[PEER_1], true);
        assert_eq!(
            tracker.get_replication_state(T0 + STALE - 1),
            ReplicationState::Healthy
        );
        assert_state(
            &tracker,
            T0 + STALE,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );
        let peers = tracker.get_peers(T0 + STALE).expect("peers are tracked");
        assert_eq!(peers.len(), 1);
        assert!(peers[0].stale);
        assert!(!peers[0].connected);
        assert_eq!(peers[0].last_success, None);
    }

    #[test]
    fn test_exchange_failures_degrade_without_failing() {
        let tracker = replicated(&[PEER_1], true);
        tracker.notify_replication_connected(PEER_1);
        tracker.notify_replication_exchange_failure(T0 + 1);
        assert_eq!(
            tracker.get_replication_state(T0 + 1),
            ReplicationState::Healthy
        );
        assert_state(
            &tracker,
            T0 + 10 * FAILED,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_apply_failures_fail_replication_and_recover() {
        let tracker = replicated(&[PEER_1], true);
        tracker.notify_replication_incremental_success(PEER_1, T0);

        let first_failure = T0 + 10;
        tracker.notify_replication_apply_failure(first_failure);
        // Transient: degraded once stale, failed only after the failed window.
        assert_eq!(
            tracker.get_replication_state(first_failure),
            ReplicationState::Healthy
        );
        let mut now = first_failure;
        while now < first_failure + FAILED - 10 {
            now += 10;
            tracker.notify_replication_apply_failure(now);
        }
        assert_state(
            &tracker,
            first_failure + FAILED - 1,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );
        assert_state(
            &tracker,
            first_failure + FAILED,
            ReplicationState::Failed,
            ServingReadiness::NotReady,
        );
        let status = tracker.build_readiness_status(first_failure + FAILED);
        assert_eq!(
            status.message,
            "Replication state 'failed' does not allow serving"
        );

        tracker.notify_replication_incremental_success(PEER_1, first_failure + FAILED + 1);
        assert_state(
            &tracker,
            first_failure + FAILED + 1,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_unknown_peer_events_are_ignored() {
        let tracker = replicated(&[PEER_1], true);
        tracker.notify_replication_refresh_required("repl://unknown.example.com:8444");
        assert_eq!(tracker.get_replication_state(T0), ReplicationState::Healthy);
        assert_eq!(tracker.get_peers(T0).map(|peers| peers.len()), Some(1));
    }

    #[test]
    fn test_events_without_replication_are_ignored() {
        let tracker = ReplicationStateTracker::new();
        tracker.mark_startup_complete(None, T0);
        tracker.notify_replication_refresh_started();
        tracker.notify_replication_apply_failure(T0);
        assert_eq!(
            tracker.get_replication_state(T0 + 10 * FAILED),
            ReplicationState::Healthy
        );
    }

    #[test]
    fn test_database_checks_fail_and_recover_independently() {
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
        assert_eq!(
            tracker.build_readiness_status(T0).message,
            "Database health check failed"
        );

        tracker.mark_database_failure(DatabaseCheck::Verify);
        // A successful commit does not clear a failed verification.
        tracker.mark_database_healthy(DatabaseCheck::Commit);
        assert_eq!(tracker.get_database_health(), DatabaseHealth::Unhealthy);

        tracker.mark_database_healthy(DatabaseCheck::Verify);
        assert_eq!(tracker.get_database_health(), DatabaseHealth::Healthy);
        assert_eq!(
            tracker.compute_serving_readiness(T0),
            ServingReadiness::Ready
        );
    }

    #[test]
    fn test_build_readiness_status() {
        let tracker = ReplicationStateTracker::new();
        tracker.mark_startup_complete(None, T0);

        let status = tracker.build_readiness_status(T0);
        assert_eq!(status.serving_ready, ServingReadiness::Ready);
        assert_eq!(status.replication_state, ReplicationState::Healthy);
        assert_eq!(status.database_health, DatabaseHealth::Healthy);
        assert_eq!(status.server_phase, "running");
        assert_eq!(status.message, "Ready to serve traffic");
        assert!(status.peers.is_none());
    }

    #[test]
    fn test_build_readiness_status_hides_peer_details() {
        let tracker = replicated(&[PEER_1, PEER_2], true);
        tracker.notify_replication_incremental_success(PEER_1, T0 + 7);

        let status = tracker.build_readiness_status(T0 + 7);
        assert_eq!(
            status.peers,
            Some(PeerSummary {
                total: 2,
                healthy: 1,
                stale: 0,
            })
        );

        // No peer URLs or timestamps are exposed in the serialised response.
        let json = serde_json::to_string(&status).expect("Failed to serialize");
        assert!(!json.contains("peer1.example.com"));
        assert!(!json.contains("1000007"));
    }

    #[test]
    fn test_build_readiness_status_not_ready() {
        let tracker = ReplicationStateTracker::new();
        tracker.set_server_phase("bootstrap".to_string());

        let status = tracker.build_readiness_status(T0);
        assert_eq!(status.serving_ready, ServingReadiness::NotReady);
        assert!(status.message.contains("not yet ready"));
    }

    #[test]
    fn test_build_readiness_status_catching_up_message() {
        let tracker = replicated(&[PEER_1], false);
        let status = tracker.build_readiness_status(T0);
        assert_eq!(status.serving_ready, ServingReadiness::NotReady);
        assert_eq!(status.replication_state, ReplicationState::CatchingUp);
        assert_eq!(
            status.message,
            "Replication state 'catching_up' does not allow serving"
        );
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
