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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};
use utoipa::ToSchema;
use uuid::Uuid;

/// A supplier peer is stale when no sync with it has succeeded for this many replication
/// intervals (`task_poll_interval`, 15 seconds by default, so one minute by default).
pub const STALE_AFTER_INTERVALS: u64 = 4;

/// Replication is failed when this node has kept failing to apply what its suppliers send
/// for this many replication intervals (5 minutes by default), with no successful sync and
/// no gap longer than the stale window between the failures.
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
    /// A supplier peer is configured with `automatic_refresh`, but this node has never
    /// completed a refresh or incremental sync from a supplier: it is a fresh replica whose
    /// content is not yet the domain's content.
    CatchingUp,
    /// The node is synced, but at least one supplier peer has not synced within the stale
    /// window (unreachable, or the exchange with it keeps failing).
    Degraded,
    /// A supplier reported that this node's content must be refreshed (domain mismatch or
    /// a replication update vector older than the supplier's changelog).
    RefreshRequired,
    /// Replica is currently performing a full refresh.
    Refreshing,
    /// This node has kept failing to apply replication changes it received for the failed
    /// window, with no successful sync in between, and the failures are still ongoing (the
    /// last one is within the stale window). Requires operator intervention.
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
    /// When the last sync (refresh or incremental) with the peer succeeded, in seconds on
    /// the monotonic clock of the tracker (see [`tracker_now`]), not since the epoch.
    pub last_success: Option<u64>,
    /// Whether no sync with the peer succeeded within the stale window.
    pub stale: bool,
    /// Whether the peer answered from another domain while this node holds replicated
    /// content: this node refuses to be refreshed from it automatically (see
    /// `ReplicationStateTracker::notify_replication_domain_mismatch`), and the peer stays
    /// stale until an operator resolves the mismatch.
    pub foreign_domain: bool,
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
    /// Peers that answered from another domain while this node holds replicated content
    /// (the domain mismatch guard). They are also counted as stale, and need an operator:
    /// this node is never refreshed from them automatically.
    #[serde(default)]
    pub foreign: usize,
}

impl PeerSummary {
    pub fn from_peers(peers: &[PeerInfo]) -> Self {
        Self {
            total: peers.len(),
            healthy: peers.iter().filter(|p| p.connected && !p.stale).count(),
            stale: peers.iter().filter(|p| p.stale).count(),
            foreign: peers.iter().filter(|p| p.foreign_domain).count(),
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
    /// A supplier peer is stale once no sync with it succeeded for this long. Failures to
    /// apply changes stop counting as ongoing after this long without a new one.
    pub stale_after: u64,
    /// Replication is failed once applying changes has kept failing for this long.
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

static TRACKER_CLOCK_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// The clock of the health tracker: whole seconds on the monotonic clock since the first
/// tracker of the process was created. Every `now` argument of [`ReplicationStateTracker`]
/// is read from here, so that wall clock jumps neither hide nor fake a stale peer.
pub fn tracker_now() -> u64 {
    TRACKER_CLOCK_START.elapsed().as_secs()
}

/// What the tracker needs to know about replication when the server finishes starting.
#[derive(Debug, Clone)]
pub struct ReplicationStartup {
    /// The peers this node pulls from (`pull` and `mutual-pull`). `allow-pull` peers only
    /// pull from this node, so their health is reported by themselves, not here.
    pub supplier_peers: Vec<String>,
    /// Whether a supplier peer is configured with `automatic_refresh`: this node expects
    /// to receive the domain's content from a supplier. Without one the node holds the
    /// domain's content by configuration (for example the node that created the domain).
    pub automatic_refresh: bool,
    /// The replication poll interval, the unit of the stale and failed thresholds.
    pub poll_interval: Duration,
    /// Whether the database shows that this node has synced from a supplier before, see
    /// `QueryServer::replication_has_synced`. This decides readiness at startup.
    pub has_synced: bool,
    /// Whether this node must be treated as holding replicated content by the domain
    /// mismatch guard (`ReplicationStateTracker::notify_replication_domain_mismatch`):
    /// `has_synced`, or the replication state of the database could not be read. An
    /// unreadable state is not proof of a sync, so it does not make the node ready, but it
    /// is not proof of an empty node either, so the node is never refreshed automatically
    /// from a peer in another domain.
    pub sync_evidence: bool,
}

#[derive(Debug, Default)]
struct PeerRecord {
    connected: bool,
    last_success: Option<u64>,
    refresh_required: bool,
    /// The peer answered with a domain mismatch while this node was in sync with another
    /// supplier: the peer is the one that must be refreshed.
    foreign_domain: bool,
}

#[derive(Debug)]
struct ReplicationTracking {
    timings: ReplicationTimings,
    /// When tracking started: the reference for peers that never synced.
    started_at: u64,
    /// A supplier peer is configured with `automatic_refresh`.
    automatic_refresh: bool,
    /// The node holds the domain's content: it has synced from a supplier, or it does not
    /// expect to receive its content from one. The second case is an assumption that
    /// makes the node ready, not evidence of anything, see `sync_evidence`.
    synced: bool,
    /// Durable evidence that this node holds replicated content: the database showed at
    /// startup that it synced from a supplier before, or could not be read
    /// (`ReplicationStartup::sync_evidence`), or a sync succeeded since. A node with this evidence is never refreshed
    /// automatically from a peer in another domain, see
    /// `ReplicationStateTracker::notify_replication_domain_mismatch`.
    sync_evidence: bool,
    refreshing: bool,
    /// When the current run of failures to apply replicated changes started.
    apply_failing_since: Option<u64>,
    /// The most recent failure to apply replicated changes.
    last_apply_failure: Option<u64>,
    last_success: Option<u64>,
    last_failure: Option<u64>,
    peers: BTreeMap<String, PeerRecord>,
}

impl ReplicationTracking {
    fn peer_stale(&self, peer: &PeerRecord, now: u64) -> bool {
        let since = peer.last_success.unwrap_or(self.started_at);
        peer.foreign_domain || now.saturating_sub(since) >= self.timings.stale_after
    }

    /// Whether failures to apply changes are ongoing: the last one is within the stale
    /// window. Otherwise an old failure is history, whatever happened since.
    fn apply_failing(&self, now: u64) -> bool {
        self.last_apply_failure
            .is_some_and(|last| now.saturating_sub(last) < self.timings.stale_after)
    }

    fn state(&self, now: u64) -> ReplicationState {
        if self.refreshing {
            ReplicationState::Refreshing
        } else if self.peers.values().any(|peer| peer.refresh_required) {
            ReplicationState::RefreshRequired
        } else if !self.synced {
            ReplicationState::CatchingUp
        } else if self.apply_failing(now)
            && self
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
                foreign_domain: peer.foreign_domain,
            })
            .collect()
    }

    fn record_apply_failure(&mut self, now: u64) {
        if !self.apply_failing(now) {
            // The previous failures (if any) are over: this one starts a new run.
            self.apply_failing_since = Some(now);
        }
        self.last_apply_failure = Some(now);
        self.last_failure = Some(now);
    }

    fn record_sync_success(&mut self, peer_url: &str, now: u64) {
        self.synced = true;
        self.sync_evidence = true;
        self.apply_failing_since = None;
        self.last_apply_failure = None;
        self.last_success = Some(now);
        if let Some(peer) = self.peers.get_mut(peer_url) {
            peer.connected = true;
            peer.last_success = Some(now);
            peer.refresh_required = false;
            peer.foreign_domain = false;
        }
    }

    /// Whether this node is in sync with a supplier other than `peer_url`: it holds the
    /// domain's content and another supplier synced within the stale window.
    fn synced_with_other_peer(&self, peer_url: &str, now: u64) -> bool {
        self.synced
            && self.peers.iter().any(|(url, peer)| {
                url != peer_url
                    && !peer.foreign_domain
                    && peer
                        .last_success
                        .is_some_and(|last| now.saturating_sub(last) < self.timings.stale_after)
            })
    }
}

/// Shared replication state tracker.
///
/// This is updated by the replication subsystem and the query server, and read by the
/// status endpoints. All time arguments are read from [`tracker_now`].
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
}

impl ReplicationStateTracker {
    pub fn new() -> Self {
        // Start the tracker clock no later than the first tracker.
        LazyLock::force(&TRACKER_CLOCK_START);
        Self {
            inner: Arc::new(ReplicationStateInner {
                replication: RwLock::new(None),
                commit_failed: AtomicBool::new(false),
                verify_failed: AtomicBool::new(false),
                server_phase: RwLock::new("bootstrap".to_string()),
            }),
        }
    }

    /// The server finished starting. `replication` is `None` when replication is not
    /// configured.
    ///
    /// A node that expects its content from a supplier (`automatic_refresh`) and has never
    /// synced from one starts in `catching_up` (not ready) until its first successful
    /// sync. Every other node holds the domain's content and is ready.
    pub fn mark_startup_complete(&self, replication: Option<ReplicationStartup>, now: u64) {
        let tracking = replication.map(|startup| {
            let synced = startup.has_synced || !startup.automatic_refresh;
            if !synced {
                info!(
                    "This node has never synced from a replication supplier: it reports not \
                     ready until its first successful refresh or incremental replication."
                );
            } else if !startup.has_synced && !startup.supplier_peers.is_empty() {
                info!(
                    "This node has not synced from a replication supplier yet, but no supplier \
                     is configured with automatic_refresh: it holds the domain's content and \
                     reports ready."
                );
            }
            ReplicationTracking {
                timings: ReplicationTimings::from_poll_interval(startup.poll_interval),
                started_at: now,
                automatic_refresh: startup.automatic_refresh,
                synced,
                sync_evidence: startup.has_synced || startup.sync_evidence,
                refreshing: false,
                apply_failing_since: None,
                last_apply_failure: None,
                last_success: None,
                last_failure: None,
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

    fn with_replication<T>(&self, f: impl FnOnce(&mut ReplicationTracking) -> T) -> Option<T> {
        self.inner
            .replication
            .write()
            .ok()
            .and_then(|mut lock| lock.as_mut().map(f))
    }

    fn read_replication<T>(&self, f: impl FnOnce(&ReplicationTracking) -> T) -> Option<T> {
        self.inner
            .replication
            .read()
            .ok()
            .and_then(|lock| lock.as_ref().map(f))
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
        self.with_replication(|tracking| {
            tracking.last_failure = Some(now);
            if let Some(peer) = tracking.peers.get_mut(peer_url) {
                peer.connected = false;
            }
        });
    }

    /// The exchange with a connected supplier peer failed (timeout, protocol or decode
    /// error, connection closed). The peer goes stale if this persists.
    pub fn notify_replication_exchange_failure(&self, now: u64) {
        self.with_replication(|tracking| tracking.last_failure = Some(now));
    }

    /// This node failed to apply what a supplier sent (or to read its own replication
    /// state). Replication fails if such failures keep happening for the failed window.
    pub fn notify_replication_apply_failure(&self, now: u64) {
        self.with_replication(|tracking| tracking.record_apply_failure(now));
    }

    /// An incremental sync with a supplier peer succeeded.
    pub fn notify_replication_incremental_success(&self, peer_url: &str, now: u64) {
        self.with_replication(|tracking| tracking.record_sync_success(peer_url, now));
    }

    /// A supplier peer reported that this node's content must be refreshed.
    pub fn notify_replication_refresh_required(&self, peer_url: &str) {
        self.with_peer(peer_url, |peer| {
            peer.connected = true;
            peer.refresh_required = true;
        });
    }

    /// A supplier peer answered that its domain differs from this node's. Returns whether
    /// this node must be refreshed.
    ///
    /// A refresh replaces the whole content of this node with the peer's, so it is only
    /// allowed when this node has nothing to lose. The peer is treated as the one out of
    /// the domain (a new replica not yet refreshed, or an empty re-created one) when:
    ///
    /// * this node expects its content from a supplier (`automatic_refresh`) and has
    ///   evidence that it holds replicated content (`sync_evidence`), whatever the other
    ///   peers do. Otherwise an empty re-created origin (which is ready at once, as it has
    ///   no `automatic_refresh` supplier) would wipe every replica that refreshes from it;
    /// * or this node holds the domain's content and another supplier synced within the
    ///   stale window.
    ///
    /// The peer is then marked stale, which degrades this node, and the node is never
    /// refreshed from it automatically: an operator runs
    /// `kubidmd refresh-replication-consumer`, which does not go through this check, when
    /// the peer's domain is the intended one. Otherwise (a fresh replica with no evidence,
    /// or a node without `automatic_refresh` that can not tell) the mismatch is a refresh
    /// requirement: a fresh replica refreshes, any other node reports not ready.
    pub fn notify_replication_domain_mismatch(&self, peer_url: &str, now: u64) -> bool {
        self.with_replication(|tracking| {
            let peer_is_foreign = (tracking.automatic_refresh && tracking.sync_evidence)
                || tracking.synced_with_other_peer(peer_url, now);
            if let Some(peer) = tracking.peers.get_mut(peer_url) {
                peer.connected = true;
                peer.foreign_domain = peer_is_foreign;
            }
            !peer_is_foreign
        })
        .unwrap_or(true)
    }

    pub fn notify_replication_refresh_started(&self) {
        self.with_replication(|tracking| tracking.refreshing = true);
    }

    /// A refresh from a supplier peer was applied: the node holds the domain's content.
    /// The refresh replaced the whole content, so an earlier failed verification no longer
    /// applies.
    pub fn notify_replication_refresh_success(&self, peer_url: &str, now: u64) {
        self.with_replication(|tracking| {
            tracking.refreshing = false;
            tracking
                .peers
                .values_mut()
                .for_each(|peer| peer.refresh_required = false);
            tracking.record_sync_success(peer_url, now);
        });
        self.mark_database_healthy(DatabaseCheck::Verify);
    }

    /// A refresh failed. The refresh is applied in a single transaction, so the content
    /// is unchanged and the state returns to what it was before the refresh started.
    pub fn notify_replication_refresh_failed(&self, now: u64) {
        self.with_replication(|tracking| {
            tracking.refreshing = false;
            tracking.last_failure = Some(now);
        });
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
        self.read_replication(|tracking| tracking.peer_infos(now))
    }

    /// When a sync with a supplier last succeeded, on the [`tracker_now`] clock.
    pub fn get_last_replication_success(&self) -> Option<u64> {
        self.read_replication(|tracking| tracking.last_success)
            .flatten()
    }

    /// When replicating from a supplier last failed, on the [`tracker_now`] clock.
    pub fn get_last_replication_failure(&self) -> Option<u64> {
        self.read_replication(|tracking| tracking.last_failure)
            .flatten()
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

        // Peers held back by the domain mismatch guard look like unreachable ones in the
        // state, but unlike them they never recover on their own: say so.
        let foreign = peers.map(|peers| peers.foreign).unwrap_or_default();
        let message = match serving_ready {
            ServingReadiness::Ready if foreign > 0 => {
                format!("Degraded: {foreign} peer(s) in another domain; operator action required")
            }
            ServingReadiness::Ready => "Ready to serve traffic".to_string(),
            ServingReadiness::NotReady => {
                if database_health != DatabaseHealth::Healthy {
                    "Database health check failed".to_string()
                } else if server_phase != "running" {
                    format!("Server not yet ready (phase: {})", server_phase)
                } else if foreign > 0 {
                    format!(
                        "Replication state '{}' does not allow serving; {foreign} peer(s) in \
                         another domain, operator action required",
                        replication_state
                    )
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

    /// The readiness status at `now`, read from [`tracker_now`].
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

    /// A node with `peers` as suppliers, configured with `automatic_refresh` when it has
    /// any (a replica that expects its content from a supplier).
    fn replicated(peers: &[&str], has_synced: bool) -> ReplicationStateTracker {
        replicated_with(peers, !peers.is_empty(), has_synced)
    }

    fn replicated_with(
        peers: &[&str],
        automatic_refresh: bool,
        has_synced: bool,
    ) -> ReplicationStateTracker {
        let tracker = ReplicationStateTracker::new();
        tracker.mark_startup_complete(
            Some(ReplicationStartup {
                supplier_peers: peers.iter().map(|peer| peer.to_string()).collect(),
                automatic_refresh,
                poll_interval: INTERVAL,
                has_synced,
                sync_evidence: has_synced,
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
                foreign: 0,
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
                foreign: 0,
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
    fn test_origin_without_automatic_refresh_is_ready_before_any_sync() {
        // The node that created the domain (pod-0 of a new cluster) has only its own
        // changes, but no supplier it would take its content from: it is ready, even if
        // every peer is still missing.
        let tracker = replicated_with(&[PEER_1, PEER_2], false, false);
        assert_state(
            &tracker,
            T0,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
        assert_state(
            &tracker,
            T0 + 10 * FAILED,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_synced_replica_with_automatic_refresh_is_ready_on_restart() {
        // has_synced comes from the durable domain origin, not from the trimmable RUV.
        let tracker = replicated_with(&[PEER_1], true, true);
        assert_state(
            &tracker,
            T0,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_single_apply_failure_then_unreachable_never_fails() {
        let tracker = replicated(&[PEER_1], true);
        tracker.notify_replication_incremental_success(PEER_1, T0);
        tracker.notify_replication_apply_failure(T0 + 10);
        let mut now = T0 + 10;
        while now < T0 + 10 * FAILED {
            now += 10;
            tracker.notify_replication_connect_failure(PEER_1, now);
            assert_ne!(tracker.get_replication_state(now), ReplicationState::Failed);
        }
        assert_state(
            &tracker,
            now,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );

        // A later failure starts a new run: failed only after a full window of it.
        tracker.notify_replication_apply_failure(now);
        assert_eq!(
            tracker.get_replication_state(now),
            ReplicationState::Degraded
        );
        let restart = now;
        while now < restart + FAILED {
            now += 10;
            tracker.notify_replication_apply_failure(now);
        }
        assert_eq!(tracker.get_replication_state(now), ReplicationState::Failed);
        // And it stops being failed once the failures stop for the stale window.
        assert_eq!(
            tracker.get_replication_state(now + STALE),
            ReplicationState::Degraded
        );
    }

    #[test]
    fn test_domain_mismatch_from_new_peer_degrades_synced_node() {
        let tracker = replicated(&[PEER_1, PEER_2], true);
        tracker.notify_replication_incremental_success(PEER_1, T0 + 10);
        // Peer 2 is a new replica, not yet refreshed: this node must not be refreshed.
        assert!(!tracker.notify_replication_domain_mismatch(PEER_2, T0 + 11));
        assert_state(
            &tracker,
            T0 + 11,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );
        assert_eq!(
            tracker.build_readiness_status(T0 + 11).peers,
            Some(PeerSummary {
                total: 2,
                healthy: 1,
                stale: 1,
                foreign: 1,
            })
        );

        // Once refreshed, peer 2 answers normally.
        tracker.notify_replication_incremental_success(PEER_1, T0 + 20);
        tracker.notify_replication_incremental_success(PEER_2, T0 + 21);
        assert_state(
            &tracker,
            T0 + 21,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_domain_mismatch_without_other_synced_peer_requires_refresh() {
        // Unsynced: the fresh replica is the one out of the domain.
        let tracker = replicated(&[PEER_1, PEER_2], false);
        assert!(tracker.notify_replication_domain_mismatch(PEER_2, T0 + 1));
        assert!(tracker.notify_replication_domain_mismatch(PEER_1, T0 + 1));

        // Without automatic_refresh (the origin, pod-0): synced, but no other supplier
        // synced within the stale window, it can not tell. The node is never refreshed
        // automatically, the mismatch makes it not ready.
        let tracker = replicated_with(&[PEER_1, PEER_2], false, false);
        tracker.notify_replication_incremental_success(PEER_1, T0);
        assert!(tracker.notify_replication_domain_mismatch(PEER_2, T0 + STALE));
        tracker.notify_replication_refresh_required(PEER_2);
        assert_state(
            &tracker,
            T0 + STALE,
            ReplicationState::RefreshRequired,
            ServingReadiness::NotReady,
        );

        // A single supplier without automatic_refresh: nobody to compare with.
        let tracker = replicated_with(&[PEER_1], false, false);
        tracker.notify_replication_incremental_success(PEER_1, T0);
        assert!(tracker.notify_replication_domain_mismatch(PEER_1, T0 + 1));

        // Without replication tracking the upstream behaviour is kept.
        let tracker = ReplicationStateTracker::new();
        assert!(tracker.notify_replication_domain_mismatch(PEER_1, T0));
    }

    #[test]
    fn test_domain_mismatch_never_refreshes_replica_with_sync_evidence() {
        // Two replicas: pod-1 synced from pod-0 before (the evidence is in its database),
        // then pod-0 was re-created empty. pod-0 has no automatic_refresh supplier, so it
        // is ready at once, and answers pod-1 with a domain mismatch. No other peer can
        // vouch for pod-1's content, but refreshing would wipe it: never refresh.
        let tracker = replicated(&[PEER_1], true);
        let mut now = T0 + 10;
        while now < T0 + 10 * FAILED {
            assert!(!tracker.notify_replication_domain_mismatch(PEER_1, now));
            assert_state(
                &tracker,
                now,
                ReplicationState::Degraded,
                ServingReadiness::Ready,
            );
            now += 10;
        }
        assert_eq!(
            tracker.build_readiness_status(now).peers,
            Some(PeerSummary {
                total: 1,
                healthy: 0,
                stale: 1,
                foreign: 1,
            })
        );

        // A full restart with three replicas: pod-1 starts first after the empty pod-0,
        // pod-2 is not up yet. The same holds.
        let tracker = replicated(&[PEER_1, PEER_2], true);
        assert!(!tracker.notify_replication_domain_mismatch(PEER_1, T0 + 1));
        assert_state(
            &tracker,
            T0 + 1,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );

        // Evidence from a sync in this process counts as well, long after it.
        let tracker = replicated(&[PEER_1], false);
        tracker.notify_replication_refresh_started();
        tracker.notify_replication_refresh_success(PEER_1, T0 + 1);
        assert!(!tracker.notify_replication_domain_mismatch(PEER_1, T0 + 10 * FAILED));
        assert_state(
            &tracker,
            T0 + 10 * FAILED,
            ReplicationState::Degraded,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_domain_mismatch_refreshes_fresh_replica() {
        // A fresh replica with no evidence of a sync is the one out of the domain: it is
        // refreshed automatically.
        let tracker = replicated(&[PEER_1], false);
        assert!(tracker.notify_replication_domain_mismatch(PEER_1, T0 + 1));
        tracker.notify_replication_refresh_required(PEER_1);
        assert_state(
            &tracker,
            T0 + 1,
            ReplicationState::RefreshRequired,
            ServingReadiness::NotReady,
        );
        tracker.notify_replication_refresh_started();
        tracker.notify_replication_refresh_success(PEER_1, T0 + 2);
        assert_state(
            &tracker,
            T0 + 2,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_manual_refresh_from_foreign_peer_recovers() {
        // The cluster was intentionally rebuilt in a new domain: the synced replica refuses
        // the automatic refresh, and the operator runs `refresh-replication-consumer`,
        // which refreshes without the domain check.
        let tracker = replicated(&[PEER_1], true);
        assert!(!tracker.notify_replication_domain_mismatch(PEER_1, T0 + 1));
        tracker.notify_replication_refresh_started();
        assert_state(
            &tracker,
            T0 + 2,
            ReplicationState::Refreshing,
            ServingReadiness::NotReady,
        );
        tracker.notify_replication_refresh_success(PEER_1, T0 + 3);
        assert_state(
            &tracker,
            T0 + 3,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
        let peers = tracker.get_peers(T0 + 3).unwrap_or_default();
        assert!(!peers[0].stale);
        tracker.notify_replication_incremental_success(PEER_1, T0 + 13);
        assert_state(
            &tracker,
            T0 + 13,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_foreign_peer_is_reported_on_readiness() {
        let tracker = replicated(&[PEER_1, PEER_2], true);
        tracker.notify_replication_incremental_success(PEER_1, T0 + 10);
        // An unreachable peer is stale, but not foreign: the usual message.
        let status = tracker.build_readiness_status(T0 + 10 + STALE);
        assert_eq!(status.replication_state, ReplicationState::Degraded);
        assert_eq!(status.peers.map(|peers| peers.foreign), Some(0));
        assert_eq!(status.message, "Ready to serve traffic");

        // A peer in another domain is held back by the guard: a distinct message.
        tracker.notify_replication_incremental_success(PEER_1, T0 + 20);
        assert!(!tracker.notify_replication_domain_mismatch(PEER_2, T0 + 21));
        let status = tracker.build_readiness_status(T0 + 21);
        assert_eq!(status.serving_ready, ServingReadiness::Ready);
        assert_eq!(status.replication_state, ReplicationState::Degraded);
        assert_eq!(
            status.peers,
            Some(PeerSummary {
                total: 2,
                healthy: 1,
                stale: 1,
                foreign: 1,
            })
        );
        assert_eq!(
            status.message,
            "Degraded: 1 peer(s) in another domain; operator action required"
        );
        let peers = tracker.get_peers(T0 + 21).unwrap_or_default();
        assert!(peers
            .iter()
            .any(|peer| peer.url == PEER_2 && peer.foreign_domain && peer.stale));

        // Once the peer answers normally again, it is no longer foreign.
        tracker.notify_replication_incremental_success(PEER_2, T0 + 22);
        let status = tracker.build_readiness_status(T0 + 22);
        assert_eq!(status.peers.map(|peers| peers.foreign), Some(0));
        assert_eq!(status.message, "Ready to serve traffic");
    }

    #[test]
    fn test_peer_summary_without_foreign_deserialises() {
        // A response of an older server, without the `foreign` count.
        let summary: PeerSummary = serde_json::from_str(r#"{"total":2,"healthy":1,"stale":1}"#)
            .expect("Failed to deserialize");
        assert_eq!(
            summary,
            PeerSummary {
                total: 2,
                healthy: 1,
                stale: 1,
                foreign: 0,
            }
        );
    }

    #[test]
    fn test_unreadable_sync_state_guards_without_making_ready() {
        // The replication state of the database could not be read at startup: the node is
        // not ready until its first sync (as before), but it is never refreshed
        // automatically from a peer in another domain either.
        let tracker = ReplicationStateTracker::new();
        tracker.mark_startup_complete(
            Some(ReplicationStartup {
                supplier_peers: vec![PEER_1.to_string()],
                automatic_refresh: true,
                poll_interval: INTERVAL,
                has_synced: false,
                sync_evidence: true,
            }),
            T0,
        );
        assert_state(
            &tracker,
            T0,
            ReplicationState::CatchingUp,
            ServingReadiness::NotReady,
        );

        assert!(!tracker.notify_replication_domain_mismatch(PEER_1, T0 + 1));
        assert_state(
            &tracker,
            T0 + 1,
            ReplicationState::CatchingUp,
            ServingReadiness::NotReady,
        );
        let status = tracker.build_readiness_status(T0 + 1);
        assert_eq!(status.peers.map(|peers| peers.foreign), Some(1));
        assert_eq!(
            status.message,
            "Replication state 'catching_up' does not allow serving; 1 peer(s) in another \
             domain, operator action required"
        );

        // A sync with a peer in the same domain makes it ready.
        tracker.notify_replication_incremental_success(PEER_1, T0 + 2);
        assert_state(
            &tracker,
            T0 + 2,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );

        // Without the evidence, the same unsynced node is refreshed from the peer.
        let tracker = replicated(&[PEER_1], false);
        assert!(tracker.notify_replication_domain_mismatch(PEER_1, T0 + 1));
    }

    #[test]
    fn test_refresh_success_clears_failed_verification() {
        let tracker = replicated(&[PEER_1], false);
        tracker.mark_database_failure(DatabaseCheck::Verify);
        tracker.notify_replication_refresh_started();
        tracker.notify_replication_refresh_success(PEER_1, T0 + 1);
        assert_eq!(tracker.get_database_health(), DatabaseHealth::Healthy);
        assert_state(
            &tracker,
            T0 + 1,
            ReplicationState::Healthy,
            ServingReadiness::Ready,
        );
    }

    #[test]
    fn test_tracker_clock_is_monotonic() {
        let first = tracker_now();
        let second = tracker_now();
        assert!(second >= first);
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
