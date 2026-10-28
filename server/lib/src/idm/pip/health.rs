//! PIP Health State Tracking
//!
//! Shared health state tracking logic for all PIP implementations.
//!
//! Health is tracked passively from real requests: a source starts `Unknown`
//! (retrievable), successful fetches mark it `Healthy`, and failures mark it
//! `Degraded` and then `Unhealthy` once `failure_threshold` is reached. While
//! `Unhealthy`, requests are short-circuited to the fallback behaviour, except
//! that one probe request is let through every `interval_secs` so the source can
//! recover without a background task. After a successful probe, requests flow
//! again until `success_threshold` consecutive successes mark it `Healthy`.

use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use super::config::PipHealthCheckConfig;
use super::PipHealthStatus;

/// Internal health state tracking shared by all PIP implementations
#[derive(Debug, Clone)]
pub struct PipHealthState {
    pub status: PipHealthStatus,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check: Option<Instant>,
    pub last_error: Option<String>,
}

impl PipHealthState {
    pub fn new() -> Self {
        PipHealthState {
            status: PipHealthStatus::Unknown,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check: None,
            last_error: None,
        }
    }

    pub fn record_success(&mut self, config: &PipHealthCheckConfig) {
        self.record_success_at(config, Instant::now());
    }

    pub fn record_success_at(&mut self, config: &PipHealthCheckConfig, now: Instant) {
        self.consecutive_failures = 0;
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);

        // The first ever successful contact establishes health directly; recovering
        // from failures requires `success_threshold` consecutive successes.
        if self.status == PipHealthStatus::Unknown
            || self.consecutive_successes >= config.success_threshold
        {
            self.status = PipHealthStatus::Healthy;
        }

        self.last_check = Some(now);
        self.last_error = None;
    }

    pub fn record_failure(&mut self, config: &PipHealthCheckConfig, error: String) {
        self.record_failure_at(config, error, Instant::now());
    }

    pub fn record_failure_at(
        &mut self,
        config: &PipHealthCheckConfig,
        error: String,
        now: Instant,
    ) {
        self.consecutive_successes = 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);

        if self.consecutive_failures >= config.failure_threshold {
            self.status = PipHealthStatus::Unhealthy;
        } else if self.consecutive_failures > 0 {
            self.status = PipHealthStatus::Degraded;
        }

        self.last_check = Some(now);
        self.last_error = Some(error);
    }

    /// Decide whether a request may be sent to the source at `now`.
    ///
    /// `Unknown`, `Healthy` and `Degraded` sources are always tried. An
    /// `Unhealthy` source is tried while it is recovering (a probe succeeded), or
    /// once `interval_secs` have passed since the last failure; in that case this
    /// call claims the probe (by updating `last_check`) so that concurrent
    /// requests do not all hit the failing source at once.
    pub fn try_begin_attempt_at(&mut self, config: &PipHealthCheckConfig, now: Instant) -> bool {
        if self.status != PipHealthStatus::Unhealthy || self.consecutive_successes > 0 {
            return true;
        }

        let interval = Duration::from_secs(config.interval_secs);
        match self.last_check {
            Some(last) if now.saturating_duration_since(last) < interval => false,
            _ => {
                self.last_check = Some(now);
                true
            }
        }
    }
}

impl Default for PipHealthState {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe, non-blocking holder of a [`PipHealthState`].
///
/// Uses a `std::sync::RwLock` whose critical sections are tiny and never held
/// across an `.await`, so it is safe to use from async code (unlike
/// `tokio::sync::RwLock::blocking_read`, which panics inside a runtime). A
/// poisoned lock is recovered, since the state is always left consistent.
#[derive(Debug, Default)]
pub struct PipHealthTracker {
    state: RwLock<PipHealthState>,
}

impl PipHealthTracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> RwLockReadGuard<'_, PipHealthState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, PipHealthState> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn status(&self) -> PipHealthStatus {
        self.read().status
    }

    pub fn snapshot(&self) -> PipHealthState {
        self.read().clone()
    }

    pub fn record_success(&self, config: &PipHealthCheckConfig) {
        self.write().record_success(config);
    }

    pub fn record_failure(&self, config: &PipHealthCheckConfig, error: String) {
        self.write().record_failure(config, error);
    }

    /// See [`PipHealthState::try_begin_attempt_at`].
    pub fn try_begin_attempt(&self, config: &PipHealthCheckConfig) -> bool {
        self.write().try_begin_attempt_at(config, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PipHealthCheckConfig {
        PipHealthCheckConfig {
            interval_secs: 60,
            failure_threshold: 3,
            success_threshold: 2,
            timeout_secs: 5,
        }
    }

    #[test]
    fn test_initial_state() {
        let state = PipHealthState::new();
        assert_eq!(state.status, PipHealthStatus::Unknown);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.consecutive_successes, 0);
        assert!(state.last_check.is_none());
        assert!(state.last_error.is_none());
    }

    #[test]
    fn test_default_state() {
        let state = PipHealthState::default();
        assert_eq!(state.status, PipHealthStatus::Unknown);
    }

    #[test]
    fn test_first_success_from_unknown_is_healthy() {
        let config = test_config();
        let mut state = PipHealthState::new();

        state.record_success(&config);
        assert_eq!(state.status, PipHealthStatus::Healthy);
        assert_eq!(state.consecutive_successes, 1);
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn test_unknown_and_degraded_always_attempt() {
        let config = test_config();
        let now = Instant::now();
        let mut state = PipHealthState::new();
        assert!(state.try_begin_attempt_at(&config, now));

        state.record_failure_at(&config, "e".to_string(), now);
        assert_eq!(state.status, PipHealthStatus::Degraded);
        assert!(state.try_begin_attempt_at(&config, now));
    }

    #[test]
    fn test_unhealthy_retries_after_interval_and_recovers() {
        let config = test_config(); // interval 60s, failure 3, success 2
        let t0 = Instant::now();
        let mut state = PipHealthState::new();

        for i in 0..3 {
            assert!(state.try_begin_attempt_at(&config, t0));
            state.record_failure_at(&config, format!("error{i}"), t0);
        }
        assert_eq!(state.status, PipHealthStatus::Unhealthy);

        // Inside the interval: short-circuit.
        assert!(!state.try_begin_attempt_at(&config, t0 + Duration::from_secs(1)));
        assert!(!state.try_begin_attempt_at(&config, t0 + Duration::from_secs(59)));

        // Interval elapsed: exactly one probe is let through.
        let t1 = t0 + Duration::from_secs(60);
        assert!(state.try_begin_attempt_at(&config, t1));
        assert!(!state.try_begin_attempt_at(&config, t1));

        // The probe fails: wait another full interval.
        state.record_failure_at(&config, "still down".to_string(), t1);
        assert_eq!(state.status, PipHealthStatus::Unhealthy);
        assert!(!state.try_begin_attempt_at(&config, t1 + Duration::from_secs(30)));

        // Next probe succeeds: requests flow while recovering...
        let t2 = t1 + Duration::from_secs(60);
        assert!(state.try_begin_attempt_at(&config, t2));
        state.record_success_at(&config, t2);
        assert_eq!(state.status, PipHealthStatus::Unhealthy);
        assert!(state.try_begin_attempt_at(&config, t2));

        // ...until success_threshold marks it healthy.
        state.record_success_at(&config, t2);
        assert_eq!(state.status, PipHealthStatus::Healthy);
        assert!(state.try_begin_attempt_at(&config, t2));
    }

    #[test]
    fn test_tracker_is_usable_from_async_context() {
        // Built on a current-thread runtime, where tokio's blocking_read() panics.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let config = test_config();
            let tracker = PipHealthTracker::new();
            assert_eq!(tracker.status(), PipHealthStatus::Unknown);
            assert!(tracker.try_begin_attempt(&config));
            tracker.record_failure(&config, "boom".to_string());
            assert_eq!(tracker.status(), PipHealthStatus::Degraded);
            tracker.record_success(&config);
            assert_eq!(tracker.snapshot().consecutive_successes, 1);
        });
    }

    #[test]
    fn test_failure_transitions_to_unhealthy() {
        let config = test_config();
        let mut state = PipHealthState::new();

        state.record_failure(&config, "error1".to_string());
        assert_eq!(state.status, PipHealthStatus::Degraded);
        assert_eq!(state.consecutive_failures, 1);
        assert!(state.last_error.is_some());

        state.record_failure(&config, "error2".to_string());
        assert_eq!(state.status, PipHealthStatus::Degraded);
        assert_eq!(state.consecutive_failures, 2);

        state.record_failure(&config, "error3".to_string());
        assert_eq!(state.status, PipHealthStatus::Unhealthy);
        assert_eq!(state.consecutive_successes, 0);
    }

    #[test]
    fn test_success_clears_failures() {
        let config = test_config();
        let mut state = PipHealthState::new();

        state.record_failure(&config, "error".to_string());
        assert_eq!(state.consecutive_failures, 1);

        state.record_success(&config);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.consecutive_successes, 1);
        assert!(state.last_error.is_none());
    }

    #[test]
    fn test_failure_clears_successes() {
        let config = test_config();
        let mut state = PipHealthState::new();

        state.record_success(&config);
        state.record_success(&config);
        assert_eq!(state.consecutive_successes, 2);

        state.record_failure(&config, "error".to_string());
        assert_eq!(state.consecutive_successes, 0);
        assert_eq!(state.consecutive_failures, 1);
    }

    #[test]
    fn test_last_check_updated_on_success() {
        let config = test_config();
        let mut state = PipHealthState::new();

        assert!(state.last_check.is_none());
        state.record_success(&config);
        assert!(state.last_check.is_some());
    }

    #[test]
    fn test_last_check_updated_on_failure() {
        let config = test_config();
        let mut state = PipHealthState::new();

        assert!(state.last_check.is_none());
        state.record_failure(&config, "error".to_string());
        assert!(state.last_check.is_some());
    }

    #[test]
    fn test_last_error_set_on_failure() {
        let config = test_config();
        let mut state = PipHealthState::new();

        state.record_failure(&config, "connection timeout".to_string());
        assert_eq!(state.last_error, Some("connection timeout".to_string()));

        state.record_failure(&config, "server error".to_string());
        assert_eq!(state.last_error, Some("server error".to_string()));
    }

    #[test]
    fn test_last_error_cleared_on_success() {
        let config = test_config();
        let mut state = PipHealthState::new();

        state.record_failure(&config, "error".to_string());
        assert!(state.last_error.is_some());

        state.record_success(&config);
        assert!(state.last_error.is_none());
    }

    #[test]
    fn test_multiple_failures_before_threshold() {
        let config = PipHealthCheckConfig {
            interval_secs: 60,
            failure_threshold: 5,
            success_threshold: 2,
            timeout_secs: 5,
        };
        let mut state = PipHealthState::new();

        for i in 1..=4 {
            state.record_failure(&config, format!("error{}", i));
            assert_eq!(state.status, PipHealthStatus::Degraded);
        }

        state.record_failure(&config, "error5".to_string());
        assert_eq!(state.status, PipHealthStatus::Unhealthy);
    }

    #[test]
    fn test_multiple_successes_before_threshold() {
        let config = PipHealthCheckConfig {
            interval_secs: 60,
            failure_threshold: 3,
            success_threshold: 5,
            timeout_secs: 5,
        };
        let mut state = PipHealthState::new();

        state.record_failure(&config, "error".to_string());
        assert_eq!(state.status, PipHealthStatus::Degraded);

        for _ in 1..=4 {
            state.record_success(&config);
            assert_eq!(state.status, PipHealthStatus::Degraded);
        }

        state.record_success(&config);
        assert_eq!(state.status, PipHealthStatus::Healthy);
    }

    #[test]
    fn test_recovery_from_unhealthy() {
        let config = test_config();
        let mut state = PipHealthState::new();

        state.record_failure(&config, "error1".to_string());
        state.record_failure(&config, "error2".to_string());
        state.record_failure(&config, "error3".to_string());
        assert_eq!(state.status, PipHealthStatus::Unhealthy);

        state.record_success(&config);
        assert_eq!(state.status, PipHealthStatus::Unhealthy);

        state.record_success(&config);
        assert_eq!(state.status, PipHealthStatus::Healthy);
    }

    #[test]
    fn test_failure_threshold_one() {
        let config = PipHealthCheckConfig {
            interval_secs: 60,
            failure_threshold: 1,
            success_threshold: 1,
            timeout_secs: 5,
        };
        let mut state = PipHealthState::new();

        state.record_failure(&config, "error".to_string());
        assert_eq!(state.status, PipHealthStatus::Unhealthy);
    }

    #[test]
    fn test_success_threshold_one() {
        let config = PipHealthCheckConfig {
            interval_secs: 60,
            failure_threshold: 3,
            success_threshold: 1,
            timeout_secs: 5,
        };
        let mut state = PipHealthState::new();

        state.record_success(&config);
        assert_eq!(state.status, PipHealthStatus::Healthy);
    }

    #[test]
    fn test_alternating_success_failure() {
        let config = test_config();
        let mut state = PipHealthState::new();

        state.record_success(&config);
        state.record_success(&config);
        assert_eq!(state.status, PipHealthStatus::Healthy);

        state.record_failure(&config, "error".to_string());
        assert_eq!(state.status, PipHealthStatus::Degraded);

        state.record_success(&config);
        state.record_success(&config);
        assert_eq!(state.status, PipHealthStatus::Healthy);
    }

    #[test]
    fn test_cloned_state_preserves_values() {
        let config = test_config();
        let mut state = PipHealthState::new();
        state.record_success(&config);
        state.record_failure(&config, "error".to_string());

        let cloned = state.clone();
        assert_eq!(cloned.status, state.status);
        assert_eq!(cloned.consecutive_failures, state.consecutive_failures);
        assert_eq!(cloned.consecutive_successes, state.consecutive_successes);
        assert_eq!(cloned.last_error, state.last_error);
    }

    #[test]
    fn test_health_status_can_retrieve() {
        assert!(PipHealthStatus::Healthy.can_retrieve());
        assert!(PipHealthStatus::Degraded.can_retrieve());
        assert!(!PipHealthStatus::Unhealthy.can_retrieve());
        assert!(PipHealthStatus::Unknown.can_retrieve());
    }

    #[test]
    fn test_health_status_is_healthy() {
        assert!(PipHealthStatus::Healthy.is_healthy());
        assert!(!PipHealthStatus::Degraded.is_healthy());
        assert!(!PipHealthStatus::Unhealthy.is_healthy());
        assert!(!PipHealthStatus::Unknown.is_healthy());
    }
}
