//! Node-local maintenance and replication handoff primitives.
//!
//! The cluster-wide sequencing belongs to an external orchestrator. This module
//! provides the local state, fence representation, readiness integration, and the
//! write permit used to make a node quiescent without stopping the process.

use crate::repl::proto::ReplRuvRange;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::RwLock;
use std::time::Duration;
use tokio::sync::SemaphorePermit;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum MaintenanceState {
    Serving = 0,
    Draining = 1,
    Fenced = 2,
    Maintenance = 3,
    Recovering = 4,
    Failed = 5,
}

impl MaintenanceState {
    pub fn is_serving(self) -> bool {
        matches!(self, Self::Serving)
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Serving,
            1 => Self::Draining,
            2 => Self::Fenced,
            3 => Self::Maintenance,
            4 => Self::Recovering,
            _ => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceOperation {
    Reindex,
    Verify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MaintenanceCapabilities {
    pub api_version: String,
    pub drain: bool,
    pub replication_fence: bool,
    pub sync_until: bool,
    pub reindex: bool,
    pub verify: bool,
    pub vacuum: bool,
    pub restore: bool,
}

impl Default for MaintenanceCapabilities {
    fn default() -> Self {
        Self {
            api_version: "v1".to_string(),
            drain: true,
            replication_fence: true,
            sync_until: true,
            reindex: true,
            verify: true,
            vacuum: false,
            restore: false,
        }
    }
}

/// Full node-local maintenance status, including the active operation id and the last
/// error. Only served on the privileged admin socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MaintenancePublicStatus {
    pub state: MaintenanceState,
    pub active_operation_id: Option<Uuid>,
    pub last_error: Option<String>,
    pub capabilities: MaintenanceCapabilities,
}

/// Maintenance status served on the unauthenticated `GET /maintenance` endpoint.
///
/// It deliberately omits the active operation id (a handle the privileged control
/// protocol keys on) and the last error (which can carry internal error details). Use
/// the admin socket `MaintenanceStatus` request for those.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MaintenanceHttpStatus {
    pub state: MaintenanceState,
    pub capabilities: MaintenanceCapabilities,
}

impl From<MaintenancePublicStatus> for MaintenanceHttpStatus {
    fn from(status: MaintenancePublicStatus) -> Self {
        Self {
            state: status.state,
            capabilities: status.capabilities,
        }
    }
}

static MAINTENANCE_STATE: AtomicU8 = AtomicU8::new(MaintenanceState::Serving as u8);
static ACTIVE_OPERATION_ID: RwLock<Option<Uuid>> = RwLock::new(None);
static LAST_ERROR: RwLock<Option<String>> = RwLock::new(None);

tokio::task_local! {
    static MAINTENANCE_WRITE_BYPASS: ();
}

fn write_allowed_for_state(state: MaintenanceState, bypass: bool) -> bool {
    state.is_serving() || bypass
}

/// Whether the current async task may start a QueryServer write transaction.
///
/// Ordinary tasks are admitted only while the node is serving. Privileged
/// maintenance work and replication recovery are scoped with
/// [`with_maintenance_write_bypass`], which is task-local and therefore can not
/// accidentally admit unrelated concurrent writers.
pub fn maintenance_write_allowed() -> bool {
    let bypass = MAINTENANCE_WRITE_BYPASS
        .try_with(|()| true)
        .unwrap_or(false);
    write_allowed_for_state(maintenance_state(), bypass)
}

/// Run one future with privileged access to QueryServer writes.
///
/// The scope is inherited only by the future being directly awaited; unrelated
/// Tokio tasks remain subject to the normal maintenance write gate.
pub async fn with_maintenance_write_bypass<F>(future: F) -> F::Output
where
    F: Future,
{
    MAINTENANCE_WRITE_BYPASS.scope((), future).await
}

pub fn maintenance_state() -> MaintenanceState {
    MaintenanceState::from_u8(MAINTENANCE_STATE.load(Ordering::Acquire))
}

pub fn set_maintenance_state(state: MaintenanceState, operation_id: Option<Uuid>) {
    if let Ok(mut active) = ACTIVE_OPERATION_ID.write() {
        *active = operation_id;
    }
    MAINTENANCE_STATE.store(state as u8, Ordering::Release);
}

pub fn set_maintenance_error(message: Option<String>) {
    if let Ok(mut error) = LAST_ERROR.write() {
        *error = message;
    }
}

pub fn maintenance_public_status() -> MaintenancePublicStatus {
    MaintenancePublicStatus {
        state: maintenance_state(),
        active_operation_id: ACTIVE_OPERATION_ID.read().ok().and_then(|id| *id),
        last_error: LAST_ERROR.read().ok().and_then(|error| (*error).clone()),
        capabilities: MaintenanceCapabilities::default(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationFenceRange {
    pub ts_min: Duration,
    pub ts_max: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationFence {
    pub version: u8,
    pub domain_uuid: Uuid,
    pub generation: Option<Uuid>,
    pub ranges: BTreeMap<Uuid, ReplicationFenceRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceSatisfaction {
    Satisfied,
    Unsatisfied,
    DomainMismatch,
    GenerationMismatch,
}

impl ReplicationFence {
    pub fn from_ruv_range(range: ReplRuvRange) -> Self {
        match range {
            ReplRuvRange::V1 {
                domain_uuid,
                ranges,
            } => Self {
                version: 1,
                domain_uuid,
                generation: None,
                ranges: ranges
                    .into_iter()
                    .map(|(server_uuid, range)| {
                        (
                            server_uuid,
                            ReplicationFenceRange {
                                ts_min: range.ts_min,
                                ts_max: range.ts_max,
                            },
                        )
                    })
                    .collect(),
            },
        }
    }

    /// Return whether `current` (a fence captured from the local replication state)
    /// has observed at least every per-replica maximum represented by this fence.
    ///
    /// `ts_min` is deliberately not required to move backwards. A node may have
    /// legitimately trimmed old replication history after applying it; the maximum
    /// CID per supplier identity is the handoff proof we need here.
    pub fn satisfaction(&self, current: &ReplicationFence) -> FenceSatisfaction {
        // Only version 1 fences are understood, on both sides.
        if self.version != 1 || current.version != 1 {
            return FenceSatisfaction::Unsatisfied;
        }

        if self.domain_uuid != current.domain_uuid {
            return FenceSatisfaction::DomainMismatch;
        }

        // Generation support is not implemented in the replication protocol yet, so
        // a generation can never actually be verified. Any non-None generation, on
        // either side, is rejected rather than compared for equality: two equal but
        // unverifiable generations are not proof that the histories are related.
        if self.generation.is_some() || current.generation.is_some() {
            return FenceSatisfaction::GenerationMismatch;
        }

        let satisfied = self.ranges.iter().all(|(server_uuid, fence_range)| {
            current
                .ranges
                .get(server_uuid)
                .is_some_and(|current_range| current_range.ts_max >= fence_range.ts_max)
        });

        if satisfied {
            FenceSatisfaction::Satisfied
        } else {
            FenceSatisfaction::Unsatisfied
        }
    }
}

/// A deliberately opaque RAII write fence.
///
/// While this value exists, the QueryServer's single writer permit is held, so
/// client, delayed/internal, and replication write transactions all queue behind
/// the maintenance fence. Read transactions remain available, which is required
/// so another replica can pull the final fenced history.
pub struct QueryServerMaintenanceWriteFence<'a> {
    _write_ticket: SemaphorePermit<'a>,
}

impl<'a> QueryServerMaintenanceWriteFence<'a> {
    pub(crate) fn new(write_ticket: SemaphorePermit<'a>) -> Self {
        Self {
            _write_ticket: write_ticket,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::proto::{ReplCidRange, ReplRuvRange};

    fn ruv(domain_uuid: Uuid, entries: &[(Uuid, u64, u64)]) -> ReplRuvRange {
        let ranges = entries
            .iter()
            .map(|(server_uuid, min, max)| {
                (
                    *server_uuid,
                    ReplCidRange {
                        ts_min: Duration::from_secs(*min),
                        ts_max: Duration::from_secs(*max),
                    },
                )
            })
            .collect();
        ReplRuvRange::V1 {
            domain_uuid,
            ranges,
        }
    }

    fn fence(domain_uuid: Uuid, entries: &[(Uuid, u64, u64)]) -> ReplicationFence {
        ReplicationFence::from_ruv_range(ruv(domain_uuid, entries))
    }

    #[test]
    fn fence_is_satisfied_by_identical_or_newer_ranges() {
        let domain = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let target = fence(domain, &[(a, 1, 10), (b, 2, 20)]);

        assert_eq!(
            target.satisfaction(&fence(domain, &[(a, 1, 10), (b, 2, 20)])),
            FenceSatisfaction::Satisfied
        );
        assert_eq!(
            target.satisfaction(&fence(domain, &[(a, 5, 11), (b, 10, 30)])),
            FenceSatisfaction::Satisfied
        );
    }

    #[test]
    fn fence_requires_every_supplier_maximum() {
        let domain = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let target = fence(domain, &[(a, 1, 10), (b, 2, 20)]);

        assert_eq!(
            target.satisfaction(&fence(domain, &[(a, 1, 10)])),
            FenceSatisfaction::Unsatisfied
        );
        assert_eq!(
            target.satisfaction(&fence(domain, &[(a, 1, 9), (b, 2, 20)])),
            FenceSatisfaction::Unsatisfied
        );
    }

    #[test]
    fn write_gate_allows_only_serving_or_privileged_tasks() {
        assert!(write_allowed_for_state(MaintenanceState::Serving, false));
        assert!(write_allowed_for_state(MaintenanceState::Serving, true));
        assert!(!write_allowed_for_state(MaintenanceState::Draining, false));
        assert!(!write_allowed_for_state(MaintenanceState::Fenced, false));
        assert!(!write_allowed_for_state(
            MaintenanceState::Maintenance,
            false
        ));
        assert!(!write_allowed_for_state(
            MaintenanceState::Recovering,
            false
        ));
        assert!(!write_allowed_for_state(MaintenanceState::Failed, false));
        assert!(write_allowed_for_state(MaintenanceState::Recovering, true));
    }

    #[test]
    fn fence_rejects_domain_or_generation_mismatch() {
        let domain = Uuid::new_v4();
        let a = Uuid::new_v4();
        let mut target = fence(domain, &[(a, 1, 10)]);

        assert_eq!(
            target.satisfaction(&fence(Uuid::new_v4(), &[(a, 1, 10)])),
            FenceSatisfaction::DomainMismatch
        );

        target.generation = Some(Uuid::new_v4());
        assert_eq!(
            target.satisfaction(&fence(domain, &[(a, 1, 10)])),
            FenceSatisfaction::GenerationMismatch
        );
    }

    #[test]
    fn fence_rejects_unverifiable_generation_even_when_equal() {
        let domain = Uuid::new_v4();
        let a = Uuid::new_v4();
        let generation = Some(Uuid::new_v4());

        let mut target = fence(domain, &[(a, 1, 10)]);
        let mut current = fence(domain, &[(a, 1, 10)]);

        // A generation present only on the current side is rejected too.
        current.generation = generation;
        assert_eq!(
            target.satisfaction(&current),
            FenceSatisfaction::GenerationMismatch
        );

        // Equal generations can not be verified by this protocol version either.
        target.generation = generation;
        assert_eq!(
            target.satisfaction(&current),
            FenceSatisfaction::GenerationMismatch
        );
    }

    #[test]
    fn fence_with_unknown_version_is_never_satisfied() {
        let domain = Uuid::new_v4();
        let a = Uuid::new_v4();

        let mut target = fence(domain, &[(a, 1, 10)]);
        target.version = 2;
        assert_eq!(
            target.satisfaction(&fence(domain, &[(a, 1, 10)])),
            FenceSatisfaction::Unsatisfied
        );

        let target = fence(domain, &[(a, 1, 10)]);
        let mut current = fence(domain, &[(a, 1, 20)]);
        current.version = 2;
        assert_eq!(
            target.satisfaction(&current),
            FenceSatisfaction::Unsatisfied
        );
    }

    #[test]
    fn empty_fence_is_satisfied_by_any_history_of_the_domain() {
        let domain = Uuid::new_v4();
        let a = Uuid::new_v4();
        let target = fence(domain, &[]);

        assert_eq!(
            target.satisfaction(&fence(domain, &[])),
            FenceSatisfaction::Satisfied
        );
        assert_eq!(
            target.satisfaction(&fence(domain, &[(a, 1, 10)])),
            FenceSatisfaction::Satisfied
        );
    }

    #[test]
    fn http_status_omits_operation_id_and_error() {
        let status = MaintenancePublicStatus {
            state: MaintenanceState::Failed,
            active_operation_id: Some(Uuid::new_v4()),
            last_error: Some("internal detail".to_string()),
            capabilities: MaintenanceCapabilities::default(),
        };
        let http: MaintenanceHttpStatus = status.into();
        assert_eq!(http.state, MaintenanceState::Failed);

        let value = serde_json::to_value(&http).expect("http status should serialize");
        assert!(value.get("active_operation_id").is_none());
        assert!(value.get("last_error").is_none());
        assert_eq!(value["state"], "failed");
    }
}
