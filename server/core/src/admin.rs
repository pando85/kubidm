use crate::{
    actors::{QueryServerReadV1, QueryServerWriteV1},
    repl::{RefreshProgress, ReplCtrl},
    CoreAction,
};
use bytes::{Buf, BufMut, BytesMut};
use crypto_glue::x509::x509b64;
use futures::{SinkExt, StreamExt};
pub use kubidm_proto::internal::{
    DomainInfo as ProtoDomainInfo, DomainUpgradeCheckReport as ProtoDomainUpgradeCheckReport,
    DomainUpgradeCheckStatus as ProtoDomainUpgradeCheckStatus,
};
use kubidm_utils_users::get_current_uid;
use kubidmd_lib::maintenance::{
    maintenance_public_status, set_maintenance_error, set_maintenance_state,
    with_maintenance_write_bypass, FenceSatisfaction, MaintenanceCapabilities,
    MaintenancePublicStatus, MaintenanceState,
};
// The request types name these, so a client of the admin socket needs them too.
pub use kubidmd_lib::maintenance::{MaintenanceOperation, ReplicationFence};
use kubidmd_lib::prelude::{duration_from_epoch_now, IdmServer, OperationError};
use kubidmd_lib::status::{DatabaseCheck, ReplicationStateTracker};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::error::Error;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, timeout_at, Instant};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{span, Instrument, Level};
use uuid::Uuid;

/// Don't hang forever waiting for a response. Also how long a manual refresh may take to
/// start: see [`start_consumer_refresh`].
const REPL_CTRL_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the requester of a refresh waits for it once a supplier task has started it.
/// A task that has not yet reached its pre-apply check refuses to apply the refresh once the
/// requester has gone away; past that check the apply finishes regardless, so this only
/// bounds how long the requester waits to learn the outcome.
const REFRESH_COMPLETION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// The most bytes of one request the server buffers while it waits for the rest of it.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// The most bytes of one response a client buffers while it waits for the rest of it.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAINTENANCE_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const MAINTENANCE_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SYNC_UNTIL_TIMEOUT: Duration = Duration::from_secs(60);
const SYNC_UNTIL_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Upper bound of a single sync-until wait. Orchestrators that need longer simply repeat
/// the request; an unbounded value would overflow the deadline computation.
const MAX_SYNC_UNTIL_TIMEOUT: Duration = Duration::from_secs(60 * 60);

#[derive(Serialize, Deserialize, Debug)]
pub enum AdminTaskRequest {
    RecoverAccount {
        name: String,
    },
    DisableAccount {
        name: String,
    },
    ShowReplicationCertificate,
    ShowReplicationCertificateMetadata,
    RenewReplicationCertificate,
    /// Refresh this node from whichever supplier answers first.
    RefreshReplicationConsumer,
    /// Refresh this node only from the supplier whose origin is `from`. A separate variant,
    /// so that the request without a source keeps its original wire form for servers and
    /// clients of other versions, and a server that does not know this one never refreshes
    /// from any supplier instead. Servers up to 1.11 do not answer it at all (their codec
    /// waits for more bytes forever), so a client must not wait on them without a limit.
    ///
    /// Only clients that know [`AdminTaskResponse::RefreshStarted`] send this, so the
    /// server answers with it first once a supplier task started the refresh, then with
    /// the outcome.
    RefreshReplicationConsumerFrom {
        from: String,
    },
    DomainShow,
    DomainUpgradeCheck,
    DomainRaise,
    DomainRemigrate {
        level: Option<u32>,
    },
    MaintenanceCapabilities,
    MaintenanceStatus,
    MaintenanceDrain {
        operation_id: Uuid,
    },
    MaintenanceRun {
        operation_id: Uuid,
        operation: MaintenanceOperation,
    },
    ReplicationFence,
    ReplicationSyncUntil {
        operation_id: Uuid,
        fence: ReplicationFence,
        timeout_seconds: Option<u64>,
    },
    MaintenanceResume {
        operation_id: Uuid,
    },
    Reload,
    /// Kubidm: break-glass for approval workflows. Disable the approval policy `name`, or
    /// every enabled policy with `None`, as the internal system identity, which turns off
    /// the approval gates they enable even when no one can act as an approval admin. A new
    /// variant, so the wire form of the other requests is unchanged; only clients that know
    /// [`AdminTaskResponse::ApprovalPoliciesDisabled`] send it.
    ApprovalPolicyDisable {
        name: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceErrorCode {
    Busy,
    InvalidState,
    OperationMismatch,
    Database,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationSyncResult {
    Satisfied,
    TimedOut,
    DomainMismatch,
    GenerationMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceRunResult {
    pub operation_id: Uuid,
    pub operation: MaintenanceOperation,
    pub success: bool,
    pub verification_errors: Vec<String>,
    pub fence: Option<ReplicationFence>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub enum AdminTaskResponse {
    RecoverAccount {
        password: String,
    },
    ShowReplicationCertificate {
        cert: String,
    },
    ShowReplicationCertificateMetadata {
        not_before: String,
        not_after: String,
        subject: String,
        expired: bool,
    },
    DomainUpgradeCheck {
        report: ProtoDomainUpgradeCheckReport,
    },
    DomainRaise {
        level: u32,
    },
    DomainShow {
        domain_info: ProtoDomainInfo,
    },
    MaintenanceCapabilities {
        capabilities: MaintenanceCapabilities,
    },
    MaintenanceStatus {
        status: MaintenancePublicStatus,
        fence: Option<ReplicationFence>,
    },
    MaintenanceDrain {
        operation_id: Uuid,
        fence: ReplicationFence,
    },
    MaintenanceRun {
        result: MaintenanceRunResult,
    },
    ReplicationFence {
        fence: ReplicationFence,
    },
    ReplicationSyncUntil {
        result: ReplicationSyncResult,
        current_fence: ReplicationFence,
    },
    MaintenanceResume {
        operation_id: Uuid,
    },
    MaintenanceError {
        code: MaintenanceErrorCode,
        message: String,
    },
    Success,
    Error,
    /// The request failed for a reason the operator can act on, given in `message`.
    ErrorMessage {
        message: String,
    },
    /// Not a final response: the refresh asked for by
    /// [`AdminTaskRequest::RefreshReplicationConsumerFrom`] started from `supplier`, and its
    /// outcome follows. Never sent for any other request, so that clients of versions
    /// without it never see it.
    RefreshStarted {
        supplier: String,
    },
    /// The answer to [`AdminTaskRequest::ApprovalPolicyDisable`]: the names of the policies
    /// that were enabled and are now disabled. Never sent for any other request.
    ApprovalPoliciesDisabled {
        names: Vec<String>,
    },
}

impl std::fmt::Debug for AdminTaskResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // the intent here is that we aren't sharing secret material in logs
            AdminTaskResponse::RecoverAccount { .. } => write!(f, "RecoverAccount {{ .. }}"),
            // the intent here is that we aren't sharing secret material in logs
            AdminTaskResponse::ShowReplicationCertificate { .. } => {
                write!(f, "ShowReplicationCertificate {{ .. }}")
            }
            AdminTaskResponse::ShowReplicationCertificateMetadata {
                not_before,
                not_after,
                subject,
                expired,
            } => {
                write!(f, "ShowReplicationCertificateMetadata {{ not_before: {:?}, not_after: {:?}, subject: {:?}, expired: {} }}", not_before, not_after, subject, expired)
            }
            AdminTaskResponse::DomainUpgradeCheck { report } => {
                write!(f, "DomainUpgradeCheck {{ report: {:?} }}", report)
            }
            AdminTaskResponse::DomainRaise { level } => {
                write!(f, "DomainRaise {{ level: {} }}", level)
            }
            AdminTaskResponse::DomainShow { domain_info } => {
                write!(f, "DomainShow {{ domain_info: {:?} }}", domain_info)
            }
            AdminTaskResponse::MaintenanceCapabilities { capabilities } => {
                write!(f, "MaintenanceCapabilities {{ {:?} }}", capabilities)
            }
            AdminTaskResponse::MaintenanceStatus { status, fence } => {
                write!(
                    f,
                    "MaintenanceStatus {{ status: {:?}, fence: {:?} }}",
                    status, fence
                )
            }
            AdminTaskResponse::MaintenanceDrain {
                operation_id,
                fence,
            } => write!(
                f,
                "MaintenanceDrain {{ operation_id: {}, fence: {:?} }}",
                operation_id, fence
            ),
            AdminTaskResponse::MaintenanceRun { result } => {
                write!(f, "MaintenanceRun {{ {:?} }}", result)
            }
            AdminTaskResponse::ReplicationFence { fence } => {
                write!(f, "ReplicationFence {{ {:?} }}", fence)
            }
            AdminTaskResponse::ReplicationSyncUntil {
                result,
                current_fence,
            } => write!(
                f,
                "ReplicationSyncUntil {{ result: {:?}, current_fence: {:?} }}",
                result, current_fence
            ),
            AdminTaskResponse::MaintenanceResume { operation_id } => {
                write!(f, "MaintenanceResume {{ operation_id: {} }}", operation_id)
            }
            AdminTaskResponse::MaintenanceError { code, message } => {
                write!(
                    f,
                    "MaintenanceError {{ code: {:?}, message: {:?} }}",
                    code, message
                )
            }
            AdminTaskResponse::Success => write!(f, "Success"),
            AdminTaskResponse::Error => write!(f, "Error"),
            AdminTaskResponse::ErrorMessage { message } => {
                write!(f, "ErrorMessage {{ message: {:?} }}", message)
            }
            AdminTaskResponse::RefreshStarted { supplier } => {
                write!(f, "RefreshStarted {{ supplier: {:?} }}", supplier)
            }
            AdminTaskResponse::ApprovalPoliciesDisabled { names } => {
                write!(f, "ApprovalPoliciesDisabled {{ names: {:?} }}", names)
            }
        }
    }
}

/// Decode one message of the admin socket from `src`.
///
/// A message is a bare JSON value (an object, or a string for a request without fields),
/// with no length prefix or delimiter: it ends where its JSON value ends. So `Ok(None)`
/// (wait for more bytes) only while the value is incomplete, which serde_json reports as an
/// end of input error. Any other error is final: malformed JSON, or a complete message this
/// side does not know (sent by a client or server of another version). Waiting for more
/// bytes then would hang both sides, so it is an `InvalidData` error instead. So is an
/// incomplete message longer than `max_bytes`, rather than buffering it without a limit.
///
/// The error is logged here, at debug only: the decoder error can quote the message.
fn decode_json_frame<T: DeserializeOwned>(
    src: &mut BytesMut,
    max_bytes: usize,
) -> Result<Option<T>, io::Error> {
    let mut values = serde_json::Deserializer::from_slice(src).into_iter::<T>();
    match values.next() {
        Some(Ok(msg)) => {
            // Keep any bytes after this message for the next one.
            let consumed = values.byte_offset();
            src.advance(consumed);
            Ok(Some(msg))
        }
        Some(Err(err)) if err.is_eof() => {
            if src.len() > max_bytes {
                debug!(
                    len = src.len(),
                    max_bytes, "Admin socket message is too large, refusing it"
                );
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "admin socket message is too large",
                ))
            } else {
                Ok(None)
            }
        }
        Some(Err(err)) => {
            debug!(?err, "Unable to decode admin socket message");
            Err(io::Error::new(io::ErrorKind::InvalidData, err))
        }
        // Nothing but whitespace.
        None => {
            src.clear();
            Ok(None)
        }
    }
}

#[derive(Default)]
pub struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = AdminTaskResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode response ...");
        decode_json_frame(src, MAX_RESPONSE_BYTES)
    }
}

impl Encoder<AdminTaskRequest> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: AdminTaskRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::other("JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

#[derive(Default)]
struct ServerCodec;

impl Decoder for ServerCodec {
    type Error = io::Error;
    type Item = AdminTaskRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        decode_json_frame(src, MAX_REQUEST_BYTES)
    }
}

impl Encoder<AdminTaskResponse> for ServerCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: AdminTaskResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::other("JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

struct HeldWriteFence {
    release: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// A maintenance step that released the controller lock to do slow work: acquiring or
/// releasing the write fence, reindexing, verifying or waiting for peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlightStep {
    Drain,
    Run,
    SyncUntil,
    Resume,
}

/// Node-local maintenance state machine.
///
/// Every request first decides, under the controller lock, whether it may proceed and
/// marks its step as in flight; it then does its slow work without the lock and
/// finally records the outcome under the lock again. The methods here are the pure
/// decisions; the async request handlers below do the I/O.
#[derive(Default)]
struct MaintenanceController {
    active_operation_id: Option<Uuid>,
    fence: Option<ReplicationFence>,
    held_write_fence: Option<HeldWriteFence>,
    last_run: Option<MaintenanceRunResult>,
    last_resumed_operation_id: Option<Uuid>,
    /// Set while a step of the active operation runs outside the lock. No other step may
    /// change the controller in the meantime: in particular a resume must not clear the
    /// operation underneath a run or sync-until that later stores a fresh write fence,
    /// which would leave a fence held that nothing can release.
    in_flight: Option<InFlightStep>,
}

/// A change of the process-global maintenance state (readiness and write gate), which
/// the caller applies while it still holds the controller lock so that the two always
/// agree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StateTransition {
    state: MaintenanceState,
    operation_id: Option<Uuid>,
    /// `Some` replaces the last error, `None` keeps it.
    error: Option<Option<String>>,
}

impl StateTransition {
    fn to(state: MaintenanceState, operation_id: Option<Uuid>) -> Self {
        Self {
            state,
            operation_id,
            error: None,
        }
    }

    fn with_error(mut self, error: Option<String>) -> Self {
        self.error = Some(error);
        self
    }

    fn apply(self) {
        if let Some(error) = self.error {
            set_maintenance_error(error);
        }
        set_maintenance_state(self.state, self.operation_id);
    }
}

/// How a drain request proceeds.
enum DrainStart {
    /// The operation already holds its fence: answer with it again.
    Fenced(ReplicationFence),
    /// Acquire the write fence. `fresh` is true when no operation was active before, so a
    /// failure can roll the node back to serving.
    Acquire {
        fresh: bool,
        transition: StateTransition,
    },
}

type WriteFenceResult = Result<(HeldWriteFence, ReplicationFence), String>;

/// The fence a locally recovering sync-until releases (if any was held), and the state to
/// enter while it waits.
type LocalRecovery = (Option<HeldWriteFence>, StateTransition);

impl MaintenanceController {
    fn in_flight_busy(&self, operation_id: Uuid) -> Option<AdminTaskResponse> {
        self.in_flight.map(|step| {
            maintenance_error(
                MaintenanceErrorCode::Busy,
                format!(
                    "maintenance operation {operation_id} has a {step:?} step in progress, retry once it completes"
                ),
            )
        })
    }

    fn begin_drain(&mut self, operation_id: Uuid) -> Result<DrainStart, AdminTaskResponse> {
        let fresh = match self.active_operation_id {
            Some(active) if active == operation_id => {
                // A retry while the first drain (or any other step) is still running must
                // not start a second fence acquisition: it can only time out behind the
                // first one and then overwrite its result.
                if let Some(busy) = self.in_flight_busy(operation_id) {
                    return Err(busy);
                }
                if let Some(fence) = self.fence.clone() {
                    return Ok(DrainStart::Fenced(fence));
                }
                // The operation lost its fence (a failed drain retry or re-fence): fence again.
                false
            }
            Some(active) => {
                return Err(maintenance_error(
                    MaintenanceErrorCode::Busy,
                    format!("maintenance operation {active} is already active"),
                ));
            }
            None => true,
        };

        self.active_operation_id = Some(operation_id);
        self.fence = None;
        self.last_run = None;
        self.in_flight = Some(InFlightStep::Drain);

        Ok(DrainStart::Acquire {
            fresh,
            transition: StateTransition::to(MaintenanceState::Draining, Some(operation_id))
                .with_error(None),
        })
    }

    fn finish_drain(
        &mut self,
        operation_id: Uuid,
        fresh: bool,
        result: WriteFenceResult,
    ) -> (AdminTaskResponse, StateTransition) {
        self.in_flight = None;
        match result {
            Ok((held, fence)) => {
                self.held_write_fence = Some(held);
                self.fence = Some(fence.clone());
                (
                    AdminTaskResponse::MaintenanceDrain {
                        operation_id,
                        fence,
                    },
                    StateTransition::to(MaintenanceState::Fenced, Some(operation_id)),
                )
            }
            Err(err) if fresh => {
                // Nothing was fenced and nothing was active before this drain, so there is
                // nothing to protect: go back to serving rather than gating writes until
                // an operator notices and resumes. The operation counts as resumed, so an
                // orchestrator that resumes after a failed drain gets an idempotent success.
                self.active_operation_id = None;
                self.fence = None;
                self.last_resumed_operation_id = Some(operation_id);
                (
                    maintenance_error(MaintenanceErrorCode::Timeout, err.clone()),
                    StateTransition::to(MaintenanceState::Serving, None).with_error(Some(err)),
                )
            }
            Err(err) => (
                // A retry for an operation that was already in progress (for example
                // after a failed reindex re-fence): keep it failed, it needs a resume.
                maintenance_error(MaintenanceErrorCode::Timeout, err.clone()),
                StateTransition::to(MaintenanceState::Failed, Some(operation_id))
                    .with_error(Some(err)),
            ),
        }
    }

    /// Start a run. The error is the immediate response, which is the previous result for
    /// an idempotent retry.
    fn begin_run(
        &mut self,
        operation_id: Uuid,
        operation: MaintenanceOperation,
    ) -> Result<(Option<HeldWriteFence>, StateTransition), AdminTaskResponse> {
        if self.active_operation_id != Some(operation_id) {
            return Err(maintenance_error(
                MaintenanceErrorCode::OperationMismatch,
                "operation id does not own the active maintenance fence",
            ));
        }
        if let Some(busy) = self.in_flight_busy(operation_id) {
            return Err(busy);
        }
        if let Some(previous) = self.last_run.as_ref() {
            if previous.operation == operation {
                return Err(AdminTaskResponse::MaintenanceRun {
                    result: previous.clone(),
                });
            }
            return Err(maintenance_error(
                MaintenanceErrorCode::OperationMismatch,
                "operation id was already used for a different maintenance operation",
            ));
        }
        if self.held_write_fence.is_none() {
            return Err(maintenance_error(
                MaintenanceErrorCode::InvalidState,
                "node is not currently fenced",
            ));
        }

        self.in_flight = Some(InFlightStep::Run);
        let held_for_reindex = if matches!(operation, MaintenanceOperation::Reindex) {
            // The node is unfenced while it reindexes, so the drain fence no longer
            // describes it; the re-fence afterwards captures a new one.
            self.fence = None;
            self.held_write_fence.take()
        } else {
            None
        };
        Ok((
            held_for_reindex,
            StateTransition::to(MaintenanceState::Maintenance, Some(operation_id)),
        ))
    }

    /// Store the write fence re-acquired after the node was briefly unfenced.
    fn store_refence(&mut self, result: WriteFenceResult) -> Result<(), String> {
        match result {
            Ok((held, fence)) => {
                self.held_write_fence = Some(held);
                self.fence = Some(fence);
                Ok(())
            }
            Err(err) => {
                // The previous fence no longer describes the node, never hand it out again.
                self.fence = None;
                Err(err)
            }
        }
    }

    fn finish_run(
        &mut self,
        operation_id: Uuid,
        operation: MaintenanceOperation,
        operation_error: Option<String>,
        verification_errors: Vec<String>,
    ) -> (MaintenanceRunResult, StateTransition) {
        self.in_flight = None;
        let success = operation_error.is_none() && verification_errors.is_empty();
        let result = MaintenanceRunResult {
            operation_id,
            operation,
            success,
            verification_errors,
            fence: self.fence.clone(),
            error: operation_error.clone(),
        };
        self.last_run = Some(result.clone());

        let transition = if success {
            StateTransition::to(MaintenanceState::Fenced, Some(operation_id)).with_error(None)
        } else {
            let message =
                operation_error.unwrap_or_else(|| "consistency verification failed".to_string());
            StateTransition::to(MaintenanceState::Failed, Some(operation_id))
                .with_error(Some(message))
        };
        (result, transition)
    }

    /// Start a sync-until. `Some` when this node owns the operation and must recover
    /// locally: release the held fence (if any) and re-fence afterwards.
    fn begin_sync_until(
        &mut self,
        operation_id: Uuid,
    ) -> Result<Option<LocalRecovery>, AdminTaskResponse> {
        match self.active_operation_id {
            Some(active) if active != operation_id => Err(maintenance_error(
                MaintenanceErrorCode::Busy,
                format!("maintenance operation {active} is already active"),
            )),
            Some(_) => {
                if let Some(busy) = self.in_flight_busy(operation_id) {
                    return Err(busy);
                }
                self.in_flight = Some(InFlightStep::SyncUntil);
                Ok(Some((
                    self.held_write_fence.take(),
                    StateTransition::to(MaintenanceState::Recovering, Some(operation_id)),
                )))
            }
            None => Ok(None),
        }
    }

    fn finish_sync_until(
        &mut self,
        operation_id: Uuid,
        result: WriteFenceResult,
    ) -> (Result<(), String>, StateTransition) {
        self.in_flight = None;
        match self.store_refence(result) {
            Ok(()) => (
                Ok(()),
                StateTransition::to(MaintenanceState::Fenced, Some(operation_id)),
            ),
            Err(err) => (
                Err(err.clone()),
                StateTransition::to(MaintenanceState::Failed, Some(operation_id))
                    .with_error(Some(err)),
            ),
        }
    }

    /// Start a resume, returning the fence to release. The error is the immediate
    /// response, which is a success for an idempotent retry.
    fn begin_resume(
        &mut self,
        operation_id: Uuid,
    ) -> Result<Option<HeldWriteFence>, AdminTaskResponse> {
        if self.active_operation_id.is_none()
            && self.last_resumed_operation_id == Some(operation_id)
        {
            return Err(AdminTaskResponse::MaintenanceResume { operation_id });
        }
        if self.active_operation_id != Some(operation_id) {
            return Err(maintenance_error(
                MaintenanceErrorCode::OperationMismatch,
                "operation id does not own the active maintenance fence",
            ));
        }
        if let Some(busy) = self.in_flight_busy(operation_id) {
            return Err(busy);
        }

        self.in_flight = Some(InFlightStep::Resume);
        Ok(self.held_write_fence.take())
    }

    fn finish_resume(&mut self, operation_id: Uuid) -> StateTransition {
        self.active_operation_id = None;
        self.fence = None;
        self.last_run = None;
        self.last_resumed_operation_id = Some(operation_id);
        self.in_flight = None;
        StateTransition::to(MaintenanceState::Serving, None).with_error(None)
    }

    /// The handler of an in-flight step stopped (a panic, or its future was dropped)
    /// before recording an outcome. The real state of the node is unknown, so release the
    /// step's claim and mark the operation failed: a drain retry or a resume recovers it.
    fn abandon_in_flight(&mut self, operation_id: Uuid, step: InFlightStep) -> StateTransition {
        self.in_flight = None;
        // A fence the step had taken out of the controller was released when the step
        // was dropped, so a captured fence no longer describes a held one.
        if self.held_write_fence.is_none() {
            self.fence = None;
        }
        StateTransition::to(MaintenanceState::Failed, Some(operation_id)).with_error(Some(format!(
            "maintenance {step:?} step of operation {operation_id} stopped before completing"
        )))
    }
}

fn lock_controller(
    controller: &Mutex<MaintenanceController>,
) -> MutexGuard<'_, MaintenanceController> {
    // The lock is never held across an await. A panic while it was held must not wedge
    // maintenance until a restart: the controller state is still meaningful, and an
    // interrupted step is repaired by its `InFlightGuard`.
    controller.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Owns the in-flight claim of one step between its `begin_*` and `finish_*`.
///
/// `finish` records the outcome. If the guard is dropped without finishing (a panic
/// unwinding through the handler, or its future being dropped), the claim is released
/// and the operation is marked failed, so the node never stays busy and write-gated
/// until a restart.
struct InFlightGuard {
    controller: Arc<Mutex<MaintenanceController>>,
    operation_id: Uuid,
    step: InFlightStep,
    publish: fn(StateTransition),
    finished: bool,
}

impl InFlightGuard {
    fn new(
        controller: Arc<Mutex<MaintenanceController>>,
        operation_id: Uuid,
        step: InFlightStep,
    ) -> Self {
        Self {
            controller,
            operation_id,
            step,
            publish: StateTransition::apply,
            finished: false,
        }
    }

    /// Record the step's outcome and publish its state transition under the lock.
    fn finish<T>(
        mut self,
        record: impl FnOnce(&mut MaintenanceController) -> (T, StateTransition),
    ) -> T {
        self.finished = true;
        let mut state = lock_controller(&self.controller);
        let (value, transition) = record(&mut state);
        (self.publish)(transition);
        value
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut state = lock_controller(&self.controller);
        if state.active_operation_id == Some(self.operation_id)
            && state.in_flight == Some(self.step)
        {
            let transition = state.abandon_in_flight(self.operation_id, self.step);
            (self.publish)(transition);
        }
    }
}

pub(crate) struct AdminActor;

impl AdminActor {
    pub async fn create_admin_sock(
        sock_path: &str,
        server_rw: &'static QueryServerWriteV1,
        server_ro: &'static QueryServerReadV1,
        broadcast_tx: broadcast::Sender<CoreAction>,
        repl_ctrl_tx: Option<mpsc::Sender<ReplCtrl>>,
    ) -> Result<tokio::task::JoinHandle<()>, ()> {
        debug!("🧹 Cleaning up sockets from previous invocations");
        rm_if_exist(sock_path);

        let listener = match UnixListener::bind(sock_path) {
            Ok(l) => l,
            Err(e) => {
                error!(err = ?e, "Failed to bind UNIX socket {}", sock_path);
                return Err(());
            }
        };

        let mut broadcast_rx = broadcast_tx.subscribe();
        let cuid = get_current_uid();
        let maintenance = Arc::new(Mutex::new(MaintenanceController::default()));

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(action) = broadcast_rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                            CoreAction::Reload => {},
                        }
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((socket, _addr)) => {
                                let peer_uid = if let Ok(ucred) = socket.peer_cred() {
                                    let incoming_uid = ucred.uid();
                                    if incoming_uid == 0 || incoming_uid == cuid {
                                        info!(uid = %incoming_uid, pid = ?ucred.pid(), "Allowing admin socket access");
                                        incoming_uid
                                    } else {
                                        warn!(%incoming_uid, "unauthorised user");
                                        continue;
                                    }
                                } else {
                                    error!("unable to determine peer credentials");
                                    continue;
                                };

                                let task_repl_ctrl_tx = repl_ctrl_tx.clone();
                                let broadcast_tx_ = broadcast_tx.clone();
                                let task_maintenance = maintenance.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_client(
                                        socket,
                                        peer_uid,
                                        server_rw,
                                        server_ro,
                                        task_repl_ctrl_tx,
                                        broadcast_tx_,
                                        task_maintenance,
                                    ).await {
                                        error!(err = ?e, "admin client error");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(err = ?e, "admin socket accept error");
                            }
                        }
                    }
                }
            }
            info!("Stopped {}", super::TaskName::AdminSocket);
        });
        Ok(handle)
    }
}

fn rm_if_exist(p: &str) {
    debug!("Attempting to remove requested file {}", p);
    let _ = std::fs::remove_file(p).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            debug!("{} not present, no need to remove.", p);
        }
        _ => {
            error!(
                "Failure while attempting to attempting to remove {} -> {}",
                p,
                e.to_string()
            );
        }
    });
}

async fn show_replication_certificate_metadata(
    ctrl_tx: &mut mpsc::Sender<ReplCtrl>,
) -> AdminTaskResponse {
    let (tx, rx) = oneshot::channel();

    if ctrl_tx
        .send(ReplCtrl::GetCertificate { respond: tx })
        .await
        .is_err()
    {
        error!("replication control channel has shutdown");
        AdminTaskResponse::Error
    } else {
        match timeout(REPL_CTRL_TIMEOUT, rx).await {
            Ok(Ok(cert)) => {
                let cert_not_after = cert.tbs_certificate().validity().not_after;
                let cert_not_before = cert.tbs_certificate().validity().not_before;
                let subject = cert.tbs_certificate().subject().to_string();

                let expired = cert_not_after.to_system_time() < std::time::SystemTime::now();
                AdminTaskResponse::ShowReplicationCertificateMetadata {
                    expired,
                    not_before: cert_not_before.to_string(),
                    not_after: cert_not_after.to_string(),
                    subject,
                }
            }
            Ok(Err(_)) => {
                error!("replication control channel did not respond with certificate.");
                AdminTaskResponse::Error
            }
            Err(_) => {
                error!("timed out waiting for replication certificate metadata.");
                AdminTaskResponse::Error
            }
        }
    }
}

async fn show_replication_certificate(ctrl_tx: &mut mpsc::Sender<ReplCtrl>) -> AdminTaskResponse {
    let (tx, rx) = oneshot::channel();

    if ctrl_tx
        .send(ReplCtrl::GetCertificate { respond: tx })
        .await
        .is_err()
    {
        error!("replication control channel has shutdown");
        return AdminTaskResponse::Error;
    }

    match timeout(REPL_CTRL_TIMEOUT, rx).await {
        Ok(Ok(cert)) => x509b64::cert_to_string(&cert)
            .map(|cert| AdminTaskResponse::ShowReplicationCertificate { cert })
            .unwrap_or(AdminTaskResponse::Error),
        Ok(Err(_)) => {
            error!("replication control channel did not respond with certificate.");
            AdminTaskResponse::Error
        }
        Err(_) => {
            error!("timed out waiting for replication certificate response.");
            AdminTaskResponse::Error
        }
    }
}

async fn renew_replication_certificate(ctrl_tx: &mut mpsc::Sender<ReplCtrl>) -> AdminTaskResponse {
    let (tx, rx) = oneshot::channel();

    if ctrl_tx
        .send(ReplCtrl::RenewCertificate { respond: tx })
        .await
        .is_err()
    {
        error!("replication control channel has shutdown");
        return AdminTaskResponse::Error;
    }

    match timeout(REPL_CTRL_TIMEOUT, rx).await {
        Ok(Ok(success)) => {
            if success {
                show_replication_certificate(ctrl_tx).await
            } else {
                error!("replication control channel indicated that certificate renewal failed.");
                AdminTaskResponse::Error
            }
        }
        Ok(Err(_)) => {
            error!("replication control channel did not respond with renewal status.");
            AdminTaskResponse::Error
        }
        Err(_) => {
            error!("timed out waiting for replication renewal status.");
            AdminTaskResponse::Error
        }
    }
}

/// Refresh this node from a supplier (only from `from` when given), and wait for the outcome.
/// `Err` is a message for the operator, also logged.
///
/// With `ack`, the client is sent [`AdminTaskResponse::RefreshStarted`] as soon as a
/// supplier task started the refresh.
async fn replication_consumer_refresh(
    ctrl_tx: &mut mpsc::Sender<ReplCtrl>,
    from: Option<String>,
    ack: Option<&mut Framed<UnixStream, ServerCodec>>,
) -> Result<(), String> {
    let progress = match start_consumer_refresh(ctrl_tx, from, REPL_CTRL_TIMEOUT).await? {
        RefreshStart::Applied => return Ok(()),
        RefreshStart::Running { supplier, progress } => {
            if let Some(ack) = ack {
                // The client stops waiting for this, but not for the outcome.
                let started = AdminTaskResponse::RefreshStarted { supplier };
                if ack.send(started).await.is_err() {
                    warn!("Unable to tell the admin client that the refresh started, it continues regardless.");
                }
            }
            progress
        }
    };
    finish_consumer_refresh(progress, REFRESH_COMPLETION_TIMEOUT).await
}

/// A manual refresh that a supplier task has started.
enum RefreshStart {
    /// A task runs the refresh from `supplier`: its outcome comes through `progress`.
    Running {
        supplier: String,
        progress: mpsc::Receiver<RefreshProgress>,
    },
    /// The refresh was already applied. Not expected: a task reports its start first.
    Applied,
}

/// Ask the replication supervisor for a refresh, and wait until a supplier task has started
/// it. `Err` is a message for the operator: the refresh was refused, or did not start.
///
/// A refresh must start within `start_timeout`. One that a task would only start later (its
/// supplier unreachable, the task busy) is not run at all, rather than replacing the
/// content of this node after the operator was told that it did not start: the requester
/// drops its receiver, which every task checks before it claims the refresh and again
/// before it applies it. Once a task reports that it started the refresh, the requester
/// waits for the outcome without that limit (see [`finish_consumer_refresh`]).
async fn start_consumer_refresh(
    ctrl_tx: &mut mpsc::Sender<ReplCtrl>,
    from: Option<String>,
    start_timeout: Duration,
) -> Result<RefreshStart, String> {
    let start_deadline = Instant::now() + start_timeout;
    let (tx, rx) = oneshot::channel();

    if ctrl_tx
        .send(ReplCtrl::RefreshConsumer {
            from,
            start_deadline,
            respond: tx,
        })
        .await
        .is_err()
    {
        let message = "Replication control channel has shut down, unable to refresh.";
        error!("{message}");
        return Err(message.to_string());
    }

    let mut progress = match timeout_at(start_deadline, rx).await {
        Ok(Ok(Ok(progress))) => progress,
        Ok(Ok(Err(message))) => return Err(message),
        Ok(Err(_)) => {
            let message = "Replication control channel did not respond with refresh status.";
            error!("{message}");
            return Err(message.to_string());
        }
        Err(_) => {
            let message = "Timed out waiting for replication refresh status, not refreshing.";
            error!("{message}");
            return Err(message.to_string());
        }
    };

    match timeout_at(start_deadline, progress.recv()).await {
        Ok(Some(RefreshProgress::Started { supplier })) => {
            info!("Replication refresh started from {supplier}, waiting for it to complete.");
            Ok(RefreshStart::Running { supplier, progress })
        }
        Ok(Some(RefreshProgress::Done)) => Ok(RefreshStart::Applied),
        Ok(None) => {
            let message =
                "No replication supplier started the refresh, nothing was changed. Please inspect the logs.";
            error!("{message}");
            Err(message.to_string())
        }
        Err(_) => Err(refresh_start_timed_out(progress, start_timeout)),
    }
}

/// The message for the operator when no task reported the start of the refresh by its start
/// deadline. Closes `progress`, which refuses any task that would start the refresh from
/// now on.
fn refresh_start_timed_out(
    mut progress: mpsc::Receiver<RefreshProgress>,
    start_timeout: Duration,
) -> String {
    progress.close();
    // A task may have claimed the refresh and reported its start at the deadline itself,
    // after the wait ended but before the close. The refresh may then be applied.
    if let Ok(RefreshProgress::Started { supplier }) = progress.try_recv() {
        let message = format!(
            "Refresh from {supplier} started at its deadline, its outcome is unknown. Check the server logs or `kubidmd domain show`."
        );
        warn!("{message}");
        return message;
    }
    let message = format!(
        "No replication supplier could start the refresh within {}s, nothing was changed. Please inspect the logs.",
        start_timeout.as_secs()
    );
    error!("{message}");
    message
}

/// Wait for the outcome of a refresh that a supplier task has started. The refresh is
/// applied locally and finishes regardless of this wait, so `completion_timeout` only bounds
/// how long the requester waits to learn the outcome: when it passes the outcome is unknown,
/// not failed.
async fn finish_consumer_refresh(
    mut progress: mpsc::Receiver<RefreshProgress>,
    completion_timeout: Duration,
) -> Result<(), String> {
    let completion_deadline = Instant::now() + completion_timeout;
    loop {
        match timeout_at(completion_deadline, progress.recv()).await {
            Ok(Some(RefreshProgress::Done)) => {
                info!("Replication refresh success");
                return Ok(());
            }
            // The task that started it failed, and another one took it over.
            Ok(Some(RefreshProgress::Started { supplier })) => {
                info!("Replication refresh started again from {supplier}.");
            }
            Ok(None) => {
                let message = "Replication refresh failed. Please inspect the logs.";
                error!("{message}");
                return Err(message.to_string());
            }
            Err(_) => {
                let message = format!(
                    "Replication refresh is still in progress after {}s, its outcome is unknown. Check the server logs, or `kubidmd domain show`, for the result.",
                    completion_timeout.as_secs()
                );
                warn!("{message}");
                return Err(message);
            }
        }
    }
}

fn maintenance_error(code: MaintenanceErrorCode, message: impl Into<String>) -> AdminTaskResponse {
    AdminTaskResponse::MaintenanceError {
        code,
        message: message.into(),
    }
}

async fn capture_fence(idms: &IdmServer) -> Result<ReplicationFence, String> {
    let mut read_txn = idms
        .proxy_read()
        .await
        .map_err(|err| format!("unable to acquire read transaction: {err:?}"))?;
    read_txn
        .qs_read
        .maintenance_replication_fence()
        .map_err(|err| format!("unable to capture replication fence: {err:?}"))
}

async fn acquire_write_fence(
    idms: Arc<IdmServer>,
) -> Result<(HeldWriteFence, ReplicationFence), String> {
    let (release_tx, release_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel::<Result<ReplicationFence, String>>();

    let task = tokio::spawn(async move {
        let qs_write = {
            let proxy_write =
                match with_maintenance_write_bypass(idms.proxy_write(duration_from_epoch_now()))
                    .await
                {
                    Ok(txn) => txn,
                    Err(err) => {
                        let _ = ready_tx.send(Err(format!(
                            "unable to acquire maintenance writer permit: {err:?}"
                        )));
                        return;
                    }
                };
            proxy_write.qs_write
        };

        // Drop every normal write transaction guard but retain the QueryServer's
        // single writer permit. Supplier/read traffic can now proceed while all
        // mutation sources are fenced.
        let write_fence = qs_write.into_maintenance_write_fence();

        let fence = match capture_fence(&idms).await {
            Ok(fence) => fence,
            Err(err) => {
                let _ = ready_tx.send(Err(err));
                return;
            }
        };

        if ready_tx.send(Ok(fence)).is_err() {
            return;
        }

        let _ = release_rx.await;
        drop(write_fence);
    });

    match timeout(MAINTENANCE_DRAIN_TIMEOUT, ready_rx).await {
        Ok(Ok(Ok(fence))) => Ok((
            HeldWriteFence {
                release: release_tx,
                task,
            },
            fence,
        )),
        Ok(Ok(Err(err))) => {
            let _ = release_tx.send(());
            task.abort();
            Err(err)
        }
        Ok(Err(_)) => {
            let _ = release_tx.send(());
            task.abort();
            Err("maintenance fence task stopped before reporting readiness".to_string())
        }
        Err(_) => {
            let _ = release_tx.send(());
            task.abort();
            Err("timed out draining QueryServer writes".to_string())
        }
    }
}

async fn release_write_fence(held: HeldWriteFence) {
    let HeldWriteFence { release, mut task } = held;
    let _ = release.send(());
    if timeout(MAINTENANCE_RELEASE_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        task.abort();
    }
}

async fn maintenance_drain(
    server_rw: &'static QueryServerWriteV1,
    controller: Arc<Mutex<MaintenanceController>>,
    operation_id: Uuid,
) -> AdminTaskResponse {
    let (fresh, guard) = {
        let mut state = lock_controller(&controller);
        match state.begin_drain(operation_id) {
            Ok(DrainStart::Fenced(fence)) => {
                return AdminTaskResponse::MaintenanceDrain {
                    operation_id,
                    fence,
                };
            }
            Ok(DrainStart::Acquire { fresh, transition }) => {
                transition.apply();
                (
                    fresh,
                    InFlightGuard::new(controller.clone(), operation_id, InFlightStep::Drain),
                )
            }
            Err(response) => return response,
        }
    };

    let result = acquire_write_fence(server_rw.idms.clone()).await;

    guard.finish(|state| state.finish_drain(operation_id, fresh, result))
}

async fn run_verification(idms: &'static IdmServer) -> Result<Vec<String>, String> {
    let mut read_txn = idms
        .proxy_read()
        .await
        .map_err(|err| format!("unable to acquire verification read transaction: {err:?}"))?;
    // A full consistency verification reads the whole database: run it on the blocking
    // pool so that it never stalls the async workers serving LDAP and HTTPS.
    tokio::task::spawn_blocking(move || {
        read_txn
            .qs_read
            .maintenance_verify()
            .into_iter()
            .filter_map(|result| result.err().map(|err| format!("{err:?}")))
            .collect()
    })
    .await
    .map_err(|err| format!("verification task failed: {err}"))
}

async fn run_reindex(idms: Arc<IdmServer>) -> Result<(), String> {
    // Reindexing rewrites every index of the database: blocking work that must not stall
    // the async workers serving LDAP and HTTPS. The write transaction holds guards that
    // are not `Send`, so it is opened on the blocking thread itself rather than moved there.
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let proxy_write = runtime
            .block_on(with_maintenance_write_bypass(
                idms.proxy_write(duration_from_epoch_now()),
            ))
            .map_err(|err| format!("unable to acquire reindex write transaction: {err:?}"))?;
        let mut qs_write = proxy_write.qs_write;
        qs_write
            .reindex(true)
            .and_then(|_| qs_write.commit())
            .map_err(|err| format!("reindex failed: {err:?}"))
    })
    .await
    .map_err(|err| format!("reindex task failed: {err}"))?
}

async fn maintenance_run(
    server_rw: &'static QueryServerWriteV1,
    controller: Arc<Mutex<MaintenanceController>>,
    operation_id: Uuid,
    operation: MaintenanceOperation,
) -> AdminTaskResponse {
    let (held_for_reindex, guard) = {
        let mut state = lock_controller(&controller);
        match state.begin_run(operation_id, operation) {
            Ok((held, transition)) => {
                transition.apply();
                (
                    held,
                    InFlightGuard::new(controller.clone(), operation_id, InFlightStep::Run),
                )
            }
            Err(response) => return response,
        }
    };

    // Reindex needs the normal QueryServer write transaction. Release the bare
    // writer permit, perform the atomic backend reindex, and immediately acquire
    // a fresh fence. Readiness remains false throughout. The new post-operation
    // fence includes any write that was already queued before the transition.
    if let Some(held) = held_for_reindex {
        release_write_fence(held).await;
    }

    let mut operation_error = None;
    if matches!(operation, MaintenanceOperation::Reindex) {
        if let Err(err) = run_reindex(server_rw.idms.clone()).await {
            operation_error = Some(err);
        }

        let refence = acquire_write_fence(server_rw.idms.clone()).await;
        let stored = lock_controller(&controller).store_refence(refence);
        if let Err(err) = stored {
            operation_error = Some(match operation_error {
                Some(previous) => format!("{previous}; unable to re-fence node: {err}"),
                None => format!("unable to re-fence node: {err}"),
            });
        }
    }

    let verification_errors = match run_verification(&server_rw.idms).await {
        Ok(errors) => errors,
        Err(err) => {
            operation_error = Some(match operation_error {
                Some(previous) => format!("{previous}; verification failed: {err}"),
                None => format!("verification failed: {err}"),
            });
            Vec::new()
        }
    };

    let result = guard.finish(|state| {
        state.finish_run(
            operation_id,
            operation,
            operation_error,
            verification_errors,
        )
    });
    AdminTaskResponse::MaintenanceRun { result }
}

/// The bounded wait of a sync-until request.
fn sync_until_timeout(timeout_seconds: Option<u64>) -> Duration {
    Duration::from_secs(
        timeout_seconds
            .unwrap_or(DEFAULT_SYNC_UNTIL_TIMEOUT.as_secs())
            .clamp(1, MAX_SYNC_UNTIL_TIMEOUT.as_secs()),
    )
}

async fn sync_until(
    idms: &IdmServer,
    target: &ReplicationFence,
    timeout_duration: Duration,
) -> Result<(ReplicationSyncResult, ReplicationFence), String> {
    let deadline = Instant::now()
        .checked_add(timeout_duration)
        .ok_or_else(|| "sync-until timeout is out of range".to_string())?;
    loop {
        let current = capture_fence(idms).await?;
        match target.satisfaction(&current) {
            FenceSatisfaction::Satisfied => {
                return Ok((ReplicationSyncResult::Satisfied, current));
            }
            FenceSatisfaction::DomainMismatch => {
                return Ok((ReplicationSyncResult::DomainMismatch, current));
            }
            FenceSatisfaction::GenerationMismatch => {
                return Ok((ReplicationSyncResult::GenerationMismatch, current));
            }
            FenceSatisfaction::Unsatisfied => {}
        }

        if Instant::now() >= deadline {
            return Ok((ReplicationSyncResult::TimedOut, current));
        }
        sleep(SYNC_UNTIL_POLL_INTERVAL).await;
    }
}

async fn replication_sync_until(
    server_rw: &'static QueryServerWriteV1,
    controller: Arc<Mutex<MaintenanceController>>,
    operation_id: Uuid,
    fence: ReplicationFence,
    timeout_seconds: Option<u64>,
) -> AdminTaskResponse {
    // When sync-until runs on the node that owns the active maintenance
    // operation, temporarily release the write fence so its replication consumer
    // can apply peer changes. It remains not-ready for the entire recovery window,
    // and a fresh write fence is captured before returning.
    let local_recovery = {
        let mut state = lock_controller(&controller);
        match state.begin_sync_until(operation_id) {
            Ok(Some((held, transition))) => {
                transition.apply();
                Some((
                    held,
                    InFlightGuard::new(controller.clone(), operation_id, InFlightStep::SyncUntil),
                ))
            }
            Ok(None) => None,
            Err(response) => return response,
        }
    };

    // Only re-fence when this request released the fence. Deciding this up front, not by
    // looking at the controller again, keeps a drain started meanwhile for the same id
    // from being fenced twice.
    let guard = match local_recovery {
        Some((held, guard)) => {
            if let Some(held) = held {
                release_write_fence(held).await;
            }
            Some(guard)
        }
        None => None,
    };

    let sync_result =
        sync_until(&server_rw.idms, &fence, sync_until_timeout(timeout_seconds)).await;

    if let Some(guard) = guard {
        let refence = acquire_write_fence(server_rw.idms.clone()).await;
        let result = guard.finish(|state| state.finish_sync_until(operation_id, refence));
        if let Err(err) = result {
            return maintenance_error(MaintenanceErrorCode::Database, err);
        }
    }

    match sync_result {
        Ok((result, current_fence)) => AdminTaskResponse::ReplicationSyncUntil {
            result,
            current_fence,
        },
        Err(err) => maintenance_error(MaintenanceErrorCode::Database, err),
    }
}

/// Resume serving after a maintenance operation. The operator decided the node is fit to
/// serve, so a failed verification no longer keeps it not ready: this clears any failed
/// verification, not only one of this operation (the health tracker keeps a single flag).
async fn maintenance_resume(
    controller: Arc<Mutex<MaintenanceController>>,
    operation_id: Uuid,
    health: &ReplicationStateTracker,
) -> AdminTaskResponse {
    let (held, guard) = {
        let mut state = lock_controller(&controller);
        match state.begin_resume(operation_id) {
            Ok(held) => (
                held,
                InFlightGuard::new(controller.clone(), operation_id, InFlightStep::Resume),
            ),
            Err(response) => return response,
        }
    };

    if let Some(held) = held {
        release_write_fence(held).await;
    }

    guard.finish(|state| ((), state.finish_resume(operation_id)));
    health.mark_database_healthy(DatabaseCheck::Verify);
    AdminTaskResponse::MaintenanceResume { operation_id }
}

async fn handle_client(
    sock: UnixStream,
    peer_uid: u32,
    server_rw: &'static QueryServerWriteV1,
    server_ro: &'static QueryServerReadV1,
    mut repl_ctrl_tx: Option<mpsc::Sender<ReplCtrl>>,
    broadcast_tx: broadcast::Sender<CoreAction>,
    maintenance: Arc<Mutex<MaintenanceController>>,
) -> Result<(), Box<dyn Error>> {
    debug!("Accepted admin socket connection");

    let mut reqs = Framed::new(sock, ServerCodec);

    trace!("Waiting for requests ...");
    while let Some(req) = reqs.next().await {
        let req = match req {
            Ok(req) => req,
            Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                // A request this server does not know, most likely from a kubidmd of another
                // version, or one too large. Answer so that the client does not wait forever,
                // then disconnect: the stream can not be decoded past it. The codec logged the
                // details, which may quote the request.
                error!(
                    "Unable to decode admin socket request, is the client the same version as this server?"
                );
                reqs.send(AdminTaskResponse::Error).await?;
                reqs.flush().await?;
                break;
            }
            Err(err) => {
                debug!(?err, "Admin socket read failed");
                break;
            }
        };
        let eventid = Uuid::new_v4();
        let nspan = span!(Level::INFO, "handle_admin_client_request", uuid = ?eventid);

        let resp = async {
            match req {
                AdminTaskRequest::RecoverAccount { name } => {
                    match server_rw.handle_admin_recover_account(name, eventid).await {
                        Ok(password) => AdminTaskResponse::RecoverAccount { password },
                        Err(e) => {
                            error!(err = ?e, "error during recover-account");
                            AdminTaskResponse::Error
                        }
                    }
                }
                AdminTaskRequest::DisableAccount { name } => {
                    match server_rw.handle_admin_disable_account(name, eventid).await {
                        Ok(()) => AdminTaskResponse::Success,
                        Err(e) => {
                            error!(err = ?e, "error during disable-account");
                            AdminTaskResponse::Error
                        }
                    }
                }
                AdminTaskRequest::ApprovalPolicyDisable { name } => {
                    info!(
                        %peer_uid,
                        policy = ?name,
                        "break-glass: approval policy disable requested from the admin socket"
                    );
                    match server_rw
                        .handle_admin_approval_policy_disable(name.clone(), eventid)
                        .await
                    {
                        Ok(names) => AdminTaskResponse::ApprovalPoliciesDisabled { names },
                        Err(OperationError::NoMatchingEntries) => AdminTaskResponse::ErrorMessage {
                            message: format!(
                                "no approval policy named {}",
                                name.unwrap_or_default()
                            ),
                        },
                        Err(e) => {
                            error!(err = ?e, "error during approval-policy disable");
                            AdminTaskResponse::Error
                        }
                    }
                }
                AdminTaskRequest::ShowReplicationCertificate => match repl_ctrl_tx.as_mut() {
                    Some(ctrl_tx) => show_replication_certificate(ctrl_tx).await,
                    None => {
                        error!("replication not configured, unable to display certificate.");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::ShowReplicationCertificateMetadata => match repl_ctrl_tx.as_mut() {
                    Some(ctrl_tx) => show_replication_certificate_metadata(ctrl_tx).await,
                    None => {
                        error!("replication not configured, unable to display certificate metadata.");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::RenewReplicationCertificate => match repl_ctrl_tx.as_mut() {
                    Some(ctrl_tx) => renew_replication_certificate(ctrl_tx).await,
                    None => {
                        error!("replication not configured, unable to renew certificate.");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::RefreshReplicationConsumer => match repl_ctrl_tx.as_mut() {
                    // Clients of any version send this one, so answer only with responses
                    // they all know: the reason of a failure is in the server log.
                    Some(ctrl_tx) => match replication_consumer_refresh(ctrl_tx, None, None).await {
                        Ok(()) => AdminTaskResponse::Success,
                        Err(_) => AdminTaskResponse::Error,
                    },
                    None => {
                        error!("replication not configured, unable to refresh consumer.");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::RefreshReplicationConsumerFrom { from } => match repl_ctrl_tx.as_mut() {
                    Some(ctrl_tx) => {
                        match replication_consumer_refresh(ctrl_tx, Some(from), Some(&mut reqs))
                            .await
                        {
                            Ok(()) => AdminTaskResponse::Success,
                            Err(message) => AdminTaskResponse::ErrorMessage { message },
                        }
                    }
                    None => {
                        error!("replication not configured, unable to refresh consumer.");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::DomainShow => match server_ro.handle_domain_show(eventid).await {
                    Ok(domain_info) => AdminTaskResponse::DomainShow { domain_info },
                    Err(e) => {
                        error!(err = ?e, "error during domain show");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::DomainUpgradeCheck => {
                    match server_ro.handle_domain_upgrade_check(eventid).await {
                        Ok(report) => AdminTaskResponse::DomainUpgradeCheck { report },
                        Err(e) => {
                            error!(err = ?e, "error during domain upgrade check");
                            AdminTaskResponse::Error
                        }
                    }
                }
                AdminTaskRequest::DomainRaise => match server_rw.handle_domain_raise(eventid).await {
                    Ok(level) => AdminTaskResponse::DomainRaise { level },
                    Err(e) => {
                        error!(err = ?e, "error during domain raise");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::DomainRemigrate { level } => {
                    match server_rw.handle_domain_remigrate(level, eventid).await {
                        Ok(()) => AdminTaskResponse::Success,
                        Err(e) => {
                            error!(err = ?e, "error during domain remigrate");
                            AdminTaskResponse::Error
                        }
                    }
                }
                AdminTaskRequest::MaintenanceCapabilities => {
                    AdminTaskResponse::MaintenanceCapabilities {
                        capabilities: MaintenanceCapabilities::default(),
                    }
                }
                AdminTaskRequest::MaintenanceStatus => {
                    let fence = lock_controller(&maintenance).fence.clone();
                    AdminTaskResponse::MaintenanceStatus {
                        status: maintenance_public_status(),
                        fence,
                    }
                }
                AdminTaskRequest::MaintenanceDrain { operation_id } => {
                    maintenance_drain(server_rw, maintenance.clone(), operation_id).await
                }
                AdminTaskRequest::MaintenanceRun {
                    operation_id,
                    operation,
                } => {
                    maintenance_run(server_rw, maintenance.clone(), operation_id, operation).await
                }
                AdminTaskRequest::ReplicationFence => match capture_fence(&server_rw.idms).await {
                    Ok(fence) => AdminTaskResponse::ReplicationFence { fence },
                    Err(err) => maintenance_error(MaintenanceErrorCode::Database, err),
                },
                AdminTaskRequest::ReplicationSyncUntil {
                    operation_id,
                    fence,
                    timeout_seconds,
                } => {
                    replication_sync_until(
                        server_rw,
                        maintenance.clone(),
                        operation_id,
                        fence,
                        timeout_seconds,
                    )
                    .await
                }
                AdminTaskRequest::MaintenanceResume { operation_id } => {
                    maintenance_resume(
                        maintenance.clone(),
                        operation_id,
                        &server_rw.idms.health_tracker(),
                    )
                    .await
                }
                AdminTaskRequest::Reload => match broadcast_tx.send(CoreAction::Reload) {
                    Ok(_) => AdminTaskResponse::Success,
                    Err(e) => {
                        error!(err = ?e, "error during server reload");
                        AdminTaskResponse::Error
                    }
                },
            }
        }
        .instrument(nspan)
        .await;

        reqs.send(resp).await?;
        reqs.flush().await?;
    }

    debug!("Disconnecting client ...");
    Ok(())
}

#[cfg(test)]
mod maintenance_protocol_tests {
    use super::*;
    use crate::repl::claim_refresh;
    use tokio::sync::Mutex as AsyncMutex;
    use tokio::time::sleep_until;

    #[test]
    fn maintenance_request_json_round_trip_preserves_operation_id() {
        let operation_id = Uuid::new_v4();
        let encoded = serde_json::to_vec(&AdminTaskRequest::MaintenanceDrain { operation_id })
            .expect("maintenance request should serialize");
        let decoded: AdminTaskRequest =
            serde_json::from_slice(&encoded).expect("maintenance request should deserialize");

        match decoded {
            AdminTaskRequest::MaintenanceDrain {
                operation_id: decoded_id,
            } => assert_eq!(decoded_id, operation_id),
            other => panic!("unexpected decoded request: {other:?}"),
        }
    }

    #[test]
    fn refresh_request_wire_forms() {
        // The request without a source keeps the wire form of released versions, so that
        // their clients and servers still understand it.
        assert_eq!(
            serde_json::to_string(&AdminTaskRequest::RefreshReplicationConsumer)
                .expect("refresh request should serialize"),
            r#""RefreshReplicationConsumer""#
        );
        let decoded: AdminTaskRequest = serde_json::from_str(r#""RefreshReplicationConsumer""#)
            .expect("old refresh request should deserialize");
        assert!(matches!(
            decoded,
            AdminTaskRequest::RefreshReplicationConsumer
        ));

        // With a source, a distinct variant that round trips.
        let from = "repl://pod-1.example.com:8444".to_string();
        let encoded = serde_json::to_string(&AdminTaskRequest::RefreshReplicationConsumerFrom {
            from: from.clone(),
        })
        .expect("refresh request should serialize");
        assert_eq!(
            encoded,
            r#"{"RefreshReplicationConsumerFrom":{"from":"repl://pod-1.example.com:8444"}}"#
        );
        let decoded: AdminTaskRequest =
            serde_json::from_str(&encoded).expect("refresh request should deserialize");
        assert!(matches!(
            decoded,
            AdminTaskRequest::RefreshReplicationConsumerFrom { from: ref decoded } if decoded == &from
        ));

        // The source can not be left out of it: that would refresh from any supplier.
        assert!(serde_json::from_str::<AdminTaskRequest>(
            r#"{"RefreshReplicationConsumerFrom":{}}"#
        )
        .is_err());
    }

    #[test]
    fn codec_waits_for_an_incomplete_message_only() {
        let complete = serde_json::to_vec(&AdminTaskRequest::RefreshReplicationConsumerFrom {
            from: "repl://pod-1.example.com:8444".to_string(),
        })
        .expect("refresh request should serialize");

        // Every proper prefix of a message is incomplete: wait for more bytes.
        for len in 0..complete.len() {
            let mut src = BytesMut::from(&complete[..len]);
            assert!(
                matches!(ServerCodec.decode(&mut src), Ok(None)),
                "prefix of {len} bytes"
            );
        }

        // The whole message decodes, and is consumed.
        let mut src = BytesMut::from(complete.as_slice());
        assert!(matches!(
            ServerCodec.decode(&mut src),
            Ok(Some(
                AdminTaskRequest::RefreshReplicationConsumerFrom { .. }
            ))
        ));
        assert!(src.is_empty());

        // Two messages in one read decode one after the other.
        let mut src = BytesMut::from(r#""RefreshReplicationConsumer" "DomainShow""#);
        assert!(matches!(
            ServerCodec.decode(&mut src),
            Ok(Some(AdminTaskRequest::RefreshReplicationConsumer))
        ));
        assert!(matches!(
            ServerCodec.decode(&mut src),
            Ok(Some(AdminTaskRequest::DomainShow))
        ));
        assert!(matches!(ServerCodec.decode(&mut src), Ok(None)));
    }

    #[test]
    fn codec_rejects_a_complete_message_it_does_not_know() {
        // A request of another version, a request that is not JSON, and the struct form
        // of the refresh request that an unreleased version sent: errors, not a wait for
        // bytes that never come.
        for bad in [
            r#"{"RefreshReplicationConsumerFromTheFuture":{"from":"x"}}"#,
            r#""NoSuchRequest""#,
            r#"{"RefreshReplicationConsumer":{"from":null}}"#,
            "not json",
            "}",
        ] {
            let mut src = BytesMut::from(bad);
            assert!(
                ServerCodec
                    .decode(&mut src)
                    .is_err_and(|err| err.kind() == io::ErrorKind::InvalidData),
                "{bad}"
            );
        }

        // The client side too: a response of a newer server.
        let mut src = BytesMut::from(r#"{"ResponseFromTheFuture":{}}"#);
        assert!(ClientCodec
            .decode(&mut src)
            .is_err_and(|err| err.kind() == io::ErrorKind::InvalidData));
        let mut src = BytesMut::from(r#"{"ErrorMessage":{"message":"x"}}"#);
        assert!(matches!(
            ClientCodec.decode(&mut src),
            Ok(Some(AdminTaskResponse::ErrorMessage { .. }))
        ));
    }

    #[tokio::test]
    async fn refresh_with_unknown_source_returns_the_reason() {
        // The replication supervisor refuses a source that is not one of its suppliers;
        // the operator gets its message back.
        let (mut ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
        let supervisor = tokio::spawn(async move {
            match ctrl_rx.recv().await {
                Some(ReplCtrl::RefreshConsumer {
                    from,
                    start_deadline,
                    respond,
                }) => {
                    assert_eq!(from.as_deref(), Some("repl://nope.example.com:8444"));
                    // The refresh must start while the requester still waits for it.
                    assert!(start_deadline > Instant::now());
                    assert!(start_deadline <= Instant::now() + REPL_CTRL_TIMEOUT);
                    let _ = respond.send(Err("not a supplier".to_string()));
                }
                _ => panic!("expected a refresh request"),
            }
        });

        let response = replication_consumer_refresh(
            &mut ctrl_tx,
            Some("repl://nope.example.com:8444".to_string()),
            None,
        )
        .await;
        assert_eq!(response, Err("not a supplier".to_string()));
        assert!(supervisor.await.is_ok());
    }

    #[tokio::test]
    async fn refresh_started_near_its_deadline_is_awaited_to_completion() {
        // Two suppliers, the first unreachable: the task of the second only claims the
        // refresh just before its start deadline, and applies it well after that deadline.
        let start_timeout = Duration::from_millis(300);
        let (mut ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
        let supervisor = tokio::spawn(async move {
            let Some(ReplCtrl::RefreshConsumer {
                start_deadline,
                respond,
                ..
            }) = ctrl_rx.recv().await
            else {
                panic!("expected a refresh request");
            };
            let (tx, rx) = mpsc::channel(1);
            let coord = AsyncMutex::new((false, tx));
            assert!(respond.send(Ok(rx)).is_ok());

            sleep_until(start_deadline - Duration::from_millis(100)).await;
            let mut guard = claim_refresh(&coord, Some(start_deadline), "repl://b:8444")
                .await
                .expect("claimed before the deadline");
            sleep(start_timeout * 2).await;
            // Right before the apply: the requester still waits.
            assert!(!guard.1.is_closed());
            guard.0 = true;
            assert!(guard.1.send(RefreshProgress::Done).await.is_ok());
        });

        let began = Instant::now();
        let Ok(RefreshStart::Running { supplier, progress }) =
            start_consumer_refresh(&mut ctrl_tx, None, start_timeout).await
        else {
            panic!("the refresh started before its deadline");
        };
        assert_eq!(supplier, "repl://b:8444");
        assert_eq!(
            finish_consumer_refresh(progress, Duration::from_secs(30)).await,
            Ok(())
        );
        // Success was reported after the start deadline, once the refresh was applied.
        assert!(began.elapsed() > start_timeout * 2);
        assert!(supervisor.await.is_ok());
    }

    #[tokio::test]
    async fn refresh_not_started_by_its_deadline_fails_and_never_runs() {
        let start_timeout = Duration::from_millis(100);
        let (mut ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
        let supervisor = tokio::spawn(async move {
            let Some(ReplCtrl::RefreshConsumer {
                start_deadline,
                respond,
                ..
            }) = ctrl_rx.recv().await
            else {
                panic!("expected a refresh request");
            };
            let (tx, rx) = mpsc::channel(1);
            assert!(respond.send(Ok(rx)).is_ok());
            // No task gets to it in time: hand the refresh to one that comes later.
            (AsyncMutex::new((false, tx)), start_deadline)
        });

        let result = start_consumer_refresh(&mut ctrl_tx, None, start_timeout).await;
        assert!(
            matches!(result, Err(ref message) if message.contains("nothing was changed")),
            "the operator is told that the refresh did not start"
        );

        // The late task is refused: past the deadline, and, deadline or not, its requester
        // closed its receiver.
        let (coord, start_deadline) = supervisor.await.expect("supervisor ran");
        assert!(claim_refresh(&coord, Some(start_deadline), "repl://b:8444")
            .await
            .is_none());
        assert!(claim_refresh(&coord, None, "repl://b:8444").await.is_none());
    }

    #[tokio::test]
    async fn refresh_started_at_its_deadline_has_an_unknown_outcome() {
        // A task reported its start after the requester's wait ended, before it closed.
        let (tx, rx) = mpsc::channel(1);
        let started = RefreshProgress::Started {
            supplier: "repl://b:8444".to_string(),
        };
        assert!(tx.send(started).await.is_ok());
        let message = refresh_start_timed_out(rx, Duration::from_secs(15));
        assert!(
            message.contains("repl://b:8444")
                && message.contains("outcome is unknown")
                && message.contains("domain show")
                && !message.contains("nothing was changed"),
            "{message}"
        );
        // The channel is closed: no other task starts it now.
        assert!(tx.is_closed());

        // No start reported: nothing was changed.
        let (tx, rx) = mpsc::channel::<RefreshProgress>(1);
        let message = refresh_start_timed_out(rx, Duration::from_secs(15));
        assert!(message.contains("nothing was changed"), "{message}");
        assert!(tx.is_closed());
    }

    #[tokio::test]
    async fn started_refresh_outcome() {
        // Not done within the (generous) wait: unknown, not failed.
        let (tx, rx) = mpsc::channel(1);
        let result = finish_consumer_refresh(rx, Duration::from_millis(50)).await;
        assert!(
            matches!(result, Err(ref message) if message.contains("still in progress")
                && message.contains("domain show")
                && !message.contains("failed")),
            "{result:?}"
        );
        drop(tx);

        // Every task that could run it gave up: failed.
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        assert!(finish_consumer_refresh(rx, Duration::from_secs(30))
            .await
            .is_err_and(|message| message.contains("failed")));

        // The first task failed and another one took it over and applied it.
        let (tx, rx) = mpsc::channel(2);
        let again = RefreshProgress::Started {
            supplier: "repl://b:8444".to_string(),
        };
        assert!(tx.send(again).await.is_ok());
        assert!(tx.send(RefreshProgress::Done).await.is_ok());
        assert_eq!(
            finish_consumer_refresh(rx, Duration::from_secs(30)).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn refresh_from_acknowledges_its_start_to_the_client() {
        let (server_sock, client_sock) = UnixStream::pair().expect("socket pair");
        let mut server = Framed::new(server_sock, ServerCodec);
        let mut client = Framed::new(client_sock, ClientCodec);

        let (mut ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
        let supervisor = tokio::spawn(async move {
            let Some(ReplCtrl::RefreshConsumer {
                start_deadline,
                respond,
                ..
            }) = ctrl_rx.recv().await
            else {
                panic!("expected a refresh request");
            };
            let (tx, rx) = mpsc::channel(1);
            let coord = AsyncMutex::new((false, tx));
            assert!(respond.send(Ok(rx)).is_ok());
            let mut guard = claim_refresh(&coord, Some(start_deadline), "repl://b:8444")
                .await
                .expect("claimed");
            guard.0 = true;
            assert!(guard.1.send(RefreshProgress::Done).await.is_ok());
        });

        let result = replication_consumer_refresh(
            &mut ctrl_tx,
            Some("repl://b:8444".to_string()),
            Some(&mut server),
        )
        .await;
        assert_eq!(result, Ok(()));
        assert!(supervisor.await.is_ok());
        assert!(matches!(
            client.next().await,
            Some(Ok(AdminTaskResponse::RefreshStarted { ref supplier })) if supplier == "repl://b:8444"
        ));
    }

    #[test]
    fn codec_refuses_an_oversized_message() {
        // An incomplete request is buffered up to its limit, not beyond.
        let mut src = BytesMut::from(r#"{"RecoverAccount":{"name":""#);
        src.extend_from_slice(&vec![b'a'; MAX_REQUEST_BYTES / 2]);
        assert!(matches!(ServerCodec.decode(&mut src), Ok(None)));
        src.extend_from_slice(&vec![b'a'; MAX_REQUEST_BYTES]);
        assert!(ServerCodec
            .decode(&mut src)
            .is_err_and(|err| err.kind() == io::ErrorKind::InvalidData));

        // Responses may be larger.
        let mut src = BytesMut::from(r#"{"ErrorMessage":{"message":""#);
        src.extend_from_slice(&vec![b'a'; MAX_REQUEST_BYTES * 2]);
        assert!(matches!(ClientCodec.decode(&mut src), Ok(None)));
        src.extend_from_slice(&vec![b'a'; MAX_RESPONSE_BYTES]);
        assert!(ClientCodec
            .decode(&mut src)
            .is_err_and(|err| err.kind() == io::ErrorKind::InvalidData));
    }

    #[test]
    fn approval_policy_disable_wire_format() {
        // New variants, so existing requests and responses keep their form.
        let req = serde_json::to_value(AdminTaskRequest::ApprovalPolicyDisable {
            name: Some("hp".to_string()),
        })
        .expect("request should serialize");
        assert_eq!(
            req,
            serde_json::json!({"ApprovalPolicyDisable": {"name": "hp"}})
        );
        let req = serde_json::to_value(AdminTaskRequest::ApprovalPolicyDisable { name: None })
            .expect("request should serialize");
        assert_eq!(
            req,
            serde_json::json!({"ApprovalPolicyDisable": {"name": null}})
        );
        assert_eq!(
            serde_json::to_value(AdminTaskRequest::Reload).expect("request should serialize"),
            serde_json::json!("Reload")
        );

        let mut src = BytesMut::from(r#"{"ApprovalPolicyDisable":{"name":null}}"#);
        assert!(matches!(
            ServerCodec.decode(&mut src),
            Ok(Some(AdminTaskRequest::ApprovalPolicyDisable { name: None }))
        ));
        let mut src = BytesMut::from(r#"{"ApprovalPoliciesDisabled":{"names":["hp"]}}"#);
        assert!(matches!(
            ClientCodec.decode(&mut src),
            Ok(Some(AdminTaskResponse::ApprovalPoliciesDisabled { ref names })) if names == &["hp".to_string()]
        ));
    }

    #[test]
    fn maintenance_run_result_json_is_structured() {
        let operation_id = Uuid::new_v4();
        let response = AdminTaskResponse::MaintenanceRun {
            result: MaintenanceRunResult {
                operation_id,
                operation: MaintenanceOperation::Verify,
                success: true,
                verification_errors: Vec::new(),
                fence: None,
                error: None,
            },
        };

        let value = serde_json::to_value(response).expect("maintenance response should serialize");
        assert_eq!(
            value["MaintenanceRun"]["result"]["operation_id"],
            operation_id.to_string()
        );
        assert_eq!(value["MaintenanceRun"]["result"]["success"], true);
    }
}

#[cfg(test)]
mod maintenance_controller_tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A stand-in for a held QueryServer write fence: a task that waits to be released.
    fn held() -> HeldWriteFence {
        let (release, released) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = released.await;
        });
        HeldWriteFence { release, task }
    }

    fn test_fence() -> ReplicationFence {
        ReplicationFence {
            version: 1,
            domain_uuid: Uuid::new_v4(),
            generation: None,
            ranges: BTreeMap::new(),
        }
    }

    fn expect_error<T>(result: Result<T, AdminTaskResponse>, expected: MaintenanceErrorCode) {
        match result {
            Err(AdminTaskResponse::MaintenanceError { code, .. }) => assert_eq!(code, expected),
            Err(other) => panic!("unexpected response: {other:?}"),
            Ok(_) => panic!("expected a {expected:?} error"),
        }
    }

    /// Drain `operation_id` to completion, returning the fence it holds.
    fn drained(controller: &mut MaintenanceController, operation_id: Uuid) -> ReplicationFence {
        let fresh = match controller.begin_drain(operation_id) {
            Ok(DrainStart::Acquire { fresh, .. }) => fresh,
            Ok(DrainStart::Fenced(_)) => panic!("operation was already fenced"),
            Err(other) => panic!("unexpected response: {other:?}"),
        };
        let fence = test_fence();
        let (response, transition) =
            controller.finish_drain(operation_id, fresh, Ok((held(), fence.clone())));
        assert!(matches!(
            response,
            AdminTaskResponse::MaintenanceDrain { .. }
        ));
        assert_eq!(
            transition,
            StateTransition::to(MaintenanceState::Fenced, Some(operation_id))
        );
        fence
    }

    #[tokio::test]
    async fn drain_retry_while_acquiring_is_busy() {
        let mut controller = MaintenanceController::default();
        let operation_id = Uuid::new_v4();

        match controller.begin_drain(operation_id) {
            Ok(DrainStart::Acquire { fresh, transition }) => {
                assert!(fresh);
                assert_eq!(
                    transition,
                    StateTransition::to(MaintenanceState::Draining, Some(operation_id))
                        .with_error(None)
                );
            }
            Ok(DrainStart::Fenced(_)) => panic!("nothing was fenced yet"),
            Err(other) => panic!("unexpected response: {other:?}"),
        }

        // Same operation, still acquiring: must not start a second acquisition.
        expect_error(
            controller.begin_drain(operation_id),
            MaintenanceErrorCode::Busy,
        );
        // A different operation is busy too.
        expect_error(
            controller.begin_drain(Uuid::new_v4()),
            MaintenanceErrorCode::Busy,
        );

        let fence = test_fence();
        let (response, transition) =
            controller.finish_drain(operation_id, true, Ok((held(), fence.clone())));
        assert!(matches!(
            response,
            AdminTaskResponse::MaintenanceDrain { .. }
        ));
        assert_eq!(transition.state, MaintenanceState::Fenced);
        assert!(controller.in_flight.is_none());

        // Once fenced, a retry is idempotent and returns the same fence.
        match controller.begin_drain(operation_id) {
            Ok(DrainStart::Fenced(returned)) => assert_eq!(returned, fence),
            Ok(DrainStart::Acquire { .. }) => panic!("drain retry acquired a second fence"),
            Err(other) => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn failed_fresh_drain_rolls_back_to_serving() {
        let mut controller = MaintenanceController::default();
        let operation_id = Uuid::new_v4();

        let fresh = match controller.begin_drain(operation_id) {
            Ok(DrainStart::Acquire { fresh, .. }) => fresh,
            _ => panic!("drain should start"),
        };
        let (response, transition) =
            controller.finish_drain(operation_id, fresh, Err("timed out".to_string()));

        assert!(matches!(
            response,
            AdminTaskResponse::MaintenanceError {
                code: MaintenanceErrorCode::Timeout,
                ..
            }
        ));
        // Nothing was fenced: writes must not stay gated.
        assert_eq!(
            transition,
            StateTransition::to(MaintenanceState::Serving, None)
                .with_error(Some("timed out".to_string()))
        );
        assert!(controller.active_operation_id.is_none());
        assert!(controller.in_flight.is_none());

        // An orchestrator resuming after the failed drain gets an idempotent success.
        assert!(matches!(
            controller.begin_resume(operation_id),
            Err(AdminTaskResponse::MaintenanceResume { operation_id: resumed }) if resumed == operation_id
        ));

        // The node is free for a new operation.
        let next = Uuid::new_v4();
        assert!(matches!(
            controller.begin_drain(next),
            Ok(DrainStart::Acquire { fresh: true, .. })
        ));
    }

    #[tokio::test]
    async fn failed_reindex_refence_is_not_handed_out_again() {
        let mut controller = MaintenanceController::default();
        let operation_id = Uuid::new_v4();
        drained(&mut controller, operation_id);

        let (held_for_reindex, transition) = controller
            .begin_run(operation_id, MaintenanceOperation::Reindex)
            .expect("run should start");
        assert!(held_for_reindex.is_some());
        assert_eq!(transition.state, MaintenanceState::Maintenance);
        // While the node is unfenced for the reindex, status shows no fence.
        assert!(controller.fence.is_none());

        assert!(controller
            .store_refence(Err("unable to fence".to_string()))
            .is_err());
        let (result, transition) = controller.finish_run(
            operation_id,
            MaintenanceOperation::Reindex,
            Some("unable to re-fence node: unable to fence".to_string()),
            Vec::new(),
        );
        assert!(!result.success);
        assert!(result.fence.is_none());
        assert_eq!(transition.state, MaintenanceState::Failed);

        // A drain retry must fence again instead of returning the stale fence, and a
        // failure of that retry keeps the operation failed rather than serving.
        let fresh = match controller.begin_drain(operation_id) {
            Ok(DrainStart::Acquire { fresh, .. }) => fresh,
            Ok(DrainStart::Fenced(_)) => panic!("stale fence was handed out"),
            Err(other) => panic!("unexpected response: {other:?}"),
        };
        assert!(!fresh);
        let (_, transition) =
            controller.finish_drain(operation_id, fresh, Err("timed out".to_string()));
        assert_eq!(transition.state, MaintenanceState::Failed);
        assert_eq!(controller.active_operation_id, Some(operation_id));
    }

    #[tokio::test]
    async fn resume_is_rejected_while_a_run_is_in_flight() {
        let mut controller = MaintenanceController::default();
        let operation_id = Uuid::new_v4();
        drained(&mut controller, operation_id);

        let (held_for_reindex, _) = controller
            .begin_run(operation_id, MaintenanceOperation::Reindex)
            .expect("run should start");
        if let Some(to_release) = held_for_reindex {
            release_write_fence(to_release).await;
        }

        // The run is unfenced and reindexing: resume, drain and another run are refused.
        expect_error(
            controller.begin_resume(operation_id),
            MaintenanceErrorCode::Busy,
        );
        expect_error(
            controller.begin_drain(operation_id),
            MaintenanceErrorCode::Busy,
        );
        expect_error(
            controller.begin_run(operation_id, MaintenanceOperation::Reindex),
            MaintenanceErrorCode::Busy,
        );
        assert_eq!(controller.active_operation_id, Some(operation_id));

        // The run re-fences and completes.
        let fence = test_fence();
        controller
            .store_refence(Ok((held(), fence.clone())))
            .expect("re-fence should be stored");
        let (result, transition) = controller.finish_run(
            operation_id,
            MaintenanceOperation::Reindex,
            None,
            Vec::new(),
        );
        assert!(result.success);
        assert_eq!(result.fence, Some(fence));
        assert_eq!(
            transition,
            StateTransition::to(MaintenanceState::Fenced, Some(operation_id)).with_error(None)
        );

        // Now resume releases the re-acquired fence.
        let to_release = controller
            .begin_resume(operation_id)
            .expect("resume should start");
        assert!(to_release.is_some());
        // A concurrent resume while releasing is busy, not a second release.
        expect_error(
            controller.begin_resume(operation_id),
            MaintenanceErrorCode::Busy,
        );
        if let Some(to_release) = to_release {
            release_write_fence(to_release).await;
        }
        assert_eq!(
            controller.finish_resume(operation_id),
            StateTransition::to(MaintenanceState::Serving, None).with_error(None)
        );
        assert!(controller.active_operation_id.is_none());
        assert!(controller.held_write_fence.is_none());

        // Resume is idempotent.
        assert!(matches!(
            controller.begin_resume(operation_id),
            Err(AdminTaskResponse::MaintenanceResume { .. })
        ));
    }

    #[tokio::test]
    async fn resume_is_rejected_while_sync_until_is_in_flight() {
        let mut controller = MaintenanceController::default();
        let operation_id = Uuid::new_v4();
        drained(&mut controller, operation_id);

        let local = controller
            .begin_sync_until(operation_id)
            .expect("sync-until should start");
        let (to_release, transition) = local.expect("this node owns the operation");
        assert!(to_release.is_some());
        assert_eq!(transition.state, MaintenanceState::Recovering);

        expect_error(
            controller.begin_resume(operation_id),
            MaintenanceErrorCode::Busy,
        );
        expect_error(
            controller.begin_sync_until(operation_id),
            MaintenanceErrorCode::Busy,
        );
        expect_error(
            controller.begin_sync_until(Uuid::new_v4()),
            MaintenanceErrorCode::Busy,
        );

        if let Some(to_release) = to_release {
            release_write_fence(to_release).await;
        }
        let (result, transition) =
            controller.finish_sync_until(operation_id, Ok((held(), test_fence())));
        assert!(result.is_ok());
        assert_eq!(
            transition,
            StateTransition::to(MaintenanceState::Fenced, Some(operation_id))
        );

        assert!(controller.begin_resume(operation_id).is_ok());
    }

    #[tokio::test]
    async fn sync_until_without_local_operation_does_not_claim_the_controller() {
        let mut controller = MaintenanceController::default();
        let local = controller
            .begin_sync_until(Uuid::new_v4())
            .expect("sync-until should start");
        assert!(local.is_none());
        assert!(controller.in_flight.is_none());
        assert!(controller.active_operation_id.is_none());
    }

    #[tokio::test]
    async fn run_requires_a_fence_and_is_idempotent() {
        let mut controller = MaintenanceController::default();
        let operation_id = Uuid::new_v4();

        expect_error(
            controller.begin_run(operation_id, MaintenanceOperation::Verify),
            MaintenanceErrorCode::OperationMismatch,
        );

        drained(&mut controller, operation_id);
        let (held_for_reindex, _) = controller
            .begin_run(operation_id, MaintenanceOperation::Verify)
            .expect("run should start");
        // Verify keeps the node fenced.
        assert!(held_for_reindex.is_none());
        assert!(controller.held_write_fence.is_some());

        let (result, transition) = controller.finish_run(
            operation_id,
            MaintenanceOperation::Verify,
            None,
            vec!["inconsistent".to_string()],
        );
        assert!(!result.success);
        assert_eq!(
            transition,
            StateTransition::to(MaintenanceState::Failed, Some(operation_id))
                .with_error(Some("consistency verification failed".to_string()))
        );

        // Retrying the same run returns the recorded result; another operation is refused.
        match controller.begin_run(operation_id, MaintenanceOperation::Verify) {
            Err(AdminTaskResponse::MaintenanceRun { result: previous }) => {
                assert_eq!(previous, result)
            }
            Err(other) => panic!("unexpected response: {other:?}"),
            Ok(_) => panic!("run was executed twice"),
        }
        expect_error(
            controller.begin_run(operation_id, MaintenanceOperation::Reindex),
            MaintenanceErrorCode::OperationMismatch,
        );
    }

    /// Transitions published by test guards, instead of the process-global state.
    static PUBLISHED: Mutex<Vec<StateTransition>> = Mutex::new(Vec::new());

    fn record_transition(transition: StateTransition) {
        PUBLISHED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(transition);
    }

    fn published_for(operation_id: Uuid) -> Vec<StateTransition> {
        PUBLISHED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|transition| transition.operation_id == Some(operation_id))
            .cloned()
            .collect()
    }

    fn test_guard(
        controller: &Arc<Mutex<MaintenanceController>>,
        operation_id: Uuid,
        step: InFlightStep,
    ) -> InFlightGuard {
        InFlightGuard {
            controller: controller.clone(),
            operation_id,
            step,
            publish: record_transition,
            finished: false,
        }
    }

    #[tokio::test]
    async fn abandoned_step_is_released_and_marked_failed() {
        let controller = Arc::new(Mutex::new(MaintenanceController::default()));
        let operation_id = Uuid::new_v4();

        assert!(matches!(
            lock_controller(&controller).begin_drain(operation_id),
            Ok(DrainStart::Acquire { .. })
        ));
        let guard = test_guard(&controller, operation_id, InFlightStep::Drain);

        // The handler panics while the step is in flight.
        let outcome = tokio::spawn(async move {
            let _guard = guard;
            panic!("simulated failure inside a maintenance step");
        })
        .await;
        assert!(outcome.is_err());

        {
            let state = lock_controller(&controller);
            assert!(state.in_flight.is_none());
            assert_eq!(state.active_operation_id, Some(operation_id));
            assert!(state.fence.is_none());
        }
        let published = published_for(operation_id);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].state, MaintenanceState::Failed);
        assert!(matches!(&published[0].error, Some(Some(message)) if message.contains("Drain")));

        // Not busy any more: the operation can be resumed (or the drain retried).
        let mut state = lock_controller(&controller);
        assert!(matches!(state.begin_resume(operation_id), Ok(None)));
        state.finish_resume(operation_id);
    }

    #[tokio::test]
    async fn abandoned_run_keeps_a_fence_it_did_not_take() {
        let controller = Arc::new(Mutex::new(MaintenanceController::default()));
        let operation_id = Uuid::new_v4();
        let fence = drained(&mut lock_controller(&controller), operation_id);

        match lock_controller(&controller).begin_run(operation_id, MaintenanceOperation::Verify) {
            Ok((held_for_reindex, _)) => assert!(held_for_reindex.is_none()),
            Err(other) => panic!("unexpected response: {other:?}"),
        }
        drop(test_guard(&controller, operation_id, InFlightStep::Run));

        let state = lock_controller(&controller);
        assert!(state.in_flight.is_none());
        // Verify left the fence held, so it still describes the node and a resume
        // releases it.
        assert!(state.held_write_fence.is_some());
        assert_eq!(state.fence, Some(fence));
        assert_eq!(
            published_for(operation_id)
                .last()
                .map(|transition| transition.state),
            Some(MaintenanceState::Failed)
        );
    }

    #[tokio::test]
    async fn finished_step_is_not_abandoned() {
        let controller = Arc::new(Mutex::new(MaintenanceController::default()));
        let operation_id = Uuid::new_v4();

        let fresh = match lock_controller(&controller).begin_drain(operation_id) {
            Ok(DrainStart::Acquire { fresh, .. }) => fresh,
            _ => panic!("drain should start"),
        };
        let guard = test_guard(&controller, operation_id, InFlightStep::Drain);
        let response = guard
            .finish(|state| state.finish_drain(operation_id, fresh, Ok((held(), test_fence()))));
        assert!(matches!(
            response,
            AdminTaskResponse::MaintenanceDrain { .. }
        ));

        let published = published_for(operation_id);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].state, MaintenanceState::Fenced);
        assert!(lock_controller(&controller).in_flight.is_none());
    }

    #[test]
    fn sync_until_timeout_is_bounded() {
        assert_eq!(sync_until_timeout(None), DEFAULT_SYNC_UNTIL_TIMEOUT);
        assert_eq!(sync_until_timeout(Some(0)), Duration::from_secs(1));
        assert_eq!(sync_until_timeout(Some(30)), Duration::from_secs(30));
        assert_eq!(sync_until_timeout(Some(u64::MAX)), MAX_SYNC_UNTIL_TIMEOUT);
        // The bounded timeout never overflows a deadline.
        assert!(Instant::now()
            .checked_add(sync_until_timeout(Some(u64::MAX)))
            .is_some());
    }

    #[tokio::test]
    async fn resume_clears_a_failed_verification() {
        use kubidmd_lib::status::DatabaseHealth;

        let mut controller = MaintenanceController::default();
        let operation_id = Uuid::new_v4();
        drained(&mut controller, operation_id);
        let controller = Arc::new(Mutex::new(controller));

        let health = ReplicationStateTracker::new();
        health.mark_database_failure(DatabaseCheck::Verify);

        // A refused resume (another operation) leaves the failure in place.
        let refused = maintenance_resume(controller.clone(), Uuid::new_v4(), &health).await;
        assert!(!matches!(
            refused,
            AdminTaskResponse::MaintenanceResume { .. }
        ));
        assert_eq!(health.get_database_health(), DatabaseHealth::Unhealthy);

        // Resuming publishes the serving state, which is also the process default.
        let response = maintenance_resume(controller, operation_id, &health).await;
        assert!(matches!(
            response,
            AdminTaskResponse::MaintenanceResume { operation_id: resumed } if resumed == operation_id
        ));
        assert_eq!(health.get_database_health(), DatabaseHealth::Healthy);
    }
}
