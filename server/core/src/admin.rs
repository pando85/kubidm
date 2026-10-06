use crate::{
    actors::{QueryServerReadV1, QueryServerWriteV1},
    repl::ReplCtrl,
    CoreAction,
};
use bytes::{BufMut, BytesMut};
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
    MaintenanceOperation, MaintenancePublicStatus, MaintenanceState, ReplicationFence,
};
use kubidmd_lib::prelude::{duration_from_epoch_now, IdmServer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{span, Instrument, Level};
use uuid::Uuid;

/// Don't hang forever waiting for a response.
const REPL_CTRL_TIMEOUT: Duration = Duration::from_secs(15);
const MAINTENANCE_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const MAINTENANCE_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SYNC_UNTIL_TIMEOUT: Duration = Duration::from_secs(60);
const SYNC_UNTIL_POLL_INTERVAL: Duration = Duration::from_secs(1);

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
    RefreshReplicationConsumer,
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
        }
    }
}

#[derive(Default)]
pub struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = AdminTaskResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        match serde_json::from_slice::<AdminTaskResponse>(src) {
            Ok(msg) => {
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
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
        match serde_json::from_slice::<AdminTaskRequest>(src) {
            Ok(msg) => {
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
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

#[derive(Default)]
struct MaintenanceController {
    active_operation_id: Option<Uuid>,
    fence: Option<ReplicationFence>,
    held_write_fence: Option<HeldWriteFence>,
    last_run: Option<MaintenanceRunResult>,
    last_resumed_operation_id: Option<Uuid>,
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
                                if let Ok(ucred) = socket.peer_cred() {
                                    let incoming_uid = ucred.uid();
                                    if incoming_uid == 0 || incoming_uid == cuid {
                                        info!(pid = ?ucred.pid(), "Allowing admin socket access");
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

async fn replication_consumer_refresh(ctrl_tx: &mut mpsc::Sender<ReplCtrl>) -> AdminTaskResponse {
    let (tx, rx) = oneshot::channel();

    if ctrl_tx
        .send(ReplCtrl::RefreshConsumer { respond: tx })
        .await
        .is_err()
    {
        error!("replication control channel has shutdown");
        return AdminTaskResponse::Error;
    }

    match timeout(REPL_CTRL_TIMEOUT, rx).await {
        Ok(Ok(mut refresh_rx)) => match timeout(REPL_CTRL_TIMEOUT, refresh_rx.recv()).await {
            Ok(Some(())) => {
                info!("Replication refresh success");
                AdminTaskResponse::Success
            }
            Ok(None) => {
                error!("Replication refresh failed. Please inspect the logs.");
                AdminTaskResponse::Error
            }
            Err(_) => {
                error!("timed out waiting for replication refresh completion.");
                AdminTaskResponse::Error
            }
        },
        Ok(Err(_)) => {
            error!("replication control channel did not respond with refresh status.");
            AdminTaskResponse::Error
        }
        Err(_) => {
            error!("timed out waiting for replication refresh status.");
            AdminTaskResponse::Error
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

fn fence_satisfaction(target: &ReplicationFence, current: &ReplicationFence) -> FenceSatisfaction {
    if target.version != current.version {
        return FenceSatisfaction::Unsatisfied;
    }
    if target.domain_uuid != current.domain_uuid {
        return FenceSatisfaction::DomainMismatch;
    }
    if target.generation != current.generation {
        return FenceSatisfaction::GenerationMismatch;
    }

    if target.ranges.iter().all(|(server_uuid, required)| {
        current
            .ranges
            .get(server_uuid)
            .is_some_and(|present| present.ts_max >= required.ts_max)
    }) {
        FenceSatisfaction::Satisfied
    } else {
        FenceSatisfaction::Unsatisfied
    }
}

async fn maintenance_drain(
    server_rw: &'static QueryServerWriteV1,
    controller: Arc<Mutex<MaintenanceController>>,
    operation_id: Uuid,
) -> AdminTaskResponse {
    {
        let mut state = controller.lock().await;
        if state.active_operation_id == Some(operation_id) {
            if let Some(fence) = state.fence.clone() {
                return AdminTaskResponse::MaintenanceDrain {
                    operation_id,
                    fence,
                };
            }
        } else if let Some(active) = state.active_operation_id {
            return maintenance_error(
                MaintenanceErrorCode::Busy,
                format!("maintenance operation {active} is already active"),
            );
        }

        state.active_operation_id = Some(operation_id);
        state.fence = None;
        state.last_run = None;
    }

    set_maintenance_error(None);
    set_maintenance_state(MaintenanceState::Draining, Some(operation_id));

    match acquire_write_fence(server_rw.idms.clone()).await {
        Ok((held, fence)) => {
            let mut state = controller.lock().await;
            state.held_write_fence = Some(held);
            state.fence = Some(fence.clone());
            set_maintenance_state(MaintenanceState::Fenced, Some(operation_id));
            AdminTaskResponse::MaintenanceDrain {
                operation_id,
                fence,
            }
        }
        Err(err) => {
            set_maintenance_error(Some(err.clone()));
            set_maintenance_state(MaintenanceState::Failed, Some(operation_id));
            maintenance_error(MaintenanceErrorCode::Timeout, err)
        }
    }
}

async fn run_verification(idms: &IdmServer) -> Result<Vec<String>, String> {
    let mut read_txn = idms
        .proxy_read()
        .await
        .map_err(|err| format!("unable to acquire verification read transaction: {err:?}"))?;
    Ok(read_txn
        .qs_read
        .maintenance_verify()
        .into_iter()
        .filter_map(|result| result.err().map(|err| format!("{err:?}")))
        .collect())
}

async fn run_reindex(idms: &IdmServer) -> Result<(), String> {
    let result = {
        let proxy_write =
            with_maintenance_write_bypass(idms.proxy_write(duration_from_epoch_now()))
                .await
                .map_err(|err| format!("unable to acquire reindex write transaction: {err:?}"))?;
        let mut qs_write = proxy_write.qs_write;
        qs_write
            .reindex(true)
            .and_then(|_| qs_write.commit())
            .map_err(|err| format!("reindex failed: {err:?}"))
    };
    result
}

async fn maintenance_run(
    server_rw: &'static QueryServerWriteV1,
    controller: Arc<Mutex<MaintenanceController>>,
    operation_id: Uuid,
    operation: MaintenanceOperation,
) -> AdminTaskResponse {
    let held_for_reindex = {
        let mut state = controller.lock().await;
        if state.active_operation_id != Some(operation_id) {
            return maintenance_error(
                MaintenanceErrorCode::OperationMismatch,
                "operation id does not own the active maintenance fence",
            );
        }
        if let Some(previous) = state.last_run.as_ref() {
            if previous.operation == operation {
                return AdminTaskResponse::MaintenanceRun {
                    result: previous.clone(),
                };
            }
            return maintenance_error(
                MaintenanceErrorCode::OperationMismatch,
                "operation id was already used for a different maintenance operation",
            );
        }
        if state.held_write_fence.is_none() {
            return maintenance_error(
                MaintenanceErrorCode::InvalidState,
                "node is not currently fenced",
            );
        }

        set_maintenance_state(MaintenanceState::Maintenance, Some(operation_id));
        if matches!(operation, MaintenanceOperation::Reindex) {
            state.held_write_fence.take()
        } else {
            None
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
        if let Err(err) = run_reindex(&server_rw.idms).await {
            operation_error = Some(err);
        }

        match acquire_write_fence(server_rw.idms.clone()).await {
            Ok((held, fence)) => {
                let mut state = controller.lock().await;
                state.held_write_fence = Some(held);
                state.fence = Some(fence);
            }
            Err(err) => {
                operation_error = Some(match operation_error {
                    Some(previous) => format!("{previous}; unable to re-fence node: {err}"),
                    None => format!("unable to re-fence node: {err}"),
                });
            }
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

    let success = operation_error.is_none() && verification_errors.is_empty();
    let fence = controller.lock().await.fence.clone();
    let result = MaintenanceRunResult {
        operation_id,
        operation,
        success,
        verification_errors,
        fence,
        error: operation_error.clone(),
    };

    {
        let mut state = controller.lock().await;
        state.last_run = Some(result.clone());
    }

    if success {
        set_maintenance_error(None);
        set_maintenance_state(MaintenanceState::Fenced, Some(operation_id));
    } else {
        let message =
            operation_error.unwrap_or_else(|| "consistency verification failed".to_string());
        set_maintenance_error(Some(message));
        set_maintenance_state(MaintenanceState::Failed, Some(operation_id));
    }

    AdminTaskResponse::MaintenanceRun { result }
}

async fn sync_until(
    idms: &IdmServer,
    target: &ReplicationFence,
    timeout_duration: Duration,
) -> Result<(ReplicationSyncResult, ReplicationFence), String> {
    let deadline = Instant::now() + timeout_duration;
    loop {
        let current = capture_fence(idms).await?;
        match fence_satisfaction(target, &current) {
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
    let locally_recovering = {
        let mut state = controller.lock().await;
        match state.active_operation_id {
            Some(active) if active != operation_id => {
                return maintenance_error(
                    MaintenanceErrorCode::Busy,
                    format!("maintenance operation {active} is already active"),
                );
            }
            Some(_) => {
                set_maintenance_state(MaintenanceState::Recovering, Some(operation_id));
                state.held_write_fence.take()
            }
            None => None,
        }
    };

    if let Some(held) = locally_recovering {
        release_write_fence(held).await;
    }

    let timeout_duration = Duration::from_secs(
        timeout_seconds
            .unwrap_or(DEFAULT_SYNC_UNTIL_TIMEOUT.as_secs())
            .max(1),
    );
    let sync_result = sync_until(&server_rw.idms, &fence, timeout_duration).await;

    let has_local_operation = controller.lock().await.active_operation_id == Some(operation_id);
    if has_local_operation {
        match acquire_write_fence(server_rw.idms.clone()).await {
            Ok((held, current_fence)) => {
                let mut state = controller.lock().await;
                state.held_write_fence = Some(held);
                state.fence = Some(current_fence);
                set_maintenance_state(MaintenanceState::Fenced, Some(operation_id));
            }
            Err(err) => {
                set_maintenance_error(Some(err.clone()));
                set_maintenance_state(MaintenanceState::Failed, Some(operation_id));
                return maintenance_error(MaintenanceErrorCode::Database, err);
            }
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

async fn maintenance_resume(
    controller: Arc<Mutex<MaintenanceController>>,
    operation_id: Uuid,
) -> AdminTaskResponse {
    let held = {
        let mut state = controller.lock().await;
        if state.active_operation_id.is_none()
            && state.last_resumed_operation_id == Some(operation_id)
        {
            return AdminTaskResponse::MaintenanceResume { operation_id };
        }
        if state.active_operation_id != Some(operation_id) {
            return maintenance_error(
                MaintenanceErrorCode::OperationMismatch,
                "operation id does not own the active maintenance fence",
            );
        }

        state.active_operation_id = None;
        state.fence = None;
        state.last_run = None;
        state.last_resumed_operation_id = Some(operation_id);
        state.held_write_fence.take()
    };

    if let Some(held) = held {
        release_write_fence(held).await;
    }

    set_maintenance_error(None);
    set_maintenance_state(MaintenanceState::Serving, None);
    AdminTaskResponse::MaintenanceResume { operation_id }
}

async fn handle_client(
    sock: UnixStream,
    server_rw: &'static QueryServerWriteV1,
    server_ro: &'static QueryServerReadV1,
    mut repl_ctrl_tx: Option<mpsc::Sender<ReplCtrl>>,
    broadcast_tx: broadcast::Sender<CoreAction>,
    maintenance: Arc<Mutex<MaintenanceController>>,
) -> Result<(), Box<dyn Error>> {
    debug!("Accepted admin socket connection");

    let mut reqs = Framed::new(sock, ServerCodec);

    trace!("Waiting for requests ...");
    while let Some(Ok(req)) = reqs.next().await {
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
                    Some(ctrl_tx) => replication_consumer_refresh(ctrl_tx).await,
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
                    let fence = maintenance.lock().await.fence.clone();
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
                    maintenance_resume(maintenance.clone(), operation_id).await
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
