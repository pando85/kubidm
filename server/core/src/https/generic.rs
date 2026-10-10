use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::{Extension, Json};
use kubidmd_lib::maintenance::{maintenance_public_status, MaintenancePublicStatus};
use kubidmd_lib::prelude::APPLICATION_JSON;
use kubidmd_lib::status::{LivenessStatus, ReadinessStatus, ServingReadiness, StatusRequestEvent};
use url::Url;

use super::{middleware::KOpId, views::constants::Urls, ServerState};
use crate::backup::metrics::PROMETHEUS_TEXT_CONTENT_TYPE;

#[utoipa::path(
    get,
    path = "/status",
    responses(
        (status = 200, description = "Ok", content_type = APPLICATION_JSON, body=bool),
    ),
    tag = "system",
    operation_id = "status"

)]
/// Legacy status endpoint for backward compatibility. Returns true when the server is up.
/// For Kubernetes probes, use /healthz (liveness) and /readyz (readiness) instead.
pub async fn status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Json<bool> {
    state
        .status_ref
        .handle_request(StatusRequestEvent {
            eventid: kopid.eventid,
        })
        .await
        .into()
}

#[utoipa::path(
    get,
    path = "/healthz",
    responses(
        (status = 200, description = "Ok", content_type = APPLICATION_JSON, body=LivenessStatus),
    ),
    tag = "system",
    operation_id = "healthz"
)]
/// Liveness probe endpoint for Kubernetes. Returns 200 if the process is alive.
/// This does NOT indicate readiness to serve traffic.
pub async fn healthz(State(state): State<ServerState>) -> Json<LivenessStatus> {
    state.status_ref.get_liveness_status().into()
}

#[utoipa::path(
    get,
    path = "/maintenance",
    responses(
        (status = 200, description = "Node maintenance state and capabilities", content_type = APPLICATION_JSON, body=MaintenancePublicStatus),
    ),
    tag = "system",
    operation_id = "maintenance_status"
)]
/// Read-only node-local maintenance state and capability discovery.
pub async fn maintenance_status() -> Json<MaintenancePublicStatus> {
    maintenance_public_status().into()
}

#[utoipa::path(
    get,
    path = "/readyz",
    responses(
        (status = 200, description = "Ok", content_type = APPLICATION_JSON, body=ReadinessStatus),
        (status = 503, description = "Service Unavailable", content_type = APPLICATION_JSON, body=ReadinessStatus),
    ),
    tag = "system",
    operation_id = "readyz"
)]
/// Readiness probe endpoint for Kubernetes. Returns 200 if the replica is ready to serve traffic,
/// 503 otherwise. Includes detailed replication state and database health information.
pub async fn readyz(State(state): State<ServerState>) -> impl IntoResponse {
    let mut status = state.status_ref.get_readiness_status();
    let maintenance = maintenance_public_status();

    // Serving readiness and administrative maintenance readiness answer different
    // questions. A node can have healthy replication and still be intentionally
    // drained/fenced. Never let it re-enter a Kubernetes Service while an exclusive
    // node operation is active.
    if !maintenance.state.is_serving() {
        status.serving_ready = ServingReadiness::NotReady;
        status.message = format!(
            "Node is unavailable for maintenance (state: {:?}, operation: {:?})",
            maintenance.state, maintenance.active_operation_id
        );
    }

    let status_code = if status.serving_ready.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status_code, Json(status))
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Backup metrics in the Prometheus text exposition format", content_type = "text/plain"),
        (status = 404, description = "online_backup.metrics_endpoint is not enabled"),
    ),
    tag = "system",
    operation_id = "metrics"
)]
/// The backup metrics in the Prometheus text exposition format: per backup destination the
/// time of the last successful and failed backup and of the last verification, and the
/// time of the last WAL archive synchronisation. Only served when
/// `online_backup.metrics_endpoint` is enabled.
pub async fn metrics(State(state): State<ServerState>) -> impl IntoResponse {
    match &state.backup_metrics {
        Some(metrics) => (
            StatusCode::OK,
            [(CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)],
            metrics.render(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/robots.txt",
    responses(
        (status = 200, description = "Ok"),
    ),
    tag = "ui",
    operation_id = "robots_txt",

)]
pub async fn robots_txt() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain;charset=utf-8")],
        axum::response::Html(
            r#"User-agent: *
        Disallow: /
"#,
        ),
    )
}

#[utoipa::path(
    get,
    path = Urls::WellKnownChangePassword.as_ref(),
    responses(
        (status = 303, description = "See other"),
    ),
    tag = "ui",
)]
pub async fn redirect_to_update_credentials() -> impl IntoResponse {
    Redirect::to(Urls::UpdateCredentials.as_ref())
}

#[serde_with::skip_serializing_none]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WellKnownPasskeyEndpoints {
    enroll: Option<Url>,
    manage: Option<Url>,
    prf_usage_details: Option<Url>,
}

pub async fn passkey_endpoints(State(state): State<ServerState>) -> impl IntoResponse {
    let mut manage = state.origin;
    manage.set_path("/ui/update_credentials");

    Json(WellKnownPasskeyEndpoints {
        enroll: None,
        manage: Some(manage),
        prf_usage_details: None,
    })
}
