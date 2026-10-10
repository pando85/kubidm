use std::sync::Arc;

use axum::extract::State;
use axum::http::{
    header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE},
    HeaderMap, StatusCode,
};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Json};
use kubidmd_lib::maintenance::{maintenance_public_status, MaintenancePublicStatus};
use kubidmd_lib::prelude::APPLICATION_JSON;
use kubidmd_lib::status::{LivenessStatus, ReadinessStatus, ServingReadiness, StatusRequestEvent};
use sha2::{Digest, Sha256};
use url::Url;

use super::{middleware::KOpId, views::constants::Urls, ServerState};
use crate::backup::metrics::{BackupMetrics, PROMETHEUS_TEXT_CONTENT_TYPE};

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

/// The `/metrics` endpoint: the backup metrics it serves and, when
/// `online_backup.metrics_token_file` is set, the SHA-256 of the bearer token a scraper
/// must present.
#[derive(Clone)]
pub struct MetricsEndpoint {
    metrics: Arc<BackupMetrics>,
    token_sha256: Option<[u8; 32]>,
}

impl MetricsEndpoint {
    pub fn new(metrics: Arc<BackupMetrics>, token: Option<String>) -> Self {
        Self {
            metrics,
            token_sha256: token.map(|token| Sha256::digest(token.as_bytes()).into()),
        }
    }

    /// Whether the request with `headers` may read the metrics: always without a token,
    /// otherwise only with `Authorization: Bearer <token>`. The digests of the tokens are
    /// compared in constant time.
    fn authorized(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.token_sha256 else {
            return true;
        };
        let Some(presented) = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return false;
        };
        let presented: [u8; 32] = Sha256::digest(presented.trim().as_bytes()).into();
        expected
            .iter()
            .zip(presented.iter())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    }
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Backup metrics in the Prometheus text exposition format", content_type = "text/plain"),
        (status = 401, description = "online_backup.metrics_token_file is set and the request has no matching bearer token"),
        (status = 404, description = "online_backup.metrics_endpoint is not enabled"),
    ),
    tag = "system",
    operation_id = "metrics"
)]
/// The backup metrics in the Prometheus text exposition format: per backup destination the
/// time of the last successful and failed backup and of the last full verification, and
/// the time of the last WAL archive synchronisation. Only served when
/// `online_backup.metrics_endpoint` is enabled, and only to a bearer of the token of
/// `online_backup.metrics_token_file` when that is set.
pub async fn metrics(State(endpoint): State<MetricsEndpoint>, headers: HeaderMap) -> Response {
    if !endpoint.authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, "Bearer")]).into_response();
    }
    (
        StatusCode::OK,
        [(CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)],
        endpoint.metrics.render(),
    )
        .into_response()
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

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(authorization: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = authorization {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(value).expect("a header value"),
            );
        }
        headers
    }

    #[test]
    fn the_metrics_need_the_bearer_token_when_one_is_configured() {
        let metrics = Arc::new(BackupMetrics::new(None));
        let open = MetricsEndpoint::new(metrics.clone(), None);
        assert!(open.authorized(&headers(None)));
        assert!(open.authorized(&headers(Some("Bearer anything"))));

        let protected = MetricsEndpoint::new(metrics, Some("s3cret-token".to_string()));
        assert!(protected.authorized(&headers(Some("Bearer s3cret-token"))));
        for refused in [
            None,
            Some("Bearer wrong"),
            Some("Bearer "),
            Some("Bearer s3cret-token-and-more"),
            Some("Basic s3cret-token"),
            Some("s3cret-token"),
        ] {
            assert!(!protected.authorized(&headers(refused)), "{refused:?}");
        }
    }
}
