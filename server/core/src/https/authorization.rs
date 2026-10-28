use super::errors::WebError;
use super::middleware::KOpId;
use super::ServerState;
use crate::https::apidocs::response_schema::ApiResponseWithout200;
use crate::https::extractors::VerifiedClientInformation;
use axum::extract::State;
use axum::routing::post;
use axum::Extension;
use axum::Json;
use axum::Router;
use kubidm_proto::internal::{
    AuthorizationRequest, AuthorizationResponse, BatchAuthorizationRequest,
    BatchAuthorizationResponse,
};

#[utoipa::path(
    post,
    path = "/v1/authorize",
    request_body = AuthorizationRequest,
    responses(
        (status = 200, description = "Ok", body = AuthorizationResponse, content_type = "application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "authorization",
    operation_id = "authorize"
)]
/// Decide whether the caller may perform an action on a resource.
///
/// The decision is ACP-level only: plugins (attribute uniqueness, referential integrity,
/// value deny lists) may still deny the real operation. Only the caller's own permissions
/// can be queried, so `subject` must be unset or the caller's uuid. A read-only session
/// that would be allowed after re-authenticating gets `reauthrequired`.
pub async fn authorize(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(req): Json<AuthorizationRequest>,
) -> Result<Json<AuthorizationResponse>, WebError> {
    state
        .qe_r_ref
        .handle_authorization_request(client_auth_info, req, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/authorize/batch",
    request_body = BatchAuthorizationRequest,
    responses(
        (status = 200, description = "Ok", body = BatchAuthorizationResponse, content_type = "application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "authorization",
    operation_id = "authorize_batch"
)]
/// Decide up to 100 authorization requests in one call.
///
/// Each request is decided as by `/v1/authorize` (ACP-level only: plugins may still deny
/// the real operation). A resource that is not found yields a `notfound` decision for
/// that item instead of failing the batch.
pub async fn authorize_batch(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(req): Json<BatchAuthorizationRequest>,
) -> Result<Json<BatchAuthorizationResponse>, WebError> {
    state
        .qe_r_ref
        .handle_batch_authorization_request(client_auth_info, req, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

pub(crate) fn route_setup() -> Router<ServerState> {
    Router::new()
        .route("/v1/authorize", post(authorize))
        .route("/v1/authorize/batch", post(authorize_batch))
}
