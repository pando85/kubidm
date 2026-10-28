//! Kubidm: OAuth2 / OIDC federation (upstream identity provider) management.
//!
//! The routes live under `/v1/federation/oauth2` so that they never shadow an OAuth2
//! resource server, which is addressed as `/v1/oauth2/{rs_name}` (and may be named
//! `federation`).

use super::apidocs::response_schema::{ApiResponseWithout200, DefaultApiResponse};
use super::errors::WebError;
use super::middleware::KOpId;
use super::v1::{
    json_rest_event_delete_id, json_rest_event_get, json_rest_event_get_id, json_rest_event_post,
};
use super::ServerState;

use crate::https::extractors::VerifiedClientInformation;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use kubidm_proto::v1::Entry as ProtoEntry;
use kubidmd_lib::prelude::*;

fn oauth2_federation_filter() -> Filter<FilterInvalid> {
    filter_all!(f_eq(Attribute::Class, EntryClass::OAuth2Federation.into()))
}

fn oauth2_federation_id(name: &str) -> Filter<FilterInvalid> {
    filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2Federation.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(name))
    ]))
}

#[utoipa::path(
    get,
    path = "/v1/federation/oauth2",
    responses(
        (status = 200, description = "Ok", content_type=APPLICATION_JSON, body=Vec<ProtoEntry>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2_federation",
    operation_id = "oauth2_federation_get"
)]
/// List the OAuth2 federation identity providers
pub(crate) async fn oauth2_federation_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    json_rest_event_get(
        state,
        None,
        oauth2_federation_filter(),
        kopid,
        client_auth_info,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/v1/federation/oauth2",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2_federation",
    operation_id = "oauth2_federation_post"
)]
/// Create an OAuth2 federation identity provider
pub(crate) async fn oauth2_federation_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec![
        EntryClass::OAuth2Federation.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/federation/oauth2/{name}",
    responses(
        (status = 200, description = "Ok", content_type=APPLICATION_JSON, body=ProtoEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2_federation",
    operation_id = "oauth2_federation_id_get"
)]
/// Get an OAuth2 federation identity provider
pub(crate) async fn oauth2_federation_id_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(name): Path<String>,
) -> Result<Json<ProtoEntry>, WebError> {
    let filter = oauth2_federation_id(&name);
    let Json(entry_opt) =
        json_rest_event_get_id(state, name, filter, None, kopid, client_auth_info).await?;
    entry_opt
        .map(Json)
        .ok_or_else(|| WebError::from(OperationError::NoMatchingEntries))
}

#[utoipa::path(
    patch,
    path = "/v1/federation/oauth2/{name}",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2_federation",
    operation_id = "oauth2_federation_id_patch"
)]
/// Modify an OAuth2 federation identity provider
pub(crate) async fn oauth2_federation_id_patch(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(name): Path<String>,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_federation_id(&name);
    state
        .qe_w_ref
        .handle_internalpatch(client_auth_info, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/federation/oauth2/{name}",
    responses(
        DefaultApiResponse,
        (status = 404, description = "The OAuth2 federation identity provider does not exist"),
    ),
    security(("token_jwt" = [])),
    tag = "oauth2_federation",
    operation_id = "oauth2_federation_id_delete"
)]
/// Delete an OAuth2 federation identity provider
pub(crate) async fn oauth2_federation_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(name): Path<String>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_federation_id(&name);
    json_rest_event_delete_id(state, name, filter, kopid, client_auth_info).await
}
