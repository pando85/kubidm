use super::apidocs::response_schema::{ApiResponseWithout200, DefaultApiResponse};
use super::errors::WebError;
use super::middleware::KOpId;
use super::v1::{json_rest_event_get, json_rest_event_get_id, json_rest_event_post};
use super::ServerState;

use crate::https::extractors::VerifiedClientInformation;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use kubidm_proto::v1::Entry as ProtoEntry;
use kubidmd_lib::prelude::*;

#[utoipa::path(
    get,
    path = "/v1/oauth2/federation",
    responses(
        (status = 200, description = "Ok", content_type=APPLICATION_JSON, body=Vec<ProtoEntry>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2_federation",
    operation_id = "oauth2_federation_get"
)]
pub(crate) async fn oauth2_federation_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::OAuth2Federation.into()));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/federation/_create",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2_federation",
    operation_id = "oauth2_federation_post"
)]
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
    path = "/v1/oauth2/federation/{name}",
    responses(
        (status = 200, description = "Ok", content_type=APPLICATION_JSON, body=ProtoEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2_federation",
    operation_id = "oauth2_federation_id_get"
)]
pub(crate) async fn oauth2_federation_id_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<ProtoEntry>, WebError> {
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2Federation.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&id))
    ]));
    let Json(entry_opt) =
        json_rest_event_get_id(state, id, filter, None, kopid, client_auth_info).await?;
    entry_opt
        .map(Json)
        .ok_or_else(|| WebError::from(OperationError::NoMatchingEntries))
}
