use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::app::AppState;
use crate::auth::AdminUser;
use crate::problems::ProblemDetails;
use crate::tokens;

use super::auth::UserProfile;
use super::tokens::{CreateTokenRequest, CreatedTokenResponse, TokenListResponse, TokenResponse};
use super::{ApiPath, Pagination, ProblemContext, deserialize_optional_field, resolve_pagination};

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub items: Vec<UserProfile>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[utoipa::path(
    get,
    path = "/_/api/v1/users",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of Users to return (default 20, maximum 100)."),
        ("offset" = Option<i64>, Query, description = "Number of Users to skip.")
    ),
    responses(
        (status = 200, description = "All Users with their role and disabled status.", body = UserListResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid pagination parameters.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<UserListResponse>, ProblemDetails> {
    let query = query.problem(&uri)?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, &uri)?;
    let (items, total) = crate::users::list_users(&state.db, limit, offset)
        .await
        .problem(&uri)?;
    Ok(Json(UserListResponse {
        items: items.into_iter().map(UserProfile::from).collect(),
        total,
        limit,
        offset,
    }))
}

#[utoipa::path(
    get,
    path = "/_/api/v1/users/{id}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The User id.")),
    responses(
        (status = 200, description = "The User.", body = UserProfile),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such User.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
) -> Result<Json<UserProfile>, ProblemDetails> {
    let Path(user_id) = path.problem(&uri)?;
    let user = crate::users::find_by_id(&state.db, user_id)
        .await
        .problem(&uri)?
        .ok_or_else(|| ProblemDetails::not_found("User not found.", &uri))?;
    Ok(Json(UserProfile::from(user)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    /// The new optional email. Omit it to keep the current email; send `null`
    /// or an empty string to clear it.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    #[schema(value_type = Option<String>)]
    pub email: Option<Option<String>>,
    /// When true, disable the User and revoke all of their API tokens. When
    /// false, re-enable the User; revoked tokens are never restored.
    pub disabled: Option<bool>,
}

#[utoipa::path(
    patch,
    path = "/_/api/v1/users/{id}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The User id.")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "The User was updated.", body = UserProfile),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such User.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The email is already in use.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The email is invalid or the body is malformed.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
    payload: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> Result<Json<UserProfile>, ProblemDetails> {
    let Path(user_id) = path.problem(&uri)?;
    let Json(payload) = payload.problem(&uri)?;
    let user = crate::users::update_user(
        &state.db,
        user_id,
        crate::users::UserChanges {
            email: payload.email,
            disabled: payload.disabled,
        },
    )
    .await
    .problem(&uri)?;
    Ok(Json(UserProfile::from(user)))
}

#[utoipa::path(
    delete,
    path = "/_/api/v1/users/{id}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The User id.")),
    responses(
        (status = 204, description = "The User was deleted."),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such User.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The User owns Links and cannot be deleted.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(user_id) = path.problem(&uri)?;
    crate::users::delete_user(&state.db, user_id)
        .await
        .problem(&uri)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/_/api/v1/users/{id}/tokens",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("id" = i64, Path, description = "The User id."),
        ("limit" = Option<i64>, Query, description = "Maximum number of API tokens to return (default 20, maximum 100)."),
        ("offset" = Option<i64>, Query, description = "Number of API tokens to skip.")
    ),
    responses(
        (status = 200, description = "The User's API tokens. Plaintext tokens are never listed.", body = TokenListResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such User.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid pagination parameters.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_user_tokens(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<TokenListResponse>, ProblemDetails> {
    let Path(user_id) = path.problem(&uri)?;
    let query = query.problem(&uri)?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, &uri)?;
    let exists = crate::users::find_by_id(&state.db, user_id)
        .await
        .problem(&uri)?
        .is_some();
    if !exists {
        return Err(ProblemDetails::not_found("User not found.", &uri));
    }
    let (items, total) = tokens::list_tokens(&state.db, user_id, limit, offset)
        .await
        .problem(&uri)?;
    Ok(Json(TokenListResponse {
        items: items.into_iter().map(TokenResponse::from).collect(),
        total,
        limit,
        offset,
    }))
}

#[utoipa::path(
    post,
    path = "/_/api/v1/users/{id}/tokens",
    tag = "users",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The User id.")),
    request_body = CreateTokenRequest,
    responses(
        (status = 201, description = "API token created for the User. The plaintext `token` is returned only in this response.", body = CreatedTokenResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such User.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The User is disabled.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The token name or expiry is invalid.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_user_token(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CreatedTokenResponse>), ProblemDetails> {
    let Path(user_id) = path.problem(&uri)?;
    let Json(payload) = payload.problem(&uri)?;
    let created = tokens::create_token(
        &state.db,
        user_id,
        &payload.name,
        payload.expires_at.as_deref(),
    )
    .await
    .problem(&uri)?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedTokenResponse::from(created)),
    ))
}

#[utoipa::path(
    delete,
    path = "/_/api/v1/users/{id}/tokens/{token_id}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("id" = i64, Path, description = "The User id."),
        ("token_id" = i64, Path, description = "The API token id.")
    ),
    responses(
        (status = 204, description = "The API token was revoked."),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such User or API token for that User.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn revoke_user_token(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<(i64, i64)>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path((user_id, token_id)) = path.problem(&uri)?;
    let exists = crate::users::find_by_id(&state.db, user_id)
        .await
        .problem(&uri)?
        .is_some();
    if !exists {
        return Err(ProblemDetails::not_found("User not found.", &uri));
    }
    tokens::revoke_token(&state.db, user_id, token_id)
        .await
        .problem(&uri)?;
    Ok(StatusCode::NO_CONTENT)
}
