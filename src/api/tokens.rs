use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::app::AppState;
use crate::auth::CurrentUser;
use crate::problems::ProblemDetails;
use crate::tokens;

use super::{ApiPath, Pagination, ProblemContext, resolve_pagination};

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub name: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

impl From<tokens::TokenSummary> for TokenResponse {
    fn from(token: tokens::TokenSummary) -> Self {
        Self {
            id: token.id,
            name: token.name,
            prefix: token.prefix,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
            revoked_at: token.revoked_at,
            created_at: token.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedTokenResponse {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    /// The plaintext API token. Returned only in this response.
    pub token: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

impl From<tokens::CreatedToken> for CreatedTokenResponse {
    fn from(token: tokens::CreatedToken) -> Self {
        Self {
            id: token.id,
            name: token.name,
            prefix: token.prefix,
            token: token.plaintext,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
            revoked_at: token.revoked_at,
            created_at: token.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenListResponse {
    pub items: Vec<TokenResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[utoipa::path(
    get,
    path = "/_/api/v1/tokens",
    tag = "tokens",
    security(("bearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of API tokens to return (default 20, maximum 100)."),
        ("offset" = Option<i64>, Query, description = "Number of API tokens to skip.")
    ),
    responses(
        (status = 200, description = "The current User's API tokens. Plaintext tokens are never listed.", body = TokenListResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid pagination parameters.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_tokens(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<TokenListResponse>, ProblemDetails> {
    let query = query.problem(&uri)?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, &uri)?;
    let (items, total) = tokens::list_tokens(&state.db, user.id(), limit, offset)
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
    path = "/_/api/v1/tokens",
    tag = "tokens",
    security(("bearerAuth" = [])),
    request_body = CreateTokenRequest,
    responses(
        (status = 201, description = "API token created. The plaintext `token` is returned only in this response.", body = CreatedTokenResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The token name or expiry is invalid.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_token(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CreatedTokenResponse>), ProblemDetails> {
    let Json(payload) = payload.problem(&uri)?;
    let created = tokens::create_token(
        &state.db,
        user.id(),
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
    path = "/_/api/v1/tokens/{id}",
    tag = "tokens",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The API token id.")),
    responses(
        (status = 204, description = "The API token was revoked."),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such API token belongs to the current User.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn revoke_token(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(token_id) = path.problem(&uri)?;
    tokens::revoke_token(&state.db, user.id(), token_id)
        .await
        .problem(&uri)?;
    Ok(StatusCode::NO_CONTENT)
}
