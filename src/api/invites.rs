use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::app::AppState;
use crate::auth::AdminUser;
use crate::invites;
use crate::problems::ProblemDetails;

use super::auth::UserProfile;
use super::{ApiPath, Pagination, ProblemContext, resolve_pagination};

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteResponse {
    pub id: i64,
    pub created_by: i64,
    /// One of `pending`, `used`, `expired`, or `revoked`.
    pub status: String,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

impl From<invites::InviteSummary> for InviteResponse {
    fn from(invite: invites::InviteSummary) -> Self {
        Self {
            id: invite.id,
            created_by: invite.created_by,
            status: invite.status.as_str().to_string(),
            expires_at: invite.expires_at,
            used_at: invite.used_at,
            revoked_at: invite.revoked_at,
            created_at: invite.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteListResponse {
    pub items: Vec<InviteResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[utoipa::path(
    get,
    path = "/_/api/v1/invites",
    tag = "invites",
    security(("bearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of Invites to return (default 20, maximum 100)."),
        ("offset" = Option<i64>, Query, description = "Number of Invites to skip.")
    ),
    responses(
        (status = 200, description = "All Invites with their status. Plaintext tokens and hashes are never listed.", body = InviteListResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid pagination parameters.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn list_invites(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<InviteListResponse>, ProblemDetails> {
    let query = query.problem(&uri)?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, &uri)?;
    let (items, total) = invites::list_invites(&state.db, limit, offset)
        .await
        .problem(&uri)?;
    Ok(Json(InviteListResponse {
        items: items.into_iter().map(InviteResponse::from).collect(),
        total,
        limit,
        offset,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedInviteResponse {
    pub id: i64,
    /// The plaintext Invite token. Returned only in this response.
    pub token: String,
    pub expires_at: String,
    pub created_at: String,
}

impl From<invites::CreatedInvite> for CreatedInviteResponse {
    fn from(invite: invites::CreatedInvite) -> Self {
        Self {
            id: invite.id,
            token: invite.plaintext,
            expires_at: invite.expires_at,
            created_at: invite.created_at,
        }
    }
}

#[utoipa::path(
    post,
    path = "/_/api/v1/invites",
    tag = "invites",
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Invite created. The plaintext `token` is returned only in this response.", body = CreatedInviteResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_invite(
    State(state): State<AppState>,
    admin: AdminUser,
    uri: ApiPath,
) -> Result<(StatusCode, Json<CreatedInviteResponse>), ProblemDetails> {
    let created = invites::create_invite(&state.db, admin.current.id())
        .await
        .problem(&uri)?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedInviteResponse::from(created)),
    ))
}

#[utoipa::path(
    delete,
    path = "/_/api/v1/invites/{id}",
    tag = "invites",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The Invite id.")),
    responses(
        (status = 204, description = "The Invite was revoked. Revoking an already revoked Invite is a no-op."),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such Invite.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The Invite has already been used.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn revoke_invite(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(invite_id) = path.problem(&uri)?;
    invites::revoke_invite(&state.db, invite_id)
        .await
        .problem(&uri)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteValidationResponse {
    /// One of `valid`, `expired`, `used`, or `revoked`.
    pub status: String,
    pub expires_at: String,
}

#[utoipa::path(
    get,
    path = "/_/api/v1/invites/{token}",
    tag = "invites",
    params(("token" = String, Path, description = "The plaintext Invite token.")),
    responses(
        (status = 200, description = "The Invite is valid, expired, used, or revoked.", body = InviteValidationResponse),
        (status = 404, description = "No such Invite.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn validate_invite(
    State(state): State<AppState>,
    uri: ApiPath,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<InviteValidationResponse>, ProblemDetails> {
    let Path(token) = path.problem(&uri)?;
    let validation = invites::validate_invite(&state.db, &token)
        .await
        .problem(&uri)?;
    Ok(Json(InviteValidationResponse {
        status: validation.status.as_validation_str().to_string(),
        expires_at: validation.expires_at,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AcceptInviteRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

#[utoipa::path(
    post,
    path = "/_/api/v1/invites/{token}/accept",
    tag = "invites",
    params(("token" = String, Path, description = "The plaintext Invite token.")),
    request_body = AcceptInviteRequest,
    responses(
        (status = 201, description = "The Invite was accepted and the User was created.", body = UserProfile),
        (status = 404, description = "No such Invite.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The Invite was already used or revoked, or the username or email is taken.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The Invite has expired.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The username, email, or password is invalid.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn accept_invite(
    State(state): State<AppState>,
    uri: ApiPath,
    path: Result<Path<String>, PathRejection>,
    payload: Result<Json<AcceptInviteRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<UserProfile>), ProblemDetails> {
    let Path(token) = path.problem(&uri)?;
    let Json(payload) = payload.problem(&uri)?;
    let user = invites::accept_invite(
        &state.db,
        &token,
        invites::AcceptInvite {
            username: payload.username,
            email: payload.email,
            password: payload.password,
        },
    )
    .await
    .problem(&uri)?;
    Ok((StatusCode::CREATED, Json(UserProfile::from(user))))
}
