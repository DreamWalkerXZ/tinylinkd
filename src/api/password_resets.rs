use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::app::AppState;
use crate::auth::AdminUser;
use crate::password_resets;
use crate::problems::ProblemDetails;

use super::{ApiPath, ProblemContext};

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedPasswordResetResponse {
    pub id: i64,
    /// The plaintext password-reset token. Returned only in this response.
    pub token: String,
    pub expires_at: String,
    pub created_at: String,
}

impl From<password_resets::CreatedPasswordReset> for CreatedPasswordResetResponse {
    fn from(reset: password_resets::CreatedPasswordReset) -> Self {
        Self {
            id: reset.id,
            token: reset.plaintext,
            expires_at: reset.expires_at,
            created_at: reset.created_at,
        }
    }
}

#[utoipa::path(
    post,
    path = "/_/api/v1/users/{id}/password-reset",
    tag = "password-resets",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The User id.")),
    responses(
        (status = 201, description = "Password-reset token created. The plaintext `token` is returned only in this response.", body = CreatedPasswordResetResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such User.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn create_password_reset(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
) -> Result<(StatusCode, Json<CreatedPasswordResetResponse>), ProblemDetails> {
    let Path(user_id) = path.problem(&uri)?;
    let created = password_resets::create_password_reset(&state.db, user_id)
        .await
        .problem(&uri)?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedPasswordResetResponse::from(created)),
    ))
}

#[utoipa::path(
    delete,
    path = "/_/api/v1/password-resets/{id}",
    tag = "password-resets",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The password-reset id.")),
    responses(
        (status = 204, description = "The password-reset token was revoked."),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such password-reset token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The password-reset token was already used.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn revoke_password_reset(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    path: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(id) = path.problem(&uri)?;
    let id: i64 = id
        .parse()
        .map_err(|_| ProblemDetails::not_found("Password-reset token not found.", &uri))?;
    password_resets::revoke_password_reset(&state.db, id)
        .await
        .problem(&uri)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasswordResetValidationResponse {
    /// One of `valid`, `expired`, `used`, or `revoked`.
    pub status: String,
    pub expires_at: String,
}

#[utoipa::path(
    get,
    path = "/_/api/v1/password-resets/{token}",
    tag = "password-resets",
    params(("token" = String, Path, description = "The plaintext password-reset token.")),
    responses(
        (status = 200, description = "The password-reset token is valid, expired, used, or revoked.", body = PasswordResetValidationResponse),
        (status = 404, description = "No such password-reset token.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn validate_password_reset(
    State(state): State<AppState>,
    uri: ApiPath,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<PasswordResetValidationResponse>, ProblemDetails> {
    let Path(token) = path.problem(&uri)?;
    let validation = password_resets::validate_password_reset(&state.db, &token)
        .await
        .problem(&uri)?;
    Ok(Json(PasswordResetValidationResponse {
        status: validation.status.as_validation_str().to_string(),
        expires_at: validation.expires_at,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AcceptPasswordResetRequest {
    pub password: String,
}

#[utoipa::path(
    post,
    path = "/_/api/v1/password-resets/{token}/accept",
    tag = "password-resets",
    params(("token" = String, Path, description = "The plaintext password-reset token.")),
    request_body = AcceptPasswordResetRequest,
    responses(
        (status = 204, description = "The password was changed and the token was consumed."),
        (status = 404, description = "No such password-reset token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The password-reset token was already used or revoked.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 410, description = "The password-reset token has expired.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The new password is invalid.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn accept_password_reset(
    State(state): State<AppState>,
    uri: ApiPath,
    path: Result<Path<String>, PathRejection>,
    payload: Result<Json<AcceptPasswordResetRequest>, JsonRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(token) = path.problem(&uri)?;
    let Json(payload) = payload.problem(&uri)?;
    password_resets::accept_password_reset(&state.db, &token, &payload.password)
        .await
        .problem(&uri)?;
    Ok(StatusCode::NO_CONTENT)
}
