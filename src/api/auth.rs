use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::app::AppState;
use crate::auth::CurrentUser;
use crate::problems::ProblemDetails;

use super::{ApiPath, ProblemContext, deserialize_optional_field};

#[derive(Debug, Serialize, ToSchema)]
pub struct UserProfile {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
    pub disabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<CurrentUser> for UserProfile {
    fn from(current: CurrentUser) -> Self {
        Self::from(current.user)
    }
}

impl From<crate::users::User> for UserProfile {
    fn from(user: crate::users::User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role.as_str().to_string(),
            disabled: user.disabled_at.is_some(),
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[utoipa::path(
    get,
    path = "/_/api/v1/me",
    tag = "auth",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "The current User profile.", body = UserProfile),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn me(user: CurrentUser) -> Json<UserProfile> {
    Json(UserProfile::from(user))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProfileRequest {
    /// The new optional email. Omit it to keep the current email; send `null`
    /// or an empty string to clear it.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    #[schema(value_type = Option<String>)]
    pub email: Option<Option<String>>,
}

#[utoipa::path(
    patch,
    path = "/_/api/v1/me",
    tag = "auth",
    security(("bearerAuth" = [])),
    request_body = UpdateProfileRequest,
    responses(
        (status = 200, description = "The updated current User profile.", body = UserProfile),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The email is already in use.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The email is invalid.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_me(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    payload: Result<Json<UpdateProfileRequest>, JsonRejection>,
) -> Result<Json<UserProfile>, ProblemDetails> {
    let Json(payload) = payload.problem(&uri)?;
    let updated = crate::users::update_email(
        &state.db,
        user.id(),
        crate::users::EmailChange {
            email: payload.email,
        },
    )
    .await
    .problem(&uri)?;
    Ok(Json(UserProfile::from(updated)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[utoipa::path(
    post,
    path = "/_/api/v1/me/password",
    tag = "auth",
    security(("bearerAuth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "The password was changed."),
        (status = 401, description = "Missing, invalid, revoked, or expired API token, or the current password is incorrect.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The new password is invalid or the body is malformed.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn change_password(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    payload: Result<Json<ChangePasswordRequest>, JsonRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Json(payload) = payload.problem(&uri)?;
    crate::users::change_password(
        &state.db,
        user.id(),
        &payload.current_password,
        &payload.new_password,
    )
    .await
    .problem(&uri)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteAccountRequest {
    /// The current password. `current_password` is accepted as an alias.
    #[serde(alias = "current_password")]
    pub password: String,
}

#[utoipa::path(
    delete,
    path = "/_/api/v1/me",
    tag = "auth",
    security(("bearerAuth" = [])),
    request_body = DeleteAccountRequest,
    responses(
        (status = 204, description = "The current User was deleted."),
        (status = 401, description = "Missing, invalid, revoked, or expired API token, or the password is incorrect.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The User owns Links and cannot be deleted.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The password is missing or the body is malformed.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn delete_me(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    payload: Result<Json<DeleteAccountRequest>, JsonRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Json(payload) = payload.problem(&uri)?;
    crate::users::delete_own_account(&state.db, user.id(), &payload.password)
        .await
        .problem(&uri)?;
    Ok(StatusCode::NO_CONTENT)
}
