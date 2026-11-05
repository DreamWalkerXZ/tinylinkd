use std::collections::BTreeMap;

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::OpenApi as _;
use utoipa::ToSchema;

use crate::analytics::{self, TimeRange};
use crate::app::{AppConfig, AppState};
use crate::auth::{AdminUser, CurrentUser};
use crate::invites;
use crate::links::{self, LinkStatus};
use crate::password_resets;
use crate::problems::ProblemDetails;
use crate::timeutil;
use crate::tokens;
use crate::users::Role;

pub const DEFAULT_PAGE_LIMIT: i64 = 20;
pub const MAX_PAGE_LIMIT: i64 = 100;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/_/api/v1/me", get(me).patch(update_me).delete(delete_me))
        .route("/_/api/v1/me/password", post(change_password))
        .route("/_/api/v1/users", get(list_users))
        .route(
            "/_/api/v1/users/{id}",
            get(get_user).patch(update_user).delete(delete_user),
        )
        .route(
            "/_/api/v1/users/{id}/tokens",
            get(list_user_tokens).post(create_user_token),
        )
        .route(
            "/_/api/v1/users/{id}/tokens/{token_id}",
            delete(revoke_user_token),
        )
        .route("/_/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/_/api/v1/tokens/{id}", delete(revoke_token))
        .route("/_/api/v1/links", get(list_links).post(create_link))
        .route(
            "/_/api/v1/links/{id}",
            get(get_link).patch(update_link).delete(delete_link),
        )
        .route("/_/api/v1/links/{id}/clicks", get(list_link_clicks))
        .route("/_/api/v1/links/{id}/stats", get(link_stats))
        .route("/_/api/v1/invites", get(list_invites).post(create_invite))
        // Axum forbids two routes that differ only in the parameter name, so
        // the Admin revoke and public validate handlers share this route and
        // parse the segment according to the method.
        .route(
            "/_/api/v1/invites/{token}",
            get(validate_invite).delete(revoke_invite),
        )
        .route("/_/api/v1/invites/{token}/accept", post(accept_invite))
        .route(
            "/_/api/v1/users/{id}/password-reset",
            post(create_password_reset),
        )
        .route(
            "/_/api/v1/password-resets/{token}",
            get(validate_password_reset),
        )
        .route(
            "/_/api/v1/password-resets/{token}/accept",
            post(accept_password_reset),
        )
        .route("/_/api/openapi.json", get(openapi))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "tinylinkd API",
        version = env!("CARGO_PKG_VERSION"),
        description = "The JSON API for a self-hosted tinylinkd Instance. Authenticate with a Bearer API token."
    ),
    paths(
        me,
        update_me,
        change_password,
        delete_me,
        list_users,
        get_user,
        update_user,
        delete_user,
        list_user_tokens,
        create_user_token,
        revoke_user_token,
        list_tokens,
        create_token,
        revoke_token,
        list_invites,
        create_invite,
        revoke_invite,
        validate_invite,
        accept_invite,
        create_password_reset,
        validate_password_reset,
        accept_password_reset,
        create_link,
        list_links,
        get_link,
        update_link,
        delete_link,
        list_link_clicks,
        link_stats
    ),
    components(schemas(
        UserProfile,
        UpdateProfileRequest,
        ChangePasswordRequest,
        DeleteAccountRequest,
        UserListResponse,
        UpdateUserRequest,
        TokenResponse,
        CreatedTokenResponse,
        TokenListResponse,
        CreateTokenRequest,
        InviteResponse,
        CreatedInviteResponse,
        InviteListResponse,
        InviteValidationResponse,
        AcceptInviteRequest,
        CreatedPasswordResetResponse,
        PasswordResetValidationResponse,
        AcceptPasswordResetRequest,
        Pagination,
        LinkResponse,
        LinkListResponse,
        LinkStatus,
        CreateLinkRequest,
        UpdateLinkRequest,
        ClickResponse,
        ClickListResponse,
        LinkStatsResponse,
        DayCount,
        ProblemDetails
    )),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default);
        components.add_security_scheme(
            "bearerAuth",
            utoipa::openapi::security::SecurityScheme::Http(utoipa::openapi::security::Http::new(
                utoipa::openapi::security::HttpAuthScheme::Bearer,
            )),
        );
    }
}

async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

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
async fn me(user: CurrentUser) -> Json<UserProfile> {
    Json(UserProfile::from(user))
}

/// Distinguish an omitted field from an explicit `null` in a PATCH body.
fn deserialize_optional_field<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
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
async fn update_me(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    payload: Result<Json<UpdateProfileRequest>, JsonRejection>,
) -> Result<Json<UserProfile>, ProblemDetails> {
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    let updated = crate::users::update_email(
        &state.db,
        user.user.id,
        crate::users::EmailChange {
            email: payload.email,
        },
    )
    .await
    .map_err(|error| error.into_problem(uri.path()))?;
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
async fn change_password(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    payload: Result<Json<ChangePasswordRequest>, JsonRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    crate::users::change_password(
        &state.db,
        user.user.id,
        &payload.current_password,
        &payload.new_password,
    )
    .await
    .map_err(|error| error.into_problem(uri.path()))?;
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
async fn delete_me(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    payload: Result<Json<DeleteAccountRequest>, JsonRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    crate::users::delete_own_account(&state.db, user.user.id, &payload.password)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok(StatusCode::NO_CONTENT)
}

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
async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<UserListResponse>, ProblemDetails> {
    let query = query.map_err(|rejection| pagination_problem(rejection, uri.path()))?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, uri.path())?;
    let (items, total) = crate::users::list_users(&state.db, limit, offset)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
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
async fn get_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
) -> Result<Json<UserProfile>, ProblemDetails> {
    let Path(user_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let user = crate::users::find_by_id(&state.db, user_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?
        .ok_or_else(|| ProblemDetails::not_found("User not found.", uri.path()))?;
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
async fn update_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
    payload: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> Result<Json<UserProfile>, ProblemDetails> {
    let Path(user_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    let user = crate::users::update_user(
        &state.db,
        user_id,
        crate::users::UserChanges {
            email: payload.email,
            disabled: payload.disabled,
        },
    )
    .await
    .map_err(|error| error.into_problem(uri.path()))?;
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
async fn delete_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(user_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    crate::users::delete_user(&state.db, user_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
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
async fn list_user_tokens(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<TokenListResponse>, ProblemDetails> {
    let Path(user_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let query = query.map_err(|rejection| pagination_problem(rejection, uri.path()))?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, uri.path())?;
    let exists = crate::users::find_by_id(&state.db, user_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?
        .is_some();
    if !exists {
        return Err(ProblemDetails::not_found("User not found.", uri.path()));
    }
    let (items, total) = tokens::list_tokens(&state.db, user_id, limit, offset)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
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
async fn create_user_token(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CreatedTokenResponse>), ProblemDetails> {
    let Path(user_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    let created = tokens::create_token(
        &state.db,
        user_id,
        &payload.name,
        payload.expires_at.as_deref(),
    )
    .await
    .map_err(|error| error.into_problem(uri.path()))?;
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
async fn revoke_user_token(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    path: Result<Path<(i64, i64)>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path((user_id, token_id)) =
        path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let exists = crate::users::find_by_id(&state.db, user_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?
        .is_some();
    if !exists {
        return Err(ProblemDetails::not_found("User not found.", uri.path()));
    }
    tokens::revoke_token(&state.db, user_id, token_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok(StatusCode::NO_CONTENT)
}

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

fn json_rejection_problem(rejection: JsonRejection, instance: &str) -> ProblemDetails {
    let status = rejection.status();
    let title = status.canonical_reason().unwrap_or("Bad Request");
    ProblemDetails::new(
        status,
        "invalid_request",
        title,
        rejection.body_text(),
        instance,
    )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Pagination {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn pagination_problem(rejection: QueryRejection, instance: &str) -> ProblemDetails {
    ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_pagination",
        "Unprocessable Entity",
        rejection.body_text(),
        instance,
    )
}

fn resolve_pagination(
    limit: Option<i64>,
    offset: Option<i64>,
    instance: &str,
) -> Result<(i64, i64), ProblemDetails> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let offset = offset.unwrap_or(0);
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        return Err(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_pagination",
            "Unprocessable Entity",
            format!("limit must be between 1 and {MAX_PAGE_LIMIT}."),
            instance,
        ));
    }
    if offset < 0 {
        return Err(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_pagination",
            "Unprocessable Entity",
            "offset must not be negative.",
            instance,
        ));
    }
    Ok((limit, offset))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLinkRequest {
    /// The absolute `http` or `https` URL the Link redirects to.
    pub destination_url: String,
    /// An optional custom Slug. An 8-character random Slug is generated when omitted.
    pub slug: Option<String>,
}

fn deserialize_optional_password<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateLinkRequest {
    /// The new absolute `http` or `https` URL the Link redirects to.
    pub destination_url: Option<String>,
    /// A new Slug. A Slug change returns a `warning` because the old short URL
    /// stops working immediately and may be reused by another Link.
    pub slug: Option<String>,
    /// Admin-only: transfer the Link to another existing User.
    pub owner_id: Option<i64>,
    /// A non-empty string sets or changes the Link's password; `null` clears
    /// it and makes the Link redirect without a password. Omit the field to
    /// leave the password unchanged.
    #[serde(default, deserialize_with = "deserialize_optional_password")]
    pub password: Option<Option<String>>,
    /// The Link's expiry as an RFC 3339 timestamp, stored and returned in UTC.
    /// Omit the field to leave the expiry unchanged; send `null` to remove it
    /// and make the Link permanent. A timestamp at or before the current time
    /// makes the Link expired.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    #[schema(value_type = Option<String>)]
    pub expires_at: Option<Option<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LinkResponse {
    pub id: i64,
    pub owner_id: i64,
    pub slug: String,
    pub short_url: String,
    pub destination_url: String,
    /// Whether the Link requires a password before it redirects.
    pub has_password: bool,
    pub expires_at: Option<String>,
    pub status: LinkStatus,
    pub created_at: String,
    pub updated_at: String,
    pub total_clicks: i64,
    pub human_clicks: i64,
    pub bot_clicks: i64,
    /// Present only when an update changed the Slug: the old short URL stops
    /// working immediately and may be reused by another Link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl LinkResponse {
    fn from_link(link: links::Link, config: &AppConfig) -> Self {
        let status = link.status();
        Self {
            id: link.id,
            owner_id: link.owner_id,
            short_url: config.short_url(&link.slug),
            slug: link.slug,
            destination_url: link.destination_url,
            has_password: link.has_password,
            expires_at: link.expires_at,
            status,
            created_at: link.created_at,
            updated_at: link.updated_at,
            total_clicks: link.total_clicks,
            human_clicks: link.human_clicks,
            bot_clicks: link.bot_clicks,
            warning: None,
        }
    }

    fn with_warning(mut self, warning: Option<String>) -> Self {
        self.warning = warning;
        self
    }
}

#[utoipa::path(
    post,
    path = "/_/api/v1/links",
    tag = "links",
    security(("bearerAuth" = [])),
    request_body = CreateLinkRequest,
    responses(
        (status = 201, description = "Link created.", body = LinkResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The custom Slug is already taken.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The Destination URL or Slug is invalid.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_link(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    payload: Result<Json<CreateLinkRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<LinkResponse>), ProblemDetails> {
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    let link = links::create_link(
        &state.db,
        user.user.id,
        &payload.destination_url,
        payload.slug.as_deref(),
    )
    .await
    .map_err(|error| error.into_problem(uri.path()))?;
    Ok((
        StatusCode::CREATED,
        Json(LinkResponse::from_link(link, &state.config)),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LinkListResponse {
    pub items: Vec<LinkResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListLinksQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter by Link status: `active` or `expired`.
    pub status: Option<String>,
    /// Search text matched against the Slug and Destination URL.
    pub q: Option<String>,
    /// Sort order: `created_at` (oldest first) or `-created_at` (newest
    /// first, the default).
    pub sort: Option<String>,
    /// Admin-only: list only the Links owned by this User.
    pub owner_id: Option<i64>,
}

fn parse_link_status(
    value: Option<&str>,
    instance: &str,
) -> Result<Option<LinkStatus>, ProblemDetails> {
    match value {
        None => Ok(None),
        Some("active") => Ok(Some(LinkStatus::Active)),
        Some("expired") => Ok(Some(LinkStatus::Expired)),
        Some(_) => Err(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_status",
            "Unprocessable Entity",
            "status must be 'active' or 'expired'.",
            instance,
        )),
    }
}

fn parse_link_sort(value: Option<&str>, instance: &str) -> Result<links::LinkSort, ProblemDetails> {
    match value {
        None | Some("-created_at") => Ok(links::LinkSort::CreatedAtDesc),
        Some("created_at") => Ok(links::LinkSort::CreatedAtAsc),
        Some(_) => Err(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_sort",
            "Unprocessable Entity",
            "sort must be 'created_at' or '-created_at'.",
            instance,
        )),
    }
}

#[utoipa::path(
    get,
    path = "/_/api/v1/links",
    tag = "links",
    security(("bearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of Links to return (default 20, maximum 100)."),
        ("offset" = Option<i64>, Query, description = "Number of Links to skip."),
        ("status" = Option<String>, Query, description = "Filter by status: `active` or `expired`."),
        ("q" = Option<String>, Query, description = "Search the Slug and Destination URL."),
        ("sort" = Option<String>, Query, description = "Sort order: `created_at` (oldest first) or `-created_at` (newest first, the default)."),
        ("owner_id" = Option<i64>, Query, description = "Admin-only: list only the Links owned by this User.")
    ),
    responses(
        (status = 200, description = "The current User's Links, or all Links for an Admin.", body = LinkListResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "A non-Admin used the Admin-only `owner_id` filter.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid pagination, status, or sort parameters.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_links(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    query: Result<Query<ListLinksQuery>, QueryRejection>,
) -> Result<Json<LinkListResponse>, ProblemDetails> {
    let query = query.map_err(|rejection| pagination_problem(rejection, uri.path()))?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, uri.path())?;
    let is_admin = user.user.role == Role::Admin;
    if query.owner_id.is_some() && !is_admin {
        return Err(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
            "Only Admins may filter Links by owner_id.",
            uri.path(),
        ));
    }
    let filter = links::LinkFilter {
        owner_id: if is_admin {
            query.owner_id
        } else {
            Some(user.user.id)
        },
        status: parse_link_status(query.status.as_deref(), uri.path())?,
        q: query.q.clone(),
        sort: parse_link_sort(query.sort.as_deref(), uri.path())?,
        limit,
        offset,
    };
    let (links, total) = links::list_links(&state.db, &filter)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok(Json(LinkListResponse {
        items: links
            .into_iter()
            .map(|link| LinkResponse::from_link(link, &state.config))
            .collect(),
        total,
        limit,
        offset,
    }))
}

#[utoipa::path(
    get,
    path = "/_/api/v1/links/{id}",
    tag = "links",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The Link id.")),
    responses(
        (status = 200, description = "The Link.", body = LinkResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The Link belongs to another User and the caller is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such Link.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_link(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
) -> Result<Json<LinkResponse>, ProblemDetails> {
    let Path(link_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let Some(link) = links::find_by_id(&state.db, link_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?
    else {
        return Err(ProblemDetails::not_found("Link not found.", uri.path()));
    };
    if link.owner_id != user.user.id && user.user.role != Role::Admin {
        return Err(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
            "You do not have permission to read this Link.",
            uri.path(),
        ));
    }
    Ok(Json(LinkResponse::from_link(link, &state.config)))
}

#[utoipa::path(
    patch,
    path = "/_/api/v1/links/{id}",
    tag = "links",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The Link id.")),
    request_body = UpdateLinkRequest,
    responses(
        (status = 200, description = "The Link was updated. A Slug change returns a `warning` because the old short URL stops working and may be reused.", body = LinkResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The Link belongs to another User and the caller is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such Link.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The requested Slug is already taken.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The Destination URL, Slug, or expiry is invalid.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn update_link(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
    payload: Result<Json<UpdateLinkRequest>, JsonRejection>,
) -> Result<Json<LinkResponse>, ProblemDetails> {
    let Path(link_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    let updated = links::update_link(
        &state.db,
        link_id,
        user.user.id,
        user.user.role == Role::Admin,
        links::LinkChanges {
            destination_url: payload.destination_url,
            slug: payload.slug,
            owner_id: payload.owner_id,
            password: payload.password,
            expires_at: payload.expires_at,
        },
    )
    .await
    .map_err(|error| error.into_problem(uri.path()))?;
    Ok(Json(
        LinkResponse::from_link(updated.link, &state.config).with_warning(updated.warning),
    ))
}

#[utoipa::path(
    delete,
    path = "/_/api/v1/links/{id}",
    tag = "links",
    security(("bearerAuth" = [])),
    params(("id" = i64, Path, description = "The Link id.")),
    responses(
        (status = 204, description = "The Link was hard-deleted with its Clicks, and its Slug was released."),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The Link belongs to another User and the caller is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such Link.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_link(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(link_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    links::delete_link(
        &state.db,
        link_id,
        user.user.id,
        user.user.role == Role::Admin,
    )
    .await
    .map_err(|error| error.into_problem(uri.path()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClickResponse {
    pub id: i64,
    pub clicked_at: String,
    pub ip: String,
    pub user_agent: String,
    pub referer: Option<String>,
    /// One of `desktop`, `mobile`, `tablet`, `bot`, or `unknown`.
    pub device: String,
    /// Whether the User-Agent matched a known crawler pattern. Bot Clicks are
    /// stored and listed but excluded from human counts.
    pub is_bot: bool,
}

impl From<analytics::Click> for ClickResponse {
    fn from(click: analytics::Click) -> Self {
        Self {
            id: click.id,
            clicked_at: click.clicked_at,
            ip: click.ip,
            user_agent: click.user_agent,
            referer: click.referer,
            device: click.device,
            is_bot: click.is_bot,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClickListResponse {
    pub items: Vec<ClickResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListClicksQuery {
    /// Include Clicks at or after this RFC 3339 UTC timestamp.
    pub from: Option<String>,
    /// Include Clicks at or before this RFC 3339 UTC timestamp.
    pub to: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn parse_time_bound(
    value: Option<&str>,
    field: &str,
    instance: &str,
) -> Result<Option<OffsetDateTime>, ProblemDetails> {
    value
        .map(|value| {
            timeutil::parse_rfc3339(value).map_err(|_| {
                ProblemDetails::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "invalid_time_range",
                    "Unprocessable Entity",
                    format!("{field} must be an RFC 3339 timestamp."),
                    instance,
                )
            })
        })
        .transpose()
}

/// Translate a Link lookup into the API's read permission rule: an unknown
/// Link is 404, and another User's Link is 403 unless the caller is an Admin.
async fn ensure_link_readable(
    state: &AppState,
    user: &CurrentUser,
    link_id: i64,
    instance: &str,
) -> Result<(), ProblemDetails> {
    let Some(link) = links::find_by_id(&state.db, link_id)
        .await
        .map_err(|error| error.into_problem(instance))?
    else {
        return Err(ProblemDetails::not_found("Link not found.", instance));
    };
    if link.owner_id != user.user.id && user.user.role != Role::Admin {
        return Err(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
            "You do not have permission to read this Link.",
            instance,
        ));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/_/api/v1/links/{id}/clicks",
    tag = "analytics",
    security(("bearerAuth" = [])),
    params(
        ("id" = i64, Path, description = "The Link id."),
        ("from" = Option<String>, Query, description = "Include Clicks at or after this RFC 3339 UTC timestamp. Unbounded when omitted."),
        ("to" = Option<String>, Query, description = "Include Clicks at or before this RFC 3339 UTC timestamp. Unbounded when omitted."),
        ("limit" = Option<i64>, Query, description = "Maximum number of Clicks to return (default 20, maximum 100)."),
        ("offset" = Option<i64>, Query, description = "Number of Clicks to skip.")
    ),
    responses(
        (status = 200, description = "The Link's Clicks, newest first.", body = ClickListResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The Link belongs to another User and the caller is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such Link.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid pagination or time range parameters.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_link_clicks(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
    query: Result<Query<ListClicksQuery>, QueryRejection>,
) -> Result<Json<ClickListResponse>, ProblemDetails> {
    let Path(link_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let query = query.map_err(|rejection| pagination_problem(rejection, uri.path()))?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, uri.path())?;
    ensure_link_readable(&state, &user, link_id, uri.path()).await?;
    let range = TimeRange {
        from: parse_time_bound(query.from.as_deref(), "from", uri.path())?,
        to: parse_time_bound(query.to.as_deref(), "to", uri.path())?,
    };
    let (clicks, total) = analytics::list_clicks(&state.db, link_id, range, limit, offset)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok(Json(ClickListResponse {
        items: clicks.into_iter().map(ClickResponse::from).collect(),
        total,
        limit,
        offset,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DayCount {
    /// The UTC calendar date, as `YYYY-MM-DD`.
    pub date: String,
    pub total_clicks: i64,
    pub human_clicks: i64,
    pub bot_clicks: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LinkStatsResponse {
    pub total_clicks: i64,
    /// Clicks whose User-Agent did not match a crawler pattern.
    pub human_clicks: i64,
    /// Clicks whose User-Agent matched a crawler pattern.
    pub bot_clicks: i64,
    /// Clicks by device, including bot-device Clicks.
    pub by_device: BTreeMap<String, i64>,
    /// Clicks by UTC calendar day, oldest first. Only days with Clicks appear.
    pub by_day: Vec<DayCount>,
}

impl From<analytics::ClickStats> for LinkStatsResponse {
    fn from(stats: analytics::ClickStats) -> Self {
        Self {
            total_clicks: stats.total_clicks,
            human_clicks: stats.human_clicks,
            bot_clicks: stats.bot_clicks,
            by_device: stats.by_device,
            by_day: stats
                .by_day
                .into_iter()
                .map(|day| DayCount {
                    date: day.date,
                    total_clicks: day.total_clicks,
                    human_clicks: day.human_clicks,
                    bot_clicks: day.bot_clicks,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LinkStatsQuery {
    /// Include Clicks at or after this RFC 3339 UTC timestamp.
    pub from: Option<String>,
    /// Include Clicks at or before this RFC 3339 UTC timestamp.
    pub to: Option<String>,
    /// Bucket size. Only `day` is supported.
    pub interval: Option<String>,
}

/// Today the only supported bucket size is `day`; T10 keeps this shape while
/// switching the bucket boundary to the Instance timezone.
fn parse_stats_interval(value: Option<&str>, instance: &str) -> Result<(), ProblemDetails> {
    match value {
        None | Some("day") => Ok(()),
        Some(_) => Err(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_interval",
            "Unprocessable Entity",
            "interval must be 'day'.",
            instance,
        )),
    }
}

#[utoipa::path(
    get,
    path = "/_/api/v1/links/{id}/stats",
    tag = "analytics",
    security(("bearerAuth" = [])),
    params(
        ("id" = i64, Path, description = "The Link id."),
        ("from" = Option<String>, Query, description = "Include Clicks at or after this RFC 3339 UTC timestamp. Unbounded when omitted."),
        ("to" = Option<String>, Query, description = "Include Clicks at or before this RFC 3339 UTC timestamp. Unbounded when omitted."),
        ("interval" = Option<String>, Query, description = "Bucket size: `day` (the default).")
    ),
    responses(
        (status = 200, description = "Total, human, and bot Click counts with by-device and by-day buckets.", body = LinkStatsResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The Link belongs to another User and the caller is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such Link.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid time range or interval parameters.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn link_stats(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
    query: Result<Query<LinkStatsQuery>, QueryRejection>,
) -> Result<Json<LinkStatsResponse>, ProblemDetails> {
    let Path(link_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let query = query.map_err(|rejection| pagination_problem(rejection, uri.path()))?;
    parse_stats_interval(query.interval.as_deref(), uri.path())?;
    ensure_link_readable(&state, &user, link_id, uri.path()).await?;
    let range = TimeRange {
        from: parse_time_bound(query.from.as_deref(), "from", uri.path())?,
        to: parse_time_bound(query.to.as_deref(), "to", uri.path())?,
    };
    let stats = analytics::click_stats(&state.db, link_id, range)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok(Json(LinkStatsResponse::from(stats)))
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
async fn list_tokens(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<TokenListResponse>, ProblemDetails> {
    let query = query.map_err(|rejection| pagination_problem(rejection, uri.path()))?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, uri.path())?;
    let (items, total) = tokens::list_tokens(&state.db, user.user.id, limit, offset)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
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
async fn create_token(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CreatedTokenResponse>), ProblemDetails> {
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    let created = tokens::create_token(
        &state.db,
        user.user.id,
        &payload.name,
        payload.expires_at.as_deref(),
    )
    .await
    .map_err(|error| error.into_problem(uri.path()))?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedTokenResponse::from(created)),
    ))
}

fn path_rejection_problem(rejection: PathRejection, instance: &str) -> ProblemDetails {
    let status = rejection.status();
    let title = status.canonical_reason().unwrap_or("Bad Request");
    ProblemDetails::new(
        status,
        "invalid_path",
        title,
        rejection.body_text(),
        instance,
    )
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
async fn revoke_token(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(token_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    tokens::revoke_token(&state.db, user.user.id, token_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok(StatusCode::NO_CONTENT)
}

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
async fn list_invites(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<InviteListResponse>, ProblemDetails> {
    let query = query.map_err(|rejection| pagination_problem(rejection, uri.path()))?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, uri.path())?;
    let (items, total) = invites::list_invites(&state.db, limit, offset)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
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
async fn create_invite(
    State(state): State<AppState>,
    admin: AdminUser,
    uri: Uri,
) -> Result<(StatusCode, Json<CreatedInviteResponse>), ProblemDetails> {
    let created = invites::create_invite(&state.db, admin.current.user.id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
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
async fn revoke_invite(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(invite_id) =
        path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    invites::revoke_invite(&state.db, invite_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
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
async fn validate_invite(
    State(state): State<AppState>,
    uri: Uri,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<InviteValidationResponse>, ProblemDetails> {
    let Path(token) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let validation = invites::validate_invite(&state.db, &token)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
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
async fn accept_invite(
    State(state): State<AppState>,
    uri: Uri,
    path: Result<Path<String>, PathRejection>,
    payload: Result<Json<AcceptInviteRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<UserProfile>), ProblemDetails> {
    let Path(token) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
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
    .map_err(|error| error.into_problem(uri.path()))?;
    Ok((StatusCode::CREATED, Json(UserProfile::from(user))))
}

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
async fn create_password_reset(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: Uri,
    path: Result<Path<i64>, PathRejection>,
) -> Result<(StatusCode, Json<CreatedPasswordResetResponse>), ProblemDetails> {
    let Path(user_id) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let created = password_resets::create_password_reset(&state.db, user_id)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedPasswordResetResponse::from(created)),
    ))
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
async fn validate_password_reset(
    State(state): State<AppState>,
    uri: Uri,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<PasswordResetValidationResponse>, ProblemDetails> {
    let Path(token) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let validation = password_resets::validate_password_reset(&state.db, &token)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok(Json(PasswordResetValidationResponse {
        status: validation.status.as_str().to_string(),
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
async fn accept_password_reset(
    State(state): State<AppState>,
    uri: Uri,
    path: Result<Path<String>, PathRejection>,
    payload: Result<Json<AcceptPasswordResetRequest>, JsonRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(token) = path.map_err(|rejection| path_rejection_problem(rejection, uri.path()))?;
    let Json(payload) =
        payload.map_err(|rejection| json_rejection_problem(rejection, uri.path()))?;
    password_resets::accept_password_reset(&state.db, &token, &payload.password)
        .await
        .map_err(|error| error.into_problem(uri.path()))?;
    Ok(StatusCode::NO_CONTENT)
}
