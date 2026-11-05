use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::OpenApi as _;
use utoipa::ToSchema;

use crate::app::AppState;
use crate::auth::{AdminUser, CurrentUser};
use crate::invites;
use crate::password_resets;
use crate::problems::ProblemDetails;
use crate::tokens;

pub const DEFAULT_PAGE_LIMIT: i64 = 20;
pub const MAX_PAGE_LIMIT: i64 = 100;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/_/api/v1/me", get(me))
        .route("/_/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/_/api/v1/tokens/{id}", delete(revoke_token))
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
        accept_password_reset
    ),
    components(schemas(
        UserProfile,
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
    query: Query<Pagination>,
    instance: &str,
) -> Result<(i64, i64), ProblemDetails> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let offset = query.offset.unwrap_or(0);
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
    let (limit, offset) = resolve_pagination(query, uri.path())?;
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
    let (limit, offset) = resolve_pagination(query, uri.path())?;
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
