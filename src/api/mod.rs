mod auth;
mod invites;
mod links;
mod password_resets;
mod settings;
mod tokens;
mod users;

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::OpenApi as _;
use utoipa::ToSchema;

use crate::app::AppState;
use crate::error::ApiError;
use crate::links::LinkStatus;
use crate::problems::ProblemDetails;

pub const DEFAULT_PAGE_LIMIT: i64 = 20;
pub const MAX_PAGE_LIMIT: i64 = 100;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/_/api/v1/me",
            get(auth::me).patch(auth::update_me).delete(auth::delete_me),
        )
        .route("/_/api/v1/me/password", post(auth::change_password))
        .route("/_/api/v1/users", get(users::list_users))
        .route(
            "/_/api/v1/users/{id}",
            get(users::get_user)
                .patch(users::update_user)
                .delete(users::delete_user),
        )
        .route(
            "/_/api/v1/users/{id}/tokens",
            get(users::list_user_tokens).post(users::create_user_token),
        )
        .route(
            "/_/api/v1/users/{id}/tokens/{token_id}",
            delete(users::revoke_user_token),
        )
        .route(
            "/_/api/v1/tokens",
            get(tokens::list_tokens).post(tokens::create_token),
        )
        .route("/_/api/v1/tokens/{id}", delete(tokens::revoke_token))
        .route(
            "/_/api/v1/settings",
            get(settings::get_settings).patch(settings::update_settings),
        )
        .route(
            "/_/api/v1/links",
            get(links::list_links).post(links::create_link),
        )
        .route(
            "/_/api/v1/links/{id}",
            get(links::get_link)
                .patch(links::update_link)
                .delete(links::delete_link),
        )
        .route("/_/api/v1/links/{id}/clicks", get(links::list_link_clicks))
        .route("/_/api/v1/links/{id}/stats", get(links::link_stats))
        .route(
            "/_/api/v1/invites",
            get(invites::list_invites).post(invites::create_invite),
        )
        // Axum forbids two routes that differ only in the parameter name, so
        // the Admin revoke and public validate handlers share this route and
        // parse the segment according to the method.
        .route(
            "/_/api/v1/invites/{token}",
            get(invites::validate_invite).delete(invites::revoke_invite),
        )
        .route(
            "/_/api/v1/invites/{token}/accept",
            post(invites::accept_invite),
        )
        .route(
            "/_/api/v1/users/{id}/password-reset",
            post(password_resets::create_password_reset),
        )
        .route(
            "/_/api/v1/password-resets/{token}",
            // The Admin revoke handler shares this route with the public
            // validation handler and parses the segment as an id.
            get(password_resets::validate_password_reset)
                .delete(password_resets::revoke_password_reset),
        )
        .route(
            "/_/api/v1/password-resets/{token}/accept",
            post(password_resets::accept_password_reset),
        )
        .route("/_/api/openapi.json", get(openapi))
}

/// The request path, extracted once and used as the Problem Details
/// `instance`.
///
/// The `Deref` to `str` lets helpers that only need the path string borrow it
/// directly, and [`ProblemContext`] fills it into errors consistently.
#[derive(Debug, Clone)]
struct ApiPath(String);

impl ApiPath {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for ApiPath {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl<S> FromRequestParts<S> for ApiPath
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.uri.path().to_string()))
    }
}

/// Convert a fallible extractor or domain call into Problem Details, using
/// the request path as the `instance`.
trait ProblemContext<T> {
    fn problem(self, path: &ApiPath) -> Result<T, ProblemDetails>;
}

impl<T> ProblemContext<T> for Result<T, ApiError> {
    fn problem(self, path: &ApiPath) -> Result<T, ProblemDetails> {
        self.map_err(|error| error.into_problem(path.as_str()))
    }
}

impl<T> ProblemContext<T> for Result<T, JsonRejection> {
    fn problem(self, path: &ApiPath) -> Result<T, ProblemDetails> {
        self.map_err(|rejection| json_rejection_problem(rejection, path.as_str()))
    }
}

impl<T> ProblemContext<T> for Result<T, PathRejection> {
    fn problem(self, path: &ApiPath) -> Result<T, ProblemDetails> {
        self.map_err(|rejection| path_rejection_problem(rejection, path.as_str()))
    }
}

impl<T> ProblemContext<T> for Result<T, QueryRejection> {
    fn problem(self, path: &ApiPath) -> Result<T, ProblemDetails> {
        self.map_err(|rejection| pagination_problem(rejection, path.as_str()))
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "tinylinkd API",
        version = env!("CARGO_PKG_VERSION"),
        description = "The JSON API for a self-hosted tinylinkd Instance. Authenticate with a Bearer API token."
    ),
    paths(
        auth::me,
        auth::update_me,
        auth::change_password,
        auth::delete_me,
        users::list_users,
        users::get_user,
        users::update_user,
        users::delete_user,
        users::list_user_tokens,
        users::create_user_token,
        users::revoke_user_token,
        tokens::list_tokens,
        tokens::create_token,
        tokens::revoke_token,
        settings::get_settings,
        settings::update_settings,
        invites::list_invites,
        invites::create_invite,
        invites::revoke_invite,
        invites::validate_invite,
        invites::accept_invite,
        password_resets::create_password_reset,
        password_resets::revoke_password_reset,
        password_resets::validate_password_reset,
        password_resets::accept_password_reset,
        links::create_link,
        links::list_links,
        links::get_link,
        links::update_link,
        links::delete_link,
        links::list_link_clicks,
        links::link_stats
    ),
    components(schemas(
        auth::UserProfile,
        auth::UpdateProfileRequest,
        auth::ChangePasswordRequest,
        auth::DeleteAccountRequest,
        users::UserListResponse,
        users::UpdateUserRequest,
        tokens::TokenResponse,
        tokens::CreatedTokenResponse,
        tokens::TokenListResponse,
        tokens::CreateTokenRequest,
        settings::SettingsResponse,
        settings::UpdateSettingsRequest,
        invites::InviteResponse,
        invites::CreatedInviteResponse,
        invites::InviteListResponse,
        invites::InviteValidationResponse,
        invites::AcceptInviteRequest,
        password_resets::CreatedPasswordResetResponse,
        password_resets::PasswordResetValidationResponse,
        password_resets::AcceptPasswordResetRequest,
        Pagination,
        links::LinkResponse,
        links::LinkListResponse,
        LinkStatus,
        links::CreateLinkRequest,
        links::UpdateLinkRequest,
        links::ClickResponse,
        links::ClickListResponse,
        links::LinkStatsResponse,
        links::DayCount,
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

/// Distinguish an omitted field from an explicit `null` in a PATCH body.
fn deserialize_optional_field<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
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
