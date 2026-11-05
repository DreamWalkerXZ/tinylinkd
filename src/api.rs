use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::OpenApi as _;
use utoipa::ToSchema;

use crate::app::{AppConfig, AppState};
use crate::auth::{AdminUser, CurrentUser};
use crate::invites;
use crate::links::{self, LinkStatus};
use crate::password_resets;
use crate::problems::ProblemDetails;
use crate::tokens;
use crate::users::Role;

pub const DEFAULT_PAGE_LIMIT: i64 = 20;
pub const MAX_PAGE_LIMIT: i64 = 100;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/_/api/v1/me", get(me))
        .route("/_/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/_/api/v1/tokens/{id}", delete(revoke_token))
        .route("/_/api/v1/links", get(list_links).post(create_link))
        .route(
            "/_/api/v1/links/{id}",
            get(get_link).patch(update_link).delete(delete_link),
        )
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
        accept_password_reset,
        create_link,
        list_links,
        get_link,
        update_link,
        delete_link
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
        LinkResponse,
        LinkListResponse,
        LinkStatus,
        CreateLinkRequest,
        UpdateLinkRequest,
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateLinkRequest {
    /// The new absolute `http` or `https` URL the Link redirects to.
    pub destination_url: Option<String>,
    /// A new Slug. A Slug change returns a `warning` because the old short URL
    /// stops working immediately and may be reused by another Link.
    pub slug: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LinkResponse {
    pub id: i64,
    pub owner_id: i64,
    pub slug: String,
    pub short_url: String,
    pub destination_url: String,
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
        (status = 422, description = "The Destination URL or Slug is invalid.", body = ProblemDetails, content_type = "application/problem+json")
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
