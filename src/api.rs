use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::OpenApi as _;
use utoipa::ToSchema;

use crate::app::{AppConfig, AppState};
use crate::auth::CurrentUser;
use crate::links::{self, LinkStatus};
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
        .route("/_/api/v1/links/{id}", get(get_link))
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
        create_link,
        list_links,
        get_link
    ),
    components(schemas(
        UserProfile,
        TokenResponse,
        CreatedTokenResponse,
        TokenListResponse,
        CreateTokenRequest,
        Pagination,
        LinkResponse,
        LinkListResponse,
        LinkStatus,
        CreateLinkRequest,
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
        let user = current.user;
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLinkRequest {
    /// The absolute `http` or `https` URL the Link redirects to.
    pub destination_url: String,
    /// An optional custom Slug. An 8-character random Slug is generated when omitted.
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
        }
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

#[utoipa::path(
    get,
    path = "/_/api/v1/links",
    tag = "links",
    security(("bearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of Links to return (default 20, maximum 100)."),
        ("offset" = Option<i64>, Query, description = "Number of Links to skip.")
    ),
    responses(
        (status = 200, description = "The current User's Links.", body = LinkListResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid pagination parameters.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_links(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: Uri,
    query: Result<Query<Pagination>, QueryRejection>,
) -> Result<Json<LinkListResponse>, ProblemDetails> {
    let query = query.map_err(|rejection| pagination_problem(rejection, uri.path()))?;
    let (limit, offset) = resolve_pagination(query, uri.path())?;
    let (links, total) = links::list_links(&state.db, user.user.id, limit, offset)
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
