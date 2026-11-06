use std::collections::BTreeMap;

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::analytics::{self, TimeRange};
use crate::app::{AppConfig, AppState};
use crate::auth::CurrentUser;
use crate::links::{self, LinkStatus};
use crate::problems::ProblemDetails;
use crate::settings;
use crate::timeutil;

use super::{ApiPath, ProblemContext, deserialize_optional_field, resolve_pagination};

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLinkRequest {
    /// The absolute `http` or `https` URL the Link redirects to.
    pub destination_url: String,
    /// An optional custom Slug. An 8-character random Slug is generated when omitted.
    pub slug: Option<String>,
    /// An optional password visitors must enter before the Link redirects.
    pub password: Option<String>,
    /// An optional RFC 3339 expiry. Stored in UTC.
    pub expires_at: Option<String>,
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
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    #[schema(value_type = Option<String>)]
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
            short_url: config.absolute_short_url(&link.slug),
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
pub(super) async fn create_link(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    payload: Result<Json<CreateLinkRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<LinkResponse>), ProblemDetails> {
    let Json(payload) = payload.problem(&uri)?;
    if let Some(retry_after) = state.link_create_limiter.check_and_record(&user.id()) {
        return Err(ProblemDetails::rate_limited(
            "The Link creation rate limit has been exceeded.",
            &uri,
            retry_after,
        ));
    }
    let link = links::create_link_with(
        &state.db,
        links::NewLink {
            owner_id: user.id(),
            destination_url: &payload.destination_url,
            slug: payload.slug.as_deref(),
            password: payload.password.as_deref(),
            expires_at: payload.expires_at.as_deref(),
        },
    )
    .await
    .problem(&uri)?;
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
pub(super) async fn list_links(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    query: Result<Query<ListLinksQuery>, QueryRejection>,
) -> Result<Json<LinkListResponse>, ProblemDetails> {
    let query = query.problem(&uri)?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, &uri)?;
    let is_admin = user.is_admin();
    if query.owner_id.is_some() && !is_admin {
        return Err(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
            "Only Admins may filter Links by owner_id.",
            uri.as_str(),
        ));
    }
    let filter = links::LinkFilter {
        owner_id: if is_admin {
            query.owner_id
        } else {
            Some(user.id())
        },
        status: parse_link_status(query.status.as_deref(), &uri)?,
        q: query.q.clone(),
        sort: parse_link_sort(query.sort.as_deref(), &uri)?,
        limit,
        offset,
    };
    let (links, total) = links::list_links(&state.db, &filter).await.problem(&uri)?;
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
pub(super) async fn get_link(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
) -> Result<Json<LinkResponse>, ProblemDetails> {
    let Path(link_id) = path.problem(&uri)?;
    let Some(link) = links::find_by_id(&state.db, link_id).await.problem(&uri)? else {
        return Err(ProblemDetails::not_found("Link not found.", &uri));
    };
    if !links::can_manage(&link, user.id(), user.is_admin()) {
        return Err(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
            "You do not have permission to read this Link.",
            uri.as_str(),
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
pub(super) async fn update_link(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
    payload: Result<Json<UpdateLinkRequest>, JsonRejection>,
) -> Result<Json<LinkResponse>, ProblemDetails> {
    let Path(link_id) = path.problem(&uri)?;
    let Json(payload) = payload.problem(&uri)?;
    let updated = links::update_link(
        &state.db,
        link_id,
        user.id(),
        user.is_admin(),
        links::LinkChanges {
            destination_url: payload.destination_url,
            slug: payload.slug,
            owner_id: payload.owner_id,
            password: payload.password,
            expires_at: payload.expires_at,
        },
    )
    .await
    .problem(&uri)?;
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
pub(super) async fn delete_link(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ProblemDetails> {
    let Path(link_id) = path.problem(&uri)?;
    links::delete_link(&state.db, link_id, user.id(), user.is_admin())
        .await
        .problem(&uri)?;
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
    if !links::can_manage(&link, user.id(), user.is_admin()) {
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
pub(super) async fn list_link_clicks(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
    query: Result<Query<ListClicksQuery>, QueryRejection>,
) -> Result<Json<ClickListResponse>, ProblemDetails> {
    let Path(link_id) = path.problem(&uri)?;
    let query = query.problem(&uri)?;
    let (limit, offset) = resolve_pagination(query.limit, query.offset, &uri)?;
    ensure_link_readable(&state, &user, link_id, &uri).await?;
    let range = TimeRange {
        from: parse_time_bound(query.from.as_deref(), "from", &uri)?,
        to: parse_time_bound(query.to.as_deref(), "to", &uri)?,
    };
    let (clicks, total) = analytics::list_clicks(&state.db, link_id, range, limit, offset)
        .await
        .problem(&uri)?;
    Ok(Json(ClickListResponse {
        items: clicks.into_iter().map(ClickResponse::from).collect(),
        total,
        limit,
        offset,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DayCount {
    /// The calendar date in the Instance timezone, as `YYYY-MM-DD`.
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
    /// Clicks by calendar day in the Instance timezone, oldest first. Only
    /// days with Clicks appear.
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
pub(super) async fn link_stats(
    State(state): State<AppState>,
    user: CurrentUser,
    uri: ApiPath,
    path: Result<Path<i64>, PathRejection>,
    query: Result<Query<LinkStatsQuery>, QueryRejection>,
) -> Result<Json<LinkStatsResponse>, ProblemDetails> {
    let Path(link_id) = path.problem(&uri)?;
    let query = query.problem(&uri)?;
    parse_stats_interval(query.interval.as_deref(), &uri)?;
    ensure_link_readable(&state, &user, link_id, &uri).await?;
    let range = TimeRange {
        from: parse_time_bound(query.from.as_deref(), "from", &uri)?,
        to: parse_time_bound(query.to.as_deref(), "to", &uri)?,
    };
    let instance_settings = settings::load(&state.db).await.problem(&uri)?;
    let stats = analytics::click_stats(&state.db, link_id, range, &instance_settings.timezone)
        .await
        .problem(&uri)?;
    Ok(Json(LinkStatsResponse::from(stats)))
}
