use askama::Template;
use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::analytics::{self, TimeRange};
use crate::app::AppState;
use crate::error::ApiError;
use crate::links;
use crate::problems::ProblemDetails;
use crate::timeutil;
use crate::users;

use super::auth::SessionUser;
use super::common::{Nav, UI_PAGE_LIMIT, error_page, html_response, load_settings_or_error};

#[derive(Debug, Clone)]
struct LinkRow {
    id: i64,
    short_url: String,
    slug: String,
    destination_url: String,
    status: &'static str,
    has_password: bool,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
    total_clicks: i64,
    human_clicks: i64,
    bot_clicks: i64,
    owner: String,
}

impl LinkRow {
    fn new(link: links::Link, short_url: String, owner: String, timezone: chrono_tz::Tz) -> Self {
        let status = match link.status() {
            links::LinkStatus::Active => "active",
            links::LinkStatus::Expired => "expired",
        };
        let expires_at = link
            .expires_at
            .as_deref()
            .map(|expires_at| timeutil::format_in_timezone(&timezone, expires_at));
        Self {
            id: link.id,
            short_url,
            slug: link.slug,
            destination_url: link.destination_url,
            status,
            has_password: link.has_password,
            expires_at,
            created_at: timeutil::format_in_timezone(&timezone, &link.created_at),
            updated_at: timeutil::format_in_timezone(&timezone, &link.updated_at),
            total_clicks: link.total_clicks,
            human_clicks: link.human_clicks,
            bot_clicks: link.bot_clicks,
            owner,
        }
    }
}

#[derive(Debug, Clone)]
struct OwnerOption {
    id: i64,
    username: String,
    selected: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct LinkListQuery {
    status: Option<String>,
    q: Option<String>,
    owner_id: Option<i64>,
    page: Option<i64>,
}

#[derive(Template)]
#[template(path = "admin_links.html")]
struct LinkListTemplate<'a> {
    nav: Nav<'a>,
    links: Vec<LinkRow>,
    total: i64,
    is_admin: bool,
    owners: Vec<OwnerOption>,
    status_filter: &'a str,
    q: &'a str,
    page: i64,
    has_previous: bool,
    has_next: bool,
}

pub(super) async fn link_list(
    State(state): State<AppState>,
    session_user: SessionUser,
    Query(query): Query<LinkListQuery>,
) -> Response {
    let instance_settings = match load_settings_or_error(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    let is_admin = session_user.is_admin();
    let owner_id = if is_admin { query.owner_id } else { None };
    let status = match query.status.as_deref() {
        Some("active") => Some(links::LinkStatus::Active),
        Some("expired") => Some(links::LinkStatus::Expired),
        _ => None,
    };
    let page = query.page.unwrap_or(1).max(1);
    let offset = (page - 1).saturating_mul(UI_PAGE_LIMIT);
    let filter = links::LinkFilter {
        owner_id: if is_admin {
            owner_id
        } else {
            Some(session_user.id())
        },
        status,
        q: query.q.clone().filter(|q| !q.trim().is_empty()),
        sort: links::LinkSort::CreatedAtDesc,
        limit: UI_PAGE_LIMIT,
        offset,
    };
    let (found, total) = match links::list_links(&state.db, &filter).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(error = %error, "failed to list Links");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let owners = if is_admin {
        match users::list_users(&state.db, 10_000, 0).await {
            Ok((users, _)) => users
                .into_iter()
                .map(|user| OwnerOption {
                    selected: owner_id == Some(user.id),
                    id: user.id,
                    username: user.username,
                })
                .collect(),
            Err(error) => {
                tracing::error!(error = %error, "failed to list Users for the owner filter");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let owner_names: std::collections::HashMap<i64, String> = owners
        .iter()
        .map(|owner| (owner.id, owner.username.clone()))
        .collect();
    let rows = found
        .into_iter()
        .map(|link| {
            let owner = if is_admin {
                owner_names
                    .get(&link.owner_id)
                    .cloned()
                    .unwrap_or_else(|| format!("User #{}", link.owner_id))
            } else {
                String::new()
            };
            let short_url = state.config.short_url(&link.slug);
            LinkRow::new(link, short_url, owner, instance_settings.timezone_tz())
        })
        .collect::<Vec<_>>();
    let template = LinkListTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        links: rows,
        total,
        is_admin,
        owners,
        status_filter: query.status.as_deref().unwrap_or(""),
        q: query.q.as_deref().unwrap_or(""),
        page,
        has_previous: page > 1,
        has_next: offset + UI_PAGE_LIMIT < total,
    };
    match template.render() {
        Ok(html) => html_response(StatusCode::OK, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the Link list");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateLinkForm {
    csrf_token: String,
    destination_url: String,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

impl CreateLinkForm {
    fn slug(&self) -> Option<&str> {
        self.slug
            .as_deref()
            .map(str::trim)
            .filter(|slug| !slug.is_empty())
    }

    fn password(&self) -> Option<&str> {
        self.password
            .as_deref()
            .filter(|password| !password.is_empty())
    }

    fn expires_at(&self) -> Option<&str> {
        self.expires_at
            .as_deref()
            .map(str::trim)
            .filter(|expires_at| !expires_at.is_empty())
    }
}

/// Validation messages for the Link forms, grouped by the field they belong
/// to. Anything unrecognized is shown as a general form error.
#[derive(Debug, Default)]
struct LinkFormErrors {
    destination_url: Option<String>,
    slug: Option<String>,
    password: Option<String>,
    expires_at: Option<String>,
    general: Option<String>,
}

impl LinkFormErrors {
    fn from_api_error(error: &ApiError) -> Self {
        let detail = error.to_string();
        let mut errors = Self::default();
        match error.code() {
            Some("invalid_destination_url") => errors.destination_url = Some(detail),
            Some("invalid_slug") | Some("slug_taken") => errors.slug = Some(detail),
            Some("invalid_password") => errors.password = Some(detail),
            Some("invalid_expires_at") => errors.expires_at = Some(detail),
            _ => errors.general = Some(detail),
        }
        errors
    }
}

#[derive(Template)]
#[template(path = "admin_link_new.html")]
struct NewLinkTemplate<'a> {
    nav: Nav<'a>,
    csrf_token: &'a str,
    destination_url: &'a str,
    slug: &'a str,
    expires_at: &'a str,
    errors: LinkFormErrors,
}

pub(super) async fn new_link_page(
    State(state): State<AppState>,
    session_user: SessionUser,
) -> Response {
    let instance_settings = match load_settings_or_error(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    let template = NewLinkTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        csrf_token: &session_user.session.csrf_token,
        destination_url: "",
        slug: "",
        expires_at: "",
        errors: LinkFormErrors::default(),
    };
    render_new_link(&template, StatusCode::OK)
}

fn render_new_link(template: &NewLinkTemplate<'_>, status: StatusCode) -> Response {
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the new Link form");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

pub(super) async fn create_link(
    State(state): State<AppState>,
    session_user: SessionUser,
    form: Result<Form<CreateLinkForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "The form could not be read.",
        );
    };
    if !session_user.session.csrf_matches(&form.csrf_token) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    }
    if let Some(retry_after) = state
        .link_create_limiter
        .check_and_record(&session_user.id())
    {
        return ProblemDetails::rate_limited(
            "The Link creation rate limit has been exceeded.",
            "/_/links",
            retry_after,
        )
        .into_response();
    }
    let result = links::create_link_with(
        &state.db,
        links::NewLink {
            owner_id: session_user.id(),
            destination_url: &form.destination_url,
            slug: form.slug(),
            password: form.password(),
            expires_at: form.expires_at(),
        },
    )
    .await;
    match result {
        Ok(link) => {
            let mut response = StatusCode::SEE_OTHER.into_response();
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&format!("/_/links/{}", link.id))
                    .expect("a Link id is a valid Location"),
            );
            response
        }
        Err(error) => {
            let status = error.status();
            if status.is_server_error() {
                tracing::error!(error = %error, "failed to create a Link");
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "An unexpected error occurred.",
                );
            }
            let instance_settings = match load_settings_or_error(&state).await {
                Ok(settings) => settings,
                Err(response) => return response,
            };
            let template = NewLinkTemplate {
                nav: Nav::new(
                    &instance_settings.instance_name,
                    &session_user.session,
                    &session_user.user,
                ),
                csrf_token: &session_user.session.csrf_token,
                destination_url: &form.destination_url,
                slug: form.slug.as_deref().unwrap_or(""),
                expires_at: form.expires_at.as_deref().unwrap_or(""),
                errors: LinkFormErrors::from_api_error(&error),
            };
            render_new_link(&template, status)
        }
    }
}

#[derive(Debug, Clone)]
struct DeviceRow {
    device: String,
    clicks: i64,
}

#[derive(Debug, Clone)]
struct DayRow {
    date: String,
    total_clicks: i64,
    human_clicks: i64,
    bot_clicks: i64,
}

#[derive(Debug, Clone)]
struct ClickRow {
    clicked_at: String,
    ip: String,
    device: String,
    user_agent: String,
    referer: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_link_detail.html")]
struct LinkDetailTemplate<'a> {
    nav: Nav<'a>,
    link: LinkRow,
    is_admin: bool,
    total_clicks: i64,
    human_clicks: i64,
    bot_clicks: i64,
    devices: Vec<DeviceRow>,
    days: Vec<DayRow>,
    clicks: Vec<ClickRow>,
    timezone: &'a str,
    warning: Option<&'a str>,
    csrf_token: &'a str,
}

pub(super) async fn link_detail(
    State(state): State<AppState>,
    session_user: SessionUser,
    Path(link_id): Path<i64>,
) -> Response {
    render_link_detail(state, session_user, link_id, None).await
}

async fn render_link_detail(
    state: AppState,
    session_user: SessionUser,
    link_id: i64,
    warning: Option<&str>,
) -> Response {
    let Some(link) = (match links::find_by_id(&state.db, link_id).await {
        Ok(link) => link,
        Err(error) => {
            tracing::error!(error = %error, link_id, "failed to read a Link");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    }) else {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The Link does not exist.",
        );
    };
    if !links::can_manage(&link, session_user.id(), session_user.is_admin()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "You do not have permission to view this Link.",
        );
    }
    let is_admin = session_user.is_admin();
    let instance_settings = match load_settings_or_error(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    let stats = match analytics::click_stats(
        &state.db,
        link_id,
        TimeRange::default(),
        &instance_settings.timezone,
    )
    .await
    {
        Ok(stats) => stats,
        Err(error) => {
            tracing::error!(error = %error, link_id, "failed to read Link statistics");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let owner = if is_admin {
        match users::find_by_id(&state.db, link.owner_id).await {
            Ok(Some(owner)) => owner.username,
            Ok(None) => format!("User #{}", link.owner_id),
            Err(error) => {
                tracing::error!(error = %error, "failed to read the Link owner");
                format!("User #{}", link.owner_id)
            }
        }
    } else {
        String::new()
    };
    let timezone = instance_settings.timezone_tz();
    let recent_clicks =
        match analytics::list_clicks(&state.db, link_id, TimeRange::default(), 20, 0).await {
            Ok((clicks, _)) => clicks
                .into_iter()
                .map(|click| ClickRow {
                    clicked_at: timeutil::format_in_timezone(&timezone, &click.clicked_at),
                    ip: click.ip,
                    device: click.device,
                    user_agent: click.user_agent,
                    referer: click.referer,
                })
                .collect(),
            Err(error) => {
                tracing::error!(error = %error, link_id, "failed to read recent Clicks");
                Vec::new()
            }
        };
    let short_url = state.config.short_url(&link.slug);
    let template = LinkDetailTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        link: LinkRow::new(link, short_url, owner, instance_settings.timezone_tz()),
        is_admin,
        total_clicks: stats.total_clicks,
        human_clicks: stats.human_clicks,
        bot_clicks: stats.bot_clicks,
        devices: stats
            .by_device
            .into_iter()
            .map(|(device, clicks)| DeviceRow { device, clicks })
            .collect(),
        days: stats
            .by_day
            .into_iter()
            .map(|day| DayRow {
                date: day.date,
                total_clicks: day.total_clicks,
                human_clicks: day.human_clicks,
                bot_clicks: day.bot_clicks,
            })
            .collect(),
        clicks: recent_clicks,
        timezone: &instance_settings.timezone,
        warning,
        csrf_token: &session_user.session.csrf_token,
    };
    match template.render() {
        Ok(html) => html_response(StatusCode::OK, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the Link detail page");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct EditLinkForm {
    csrf_token: String,
    destination_url: String,
    slug: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    remove_password: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    remove_expiry: Option<String>,
    #[serde(default)]
    owner_id: Option<i64>,
}

impl EditLinkForm {
    fn password_change(&self) -> Option<Option<String>> {
        if self.remove_password.is_some() {
            return Some(None);
        }
        self.password
            .as_deref()
            .filter(|password| !password.is_empty())
            .map(|password| Some(password.to_string()))
    }

    fn expiry_change(&self) -> Option<Option<String>> {
        if self.remove_expiry.is_some() {
            return Some(None);
        }
        self.expires_at
            .as_deref()
            .map(str::trim)
            .filter(|expires_at| !expires_at.is_empty())
            .map(|expires_at| Some(expires_at.to_string()))
    }
}

#[derive(Template)]
#[template(path = "admin_link_edit.html")]
struct EditLinkTemplate<'a> {
    nav: Nav<'a>,
    link_id: i64,
    csrf_token: &'a str,
    destination_url: &'a str,
    slug: &'a str,
    expires_at: &'a str,
    has_password: bool,
    is_admin: bool,
    owners: Vec<OwnerOption>,
    errors: LinkFormErrors,
}

/// The owner selector choices an Admin gets on the Link edit form.
async fn owner_options(
    db: &crate::db::Database,
    selected_id: i64,
) -> Result<Vec<OwnerOption>, crate::error::ApiError> {
    let (users, _) = users::list_users(db, 10_000, 0).await?;
    Ok(users
        .into_iter()
        .map(|user| OwnerOption {
            id: user.id,
            username: user.username,
            selected: user.id == selected_id,
        })
        .collect())
}

pub(super) async fn edit_link_page(
    State(state): State<AppState>,
    session_user: SessionUser,
    Path(link_id): Path<i64>,
) -> Response {
    let Some(link) = (match links::find_by_id(&state.db, link_id).await {
        Ok(link) => link,
        Err(error) => {
            tracing::error!(error = %error, link_id, "failed to read a Link");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    }) else {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The Link does not exist.",
        );
    };
    if !links::can_manage(&link, session_user.id(), session_user.is_admin()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "You do not have permission to edit this Link.",
        );
    }
    let instance_settings = match load_settings_or_error(&state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    let is_admin = session_user.is_admin();
    let owners = if is_admin {
        match owner_options(&state.db, link.owner_id).await {
            Ok(owners) => owners,
            Err(error) => {
                tracing::error!(error = %error, "failed to list Link owners");
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "An unexpected error occurred.",
                );
            }
        }
    } else {
        Vec::new()
    };
    let template = EditLinkTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        link_id,
        csrf_token: &session_user.session.csrf_token,
        destination_url: &link.destination_url,
        slug: &link.slug,
        expires_at: link.expires_at.as_deref().unwrap_or(""),
        has_password: link.has_password,
        is_admin,
        owners,
        errors: LinkFormErrors::default(),
    };
    render_edit_link(&template, StatusCode::OK)
}

fn render_edit_link(template: &EditLinkTemplate<'_>, status: StatusCode) -> Response {
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the edit Link form");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

pub(super) async fn update_link(
    State(state): State<AppState>,
    session_user: SessionUser,
    Path(link_id): Path<i64>,
    form: Result<Form<EditLinkForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "The form could not be read.",
        );
    };
    if !session_user.session.csrf_matches(&form.csrf_token) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    }
    let Some(link) = (match links::find_by_id(&state.db, link_id).await {
        Ok(link) => link,
        Err(error) => {
            tracing::error!(error = %error, link_id, "failed to read a Link");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    }) else {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The Link does not exist.",
        );
    };
    if !links::can_manage(&link, session_user.id(), session_user.is_admin()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "You do not have permission to edit this Link.",
        );
    }
    let result = links::update_link(
        &state.db,
        link_id,
        session_user.id(),
        session_user.is_admin(),
        links::LinkChanges {
            destination_url: Some(form.destination_url.clone()),
            slug: Some(form.slug.trim().to_string()),
            owner_id: form.owner_id,
            password: form.password_change(),
            expires_at: form.expiry_change(),
        },
    )
    .await;
    match result {
        Ok(updated) => {
            render_link_detail(
                state,
                session_user,
                updated.link.id,
                updated.warning.as_deref(),
            )
            .await
        }
        Err(error) => {
            let status = error.status();
            if status == StatusCode::NOT_FOUND {
                return error_page(
                    StatusCode::NOT_FOUND,
                    "Not Found",
                    "The Link does not exist.",
                );
            }
            if status.is_server_error() {
                tracing::error!(error = %error, "failed to update a Link");
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "An unexpected error occurred.",
                );
            }
            let instance_settings = match load_settings_or_error(&state).await {
                Ok(settings) => settings,
                Err(response) => return response,
            };
            let is_admin = session_user.is_admin();
            let owners = if is_admin {
                match owner_options(&state.db, form.owner_id.unwrap_or(link.owner_id)).await {
                    Ok(owners) => owners,
                    Err(owners_error) => {
                        tracing::error!(error = %owners_error, "failed to list Link owners");
                        return error_page(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Internal Server Error",
                            "An unexpected error occurred.",
                        );
                    }
                }
            } else {
                Vec::new()
            };
            let template = EditLinkTemplate {
                nav: Nav::new(
                    &instance_settings.instance_name,
                    &session_user.session,
                    &session_user.user,
                ),
                link_id,
                csrf_token: &session_user.session.csrf_token,
                destination_url: &form.destination_url,
                slug: &form.slug,
                expires_at: form.expires_at.as_deref().unwrap_or(""),
                has_password: link.has_password,
                is_admin,
                owners,
                errors: LinkFormErrors::from_api_error(&error),
            };
            render_edit_link(&template, status)
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteLinkForm {
    csrf_token: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub(super) async fn delete_link(
    State(state): State<AppState>,
    session_user: SessionUser,
    Path(link_id): Path<i64>,
    form: Result<Form<DeleteLinkForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "The form could not be read.",
        );
    };
    if !session_user.session.csrf_matches(&form.csrf_token) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    }
    let Some(link) = (match links::find_by_id(&state.db, link_id).await {
        Ok(link) => link,
        Err(error) => {
            tracing::error!(error = %error, link_id, "failed to read a Link");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    }) else {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The Link does not exist.",
        );
    };
    if !links::can_manage(&link, session_user.id(), session_user.is_admin()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "You do not have permission to delete this Link.",
        );
    }
    if form.confirm.is_none() {
        return error_page(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Confirmation required",
            "Confirm that you want to delete this Link before submitting the form.",
        );
    }
    if let Err(error) = links::delete_link(
        &state.db,
        link_id,
        session_user.id(),
        session_user.is_admin(),
    )
    .await
    {
        tracing::error!(error = %error, link_id, "failed to delete a Link");
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "An unexpected error occurred.",
        );
    }
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/_/links"));
    response
}
