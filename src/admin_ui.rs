use askama::Template;
use axum::Form;
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use crate::analytics::{self, TimeRange};
use crate::app::AppState;
use crate::invites;
use crate::links;
use crate::redirect::{ClientIp, client_ip};
use crate::sessions;
use crate::settings;
use crate::users::{self, Role};

const ADMIN_CSS: &str = include_str!("../templates/admin.css");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/_/login", get(login_page).post(login))
        .route("/_/links", get(link_list).post(create_link))
        .route("/_/links/new", get(new_link_page))
        .route("/_/logout", axum::routing::post(logout))
        .route("/_/links/{id}", get(link_detail).post(update_link))
        .route("/_/links/{id}/edit", get(edit_link_page))
        .route("/_/links/{id}/delete", axum::routing::post(delete_link))
        .route("/_/users", get(users_page))
        .route("/_/users/{id}/disable", axum::routing::post(user_disable))
        .route("/_/users/{id}/enable", axum::routing::post(user_enable))
        .route("/_/users/{id}/delete", axum::routing::post(user_delete))
        .route("/_/invites", get(invites_page).post(invite_create))
        .route("/_/invites/{id}/revoke", axum::routing::post(invite_revoke))
        .route("/_/settings", get(settings_page).post(settings_update))
        .route("/_/static/admin.css", get(admin_css))
}

/// The User behind the browser session cookie. A missing, invalid, expired, or
/// revoked session redirects to the login page.
pub struct SessionUser {
    pub session: sessions::Session,
    pub user: users::User,
}

pub enum SessionRejection {
    Login,
    Forbidden,
    Internal,
}

impl IntoResponse for SessionRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Login => {
                let mut response = StatusCode::SEE_OTHER.into_response();
                response
                    .headers_mut()
                    .insert(header::LOCATION, HeaderValue::from_static("/_/login"));
                response
            }
            Self::Forbidden => error_page(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "You do not have permission to access this page.",
            ),
            Self::Internal => error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            ),
        }
    }
}

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = SessionRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = sessions::cookie_value(&parts.headers, sessions::SESSION_COOKIE_NAME)
        else {
            return Err(SessionRejection::Login);
        };
        match sessions::authenticate(&state.db, &token).await {
            Ok(Some((session, user))) => Ok(Self { session, user }),
            Ok(None) => Err(SessionRejection::Login),
            Err(error) => {
                tracing::error!(error = %error, "failed to authenticate a browser session");
                Err(SessionRejection::Internal)
            }
        }
    }
}

/// The Admin behind a browser session. A signed-in non-Admin gets 403; an
/// unauthenticated browser is redirected to the login page.
pub struct AdminUser(pub SessionUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = SessionRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session_user = SessionUser::from_request_parts(parts, state).await?;
        if session_user.user.role != Role::Admin {
            return Err(SessionRejection::Forbidden);
        }
        Ok(Self(session_user))
    }
}

#[derive(Debug, Clone)]
struct Nav<'a> {
    instance_name: &'a str,
    username: &'a str,
    is_admin: bool,
    csrf_token: &'a str,
}

impl<'a> Nav<'a> {
    fn new(instance_name: &'a str, session: &'a sessions::Session, user: &'a users::User) -> Self {
        Self {
            instance_name,
            username: &user.username,
            is_admin: user.role == Role::Admin,
            csrf_token: &session.csrf_token,
        }
    }
}

#[derive(Debug, Clone)]
struct LinkRow {
    id: i64,
    short_url: String,
    slug: String,
    destination_url: String,
    status: &'static str,
    has_password: bool,
    expires_at: Option<String>,
    total_clicks: i64,
    human_clicks: i64,
    bot_clicks: i64,
    owner: String,
}

impl LinkRow {
    fn new(link: links::Link, short_url: String, owner: String) -> Self {
        let status = match link.status() {
            links::LinkStatus::Active => "active",
            links::LinkStatus::Expired => "expired",
        };
        Self {
            id: link.id,
            short_url,
            slug: link.slug,
            destination_url: link.destination_url,
            status,
            has_password: link.has_password,
            expires_at: link.expires_at,
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
struct LinkListQuery {
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

const UI_PAGE_LIMIT: i64 = 50;

async fn link_list(
    State(state): State<AppState>,
    session_user: SessionUser,
    Query(query): Query<LinkListQuery>,
) -> Response {
    let instance_settings = match settings::load(&state.db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let is_admin = session_user.user.role == Role::Admin;
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
            Some(session_user.user.id)
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
            LinkRow::new(link, short_url, owner)
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
struct CreateLinkForm {
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

#[derive(Template)]
#[template(path = "admin_link_new.html")]
struct NewLinkTemplate<'a> {
    nav: Nav<'a>,
    csrf_token: &'a str,
    destination_url: &'a str,
    slug: &'a str,
    expires_at: &'a str,
    error: Option<&'a str>,
}

async fn new_link_page(State(state): State<AppState>, session_user: SessionUser) -> Response {
    let instance_settings = match settings::load(&state.db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
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
        error: None,
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

async fn create_link(
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
    let result = links::create_link_with(
        &state.db,
        links::NewLink {
            owner_id: session_user.user.id,
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
            let instance_settings = match settings::load(&state.db).await {
                Ok(settings) => settings,
                Err(settings_error) => {
                    tracing::error!(error = %settings_error, "failed to load Instance settings");
                    return error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        "An unexpected error occurred.",
                    );
                }
            };
            let message = error.to_string();
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
                error: Some(&message),
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
    timezone: &'a str,
    warning: Option<&'a str>,
    csrf_token: &'a str,
}

async fn link_detail(
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
    let is_admin = session_user.user.role == Role::Admin;
    if link.owner_id != session_user.user.id && !is_admin {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "You do not have permission to view this Link.",
        );
    }
    let instance_settings = match settings::load(&state.db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
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
    let short_url = state.config.short_url(&link.slug);
    let template = LinkDetailTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        link: LinkRow::new(link, short_url, owner),
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
struct EditLinkForm {
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
    error: Option<&'a str>,
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

async fn edit_link_page(
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
    if !can_manage(&session_user, &link) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "You do not have permission to edit this Link.",
        );
    }
    let instance_settings = match settings::load(&state.db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let is_admin = session_user.user.role == Role::Admin;
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
        error: None,
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

async fn update_link(
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
    if !can_manage(&session_user, &link) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "You do not have permission to edit this Link.",
        );
    }
    let result = links::update_link(
        &state.db,
        link_id,
        session_user.user.id,
        session_user.user.role == Role::Admin,
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
            let instance_settings = match settings::load(&state.db).await {
                Ok(settings) => settings,
                Err(settings_error) => {
                    tracing::error!(error = %settings_error, "failed to load Instance settings");
                    return error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        "An unexpected error occurred.",
                    );
                }
            };
            let message = error.to_string();
            let is_admin = session_user.user.role == Role::Admin;
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
                error: Some(&message),
            };
            render_edit_link(&template, status)
        }
    }
}

/// Whether the session User owns this Link or is an Admin.
fn can_manage(session_user: &SessionUser, link: &links::Link) -> bool {
    link.owner_id == session_user.user.id || session_user.user.role == Role::Admin
}

#[derive(Debug, Deserialize)]
struct DeleteLinkForm {
    csrf_token: String,
    #[serde(default)]
    confirm: Option<String>,
}

async fn delete_link(
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
    if !can_manage(&session_user, &link) {
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
        session_user.user.id,
        session_user.user.role == Role::Admin,
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

/// A pagination query shared by the Admin list pages.
#[derive(Debug, Deserialize)]
struct PageQuery {
    page: Option<i64>,
}

/// A 303 redirect to a fixed admin UI path.
fn see_other(location: &'static str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(location));
    response
}

#[derive(Debug, Clone)]
struct UserRow {
    id: i64,
    username: String,
    email: Option<String>,
    role: &'static str,
    disabled: bool,
    disabled_at: Option<String>,
    created_at: String,
    updated_at: String,
    link_count: i64,
}

#[derive(Template)]
#[template(path = "admin_users.html")]
struct UsersTemplate<'a> {
    nav: Nav<'a>,
    users: Vec<UserRow>,
    total: i64,
    page: i64,
    has_previous: bool,
    has_next: bool,
    error: Option<&'a str>,
    csrf_token: &'a str,
}

async fn users_page(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Query(query): Query<PageQuery>,
) -> Response {
    render_users(
        &state,
        &session_user,
        query.page.unwrap_or(1).max(1),
        None,
        StatusCode::OK,
    )
    .await
}

async fn render_users(
    state: &AppState,
    session_user: &SessionUser,
    page: i64,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let instance_settings = match settings::load(&state.db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let offset = (page - 1).saturating_mul(UI_PAGE_LIMIT);
    let (found, total) = match users::list_users(&state.db, UI_PAGE_LIMIT, offset).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(error = %error, "failed to list Users");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let counts = match link_counts(&state.db).await {
        Ok(counts) => counts,
        Err(error) => {
            tracing::error!(error = %error, "failed to count the Links owned by each User");
            std::collections::HashMap::new()
        }
    };
    let rows = found
        .into_iter()
        .map(|user| {
            let disabled = user.disabled_at.is_some();
            UserRow {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role.as_str(),
                disabled,
                disabled_at: user.disabled_at,
                created_at: user.created_at,
                updated_at: user.updated_at,
                link_count: counts.get(&user.id).copied().unwrap_or(0),
            }
        })
        .collect::<Vec<_>>();
    let template = UsersTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        users: rows,
        total,
        page,
        has_previous: page > 1,
        has_next: offset + UI_PAGE_LIMIT < total,
        error,
        csrf_token: &session_user.session.csrf_token,
    };
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the Users page");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

async fn link_counts(
    db: &crate::db::Database,
) -> Result<std::collections::HashMap<i64, i64>, sqlx::Error> {
    let rows: Vec<(i64, i64)> =
        sqlx::query_as("SELECT owner_id, COUNT(*) FROM links GROUP BY owner_id")
            .fetch_all(db.read_pool())
            .await?;
    Ok(rows.into_iter().collect())
}

async fn user_disable(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Path(user_id): Path<i64>,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    set_user_disabled(state, session_user, user_id, true, form).await
}

async fn user_enable(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Path(user_id): Path<i64>,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    set_user_disabled(state, session_user, user_id, false, form).await
}

async fn set_user_disabled(
    state: AppState,
    session_user: SessionUser,
    user_id: i64,
    disabled: bool,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    };
    if let Some(response) = require_csrf(&session_user.session, &form.csrf_token) {
        return response;
    }
    match users::update_user(
        &state.db,
        user_id,
        users::UserChanges {
            email: None,
            disabled: Some(disabled),
        },
    )
    .await
    {
        Ok(_) => see_other("/_/users"),
        Err(error) if error.status() == StatusCode::NOT_FOUND => error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The User does not exist.",
        ),
        Err(error) if error.status().is_client_error() => {
            let message = error.to_string();
            render_users(&state, &session_user, 1, Some(&message), error.status()).await
        }
        Err(error) => {
            tracing::error!(error = %error, user_id, "failed to change a User's disabled status");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeleteUserForm {
    csrf_token: String,
    #[serde(default)]
    confirm: Option<String>,
}

async fn user_delete(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Path(user_id): Path<i64>,
    form: Result<Form<DeleteUserForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    };
    if let Some(response) = require_csrf(&session_user.session, &form.csrf_token) {
        return response;
    }
    if form.confirm.is_none() {
        return error_page(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Confirmation required",
            "Confirm that you want to delete this User before submitting the form.",
        );
    }
    match users::delete_user(&state.db, user_id).await {
        Ok(()) => see_other("/_/users"),
        Err(error) if error.status() == StatusCode::NOT_FOUND => error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The User does not exist.",
        ),
        Err(error) if error.status().is_client_error() => {
            let message = error.to_string();
            render_users(&state, &session_user, 1, Some(&message), error.status()).await
        }
        Err(error) => {
            tracing::error!(error = %error, user_id, "failed to delete a User");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

#[derive(Debug, Clone)]
struct InviteRow {
    id: i64,
    status: &'static str,
    created_at: String,
    expires_at: String,
    used_at: Option<String>,
    revoked_at: Option<String>,
    created_by: String,
    can_revoke: bool,
}

/// The one-time Invite credential rendered immediately after creation. It is
/// held only for this response; the database stores just its hash.
#[derive(Debug, Clone)]
struct CreatedInviteView {
    token: String,
    expires_at: String,
}

#[derive(Template)]
#[template(path = "admin_invites.html")]
struct InvitesTemplate<'a> {
    nav: Nav<'a>,
    invites: Vec<InviteRow>,
    total: i64,
    page: i64,
    has_previous: bool,
    has_next: bool,
    created: Option<CreatedInviteView>,
    error: Option<&'a str>,
    csrf_token: &'a str,
}

async fn invites_page(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Query(query): Query<PageQuery>,
) -> Response {
    render_invites(
        &state,
        &session_user,
        query.page.unwrap_or(1).max(1),
        None,
        None,
        StatusCode::OK,
    )
    .await
}

async fn render_invites(
    state: &AppState,
    session_user: &SessionUser,
    page: i64,
    created: Option<CreatedInviteView>,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let instance_settings = match settings::load(&state.db).await {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let offset = (page - 1).saturating_mul(UI_PAGE_LIMIT);
    let (found, total) = match invites::list_invites(&state.db, UI_PAGE_LIMIT, offset).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(error = %error, "failed to list Invites");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let created_by: std::collections::HashMap<i64, String> =
        match users::list_users(&state.db, 10_000, 0).await {
            Ok((users, _)) => users
                .into_iter()
                .map(|user| (user.id, user.username))
                .collect(),
            Err(error) => {
                tracing::error!(error = %error, "failed to list Users for the Invite list");
                std::collections::HashMap::new()
            }
        };
    let rows = found
        .into_iter()
        .map(|invite| {
            let can_revoke = invite.used_at.is_none() && invite.revoked_at.is_none();
            InviteRow {
                id: invite.id,
                status: invite.status.as_str(),
                created_at: invite.created_at,
                expires_at: invite.expires_at,
                used_at: invite.used_at,
                revoked_at: invite.revoked_at,
                created_by: created_by
                    .get(&invite.created_by)
                    .cloned()
                    .unwrap_or_else(|| format!("User #{}", invite.created_by)),
                can_revoke,
            }
        })
        .collect::<Vec<_>>();
    let template = InvitesTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        invites: rows,
        total,
        page,
        has_previous: page > 1,
        has_next: offset + UI_PAGE_LIMIT < total,
        created,
        error,
        csrf_token: &session_user.session.csrf_token,
    };
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the Invites page");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

async fn invite_create(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    };
    if let Some(response) = require_csrf(&session_user.session, &form.csrf_token) {
        return response;
    }
    match invites::create_invite(&state.db, session_user.user.id).await {
        Ok(created) => {
            let view = CreatedInviteView {
                token: created.plaintext,
                expires_at: created.expires_at,
            };
            render_invites(
                &state,
                &session_user,
                1,
                Some(view),
                None,
                StatusCode::CREATED,
            )
            .await
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to create an Invite");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

async fn invite_revoke(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Path(invite_id): Path<i64>,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    };
    if let Some(response) = require_csrf(&session_user.session, &form.csrf_token) {
        return response;
    }
    match invites::revoke_invite(&state.db, invite_id).await {
        Ok(()) => see_other("/_/invites"),
        Err(error) if error.status() == StatusCode::NOT_FOUND => error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The Invite does not exist.",
        ),
        Err(error) if error.status().is_client_error() => {
            let message = error.to_string();
            render_invites(
                &state,
                &session_user,
                1,
                None,
                Some(&message),
                error.status(),
            )
            .await
        }
        Err(error) => {
            tracing::error!(error = %error, invite_id, "failed to revoke an Invite");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

/// The editable Instance settings as shown in the form. Values are kept as
/// submitted strings so an invalid entry can be redisplayed unchanged.
#[derive(Debug, Clone)]
struct SettingsFormValues {
    instance_name: String,
    timezone: String,
    click_retention_days: String,
    password_unlock_ttl_seconds: String,
}

impl SettingsFormValues {
    fn from_settings(settings: &settings::InstanceSettings) -> Self {
        Self {
            instance_name: settings.instance_name.clone(),
            timezone: settings.timezone.clone(),
            click_retention_days: settings.click_retention_days.to_string(),
            password_unlock_ttl_seconds: settings.password_unlock_ttl_seconds.to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "admin_settings.html")]
struct SettingsTemplate<'a> {
    nav: Nav<'a>,
    values: SettingsFormValues,
    error: Option<&'a str>,
    csrf_token: &'a str,
}

fn render_settings_page(
    session_user: &SessionUser,
    instance_name: &str,
    values: SettingsFormValues,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let template = SettingsTemplate {
        nav: Nav::new(instance_name, &session_user.session, &session_user.user),
        values,
        error,
        csrf_token: &session_user.session.csrf_token,
    };
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the Settings page");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

async fn render_settings_error(
    state: &AppState,
    session_user: &SessionUser,
    values: SettingsFormValues,
    message: String,
    status: StatusCode,
) -> Response {
    match settings::load(&state.db).await {
        Ok(current) => render_settings_page(
            session_user,
            &current.instance_name,
            values,
            Some(&message),
            status,
        ),
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

async fn settings_page(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
) -> Response {
    match settings::load(&state.db).await {
        Ok(current) => {
            let values = SettingsFormValues::from_settings(&current);
            render_settings_page(
                &session_user,
                &current.instance_name,
                values,
                None,
                StatusCode::OK,
            )
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
struct SettingsForm {
    csrf_token: String,
    instance_name: String,
    timezone: String,
    click_retention_days: String,
    password_unlock_ttl_seconds: String,
}

async fn settings_update(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    form: Result<Form<SettingsForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    };
    if let Some(response) = require_csrf(&session_user.session, &form.csrf_token) {
        return response;
    }
    let values = SettingsFormValues {
        instance_name: form.instance_name.clone(),
        timezone: form.timezone.clone(),
        click_retention_days: form.click_retention_days.clone(),
        password_unlock_ttl_seconds: form.password_unlock_ttl_seconds.clone(),
    };
    let click_retention_days = match form.click_retention_days.trim().parse::<i64>() {
        Ok(value) => value,
        Err(_) => {
            return render_settings_error(
                &state,
                &session_user,
                values,
                "click_retention_days must be a whole number of days.".to_string(),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    };
    let password_unlock_ttl_seconds = match form.password_unlock_ttl_seconds.trim().parse::<i64>() {
        Ok(value) => value,
        Err(_) => {
            return render_settings_error(
                &state,
                &session_user,
                values,
                "password_unlock_ttl_seconds must be a whole number of seconds.".to_string(),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    };
    let changes = settings::SettingsChanges {
        instance_name: Some(form.instance_name),
        timezone: Some(form.timezone),
        click_retention_days: Some(click_retention_days),
        password_unlock_ttl_seconds: Some(password_unlock_ttl_seconds),
    };
    match settings::update(&state.db, changes).await {
        Ok(_) => see_other("/_/settings"),
        Err(error) if error.status().is_client_error() => {
            let status = error.status();
            let message = error.to_string();
            render_settings_error(&state, &session_user, values, message, status).await
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to update Instance settings");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

/// The root path: send a signed-in browser to the Link list and everyone else
/// to the login page.
async fn root(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let authenticated = match sessions::cookie_value(&headers, sessions::SESSION_COOKIE_NAME) {
        Some(token) => matches!(sessions::authenticate(&state.db, &token).await, Ok(Some(_))),
        None => false,
    };
    let target = if authenticated {
        "/_/links"
    } else {
        "/_/login"
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(target));
    response
}

#[derive(Template)]
#[template(path = "admin_login.html")]
struct LoginTemplate<'a> {
    csrf_token: &'a str,
    username: &'a str,
    error: Option<&'a str>,
}

async fn login_page(State(state): State<AppState>) -> Response {
    let Ok(csrf_token) = sessions::generate_token() else {
        tracing::error!("failed to generate a login CSRF token");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let secure = state.config.base_url.scheme() == "https";
    let set_cookie = sessions::login_csrf_set_cookie(&csrf_token, secure);
    let template = LoginTemplate {
        csrf_token: &csrf_token,
        username: "",
        error: None,
    };
    let mut response = render_login(&template, StatusCode::OK);
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_cookie).expect("the login CSRF cookie is a valid header value"),
    );
    response
}

#[derive(Debug, Deserialize)]
struct CsrfForm {
    csrf_token: String,
}

/// Reject a state-changing form whose CSRF token does not match the session.
fn require_csrf(session: &sessions::Session, submitted: &str) -> Option<Response> {
    if session.csrf_matches(submitted) {
        None
    } else {
        Some(error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        ))
    }
}

async fn logout(
    State(state): State<AppState>,
    session_user: SessionUser,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    };
    if let Some(response) = require_csrf(&session_user.session, &form.csrf_token) {
        return response;
    }
    if let Err(error) = sessions::revoke(&state.db, session_user.session.id).await {
        tracing::error!(error = %error, "failed to revoke a browser session");
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "An unexpected error occurred.",
        );
    }
    let secure = state.config.base_url.scheme() == "https";
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/_/login"));
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&sessions::clear_session_cookie(secure))
            .expect("the cleared session cookie is a valid header value"),
    );
    response
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    client: ClientIp,
    form: Result<Form<LoginForm>, FormRejection>,
) -> Response {
    let Some(csrf_cookie) = sessions::cookie_value(&headers, sessions::LOGIN_CSRF_COOKIE_NAME)
    else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The login form is missing its CSRF token.",
        );
    };
    let Ok(Form(form)) = form else {
        return login_failure(
            &csrf_cookie,
            "",
            "Enter a username and password.",
            StatusCode::BAD_REQUEST,
        );
    };
    if !sessions::csrf_matches(&csrf_cookie, &form.csrf_token) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The login form's CSRF token is invalid.",
        );
    }

    let ip = client_ip(client.0, &headers, state.config.trust_proxy);
    if let Some(retry_after) = state.login_limiter.check(&ip) {
        return login_rate_limited(&csrf_cookie, retry_after);
    }

    let user = match users::authenticate(&state.db, &form.username, &form.password).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            state.login_limiter.record_failure(&ip);
            return login_failure(
                &csrf_cookie,
                &form.username,
                "Invalid username or password.",
                StatusCode::UNAUTHORIZED,
            );
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to authenticate a browser login");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };

    let previous_token = sessions::cookie_value(&headers, sessions::SESSION_COOKIE_NAME);
    let created =
        match sessions::create_session(&state.db, user.id, previous_token.as_deref()).await {
            Ok(created) => created,
            Err(error) => {
                tracing::error!(error = %error, "failed to create a browser session");
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "An unexpected error occurred.",
                );
            }
        };

    let secure = state.config.base_url.scheme() == "https";
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/_/links"));
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&sessions::session_set_cookie(&created.plaintext, secure))
            .expect("the session cookie is a valid header value"),
    );
    response
}

fn login_rate_limited(csrf_token: &str, retry_after: u64) -> Response {
    let mut response = login_failure(
        csrf_token,
        "",
        "Too many failed attempts. Try again later.",
        StatusCode::TOO_MANY_REQUESTS,
    );
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string())
            .expect("a seconds value is a valid header value"),
    );
    response
}

fn login_failure(csrf_token: &str, username: &str, message: &str, status: StatusCode) -> Response {
    let template = LoginTemplate {
        csrf_token,
        username,
        error: Some(message),
    };
    render_login(&template, status)
}

fn render_login(template: &LoginTemplate<'_>, status: StatusCode) -> Response {
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the login page");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        }
    }
}

async fn admin_css() -> Response {
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        ADMIN_CSS,
    )
        .into_response();
    add_security_headers(response.headers_mut());
    response
}

#[derive(Template)]
#[template(path = "admin_error.html")]
struct ErrorTemplate<'a> {
    title: &'a str,
    message: &'a str,
}

fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    match (ErrorTemplate { title, message }).render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render an error page");
            (status, title.to_string()).into_response()
        }
    }
}

/// Render an HTML page with the security headers required for the admin UI.
fn html_response(status: StatusCode, html: String) -> Response {
    let mut response = (status, Html(html)).into_response();
    add_security_headers(response.headers_mut());
    response
}

fn add_security_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}
