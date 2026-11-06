use askama::Template;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::AppState;
use crate::sessions;
use crate::settings;
use crate::users::{self, Role};

pub(super) use crate::security_headers::html_response;

const ADMIN_CSS: &str = include_str!("../../templates/admin.css");

/// The number of rows shown on each Admin list page.
pub(super) const UI_PAGE_LIMIT: i64 = 50;

/// The bound used when loading Users for a `<select>` option list. Owner and
/// invite forms need every User, and this is far above any realistic Instance
/// size.
pub(super) const USER_OPTIONS_LIMIT: i64 = 10_000;

#[derive(Debug, Clone)]
pub(super) struct Nav<'a> {
    pub(super) instance_name: &'a str,
    pub(super) username: &'a str,
    pub(super) is_admin: bool,
    pub(super) csrf_token: &'a str,
}

impl<'a> Nav<'a> {
    pub(super) fn new(
        instance_name: &'a str,
        session: &'a sessions::Session,
        user: &'a users::User,
    ) -> Self {
        Self {
            instance_name,
            username: &user.username,
            is_admin: user.role == Role::Admin,
            csrf_token: &session.csrf_token,
        }
    }
}

/// A pagination query shared by the Admin list pages.
#[derive(Debug, Deserialize)]
pub(super) struct PageQuery {
    pub(super) page: Option<i64>,
}

/// A 303 redirect to a fixed admin UI path.
pub(super) fn see_other(location: &'static str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(location));
    response
}

/// Load the Instance settings or render the shared internal error page.
///
/// The caller returns the error response unchanged when settings cannot be
/// loaded, so every admin page fails the same way.
pub(super) async fn load_settings_or_error(
    state: &AppState,
) -> Result<settings::InstanceSettings, Response> {
    match settings::load(&state.db).await {
        Ok(settings) => Ok(settings),
        Err(error) => {
            tracing::error!(error = %error, "failed to load Instance settings");
            Err(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            ))
        }
    }
}

pub(super) async fn admin_css() -> Response {
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        ADMIN_CSS,
    )
        .into_response();
    crate::security_headers::add_html_security_headers(response.headers_mut());
    response
}

#[derive(Template)]
#[template(path = "admin_error.html")]
struct ErrorTemplate<'a> {
    title: &'a str,
    message: &'a str,
}

pub(super) fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    match (ErrorTemplate { title, message }).render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render an error page");
            (status, title.to_string()).into_response()
        }
    }
}
