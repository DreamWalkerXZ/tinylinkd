use askama::Template;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

#[derive(Template)]
#[template(path = "not_found.html")]
struct NotFoundTemplate<'a> {
    slug: &'a str,
}

#[derive(Template)]
#[template(path = "password_form.html")]
struct PasswordFormTemplate<'a> {
    slug: &'a str,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "expired.html")]
struct ExpiredTemplate<'a> {
    slug: &'a str,
}

/// Render the public "link not found" page with a 404 status.
pub fn not_found(slug: &str) -> Response {
    match (NotFoundTemplate { slug }).render() {
        Ok(html) => html_response(StatusCode::NOT_FOUND, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the not-found page");
            (StatusCode::NOT_FOUND, "Not Found").into_response()
        }
    }
}

/// Render the public "link expired" page with a 410 status.
pub fn expired(slug: &str) -> Response {
    match (ExpiredTemplate { slug }).render() {
        Ok(html) => html_response(StatusCode::GONE, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the expired page");
            (StatusCode::GONE, "Link expired").into_response()
        }
    }
}

/// Render the public password form. Callers choose the status: 200 for the
/// initial form, 401 after a wrong password, or 429 when rate-limited.
pub fn password_form(status: StatusCode, slug: &str, error: Option<&str>) -> Response {
    match (PasswordFormTemplate { slug, error }).render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the password form");
            (status, "Password required").into_response()
        }
    }
}

fn html_response(status: StatusCode, html: String) -> Response {
    let mut response = (status, Html(html)).into_response();
    let headers = response.headers_mut();
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
    response
}
