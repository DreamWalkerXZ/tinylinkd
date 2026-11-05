use askama::Template;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

#[derive(Template)]
#[template(path = "not_found.html")]
struct NotFoundTemplate<'a> {
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
