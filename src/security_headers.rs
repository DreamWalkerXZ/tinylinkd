use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

/// Render an HTML page with the security headers required for server-rendered
/// pages.
pub(crate) fn html_response(status: StatusCode, html: String) -> Response {
    let mut response = (status, Html(html)).into_response();
    add_html_security_headers(response.headers_mut());
    response
}

/// Add the security headers that are specific to server-rendered HTML
/// responses. `X-Content-Type-Options: nosniff` is added to every response by
/// the router-level middleware, so it is not duplicated here.
pub(crate) fn add_html_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// Add `X-Content-Type-Options: nosniff` so browsers never reinterpret a
/// response's content type.
pub(crate) fn add_nosniff(headers: &mut HeaderMap) {
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}
