use axum::http::{HeaderMap, HeaderValue, header};

/// Add the security headers carried by every server-rendered HTML response.
pub(crate) fn add_html_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'"),
    );
    add_nosniff(headers);
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// Add `X-Content-Type-Options: nosniff` to a JSON or Problem Details
/// response so browsers never reinterpret its content type.
pub(crate) fn add_nosniff(headers: &mut HeaderMap) {
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}
