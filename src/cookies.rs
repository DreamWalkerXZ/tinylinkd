use axum::http::{HeaderMap, header};

/// Find a cookie value by name across every `Cookie` request header.
///
/// Browsers normally send one `Cookie` header, but HTTP permits several, so
/// all of them are scanned. Pair names and values are trimmed of the
/// optional whitespace around the `;` and `=` separators.
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key.trim() == name).then(|| value.to_string()))
}
