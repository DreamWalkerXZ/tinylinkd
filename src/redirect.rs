use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use url::Url;

use crate::app::AppState;
use crate::links::{self, NewClick};
use crate::pages;

pub fn router() -> Router<AppState> {
    Router::new().route("/{slug}", get(redirect).head(redirect_head))
}

async fn redirect(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    client: ClientIp,
) -> Response {
    respond(state, slug, uri.query(), headers, client, true).await
}

async fn redirect_head(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    client: ClientIp,
) -> Response {
    respond(state, slug, uri.query(), headers, client, false).await
}

async fn respond(
    state: AppState,
    slug: String,
    query: Option<&str>,
    headers: HeaderMap,
    client: ClientIp,
    record_click: bool,
) -> Response {
    let link = match links::find_by_slug(&state.db, &slug).await {
        Ok(Some(link)) => link,
        Ok(None) => return pages::not_found(&slug),
        Err(error) => {
            tracing::error!(error = %error, slug = %slug, "failed to look up Link for redirect");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if record_click {
        let user_agent = header_value(&headers, header::USER_AGENT).unwrap_or_default();
        let (device, is_bot) = links::classify_user_agent(&user_agent);
        let click = NewClick {
            ip: client_ip(client.0, &headers, state.config.trust_proxy),
            user_agent,
            referer: header_value(&headers, header::REFERER),
            device,
            is_bot,
        };
        if let Err(error) = links::record_click(&state.db, link.id, click).await {
            tracing::warn!(
                error = %error,
                link_id = link.id,
                "failed to record Click for redirect"
            );
        }
    }

    let Some(location) = location_header(&link.destination_url, query) else {
        tracing::error!(
            link_id = link.id,
            "failed to build a Location header for the Destination URL"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let mut response = StatusCode::FOUND.into_response();
    let response_headers = response.headers_mut();
    response_headers.insert(header::LOCATION, location);
    response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn header_value(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn location_header(destination_url: &str, query: Option<&str>) -> Option<HeaderValue> {
    let target = links::redirect_target(destination_url, query);
    if let Ok(value) = HeaderValue::from_str(&target) {
        return Some(value);
    }

    // The Destination URL was validated when the Link was created, but it may
    // contain non-ASCII characters that a raw header value cannot. Fall back to
    // the URL parser's percent-encoded serialization.
    let mut url = Url::parse(destination_url).ok()?;
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        let combined = match url.query().filter(|existing| !existing.is_empty()) {
            Some(existing) => format!("{existing}&{query}"),
            None => query.to_string(),
        };
        url.set_query(Some(&combined));
    }
    HeaderValue::from_str(url.as_str()).ok()
}

/// The client IP for a request: the socket peer by default, or the first
/// address in `X-Forwarded-For` when proxy trust is enabled.
fn client_ip(peer: Option<SocketAddr>, headers: &HeaderMap, trust_proxy: bool) -> String {
    if trust_proxy {
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .and_then(|first| first.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip.to_string();
        }
    }
    peer.map(|peer| peer.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The socket peer address attached by `into_make_service_with_connect_info`,
/// or `None` when the router is called without connect info (for example in
/// `oneshot` tests that do not inject a peer).
pub struct ClientIp(Option<SocketAddr>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|connect_info| connect_info.0),
        ))
    }
}
