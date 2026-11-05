use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::Form;
use axum::Router;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::rejection::FormRejection;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use url::Url;

use crate::app::AppState;
use crate::auth;
use crate::links::{self, Link, NewClick};
use crate::pages;
use crate::secrets;
use crate::timeutil;
use crate::unlock;

pub fn router() -> Router<AppState> {
    Router::new().route("/{slug}", get(redirect).head(redirect_head).post(unlock))
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

    // Expiry is checked immediately after the Slug lookup and before the
    // password check, so an Expired Link reveals nothing about its password.
    if link.is_expired() {
        return pages::expired(&slug);
    }

    if link.has_password && !is_unlocked(&state, &link, &headers).await {
        return pages::password_form(StatusCode::OK, &slug, None);
    }

    redirect_to_destination(&state, &link, query, &headers, client.0, record_click).await
}

/// Whether the request carries a valid unlock cookie for this Link's current
/// password version.
async fn is_unlocked(state: &AppState, link: &Link, headers: &HeaderMap) -> bool {
    let Some(cookie) = unlock::cookie_from_headers(headers, link.id) else {
        return false;
    };
    let secret = match secrets::unlock_cookie_signing_key(&state.db).await {
        Ok(secret) => secret,
        Err(error) => {
            tracing::error!(
                error = %error,
                link_id = link.id,
                "failed to read the unlock signing key"
            );
            return false;
        }
    };
    unlock::cookie_is_valid(
        &secret,
        &cookie,
        link.id,
        link.password_version,
        timeutil::now(),
    )
}

async fn redirect_to_destination(
    state: &AppState,
    link: &Link,
    query: Option<&str>,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    record_click: bool,
) -> Response {
    if record_click {
        let user_agent = header_value(headers, header::USER_AGENT).unwrap_or_default();
        let (device, is_bot) = links::classify_user_agent(&user_agent);
        let click = NewClick {
            ip: client_ip(peer, headers, state.config.trust_proxy),
            user_agent,
            referer: header_value(headers, header::REFERER),
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

#[derive(Debug, Deserialize)]
struct PasswordForm {
    password: String,
}

/// Submit the public password form: a correct password sets the unlock cookie
/// and redirects to the short URL; a wrong one returns the form with 401.
async fn unlock(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    client: ClientIp,
    form: Result<Form<PasswordForm>, FormRejection>,
) -> Response {
    let link = match links::find_by_slug(&state.db, &slug).await {
        Ok(Some(link)) => link,
        Ok(None) => return pages::not_found(&slug),
        Err(error) => {
            tracing::error!(error = %error, slug = %slug, "failed to look up Link for password");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if link.is_expired() {
        return pages::expired(&slug);
    }

    if !link.has_password {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }

    let ip = client_ip(client.0, &headers, state.config.trust_proxy);
    if let Some(retry_after) = state.unlock_limiter.check(&ip, link.id) {
        let mut response = pages::password_form(
            StatusCode::TOO_MANY_REQUESTS,
            &slug,
            Some("Too many failed attempts. Try again later."),
        );
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&retry_after.to_string())
                .expect("a seconds value is a valid header value"),
        );
        return response;
    }

    let Ok(Form(form)) = form else {
        state.unlock_limiter.record_failure(&ip, link.id);
        return pages::password_form(
            StatusCode::UNAUTHORIZED,
            &slug,
            Some("Enter the Link password."),
        );
    };

    let password_hash = match links::find_password_hash(&state.db, link.id).await {
        Ok(Some(password_hash)) => password_hash,
        // The password was cleared between the lookup and verification.
        Ok(None) => return redirect_to_short_url(&slug),
        Err(error) => {
            tracing::error!(
                error = %error,
                link_id = link.id,
                "failed to read the Link password"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if !auth::verify_password(&form.password, &password_hash) {
        state.unlock_limiter.record_failure(&ip, link.id);
        return pages::password_form(
            StatusCode::UNAUTHORIZED,
            &slug,
            Some("Incorrect password. Please try again."),
        );
    }

    let secret = match secrets::unlock_cookie_signing_key(&state.db).await {
        Ok(secret) => secret,
        Err(error) => {
            tracing::error!(error = %error, link_id = link.id, "failed to read the unlock signing key");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let value = unlock::issue_cookie(&secret, link.id, link.password_version, timeutil::now());
    let secure = state.config.base_url.scheme() == "https";
    let set_cookie = unlock::set_cookie_header(link.id, &value, secure);

    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/{slug}")).expect("a Slug is a valid Location"),
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_cookie).expect("the unlock cookie is a valid header value"),
    );
    response
}

fn redirect_to_short_url(slug: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/{slug}")).expect("a Slug is a valid Location"),
    );
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
