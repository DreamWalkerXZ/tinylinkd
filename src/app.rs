use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use url::Url;

use crate::db::Database;
use crate::problems::ProblemDetails;
use crate::ratelimit::{
    API_REQUEST_LIMIT, API_REQUEST_WINDOW, LINK_CREATION_LIMIT, LINK_CREATION_WINDOW, RateLimiter,
};
use crate::sessions::LoginAttemptLimiter;
use crate::unlock::PasswordAttemptLimiter;

/// Deployment configuration needed by request handlers.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub base_url: Url,
    pub trust_proxy: bool,
}

impl AppConfig {
    pub fn new(base_url: Url, trust_proxy: bool) -> Self {
        Self {
            base_url,
            trust_proxy,
        }
    }

    /// The default used by [`build_router`] for callers that do not provide
    /// deployment configuration, notably the HTTP-seam tests.
    pub fn test_default() -> Self {
        Self::new(
            Url::parse("http://localhost:8080").expect("the default base URL is valid"),
            false,
        )
    }

    pub fn short_url(&self, slug: &str) -> String {
        format!("{}/{}", self.base_url.as_str().trim_end_matches('/'), slug)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: AppConfig,
    pub unlock_limiter: Arc<PasswordAttemptLimiter>,
    pub login_limiter: Arc<LoginAttemptLimiter>,
    pub link_create_limiter: Arc<RateLimiter<i64>>,
    pub api_rate_limiter: Arc<RateLimiter<i64>>,
}

/// Build the router with a test default base URL and proxy trust disabled.
///
/// Production callers use [`build_router_with_config`].
pub fn build_router(db: Database) -> Router {
    build_router_with_config(db, AppConfig::test_default())
}

pub fn build_router_with_config(db: Database, config: AppConfig) -> Router {
    let state = AppState {
        db,
        config,
        unlock_limiter: Arc::new(PasswordAttemptLimiter::new()),
        login_limiter: Arc::new(LoginAttemptLimiter::new()),
        link_create_limiter: Arc::new(RateLimiter::new(LINK_CREATION_LIMIT, LINK_CREATION_WINDOW)),
        api_rate_limiter: Arc::new(RateLimiter::new(API_REQUEST_LIMIT, API_REQUEST_WINDOW)),
    };
    Router::new()
        .route("/_/health", get(health))
        .merge(crate::admin_ui::router())
        .merge(crate::api::router())
        .merge(crate::redirect::router())
        .fallback(fallback)
        .layer(middleware::from_fn(add_nosniff_to_json))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            refresh_session_cookie,
        ))
        .with_state(state)
}

/// API responses are JSON or Problem Details; both must disable content-type
/// sniffing. HTML responses set their own security headers.
async fn add_nosniff_to_json(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.starts_with("application/json") || value.starts_with("application/problem+json")
        });
    if is_json {
        response.headers_mut().insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
    }
    response
}

/// Re-issue the browser session cookie on authenticated admin UI responses.
///
/// The server-side session row already slides its 7-day idle expiry on every
/// request; without this middleware the browser cookie would still expire at
/// its original 7-day mark and sign an active User out.
async fn refresh_session_cookie(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let is_admin_ui = path == "/" || (path.starts_with("/_/") && !path.starts_with("/_/api/"));
    let token = if is_admin_ui {
        crate::sessions::cookie_value(request.headers(), crate::sessions::SESSION_COOKIE_NAME)
    } else {
        None
    };
    let mut response = next.run(request).await;
    let Some(token) = token else {
        return response;
    };
    let session_cookie_prefix = format!("{}=", crate::sessions::SESSION_COOKIE_NAME);
    let already_sets_session = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with(&session_cookie_prefix));
    if already_sets_session {
        return response;
    }
    match crate::sessions::is_valid(&state.db, &token).await {
        Ok(true) => {
            let secure = state.config.base_url.scheme() == "https";
            let cookie = crate::sessions::session_set_cookie(&token, secure);
            match HeaderValue::from_str(&cookie) {
                Ok(value) => {
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
                Err(error) => {
                    tracing::warn!(error = %error, "failed to build a refreshed session cookie");
                }
            }
        }
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(error = %error, "failed to check a session for cookie refresh");
        }
    }
    response
}

async fn fallback(uri: Uri) -> Response {
    if uri.path().starts_with("/_/api/") {
        ProblemDetails::not_found("No such API route.", uri.path()).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum HealthStatus {
    Ok,
    Error,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum DatabaseStatus {
    Ok,
    Unavailable,
}

#[derive(Serialize)]
struct HealthResponse {
    status: HealthStatus,
    version: &'static str,
    database: DatabaseStatus,
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.ping().await {
        Ok(()) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: HealthStatus::Ok,
                version: env!("CARGO_PKG_VERSION"),
                database: DatabaseStatus::Ok,
            }),
        ),
        Err(error) => {
            tracing::error!(error = %error, "database health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: HealthStatus::Error,
                    version: env!("CARGO_PKG_VERSION"),
                    database: DatabaseStatus::Unavailable,
                }),
            )
        }
    }
}
