use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use url::Url;

use crate::db::Database;
use crate::problems::ProblemDetails;
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
}

/// Build the router with a test default base URL and proxy trust disabled.
///
/// Production callers use [`build_router_with_config`].
pub fn build_router(db: Database) -> Router {
    build_router_with_config(db, AppConfig::test_default())
}

pub fn build_router_with_config(db: Database, config: AppConfig) -> Router {
    Router::new()
        .route("/_/health", get(health))
        .merge(crate::api::router())
        .merge(crate::redirect::router())
        .fallback(fallback)
        .with_state(AppState {
            db,
            config,
            unlock_limiter: Arc::new(PasswordAttemptLimiter::new()),
        })
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
