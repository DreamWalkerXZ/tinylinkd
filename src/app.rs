use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::db::Database;
use crate::problems::ProblemDetails;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
}

pub fn build_router(db: Database) -> Router {
    Router::new()
        .route("/_/health", get(health))
        .merge(crate::api::router())
        .fallback(fallback)
        .with_state(AppState { db })
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
