use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::db::Database;

#[derive(Clone)]
struct AppState {
    db: Database,
}

pub fn build_router(db: Database) -> Router {
    Router::new()
        .route("/_/health", get(health))
        .with_state(AppState { db })
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
