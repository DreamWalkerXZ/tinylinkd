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
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    database: &'static str,
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let (status, status_text, database) = match state.db.ping().await {
        Ok(()) => (StatusCode::OK, "ok", "ok"),
        Err(error) => {
            tracing::error!(error = %error, "database health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "error", "unavailable")
        }
    };

    (
        status,
        Json(HealthResponse {
            status: status_text,
            version: env!("CARGO_PKG_VERSION"),
            database,
        }),
    )
}
