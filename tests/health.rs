use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tinylinkd::app::build_router;
use tinylinkd::db::Database;
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok_with_database_check() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");
    let app = build_router(db);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/_/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["database"], "ok");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn health_returns_503_when_database_is_unavailable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");
    let pool = db.pool().clone();
    let app = build_router(db);
    pool.close().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/_/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["status"], "error");
    assert_eq!(json["database"], "unavailable");
}

#[tokio::test]
async fn connect_applies_embedded_migrations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");

    let schema_version: String =
        sqlx::query_scalar("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            .fetch_one(db.pool())
            .await
            .expect("schema_meta");
    assert_eq!(schema_version, "1");

    let applied: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = 1")
            .fetch_one(db.pool())
            .await
            .expect("migrations");
    assert!(applied >= 1);
}

#[tokio::test]
async fn database_enables_wal_and_foreign_keys() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");

    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(db.pool())
        .await
        .expect("journal_mode");
    assert_eq!(journal_mode.to_lowercase(), "wal");

    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(db.pool())
        .await
        .expect("foreign_keys");
    assert_eq!(foreign_keys, 1);
}
