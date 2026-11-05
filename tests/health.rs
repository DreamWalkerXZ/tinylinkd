use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tinylinkd::app::build_router;
use tinylinkd::db::Database;
use tower::ServiceExt;

async fn get_json(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, serde_json::from_slice(&body).expect("json"))
}

#[tokio::test]
async fn health_returns_ok_with_database_check() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");
    let app = build_router(db);

    let (status, json) = get_json(&app, "/_/health").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["database"], "ok");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn health_returns_503_when_database_is_unavailable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");
    let pool = db.read_pool().clone();
    let app = build_router(db);
    pool.close().await;

    let (status, json) = get_json(&app, "/_/health").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["status"], "error");
    assert_eq!(json["database"], "unavailable");
}

#[cfg(unix)]
#[tokio::test]
async fn health_returns_503_when_database_file_is_removed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");
    let app = build_router(db);

    std::fs::remove_file(dir.path().join("tinylinkd.db")).expect("remove database");
    let _ = std::fs::remove_file(dir.path().join("tinylinkd.db-wal"));
    let _ = std::fs::remove_file(dir.path().join("tinylinkd.db-shm"));

    let (status, json) = get_json(&app, "/_/health").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["status"], "error");
    assert_eq!(json["database"], "unavailable");
}

#[tokio::test]
async fn connect_applies_embedded_migrations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");

    let setting_keys: Vec<String> = sqlx::query_scalar("SELECT key FROM settings ORDER BY key")
        .fetch_all(db.read_pool())
        .await
        .expect("settings table");
    assert_eq!(
        setting_keys,
        [
            "click_retention_days",
            "instance_name",
            "password_unlock_ttl_seconds",
            "timezone"
        ],
        "connect must insert the default Instance settings"
    );

    let applied: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = 1")
            .fetch_one(db.read_pool())
            .await
            .expect("migrations");
    assert!(applied >= 2, "expected embedded migrations to be applied");
}

#[tokio::test]
async fn database_enables_wal_and_foreign_keys() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::connect(dir.path()).await.expect("database");

    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(db.read_pool())
        .await
        .expect("journal_mode");
    assert_eq!(journal_mode.to_lowercase(), "wal");

    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(db.read_pool())
        .await
        .expect("foreign_keys");
    assert_eq!(foreign_keys, 1);
}
