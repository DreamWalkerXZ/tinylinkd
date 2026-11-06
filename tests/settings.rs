mod common;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use common::{TestContext, TestResponse, create_link_with_slug, create_user_with_token};
use serde_json::{Value, json};
use tinylinkd::users::Role;

const SETTINGS_URI: &str = "/_/api/v1/settings";

async fn ensure_admin_token(context: &TestContext) -> String {
    create_user_with_token(context, "admin", Role::Admin)
        .await
        .1
}

async fn patch_settings(context: &TestContext, token: &str, body: Value) -> TestResponse {
    context
        .request(Method::PATCH, SETTINGS_URI, Some(token), Some(body))
        .await
}

async fn get_settings(context: &TestContext, token: &str) -> TestResponse {
    context.get(SETTINGS_URI, Some(token)).await
}

fn defaults() -> Value {
    json!({
        "instance_name": "tinylinkd",
        "timezone": "UTC",
        "click_retention_days": 90,
        "password_unlock_ttl_seconds": 3600
    })
}

async fn protect_link(context: &TestContext, token: &str, slug: &str, password: &str) -> i64 {
    let link = create_link_with_slug(context, token, slug).await;
    let id = link["id"].as_i64().expect("link id");
    let response = context
        .request(
            Method::PATCH,
            &format!("/_/api/v1/links/{id}"),
            Some(token),
            Some(json!({"password": password})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    id
}

async fn submit_password(context: &TestContext, slug: &str, password: &str) -> TestResponse {
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/{slug}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("password={password}")))
        .expect("request");
    context.send(request).await
}

fn set_cookie(response: &TestResponse) -> String {
    response
        .headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("missing Set-Cookie: {:?}", response.headers))
        .to_string()
}

fn cookie_header(set_cookie: &str) -> HeaderMap {
    let pair = set_cookie
        .split(';')
        .next()
        .expect("the cookie pair before the attributes");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(pair).expect("cookie header"),
    );
    headers
}

async fn insert_click(context: &TestContext, link_id: i64, clicked_at: &str) {
    sqlx::query(
        "INSERT INTO clicks (link_id, clicked_at, ip, user_agent, referer, device, is_bot, created_at)
         VALUES (?, ?, '198.51.100.1', 'Mozilla/5.0', NULL, 'desktop', 0, ?)",
    )
    .bind(link_id)
    .bind(clicked_at)
    .bind(clicked_at)
    .execute(context.db.write_pool())
    .await
    .expect("insert click");
}

fn fixed_now(value: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .expect("fixed now")
}

#[tokio::test]
async fn an_admin_reads_the_default_instance_settings() {
    let context = TestContext::new().await;
    let token = ensure_admin_token(&context).await;

    let response = get_settings(&context, &token).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(
        response.content_type().starts_with("application/json"),
        "content type: {}",
        response.content_type()
    );
    assert_eq!(response.json(), defaults());
}

#[tokio::test]
async fn instance_settings_are_admin_only() {
    let context = TestContext::new().await;
    let (_, user_token) = create_user_with_token(&context, "alice", Role::User).await;

    let read = get_settings(&context, &user_token).await;
    assert_eq!(read.status, StatusCode::FORBIDDEN);
    assert_eq!(read.content_type(), "application/problem+json");
    assert_eq!(read.json()["code"], "forbidden");

    let write = patch_settings(&context, &user_token, json!({"instance_name": "hijacked"})).await;
    assert_eq!(write.status, StatusCode::FORBIDDEN);
    assert_eq!(write.content_type(), "application/problem+json");
    assert_eq!(write.json()["code"], "forbidden");

    let unauthenticated = context.get(SETTINGS_URI, None).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthenticated.json()["code"], "authentication_required");

    let unauthenticated_write = context
        .request(
            Method::PATCH,
            SETTINGS_URI,
            None,
            Some(json!({"instance_name": "hijacked"})),
        )
        .await;
    assert_eq!(unauthenticated_write.status, StatusCode::UNAUTHORIZED);

    let unchanged = get_settings(&context, &ensure_admin_token(&context).await).await;
    assert_eq!(unchanged.json(), defaults());
}

#[tokio::test]
async fn an_admin_updates_the_instance_settings() {
    let context = TestContext::new().await;
    let token = ensure_admin_token(&context).await;

    let updated = patch_settings(
        &context,
        &token,
        json!({
            "instance_name": "  Example Links  ",
            "timezone": "America/New_York",
            "click_retention_days": 30,
            "password_unlock_ttl_seconds": 120
        }),
    )
    .await;

    assert_eq!(
        updated.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&updated.body)
    );
    assert_eq!(
        updated.json(),
        json!({
            "instance_name": "Example Links",
            "timezone": "America/New_York",
            "click_retention_days": 30,
            "password_unlock_ttl_seconds": 120
        })
    );
    assert_eq!(get_settings(&context, &token).await.json(), updated.json());

    let partial = patch_settings(&context, &token, json!({"timezone": "Europe/London"})).await;
    assert_eq!(partial.status, StatusCode::OK);
    assert_eq!(
        partial.json(),
        json!({
            "instance_name": "Example Links",
            "timezone": "Europe/London",
            "click_retention_days": 30,
            "password_unlock_ttl_seconds": 120
        }),
        "a PATCH must leave omitted settings unchanged"
    );
    assert_eq!(get_settings(&context, &token).await.json(), partial.json());
}

#[tokio::test]
async fn invalid_settings_are_rejected_without_partial_updates() {
    let context = TestContext::new().await;
    let token = ensure_admin_token(&context).await;

    let cases: Vec<(&str, Value)> = vec![
        ("invalid_instance_name", json!({"instance_name": ""})),
        ("invalid_instance_name", json!({"instance_name": "   "})),
        ("invalid_timezone", json!({"timezone": "Not/AZone"})),
        ("invalid_timezone", json!({"timezone": ""})),
        (
            "invalid_click_retention_days",
            json!({"click_retention_days": 0}),
        ),
        (
            "invalid_click_retention_days",
            json!({"click_retention_days": -7}),
        ),
        (
            "invalid_password_unlock_ttl",
            json!({"password_unlock_ttl_seconds": 0}),
        ),
        (
            "invalid_password_unlock_ttl",
            json!({"password_unlock_ttl_seconds": -5}),
        ),
    ];
    for (expected_code, body) in cases {
        let response = patch_settings(&context, &token, body.clone()).await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "body {body} must be rejected"
        );
        assert_eq!(response.content_type(), "application/problem+json");
        assert_eq!(
            response.json()["code"],
            expected_code,
            "unexpected code for {body}: {}",
            response.json()
        );
    }

    let mixed = patch_settings(
        &context,
        &token,
        json!({"instance_name": "changed", "timezone": "Bad/Zone"}),
    )
    .await;
    assert_eq!(mixed.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        get_settings(&context, &token).await.json(),
        defaults(),
        "a PATCH with any invalid field must not apply its valid fields"
    );

    let malformed =
        patch_settings(&context, &token, json!({"click_retention_days": "ninety"})).await;
    assert_eq!(malformed.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(malformed.content_type(), "application/problem+json");
    assert_eq!(malformed.json()["code"], "invalid_request");
}

#[tokio::test]
async fn settings_never_expose_the_secrets_table_or_signing_key() {
    let context = TestContext::new().await;
    let token = ensure_admin_token(&context).await;
    let secret = "unlock-cookie-signing-key-value-for-test";
    sqlx::query("INSERT INTO secrets (key, value) VALUES (?, ?)")
        .bind(tinylinkd::secrets::UNLOCK_COOKIE_SIGNING_KEY)
        .bind(secret)
        .execute(context.db.write_pool())
        .await
        .expect("store a signing key");

    let mut smuggling = json!({"instance_name": "Example", "signing_key": secret});
    smuggling[tinylinkd::secrets::UNLOCK_COOKIE_SIGNING_KEY] = json!(secret);

    for response in [
        get_settings(&context, &token).await,
        patch_settings(&context, &token, smuggling).await,
        get_settings(&context, &token).await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8_lossy(&response.body);
        assert!(
            !body.contains(secret),
            "the signing key must never appear in settings responses: {body}"
        );
        assert!(
            !body.contains(tinylinkd::secrets::UNLOCK_COOKIE_SIGNING_KEY),
            "secret keys must never appear in settings responses: {body}"
        );
    }

    let stored: String = sqlx::query_scalar("SELECT value FROM secrets WHERE key = ?")
        .bind(tinylinkd::secrets::UNLOCK_COOKIE_SIGNING_KEY)
        .fetch_one(context.db.read_pool())
        .await
        .expect("read the signing key");
    assert_eq!(stored, secret);
    let secret_settings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM settings WHERE key LIKE '%secret%' OR key LIKE '%signing%'",
    )
    .fetch_one(context.db.read_pool())
    .await
    .expect("count secret settings");
    assert_eq!(secret_settings, 0);
}

#[tokio::test]
async fn unlock_cookie_max_age_follows_the_ttl_setting() {
    let context = TestContext::new().await;
    let token = ensure_admin_token(&context).await;

    let configured = patch_settings(
        &context,
        &token,
        json!({"password_unlock_ttl_seconds": 120}),
    )
    .await;
    assert_eq!(configured.status, StatusCode::OK);
    protect_link(&context, &token, "guarded", "open sesame").await;

    let unlocked = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    let cookie = set_cookie(&unlocked);
    assert!(
        cookie.contains("Max-Age=120"),
        "the cookie must use the configured TTL: {cookie}"
    );
    assert!(!cookie.contains("Max-Age=3600"), "cookie: {cookie}");

    let changed =
        patch_settings(&context, &token, json!({"password_unlock_ttl_seconds": 45})).await;
    assert_eq!(changed.status, StatusCode::OK);
    let unlocked = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    let cookie = set_cookie(&unlocked);
    assert!(
        cookie.contains("Max-Age=45"),
        "a changed TTL must apply to subsequent unlocks: {cookie}"
    );

    let redirect = context
        .get_with_headers("/guarded", cookie_header(&cookie))
        .await;
    assert_eq!(redirect.status, StatusCode::FOUND);
}

#[tokio::test]
async fn click_retention_cleanup_uses_the_configured_days() {
    let context = TestContext::new().await;
    let token = ensure_admin_token(&context).await;
    let link = create_link_with_slug(&context, &token, "retention-link").await;
    let link_id = link["id"].as_i64().expect("link id");
    let now = fixed_now("2026-06-01T00:00:00Z");

    insert_click(&context, link_id, "2026-05-24T00:00:00Z").await; // 8 days old
    insert_click(&context, link_id, "2026-05-25T00:00:00Z").await; // exactly 7 days old

    let response = patch_settings(&context, &token, json!({"click_retention_days": 7})).await;
    assert_eq!(response.status, StatusCode::OK);
    let deleted = tinylinkd::analytics::cleanup_old_clicks_for_instance(&context.db, now)
        .await
        .expect("cleanup");
    assert_eq!(
        deleted, 1,
        "cleanup must use the configured 7-day retention instead of the 90-day default"
    );
    let remaining = context
        .get(&format!("/_/api/v1/links/{link_id}/clicks"), Some(&token))
        .await
        .json();
    assert_eq!(remaining["total"], 1, "remaining: {remaining}");

    insert_click(&context, link_id, "2026-05-12T00:00:00Z").await; // 20 days old
    let response = patch_settings(&context, &token, json!({"click_retention_days": 30})).await;
    assert_eq!(response.status, StatusCode::OK);
    let deleted = tinylinkd::analytics::cleanup_old_clicks_for_instance(&context.db, now)
        .await
        .expect("cleanup");
    assert_eq!(
        deleted, 0,
        "a longer retention must take effect without restarting the task"
    );

    insert_click(&context, link_id, "2026-05-31T00:00:00Z").await; // exactly 1 day old
    let response = patch_settings(&context, &token, json!({"click_retention_days": 1})).await;
    assert_eq!(response.status, StatusCode::OK);
    let deleted = tinylinkd::analytics::cleanup_old_clicks_for_instance(&context.db, now)
        .await
        .expect("cleanup");
    assert_eq!(
        deleted, 2,
        "a shorter retention must prune Clicks older than one day"
    );
    let remaining = context
        .get(&format!("/_/api/v1/links/{link_id}/clicks"), Some(&token))
        .await
        .json();
    assert_eq!(remaining["total"], 1, "remaining: {remaining}");
    assert_eq!(remaining["items"][0]["clicked_at"], "2026-05-31T00:00:00Z");
}

#[tokio::test]
async fn daily_stats_bucket_in_the_instance_timezone() {
    let context = TestContext::new().await;
    let token = ensure_admin_token(&context).await;
    let link = create_link_with_slug(&context, &token, "timezone-link").await;
    let link_id = link["id"].as_i64().expect("link id");

    let configured =
        patch_settings(&context, &token, json!({"timezone": "America/New_York"})).await;
    assert_eq!(configured.status, StatusCode::OK);

    // In New York on 2026-03-01 (EST, UTC-5), local midnight is 05:00 UTC.
    insert_click(&context, link_id, "2026-03-01T03:30:00Z").await;
    insert_click(&context, link_id, "2026-03-01T04:30:00Z").await;
    insert_click(&context, link_id, "2026-03-01T05:30:00Z").await;

    let stats = context
        .get(&format!("/_/api/v1/links/{link_id}/stats"), Some(&token))
        .await
        .json();
    assert_eq!(
        stats["by_day"],
        json!([
            {"date": "2026-02-28", "total_clicks": 2, "human_clicks": 2, "bot_clicks": 0},
            {"date": "2026-03-01", "total_clicks": 1, "human_clicks": 1, "bot_clicks": 0}
        ]),
        "UTC Clicks after local midnight must not be grouped by their UTC date: {stats}"
    );

    let configured = patch_settings(&context, &token, json!({"timezone": "UTC"})).await;
    assert_eq!(configured.status, StatusCode::OK);
    let stats = context
        .get(&format!("/_/api/v1/links/{link_id}/stats"), Some(&token))
        .await
        .json();
    assert_eq!(
        stats["by_day"],
        json!([
            {"date": "2026-03-01", "total_clicks": 3, "human_clicks": 3, "bot_clicks": 0}
        ]),
        "changing the timezone must change subsequent buckets: {stats}"
    );
}

#[tokio::test]
async fn daily_stats_handle_dst_transitions() {
    let context = TestContext::new().await;
    let token = ensure_admin_token(&context).await;
    let link = create_link_with_slug(&context, &token, "dst-link").await;
    let link_id = link["id"].as_i64().expect("link id");

    let configured =
        patch_settings(&context, &token, json!({"timezone": "America/New_York"})).await;
    assert_eq!(configured.status, StatusCode::OK);

    // US daylight saving starts on 2026-03-08 at 02:00 local: EST (UTC-5)
    // becomes EDT (UTC-4), so these instants map to the dates below.
    for clicked_at in [
        "2026-03-08T04:30:00Z", // 2026-03-07 23:30 EST
        "2026-03-08T05:30:00Z", // 2026-03-08 00:30 EST
        "2026-03-08T06:30:00Z", // 2026-03-08 01:30 EST
        "2026-03-08T07:30:00Z", // 2026-03-08 03:30 EDT
        "2026-03-09T03:30:00Z", // 2026-03-08 23:30 EDT
        "2026-03-09T04:30:00Z", // 2026-03-09 00:30 EDT
    ] {
        insert_click(&context, link_id, clicked_at).await;
    }

    let stats = context
        .get(&format!("/_/api/v1/links/{link_id}/stats"), Some(&token))
        .await
        .json();
    assert_eq!(
        stats["by_day"],
        json!([
            {"date": "2026-03-07", "total_clicks": 1, "human_clicks": 1, "bot_clicks": 0},
            {"date": "2026-03-08", "total_clicks": 4, "human_clicks": 4, "bot_clicks": 0},
            {"date": "2026-03-09", "total_clicks": 1, "human_clicks": 1, "bot_clicks": 0}
        ]),
        "day buckets must follow the local offset across a DST transition: {stats}"
    );
}
