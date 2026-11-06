mod common;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use common::{TEST_PEER, TestContext};
use serde_json::{Value, json};
use sqlx::Row;
use tinylinkd::tokens::create_token;
use tinylinkd::users::{NewUser, Role, User};

const BASE_URL: &str = "http://localhost:8080";

async fn create_user_with_token(
    context: &TestContext,
    username: &str,
    role: Role,
) -> (User, String) {
    let user = tinylinkd::users::create_user(
        &context.db,
        NewUser {
            username: username.into(),
            email: None,
            password: "correct horse battery staple".into(),
            role,
        },
    )
    .await
    .expect("create user");
    let token = create_token(&context.db, user.id, "test token", None)
        .await
        .expect("create token");
    (user, token.plaintext)
}

fn browser_headers(user_agent: &str, referer: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_str(user_agent).expect("user agent"),
    );
    if let Some(referer) = referer {
        headers.insert(
            header::REFERER,
            HeaderValue::from_str(referer).expect("referer"),
        );
    }
    headers
}

#[derive(Debug)]
struct StoredClick {
    clicked_at: String,
    ip: String,
    user_agent: String,
    referer: Option<String>,
    device: String,
    is_bot: i64,
}

async fn stored_clicks(context: &TestContext) -> Vec<StoredClick> {
    let rows = sqlx::query(
        "SELECT clicked_at, ip, user_agent, referer, device, is_bot FROM clicks ORDER BY id",
    )
    .fetch_all(context.db.read_pool())
    .await
    .expect("query clicks");
    rows.iter()
        .map(|row| StoredClick {
            clicked_at: row.try_get("clicked_at").expect("clicked_at"),
            ip: row.try_get("ip").expect("ip"),
            user_agent: row.try_get("user_agent").expect("user_agent"),
            referer: row.try_get("referer").expect("referer"),
            device: row.try_get("device").expect("device"),
            is_bot: row.try_get("is_bot").expect("is_bot"),
        })
        .collect()
}

async fn create_link(context: &TestContext, token: &str, body: Value) -> Value {
    let response = context.post("/_/api/v1/links", Some(token), body).await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

#[tokio::test]
async fn creating_links_through_the_api_is_rate_limited_per_user() {
    let context = TestContext::new().await;
    let (_user, token) = create_user_with_token(&context, "alice", Role::User).await;

    for index in 0..30 {
        let response = context
            .post(
                "/_/api/v1/links",
                Some(&token),
                json!({
                    "destination_url": "https://example.com/target",
                    "slug": format!("rate-{index}"),
                }),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "request {index}: {}",
            String::from_utf8_lossy(&response.body)
        );
    }

    let limited = context
        .post(
            "/_/api/v1/links",
            Some(&token),
            json!({
                "destination_url": "https://example.com/target",
                "slug": "rate-overflow",
            }),
        )
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.content_type(), "application/problem+json");
    let retry_after = limited
        .headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .expect("Retry-After header");
    let seconds: u64 = retry_after.parse().expect("Retry-After in seconds");
    assert!(
        (1..=60).contains(&seconds),
        "unexpected Retry-After: {retry_after}"
    );
    let problem = limited.json();
    assert_eq!(problem["status"], 429);
    assert_eq!(problem["code"], "rate_limited");
    assert_eq!(problem["instance"], "/_/api/v1/links");
}

#[tokio::test]
async fn user_creates_a_link_with_a_custom_slug() {
    let context = TestContext::new().await;
    let (alice, token) = create_user_with_token(&context, "alice", Role::User).await;

    let link = create_link(
        &context,
        &token,
        json!({
            "destination_url": "https://example.com/very/long?existing=1",
            "slug": "launch-2026"
        }),
    )
    .await;

    assert_eq!(link["owner_id"], alice.id);
    assert_eq!(link["slug"], "launch-2026");
    assert_eq!(
        link["short_url"],
        format!("{BASE_URL}/launch-2026"),
        "unexpected short URL: {link}"
    );
    assert_eq!(
        link["destination_url"],
        "https://example.com/very/long?existing=1"
    );
    assert_eq!(link["has_password"], false);
    assert!(link["expires_at"].is_null(), "{link}");
    assert_eq!(link["status"], "active");
    assert_eq!(link["total_clicks"], 0);
    assert_eq!(link["human_clicks"], 0);
    assert_eq!(link["bot_clicks"], 0);
    assert!(link["id"].as_i64().is_some(), "{link}");
    for field in ["created_at", "updated_at"] {
        let value = link[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field}"));
        assert!(
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .is_ok(),
            "{field} is not RFC 3339: {value}"
        );
    }
}

#[tokio::test]
async fn creating_a_link_without_a_slug_generates_an_eight_character_slug() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;

    let link = create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/"}),
    )
    .await;

    let slug = link["slug"].as_str().expect("slug");
    assert_eq!(slug.len(), 8, "slug: {slug}");
    assert!(
        slug.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
        "slug has invalid characters: {slug}"
    );
    assert_eq!(
        link["short_url"],
        format!("{BASE_URL}/{slug}"),
        "unexpected short URL: {link}"
    );
}

#[tokio::test]
async fn valid_slugs_are_accepted() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;

    let six_four = "a".repeat(64);
    for slug in [
        "abc",
        "123",
        "a1-b2-c3",
        "launch---2026",
        "0start-and-end9",
        six_four.as_str(),
    ] {
        let link = create_link(
            &context,
            &token,
            json!({"destination_url": "https://example.com/", "slug": slug}),
        )
        .await;
        assert_eq!(link["slug"], slug);
    }
}

#[tokio::test]
async fn invalid_slugs_are_rejected_with_422() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;

    let too_long = "a".repeat(65);
    for slug in [
        "",
        "ab",
        too_long.as_str(),
        "Launch",
        "my-slug-",
        "-my-slug",
        "under_score",
        "dot.slug",
        "with space",
        "caf\u{e9}",
        "slash/slug",
    ] {
        let response = context
            .post(
                "/_/api/v1/links",
                Some(&token),
                json!({"destination_url": "https://example.com/", "slug": slug}),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "slug {slug:?} was accepted"
        );
        assert_eq!(response.content_type(), "application/problem+json");
        assert_eq!(response.json()["code"], "invalid_slug", "slug: {slug:?}");
    }
}

#[tokio::test]
async fn a_taken_custom_slug_returns_409() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;

    create_link(
        &context,
        &alice_token,
        json!({"destination_url": "https://example.com/", "slug": "taken-slug"}),
    )
    .await;

    let response = context
        .post(
            "/_/api/v1/links",
            Some(&bob_token),
            json!({"destination_url": "https://example.org/", "slug": "taken-slug"}),
        )
        .await;

    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "slug_taken");
}

#[tokio::test]
async fn invalid_destination_urls_are_rejected_with_422() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;

    for destination in [
        "not a url",
        "/relative/path",
        "example.com",
        "ftp://example.com/file",
        "mailto:someone@example.com",
        "",
    ] {
        let response = context
            .post(
                "/_/api/v1/links",
                Some(&token),
                json!({"destination_url": destination}),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "destination {destination:?} was accepted"
        );
        assert_eq!(
            response.json()["code"],
            "invalid_destination_url",
            "destination: {destination:?}"
        );
    }

    let missing = context
        .post("/_/api/v1/links", Some(&token), json!({}))
        .await;
    assert_eq!(missing.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(missing.content_type(), "application/problem+json");
    assert_eq!(missing.json()["code"], "invalid_request");
}

#[tokio::test]
async fn link_list_returns_only_the_current_users_links_with_pagination() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    create_link(
        &context,
        &alice_token,
        json!({"destination_url": "https://example.com/one", "slug": "alice-one"}),
    )
    .await;
    create_link(
        &context,
        &alice_token,
        json!({"destination_url": "https://example.com/two", "slug": "alice-two"}),
    )
    .await;
    create_link(
        &context,
        &bob_token,
        json!({"destination_url": "https://example.com/bob", "slug": "bob-one"}),
    )
    .await;

    let response = context.get("/_/api/v1/links", Some(&alice_token)).await;
    assert_eq!(response.status, StatusCode::OK);
    let list = response.json();
    assert_eq!(list["total"], 2);
    assert_eq!(list["limit"], 20);
    assert_eq!(list["offset"], 0);
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0]["slug"], "alice-two",
        "the default sort is newest first"
    );
    assert_eq!(items[1]["slug"], "alice-one");

    let bob_list = context
        .get("/_/api/v1/links", Some(&bob_token))
        .await
        .json();
    assert_eq!(bob_list["total"], 1);
    assert_eq!(bob_list["items"][0]["slug"], "bob-one");

    let page = context
        .get("/_/api/v1/links?limit=1&offset=1", Some(&alice_token))
        .await
        .json();
    assert_eq!(page["total"], 2);
    assert_eq!(page["limit"], 1);
    assert_eq!(page["offset"], 1);
    let items = page["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["slug"], "alice-one");

    let invalid = context
        .get("/_/api/v1/links?limit=0", Some(&alice_token))
        .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid.json()["code"], "invalid_pagination");

    let unauthenticated = context.get("/_/api/v1/links", None).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn link_read_is_limited_to_the_owner_and_admins() {
    let context = TestContext::new().await;
    let (alice, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let link = create_link(
        &context,
        &alice_token,
        json!({"destination_url": "https://example.com/", "slug": "alice-link"}),
    )
    .await;
    let link_id = link["id"].as_i64().expect("link id");
    let uri = format!("/_/api/v1/links/{link_id}");

    let owner = context.get(&uri, Some(&alice_token)).await;
    assert_eq!(owner.status, StatusCode::OK);
    let read = owner.json();
    assert_eq!(read["id"], link_id);
    assert_eq!(read["owner_id"], alice.id);
    assert_eq!(read["slug"], "alice-link");
    assert_eq!(read["short_url"], format!("{BASE_URL}/alice-link"));

    let admin = context.get(&uri, Some(&admin_token)).await;
    assert_eq!(admin.status, StatusCode::OK);
    assert_eq!(admin.json()["slug"], "alice-link");

    let other_user = context.get(&uri, Some(&bob_token)).await;
    assert_eq!(other_user.status, StatusCode::FORBIDDEN);
    assert_eq!(other_user.content_type(), "application/problem+json");
    assert_eq!(other_user.json()["code"], "forbidden");

    let unknown = context
        .get("/_/api/v1/links/999999", Some(&alice_token))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.content_type(), "application/problem+json");
    assert_eq!(unknown.json()["code"], "not_found");

    let unauthenticated = context.get(&uri, None).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn redirects_to_the_destination_url_with_302_and_no_store() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    create_link(
        &context,
        &token,
        json!({
            "destination_url": "https://example.com/some/page",
            "slug": "go-page"
        }),
    )
    .await;

    let response = context.get("/go-page", None).await;

    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        response
            .headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("https://example.com/some/page")
    );
    assert_eq!(
        response
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
}

#[tokio::test]
async fn redirect_appends_the_short_url_query_string_to_the_destination() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;

    let cases = [
        (
            "https://example.com/page",
            "/plain?utm_source=news&utm_campaign=x",
            "https://example.com/page?utm_source=news&utm_campaign=x",
        ),
        (
            "https://example.com/page?existing=1",
            "/existing?a=1&b=2",
            "https://example.com/page?existing=1&a=1&b=2",
        ),
        (
            "https://example.com/page?existing=1#section",
            "/fragment?a=1",
            "https://example.com/page?existing=1&a=1#section",
        ),
        (
            "https://example.com/page#section",
            "/fragment-only?a=1",
            "https://example.com/page?a=1#section",
        ),
        (
            "https://example.com/page?",
            "/empty-query?a=1",
            "https://example.com/page?a=1",
        ),
        (
            "https://example.com/page?existing=1",
            "/no-query",
            "https://example.com/page?existing=1",
        ),
    ];

    for (destination, short_uri, expected) in cases {
        let slug = short_uri
            .trim_start_matches('/')
            .split('?')
            .next()
            .expect("slug");
        create_link(
            &context,
            &token,
            json!({"destination_url": destination, "slug": slug}),
        )
        .await;

        let response = context.get(short_uri, None).await;
        assert_eq!(response.status, StatusCode::FOUND, "uri: {short_uri}");
        assert_eq!(
            response
                .headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some(expected),
            "destination: {destination}, uri: {short_uri}"
        );
    }
}

#[tokio::test]
async fn unknown_slugs_return_the_not_found_page() {
    let context = TestContext::new().await;

    let response = context.get("/does-not-exist", None).await;

    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert!(
        response.content_type().starts_with("text/html"),
        "content type: {}",
        response.content_type()
    );
    let body = String::from_utf8_lossy(&response.body).to_lowercase();
    assert!(body.contains("not found"), "body: {body}");
}

#[tokio::test]
async fn uppercase_and_trailing_slash_do_not_resolve() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/", "slug": "case-test"}),
    )
    .await;

    let uppercase = context.get("/CASE-TEST", None).await;
    assert_eq!(uppercase.status, StatusCode::NOT_FOUND);

    let mixed_case = context.get("/Case-Test", None).await;
    assert_eq!(mixed_case.status, StatusCode::NOT_FOUND);

    let trailing_slash = context.get("/case-test/", None).await;
    assert_eq!(trailing_slash.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn head_returns_the_redirect_status_and_headers() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/page?x=1", "slug": "head-link"}),
    )
    .await;

    let response = context.head("/head-link?more=2").await;

    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        response
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://example.com/page?x=1&more=2")
    );
    assert_eq!(
        response
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(response.body.is_empty(), "HEAD response has a body");
}

#[tokio::test]
async fn a_click_records_time_ip_user_agent_referer_and_device() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/", "slug": "click-me"}),
    )
    .await;
    let link_id = link["id"].as_i64().expect("link id");
    let user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
                      AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 \
                      Mobile/15E148 Safari/604.1";

    let before = time::OffsetDateTime::now_utc() - time::Duration::seconds(2);
    let response = context
        .get_with_headers(
            "/click-me",
            browser_headers(user_agent, Some("https://ref.example/page")),
        )
        .await;
    let after = time::OffsetDateTime::now_utc() + time::Duration::seconds(2);

    assert_eq!(response.status, StatusCode::FOUND);

    let clicks = stored_clicks(&context).await;
    assert_eq!(clicks.len(), 1, "clicks: {clicks:?}");
    let click = &clicks[0];
    let clicked_at = time::OffsetDateTime::parse(
        &click.clicked_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("clicked_at is RFC 3339");
    assert!(
        clicked_at >= before && clicked_at <= after,
        "clicked_at out of range: {}",
        click.clicked_at
    );
    assert_eq!(click.ip, TEST_PEER.ip().to_string());
    assert_eq!(click.user_agent, user_agent);
    assert_eq!(click.referer.as_deref(), Some("https://ref.example/page"));
    assert_eq!(click.device, "mobile");
    assert_eq!(click.is_bot, 0);

    let read = context
        .get(&format!("/_/api/v1/links/{link_id}"), Some(&token))
        .await
        .json();
    assert_eq!(read["total_clicks"], 1);
    assert_eq!(read["human_clicks"], 1);
    assert_eq!(read["bot_clicks"], 0);
}

#[tokio::test]
async fn bot_clicks_are_flagged_and_counted_separately() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/", "slug": "bot-link"}),
    )
    .await;
    let link_id = link["id"].as_i64().expect("link id");

    let response = context
        .get_with_headers(
            "/bot-link",
            browser_headers("Googlebot/2.1 (+http://www.google.com/bot.html)", None),
        )
        .await;
    assert_eq!(response.status, StatusCode::FOUND);

    let clicks = stored_clicks(&context).await;
    assert_eq!(clicks.len(), 1);
    assert_eq!(clicks[0].device, "bot");
    assert_eq!(clicks[0].is_bot, 1);
    assert!(clicks[0].referer.is_none());

    let read = context
        .get(&format!("/_/api/v1/links/{link_id}"), Some(&token))
        .await
        .json();
    assert_eq!(read["total_clicks"], 1);
    assert_eq!(read["human_clicks"], 0);
    assert_eq!(read["bot_clicks"], 1);
}

#[tokio::test]
async fn device_classification_uses_the_user_agent() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let cases = [
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "desktop",
            0,
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "desktop",
            0,
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
             AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 \
             Mobile/15E148 Safari/604.1",
            "mobile",
            0,
        ),
        (
            "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "tablet",
            0,
        ),
        (
            "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "tablet",
            0,
        ),
        (
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "mobile",
            0,
        ),
        ("Googlebot/2.1 (+http://www.google.com/bot.html)", "bot", 1),
        ("SomeUnknownClient/1.0", "unknown", 0),
    ];

    for (index, (user_agent, _, _)) in cases.iter().enumerate() {
        let slug = format!("device-{index}");
        create_link(
            &context,
            &token,
            json!({"destination_url": "https://example.com/", "slug": slug}),
        )
        .await;
        let response = context
            .get_with_headers(&format!("/{slug}"), browser_headers(user_agent, None))
            .await;
        assert_eq!(response.status, StatusCode::FOUND);
    }

    let clicks = stored_clicks(&context).await;
    assert_eq!(clicks.len(), cases.len());
    for (click, (user_agent, expected_device, expected_bot)) in clicks.iter().zip(cases) {
        assert_eq!(click.device, expected_device, "user agent: {user_agent}");
        assert_eq!(click.is_bot, expected_bot, "user agent: {user_agent}");
    }
}

#[tokio::test]
async fn head_requests_do_not_record_clicks() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/", "slug": "no-click"}),
    )
    .await;

    let response = context.head("/no-click").await;
    assert_eq!(response.status, StatusCode::FOUND);

    assert!(stored_clicks(&context).await.is_empty());
}

#[tokio::test]
async fn trust_proxy_uses_the_first_forwarded_address() {
    let context = TestContext::with_config(BASE_URL, true).await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/", "slug": "proxied"}),
    )
    .await;

    let mut headers = browser_headers("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", None);
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("198.51.100.23, 10.0.0.1"),
    );
    let response = context.get_with_headers("/proxied", headers).await;
    assert_eq!(response.status, StatusCode::FOUND);

    let clicks = stored_clicks(&context).await;
    assert_eq!(clicks.len(), 1);
    assert_eq!(clicks[0].ip, "198.51.100.23");
}

#[tokio::test]
async fn forwarded_for_is_ignored_without_proxy_trust() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/", "slug": "not-proxied"}),
    )
    .await;

    let mut headers = browser_headers("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", None);
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("198.51.100.23, 10.0.0.1"),
    );
    let response = context.get_with_headers("/not-proxied", headers).await;
    assert_eq!(response.status, StatusCode::FOUND);

    let clicks = stored_clicks(&context).await;
    assert_eq!(clicks.len(), 1);
    assert_eq!(clicks[0].ip, TEST_PEER.ip().to_string());
}

#[tokio::test]
async fn redirect_still_succeeds_when_click_recording_fails() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/still/works", "slug": "broken-click"}),
    )
    .await;
    context.db.write_pool().close().await;

    let response = context.get("/broken-click", None).await;

    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        response
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://example.com/still/works")
    );
    let clicks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM clicks")
        .fetch_one(context.db.read_pool())
        .await
        .expect("count clicks");
    assert_eq!(clicks, 0);
}

#[tokio::test]
async fn creating_a_link_requires_authentication() {
    let context = TestContext::new().await;

    let response = context
        .post(
            "/_/api/v1/links",
            None,
            json!({"destination_url": "https://example.com/"}),
        )
        .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "authentication_required");
}
