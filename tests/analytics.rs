mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::json;
use tinylinkd::tokens::create_token;
use tinylinkd::users::{NewUser, Role, User};

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

async fn create_link(context: &TestContext, token: &str, slug: &str) -> i64 {
    let response = context
        .post(
            "/_/api/v1/links",
            Some(token),
            json!({"destination_url": "https://example.com/target", "slug": slug}),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()["id"].as_i64().expect("link id")
}

struct SeededClick<'a> {
    clicked_at: &'a str,
    ip: &'a str,
    user_agent: &'a str,
    referer: Option<&'a str>,
    device: &'a str,
    is_bot: bool,
}

impl<'a> SeededClick<'a> {
    fn human(
        clicked_at: &'a str,
        ip: &'a str,
        user_agent: &'a str,
        referer: Option<&'a str>,
        device: &'a str,
    ) -> Self {
        Self {
            clicked_at,
            ip,
            user_agent,
            referer,
            device,
            is_bot: false,
        }
    }

    fn bot(clicked_at: &'a str, ip: &'a str, user_agent: &'a str) -> Self {
        Self {
            clicked_at,
            ip,
            user_agent,
            referer: None,
            device: "bot",
            is_bot: true,
        }
    }
}

async fn insert_click(context: &TestContext, link_id: i64, click: SeededClick<'_>) {
    sqlx::query(
        "INSERT INTO clicks (link_id, clicked_at, ip, user_agent, referer, device, is_bot, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(link_id)
    .bind(click.clicked_at)
    .bind(click.ip)
    .bind(click.user_agent)
    .bind(click.referer)
    .bind(click.device)
    .bind(if click.is_bot { 1_i64 } else { 0_i64 })
    .bind(click.clicked_at)
    .execute(context.db.write_pool())
    .await
    .expect("insert click");
}

#[tokio::test]
async fn click_list_supports_time_filters_and_pagination() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link_id = create_link(&context, &token, "analytics-link").await;
    let uri = format!("/_/api/v1/links/{link_id}/clicks");

    insert_click(
        &context,
        link_id,
        SeededClick::human(
            "2026-01-01T10:00:00Z",
            "198.51.100.10",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            Some("https://ref.example/one"),
            "desktop",
        ),
    )
    .await;
    insert_click(
        &context,
        link_id,
        SeededClick::human(
            "2026-01-02T10:00:00Z",
            "198.51.100.20",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            None,
            "mobile",
        ),
    )
    .await;
    insert_click(
        &context,
        link_id,
        SeededClick::bot("2026-01-03T10:00:00Z", "198.51.100.30", "Googlebot/2.1"),
    )
    .await;

    let response = context.get(&uri, Some(&token)).await;
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
    let list = response.json();
    assert_eq!(list["total"], 3);
    assert_eq!(list["limit"], 20);
    assert_eq!(list["offset"], 0);
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    assert_eq!(
        items[0]["clicked_at"], "2026-01-03T10:00:00Z",
        "Clicks are listed newest first: {list}"
    );
    assert_eq!(items[0]["ip"], "198.51.100.30");
    assert_eq!(items[0]["user_agent"], "Googlebot/2.1");
    assert!(items[0]["referer"].is_null(), "bot referer: {list}");
    assert_eq!(items[0]["device"], "bot");
    assert_eq!(items[0]["is_bot"], true);
    assert_eq!(items[1]["clicked_at"], "2026-01-02T10:00:00Z");
    assert_eq!(items[2]["clicked_at"], "2026-01-01T10:00:00Z");
    assert_eq!(items[2]["referer"], "https://ref.example/one");
    assert_eq!(items[2]["device"], "desktop");
    assert_eq!(items[2]["is_bot"], false);

    let one_day = context
        .get(
            &format!("{uri}?from=2026-01-02T00:00:00Z&to=2026-01-02T23:59:59Z"),
            Some(&token),
        )
        .await
        .json();
    assert_eq!(one_day["total"], 1, "time range filter: {one_day}");
    assert_eq!(one_day["items"][0]["clicked_at"], "2026-01-02T10:00:00Z");

    let from_is_inclusive = context
        .get(&format!("{uri}?from=2026-01-02T10:00:00Z"), Some(&token))
        .await
        .json();
    assert_eq!(
        from_is_inclusive["total"], 2,
        "from must be inclusive: {from_is_inclusive}"
    );

    let to_is_inclusive = context
        .get(&format!("{uri}?to=2026-01-01T10:00:00Z"), Some(&token))
        .await
        .json();
    assert_eq!(
        to_is_inclusive["total"], 1,
        "to must be inclusive: {to_is_inclusive}"
    );

    let page = context
        .get(&format!("{uri}?limit=1&offset=1"), Some(&token))
        .await
        .json();
    assert_eq!(page["total"], 3);
    assert_eq!(page["limit"], 1);
    assert_eq!(page["offset"], 1);
    let items = page["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["clicked_at"], "2026-01-02T10:00:00Z");

    let invalid_limit = context.get(&format!("{uri}?limit=0"), Some(&token)).await;
    assert_eq!(invalid_limit.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid_limit.content_type(), "application/problem+json");
    assert_eq!(invalid_limit.json()["code"], "invalid_pagination");

    let invalid_from = context
        .get(&format!("{uri}?from=yesterday"), Some(&token))
        .await;
    assert_eq!(invalid_from.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid_from.content_type(), "application/problem+json");
    assert_eq!(invalid_from.json()["code"], "invalid_time_range");

    let unknown = context
        .get("/_/api/v1/links/999999/clicks", Some(&token))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.json()["code"], "not_found");
}

#[tokio::test]
async fn click_list_is_limited_to_the_owner_and_admins() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let link_id = create_link(&context, &alice_token, "owned-clicks").await;
    let uri = format!("/_/api/v1/links/{link_id}/clicks");

    let owner = context.get(&uri, Some(&alice_token)).await;
    assert_eq!(owner.status, StatusCode::OK);

    let admin = context.get(&uri, Some(&admin_token)).await;
    assert_eq!(admin.status, StatusCode::OK);

    let other_user = context.get(&uri, Some(&bob_token)).await;
    assert_eq!(other_user.status, StatusCode::FORBIDDEN);
    assert_eq!(other_user.content_type(), "application/problem+json");
    assert_eq!(other_user.json()["code"], "forbidden");

    let unauthenticated = context.get(&uri, None).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthenticated.json()["code"], "authentication_required");
}

#[tokio::test]
async fn retention_cleanup_deletes_only_clicks_older_than_the_window() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link_id = create_link(&context, &token, "retention-link").await;
    let other_link_id = create_link(&context, &token, "retention-other").await;

    // 90 days before this instant is 2026-03-03T00:00:00Z.
    let now = time::OffsetDateTime::parse(
        "2026-06-01T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("fixed now");
    assert_eq!(tinylinkd::analytics::CLICK_RETENTION_DAYS, 90);

    for clicked_at in [
        "2026-03-02T23:59:59Z", // just over 90 days old
        "2025-12-01T00:00:00Z", // long expired
    ] {
        insert_click(
            &context,
            link_id,
            SeededClick::human(clicked_at, "198.51.100.1", "Mozilla/5.0", None, "desktop"),
        )
        .await;
    }
    insert_click(
        &context,
        other_link_id,
        SeededClick::human(
            "2026-01-01T00:00:00Z",
            "198.51.100.2",
            "Mozilla/5.0",
            None,
            "desktop",
        ),
    )
    .await;
    for clicked_at in [
        "2026-03-03T00:00:00Z", // exactly 90 days old: not older, so kept
        "2026-05-31T12:00:00Z",
        "2027-01-01T00:00:00Z",
    ] {
        insert_click(
            &context,
            link_id,
            SeededClick::human(clicked_at, "198.51.100.3", "Mozilla/5.0", None, "desktop"),
        )
        .await;
    }

    let deleted = tinylinkd::analytics::cleanup_old_clicks(
        &context.db,
        tinylinkd::analytics::CLICK_RETENTION_DAYS,
        now,
    )
    .await
    .expect("cleanup");
    assert_eq!(
        deleted, 3,
        "cleanup must delete every Click older than the window, across Links"
    );

    let remaining = context
        .get(
            &format!("/_/api/v1/links/{link_id}/clicks?limit=100"),
            Some(&token),
        )
        .await
        .json();
    assert_eq!(remaining["total"], 3, "remaining: {remaining}");
    let clicked_at: Vec<&str> = remaining["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["clicked_at"].as_str().expect("clicked_at"))
        .collect();
    assert_eq!(
        clicked_at,
        [
            "2027-01-01T00:00:00Z",
            "2026-05-31T12:00:00Z",
            "2026-03-03T00:00:00Z"
        ]
    );

    let other_remaining = context
        .get(
            &format!("/_/api/v1/links/{other_link_id}/clicks?limit=100"),
            Some(&token),
        )
        .await
        .json();
    assert_eq!(other_remaining["total"], 0);

    let second_run = tinylinkd::analytics::cleanup_old_clicks(&context.db, 90, now)
        .await
        .expect("cleanup");
    assert_eq!(second_run, 0, "cleanup must be idempotent");
}

#[tokio::test]
async fn stats_report_totals_devices_and_utc_days() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link_id = create_link(&context, &token, "stats-link").await;
    let uri = format!("/_/api/v1/links/{link_id}/stats");

    let desktop = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    let mobile = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)";
    let tablet = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)";
    let crawler = "Googlebot/2.1 (+http://www.google.com/bot.html)";
    for click in [
        SeededClick::human(
            "2026-03-01T01:00:00Z",
            "198.51.100.1",
            desktop,
            None,
            "desktop",
        ),
        SeededClick::human(
            "2026-03-01T02:00:00Z",
            "198.51.100.2",
            desktop,
            None,
            "desktop",
        ),
        SeededClick::human(
            "2026-03-01T03:00:00Z",
            "198.51.100.3",
            mobile,
            None,
            "mobile",
        ),
        SeededClick::bot("2026-03-01T04:00:00Z", "198.51.100.4", crawler),
        SeededClick::human(
            "2026-03-02T23:30:00Z",
            "198.51.100.5",
            tablet,
            None,
            "tablet",
        ),
        SeededClick::human(
            "2026-03-02T23:45:00Z",
            "198.51.100.6",
            "SomeUnknownClient/1.0",
            None,
            "unknown",
        ),
        SeededClick {
            clicked_at: "2026-03-03T00:10:00Z",
            ip: "198.51.100.7",
            user_agent: crawler,
            referer: None,
            device: "desktop",
            is_bot: true,
        },
    ] {
        insert_click(&context, link_id, click).await;
    }
    let other_link = create_link(&context, &token, "stats-other-link").await;
    insert_click(
        &context,
        other_link,
        SeededClick::human(
            "2026-03-01T05:00:00Z",
            "198.51.100.8",
            desktop,
            None,
            "desktop",
        ),
    )
    .await;

    let response = context.get(&uri, Some(&token)).await;
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
    assert_eq!(
        response.json(),
        json!({
            "total_clicks": 7,
            "human_clicks": 5,
            "bot_clicks": 2,
            "by_device": {
                "desktop": 3,
                "mobile": 1,
                "tablet": 1,
                "bot": 1,
                "unknown": 1
            },
            "by_day": [
                {"date": "2026-03-01", "total_clicks": 4, "human_clicks": 3, "bot_clicks": 1},
                {"date": "2026-03-02", "total_clicks": 2, "human_clicks": 2, "bot_clicks": 0},
                {"date": "2026-03-03", "total_clicks": 1, "human_clicks": 0, "bot_clicks": 1}
            ]
        })
    );

    let one_day = context
        .get(
            &format!("{uri}?from=2026-03-02T00:00:00Z&to=2026-03-02T23:59:59Z"),
            Some(&token),
        )
        .await
        .json();
    assert_eq!(
        one_day,
        json!({
            "total_clicks": 2,
            "human_clicks": 2,
            "bot_clicks": 0,
            "by_device": {"tablet": 1, "unknown": 1},
            "by_day": [
                {"date": "2026-03-02", "total_clicks": 2, "human_clicks": 2, "bot_clicks": 0}
            ]
        }),
        "stats must honour the time range"
    );

    let explicit_day = context
        .get(&format!("{uri}?interval=day"), Some(&token))
        .await;
    assert_eq!(explicit_day.status, StatusCode::OK);

    let invalid_interval = context
        .get(&format!("{uri}?interval=week"), Some(&token))
        .await;
    assert_eq!(invalid_interval.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid_interval.content_type(), "application/problem+json");
    assert_eq!(invalid_interval.json()["code"], "invalid_interval");

    let invalid_from = context
        .get(&format!("{uri}?from=not-a-timestamp"), Some(&token))
        .await;
    assert_eq!(invalid_from.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid_from.json()["code"], "invalid_time_range");

    let empty_link = create_link(&context, &token, "stats-empty").await;
    let empty = context
        .get(&format!("/_/api/v1/links/{empty_link}/stats"), Some(&token))
        .await
        .json();
    assert_eq!(
        empty,
        json!({
            "total_clicks": 0,
            "human_clicks": 0,
            "bot_clicks": 0,
            "by_device": {},
            "by_day": []
        })
    );
}

#[tokio::test]
async fn stats_are_limited_to_the_owner_and_admins() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let link_id = create_link(&context, &alice_token, "owned-stats").await;
    let uri = format!("/_/api/v1/links/{link_id}/stats");

    assert_eq!(
        context.get(&uri, Some(&alice_token)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        context.get(&uri, Some(&admin_token)).await.status,
        StatusCode::OK
    );

    let other_user = context.get(&uri, Some(&bob_token)).await;
    assert_eq!(other_user.status, StatusCode::FORBIDDEN);
    assert_eq!(other_user.content_type(), "application/problem+json");
    assert_eq!(other_user.json()["code"], "forbidden");

    let unknown = context
        .get("/_/api/v1/links/999999/stats", Some(&alice_token))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.json()["code"], "not_found");

    let unauthenticated = context.get(&uri, None).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthenticated.json()["code"], "authentication_required");
}
