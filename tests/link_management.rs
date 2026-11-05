mod common;

use axum::http::{Method, StatusCode, header};
use common::TestContext;
use serde_json::{Value, json};
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

async fn patch_link(
    context: &TestContext,
    token: &str,
    link_id: i64,
    body: Value,
) -> common::TestResponse {
    context
        .request(
            Method::PATCH,
            &format!("/_/api/v1/links/{link_id}"),
            Some(token),
            Some(body),
        )
        .await
}

async fn list_links_json(context: &TestContext, token: &str, query: &str) -> Value {
    let response = context
        .get(&format!("/_/api/v1/links?{query}"), Some(token))
        .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

fn link_id(link: &Value) -> i64 {
    link["id"].as_i64().expect("link id")
}

fn location(response: &common::TestResponse) -> Option<&str> {
    response
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn deleting_a_link_cascades_clicks_and_releases_the_slug() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let link = create_link(
        &context,
        &alice_token,
        json!({
            "destination_url": "https://example.com/bye",
            "slug": "delete-me"
        }),
    )
    .await;
    let id = link_id(&link);

    assert_eq!(
        context.get("/delete-me", None).await.status,
        StatusCode::FOUND
    );
    assert_eq!(
        context.get("/delete-me", None).await.status,
        StatusCode::FOUND
    );
    let clicks_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM clicks")
        .fetch_one(context.db.read_pool())
        .await
        .expect("count clicks");
    assert_eq!(clicks_before, 2);

    let response = context
        .delete(&format!("/_/api/v1/links/{id}"), Some(&alice_token))
        .await;

    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(response.body.is_empty(), "204 must have an empty body");

    let read = context
        .get(&format!("/_/api/v1/links/{id}"), Some(&alice_token))
        .await;
    assert_eq!(read.status, StatusCode::NOT_FOUND);
    assert_eq!(read.content_type(), "application/problem+json");
    assert_eq!(read.json()["code"], "not_found");

    let redirect = context.get("/delete-me", None).await;
    assert_eq!(redirect.status, StatusCode::NOT_FOUND);

    let clicks_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM clicks")
        .fetch_one(context.db.read_pool())
        .await
        .expect("count clicks");
    assert_eq!(clicks_after, 0, "deleting a Link must cascade its Clicks");

    let replacement = create_link(
        &context,
        &bob_token,
        json!({
            "destination_url": "https://example.com/bob",
            "slug": "delete-me"
        }),
    )
    .await;
    assert_eq!(replacement["slug"], "delete-me");
    let redirect = context.get("/delete-me", None).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(location(&redirect), Some("https://example.com/bob"));
}

#[tokio::test]
async fn deleting_an_unknown_link_returns_404() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;

    let response = context.delete("/_/api/v1/links/999999", Some(&token)).await;

    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "not_found");
}

#[tokio::test]
async fn only_the_owner_or_an_admin_can_edit_or_delete_a_link() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let link = create_link(
        &context,
        &alice_token,
        json!({
            "destination_url": "https://example.com/alice",
            "slug": "alice-owned"
        }),
    )
    .await;
    let id = link_id(&link);
    let uri = format!("/_/api/v1/links/{id}");

    let bob_edit = patch_link(
        &context,
        &bob_token,
        id,
        json!({"destination_url": "https://example.com/bob"}),
    )
    .await;
    assert_eq!(bob_edit.status, StatusCode::FORBIDDEN);
    assert_eq!(bob_edit.content_type(), "application/problem+json");
    assert_eq!(bob_edit.json()["code"], "forbidden");

    let bob_delete = context.delete(&uri, Some(&bob_token)).await;
    assert_eq!(bob_delete.status, StatusCode::FORBIDDEN);
    assert_eq!(bob_delete.json()["code"], "forbidden");

    let unchanged = context.get(&uri, Some(&alice_token)).await.json();
    assert_eq!(unchanged["destination_url"], "https://example.com/alice");
    assert_eq!(unchanged["slug"], "alice-owned");

    let admin_edit = patch_link(
        &context,
        &admin_token,
        id,
        json!({"destination_url": "https://example.com/admin-edited"}),
    )
    .await;
    assert_eq!(admin_edit.status, StatusCode::OK);
    assert_eq!(
        admin_edit.json()["destination_url"],
        "https://example.com/admin-edited"
    );

    let admin_delete = context.delete(&uri, Some(&admin_token)).await;
    assert_eq!(admin_delete.status, StatusCode::NO_CONTENT);

    let gone = context.get(&uri, Some(&alice_token)).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn editing_an_unknown_link_returns_404() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;

    let response = context
        .request(
            Method::PATCH,
            "/_/api/v1/links/999999",
            Some(&token),
            Some(json!({"destination_url": "https://example.com/"})),
        )
        .await;

    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "not_found");
}

#[tokio::test]
async fn editing_and_deleting_require_authentication() {
    let context = TestContext::new().await;

    let edit = context
        .request(
            Method::PATCH,
            "/_/api/v1/links/1",
            None,
            Some(json!({"destination_url": "https://example.com/"})),
        )
        .await;
    assert_eq!(edit.status, StatusCode::UNAUTHORIZED);
    assert_eq!(edit.content_type(), "application/problem+json");
    assert_eq!(edit.json()["code"], "authentication_required");

    let delete = context.delete("/_/api/v1/links/1", None).await;
    assert_eq!(delete.status, StatusCode::UNAUTHORIZED);
    assert_eq!(delete.json()["code"], "authentication_required");
}

#[tokio::test]
async fn another_link_can_claim_the_released_slug_immediately() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let alice_link = create_link(
        &context,
        &alice_token,
        json!({
            "destination_url": "https://example.com/alice",
            "slug": "shared-slug"
        }),
    )
    .await;

    patch_link(
        &context,
        &alice_token,
        link_id(&alice_link),
        json!({"slug": "renamed-slug"}),
    )
    .await;

    let bob_link = create_link(
        &context,
        &bob_token,
        json!({
            "destination_url": "https://example.com/bob",
            "slug": "shared-slug"
        }),
    )
    .await;
    assert_eq!(bob_link["slug"], "shared-slug");

    let redirect = context.get("/shared-slug", None).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(
        location(&redirect),
        Some("https://example.com/bob"),
        "the released Slug must resolve to its new owner"
    );

    let alice_redirect = context.get("/renamed-slug", None).await;
    assert_eq!(alice_redirect.status, StatusCode::FOUND);
    assert_eq!(location(&alice_redirect), Some("https://example.com/alice"));
}

#[tokio::test]
async fn a_taken_slug_returns_409_and_leaves_the_link_unchanged() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let alice_link = create_link(
        &context,
        &alice_token,
        json!({
            "destination_url": "https://example.com/alice",
            "slug": "alice-slug"
        }),
    )
    .await;
    let alice_id = link_id(&alice_link);
    create_link(
        &context,
        &bob_token,
        json!({
            "destination_url": "https://example.com/bob",
            "slug": "bob-slug"
        }),
    )
    .await;

    let response = patch_link(
        &context,
        &alice_token,
        alice_id,
        json!({
            "destination_url": "https://example.com/changed",
            "slug": "bob-slug"
        }),
    )
    .await;

    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "slug_taken");

    let read = context
        .get(&format!("/_/api/v1/links/{alice_id}"), Some(&alice_token))
        .await
        .json();
    assert_eq!(read["slug"], "alice-slug");
    assert_eq!(
        read["destination_url"], "https://example.com/alice",
        "a failed Slug change must not apply the Destination URL edit: {read}"
    );

    let redirect = context.get("/alice-slug", None).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(location(&redirect), Some("https://example.com/alice"));
}

#[tokio::test]
async fn editing_validates_the_destination_url_and_slug() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(
        &context,
        &token,
        json!({
            "destination_url": "https://example.com/",
            "slug": "valid-slug"
        }),
    )
    .await;
    let id = link_id(&link);

    for destination in ["not a url", "/relative", "ftp://example.com/file", ""] {
        let response = patch_link(
            &context,
            &token,
            id,
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

    for slug in [
        "",
        "ab",
        "Uppercase",
        "-leading",
        "trailing-",
        "under_score",
    ] {
        let response = patch_link(&context, &token, id, json!({"slug": slug})).await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "slug {slug:?} was accepted"
        );
        assert_eq!(response.json()["code"], "invalid_slug", "slug: {slug:?}");
    }

    let read = context
        .get(&format!("/_/api/v1/links/{id}"), Some(&token))
        .await
        .json();
    assert_eq!(read["slug"], "valid-slug");
    assert_eq!(read["destination_url"], "https://example.com/");
}

#[tokio::test]
async fn changing_the_slug_returns_a_warning_and_releases_the_old_slug() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(
        &context,
        &token,
        json!({
            "destination_url": "https://example.com/destination",
            "slug": "old-slug"
        }),
    )
    .await;
    let id = link_id(&link);

    let response = patch_link(&context, &token, id, json!({"slug": "new-slug"})).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let updated = response.json();
    assert_eq!(updated["slug"], "new-slug");
    assert_eq!(updated["short_url"], format!("{BASE_URL}/new-slug"));
    let warning = updated["warning"]
        .as_str()
        .unwrap_or_else(|| panic!("missing warning: {updated}"));
    assert!(
        warning.contains("stops working"),
        "warning must explain the old URL stops working: {warning}"
    );
    assert!(
        warning.contains("reused"),
        "warning must explain the old URL may be reused: {warning}"
    );

    let old = context.get("/old-slug", None).await;
    assert_eq!(old.status, StatusCode::NOT_FOUND);

    let new = context.get("/new-slug", None).await;
    assert_eq!(new.status, StatusCode::FOUND);
    assert_eq!(location(&new), Some("https://example.com/destination"));

    let read = context
        .get(&format!("/_/api/v1/links/{id}"), Some(&token))
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let read = read.json();
    assert_eq!(read["slug"], "new-slug");
    assert!(
        read.get("warning").is_none(),
        "a read must not carry a warning: {read}"
    );
}

async fn seed_expiry(context: &TestContext, link_id: i64, expires_at: &str) {
    sqlx::query("UPDATE links SET expires_at = ? WHERE id = ?")
        .bind(expires_at)
        .bind(link_id)
        .execute(context.db.write_pool())
        .await
        .expect("seed expires_at");
}

#[tokio::test]
async fn list_filters_by_status() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let active = create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/a", "slug": "no-expiry"}),
    )
    .await;
    let expired = create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/b", "slug": "past-expiry"}),
    )
    .await;
    let future = create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/c", "slug": "future-expiry"}),
    )
    .await;
    seed_expiry(&context, link_id(&expired), "2020-01-01T00:00:00Z").await;
    seed_expiry(&context, link_id(&future), "2999-01-01T00:00:00Z").await;

    let all = context.get("/_/api/v1/links", Some(&token)).await.json();
    assert_eq!(all["total"], 3);

    let active_list = context
        .get("/_/api/v1/links?status=active", Some(&token))
        .await
        .json();
    assert_eq!(active_list["total"], 2);
    let slugs: Vec<&str> = active_list["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["slug"].as_str().expect("slug"))
        .collect();
    assert!(slugs.contains(&"no-expiry"), "slugs: {slugs:?}");
    assert!(slugs.contains(&"future-expiry"), "slugs: {slugs:?}");
    assert!(!slugs.contains(&"past-expiry"), "slugs: {slugs:?}");
    assert_eq!(active["status"], "active");
    assert_eq!(future["status"], "active");

    let expired_read = context
        .get(
            &format!("/_/api/v1/links/{}", link_id(&expired)),
            Some(&token),
        )
        .await
        .json();
    assert_eq!(expired_read["status"], "expired");

    let expired_list = context
        .get("/_/api/v1/links?status=expired", Some(&token))
        .await
        .json();
    assert_eq!(expired_list["total"], 1);
    assert_eq!(expired_list["items"][0]["slug"], "past-expiry");
    assert_eq!(expired_list["items"][0]["status"], "expired");

    let invalid = context
        .get("/_/api/v1/links?status=disabled", Some(&token))
        .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid.content_type(), "application/problem+json");
    assert_eq!(invalid.json()["code"], "invalid_status");
}

#[tokio::test]
async fn list_filters_by_search_text_on_slug_and_destination_url() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    create_link(
        &context,
        &alice_token,
        json!({
            "destination_url": "https://example.com/very/long/path",
            "slug": "launch-2026"
        }),
    )
    .await;
    create_link(
        &context,
        &alice_token,
        json!({
            "destination_url": "https://example.com/100%_done",
            "slug": "percent-link"
        }),
    )
    .await;
    create_link(
        &context,
        &alice_token,
        json!({
            "destination_url": "https://example.com/100Xdone",
            "slug": "wildcard-link"
        }),
    )
    .await;
    create_link(
        &context,
        &bob_token,
        json!({
            "destination_url": "https://example.com/launch/bob",
            "slug": "launch-bob"
        }),
    )
    .await;

    let slug_match = list_links_json(&context, &alice_token, "q=launch").await;
    assert_eq!(slug_match["total"], 1);
    assert_eq!(slug_match["items"][0]["slug"], "launch-2026");

    let destination_match = list_links_json(&context, &alice_token, "q=very%2Flong").await;
    assert_eq!(destination_match["total"], 1);
    assert_eq!(destination_match["items"][0]["slug"], "launch-2026");

    let literal_percent = list_links_json(&context, &alice_token, "q=100%25").await;
    assert_eq!(
        literal_percent["total"], 1,
        "`%` must be escaped, not a wildcard: {literal_percent}"
    );
    assert_eq!(literal_percent["items"][0]["slug"], "percent-link");

    let literal_underscore = list_links_json(&context, &alice_token, "q=%25_done").await;
    assert_eq!(
        literal_underscore["total"], 1,
        "`_` must be escaped, not a wildcard: {literal_underscore}"
    );
    assert_eq!(literal_underscore["items"][0]["slug"], "percent-link");

    let no_match = list_links_json(&context, &alice_token, "q=nothing-matches-this").await;
    assert_eq!(no_match["total"], 0);
    assert!(no_match["items"].as_array().expect("items").is_empty());
}

#[tokio::test]
async fn list_sorts_by_created_at_and_paginates() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    for slug in ["first-link", "second-link", "third-link"] {
        create_link(
            &context,
            &token,
            json!({"destination_url": "https://example.com/", "slug": slug}),
        )
        .await;
    }

    let slugs = |value: &Value| -> Vec<String> {
        value["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["slug"].as_str().expect("slug").to_string())
            .collect()
    };

    let default_order = context.get("/_/api/v1/links", Some(&token)).await.json();
    assert_eq!(
        slugs(&default_order),
        ["third-link", "second-link", "first-link"],
        "default sort must be newest first"
    );

    let newest_first = context
        .get("/_/api/v1/links?sort=-created_at", Some(&token))
        .await
        .json();
    assert_eq!(slugs(&newest_first), slugs(&default_order));

    let oldest_first = context
        .get("/_/api/v1/links?sort=created_at", Some(&token))
        .await
        .json();
    assert_eq!(
        slugs(&oldest_first),
        ["first-link", "second-link", "third-link"]
    );

    let page = context
        .get(
            "/_/api/v1/links?sort=created_at&limit=1&offset=1",
            Some(&token),
        )
        .await
        .json();
    assert_eq!(page["total"], 3);
    assert_eq!(page["limit"], 1);
    assert_eq!(page["offset"], 1);
    assert_eq!(slugs(&page), ["second-link"]);

    let invalid = context.get("/_/api/v1/links?sort=slug", Some(&token)).await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid.json()["code"], "invalid_sort");

    let invalid_limit = context.get("/_/api/v1/links?limit=0", Some(&token)).await;
    assert_eq!(invalid_limit.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid_limit.json()["code"], "invalid_pagination");
}

#[tokio::test]
async fn admins_can_filter_by_owner_id_and_see_all_links() {
    let context = TestContext::new().await;
    let (alice, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (bob, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    create_link(
        &context,
        &alice_token,
        json!({"destination_url": "https://example.com/a1", "slug": "alice-one"}),
    )
    .await;
    create_link(
        &context,
        &alice_token,
        json!({"destination_url": "https://example.com/a2", "slug": "alice-two"}),
    )
    .await;
    create_link(
        &context,
        &bob_token,
        json!({"destination_url": "https://example.com/b1", "slug": "bob-one"}),
    )
    .await;

    let everything = context
        .get("/_/api/v1/links", Some(&admin_token))
        .await
        .json();
    assert_eq!(everything["total"], 3, "Admins see all Links");

    let alice_links = context
        .get(
            &format!("/_/api/v1/links?owner_id={}", alice.id),
            Some(&admin_token),
        )
        .await
        .json();
    assert_eq!(alice_links["total"], 2);
    assert!(
        alice_links["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|item| item["owner_id"] == alice.id),
        "{alice_links}"
    );

    let bob_links = context
        .get(
            &format!("/_/api/v1/links?owner_id={}", bob.id),
            Some(&admin_token),
        )
        .await
        .json();
    assert_eq!(bob_links["total"], 1);
    assert_eq!(bob_links["items"][0]["slug"], "bob-one");

    let unknown_owner = context
        .get("/_/api/v1/links?owner_id=999999", Some(&admin_token))
        .await
        .json();
    assert_eq!(unknown_owner["total"], 0);

    let bob_default = context
        .get("/_/api/v1/links", Some(&bob_token))
        .await
        .json();
    assert_eq!(bob_default["total"], 1);
    assert_eq!(bob_default["items"][0]["slug"], "bob-one");

    let forbidden = context
        .get(
            &format!("/_/api/v1/links?owner_id={}", alice.id),
            Some(&bob_token),
        )
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.content_type(), "application/problem+json");
    assert_eq!(forbidden.json()["code"], "forbidden");
}

#[tokio::test]
async fn owner_edits_the_destination_url() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(
        &context,
        &token,
        json!({
            "destination_url": "https://example.com/old",
            "slug": "edit-target"
        }),
    )
    .await;

    let response = patch_link(
        &context,
        &token,
        link_id(&link),
        json!({"destination_url": "https://example.com/new"}),
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let updated = response.json();
    assert_eq!(updated["id"], link["id"]);
    assert_eq!(updated["destination_url"], "https://example.com/new");
    assert_eq!(updated["slug"], "edit-target");
    assert_eq!(updated["short_url"], format!("{BASE_URL}/edit-target"));
    assert!(
        updated.get("warning").is_none(),
        "a Destination URL edit must not warn: {updated}"
    );

    let redirect = context.get("/edit-target", None).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(location(&redirect), Some("https://example.com/new"));

    let read = context
        .get(&format!("/_/api/v1/links/{}", link_id(&link)), Some(&token))
        .await
        .json();
    assert_eq!(read["destination_url"], "https://example.com/new");
    assert!(read.get("warning").is_none(), "unexpected warning: {read}");
}
