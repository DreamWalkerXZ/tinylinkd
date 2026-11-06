mod common;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use common::{TestContext, TestResponse};
use serde_json::{Value, json};
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

async fn create_link(context: &TestContext, token: &str, slug: &str) -> Value {
    let response = context
        .post(
            "/_/api/v1/links",
            Some(token),
            json!({"destination_url": "https://example.com/destination", "slug": slug}),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

async fn patch_link(context: &TestContext, token: &str, link_id: i64, body: Value) -> TestResponse {
    context
        .request(
            Method::PATCH,
            &format!("/_/api/v1/links/{link_id}"),
            Some(token),
            Some(body),
        )
        .await
}

fn link_id(link: &Value) -> i64 {
    link["id"].as_i64().expect("link id")
}

fn location(response: &TestResponse) -> Option<&str> {
    response
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
}

async fn click_count(context: &TestContext) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM clicks")
        .fetch_one(context.db.read_pool())
        .await
        .expect("count clicks")
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

#[tokio::test]
async fn api_link_creation_accepts_an_expiry_like_the_ui_and_normalizes_it_to_utc() {
    let context = TestContext::new().await;
    let (_user, token) = create_user_with_token(&context, "alice", Role::User).await;

    let response = context
        .post(
            "/_/api/v1/links",
            Some(&token),
            json!({
                "destination_url": "https://example.com/expiring",
                "slug": "api-expiry",
                "expires_at": "2030-01-02T05:04:05+02:00",
            }),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let link = response.json();
    assert_eq!(link["expires_at"], "2030-01-02T03:04:05Z");
    assert_eq!(link["status"], "active");

    let redirect = context.get("/api-expiry", None).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(location(&redirect), Some("https://example.com/expiring"));

    let expired = context
        .post(
            "/_/api/v1/links",
            Some(&token),
            json!({
                "destination_url": "https://example.com/gone",
                "slug": "api-expired",
                "expires_at": "2020-01-01T00:00:00Z",
            }),
        )
        .await;
    assert_eq!(
        expired.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&expired.body)
    );
    assert_eq!(expired.json()["status"], "expired");
    let page = context.get("/api-expired", None).await;
    assert_eq!(page.status, StatusCode::GONE);

    let invalid = context
        .post(
            "/_/api/v1/links",
            Some(&token),
            json!({
                "destination_url": "https://example.com/unknown",
                "slug": "api-invalid-expiry",
                "expires_at": "tomorrow",
            }),
        )
        .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid.content_type(), "application/problem+json");
    assert_eq!(invalid.json()["code"], "invalid_expires_at");
}

#[tokio::test]
async fn owner_sets_extends_and_clears_the_link_expiry() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(&context, &token, "scheduled").await;
    let id = link_id(&link);
    let uri = format!("/_/api/v1/links/{id}");

    let set = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": "2999-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(
        set.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&set.body)
    );
    let set = set.json();
    assert_eq!(set["expires_at"], "2999-01-01T00:00:00Z");
    assert_eq!(set["status"], "active");
    assert_eq!(
        context.get("/scheduled", None).await.status,
        StatusCode::FOUND
    );

    let untouched = patch_link(
        &context,
        &token,
        id,
        json!({"destination_url": "https://example.com/moved"}),
    )
    .await;
    assert_eq!(untouched.status, StatusCode::OK);
    assert_eq!(
        untouched.json()["expires_at"],
        "2999-01-01T00:00:00Z",
        "omitting `expires_at` must not clear or change it"
    );

    let expired = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": "2020-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(expired.status, StatusCode::OK);
    let expired = expired.json();
    assert_eq!(expired["expires_at"], "2020-01-01T00:00:00Z");
    assert_eq!(expired["status"], "expired");

    let read = context.get(&uri, Some(&token)).await.json();
    assert_eq!(read["expires_at"], "2020-01-01T00:00:00Z");
    assert_eq!(read["status"], "expired");

    let cleared = patch_link(&context, &token, id, json!({"expires_at": null})).await;
    assert_eq!(cleared.status, StatusCode::OK);
    let cleared = cleared.json();
    assert!(
        cleared["expires_at"].is_null(),
        "clearing the expiry must remove it: {cleared}"
    );
    assert_eq!(cleared["status"], "active");
    assert_eq!(
        context.get("/scheduled", None).await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn expired_links_serve_a_410_page_and_record_no_click() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(&context, &token, "expired-link").await;
    let id = link_id(&link);

    let active = context.get("/expired-link", None).await;
    assert_eq!(active.status, StatusCode::FOUND);
    assert_eq!(click_count(&context).await, 1);

    let expired = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": "2020-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(expired.status, StatusCode::OK);

    let page = context.get("/expired-link", None).await;
    assert_eq!(page.status, StatusCode::GONE);
    assert!(
        page.content_type().starts_with("text/html"),
        "content type: {}",
        page.content_type()
    );
    let body = String::from_utf8_lossy(&page.body);
    assert!(
        body.to_lowercase().contains("expired"),
        "the page must explain that the Link expired: {body}"
    );
    assert!(
        page.headers.get(header::LOCATION).is_none(),
        "an expired Link must not redirect"
    );
    assert_eq!(
        click_count(&context).await,
        1,
        "serving the 410 page must not record a Click"
    );

    let head = context.head("/expired-link").await;
    assert_eq!(
        head.status,
        StatusCode::GONE,
        "HEAD must return the same 410 as GET"
    );
    assert_eq!(
        click_count(&context).await,
        1,
        "a HEAD request must not record a Click"
    );
}

#[tokio::test]
async fn expiry_is_stored_and_returned_in_utc() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(&context, &token, "time-zoned").await;
    let id = link_id(&link);
    let uri = format!("/_/api/v1/links/{id}");

    let response = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": "2030-06-01T12:00:00+02:00"}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["expires_at"], "2030-06-01T10:00:00Z");

    let read = context.get(&uri, Some(&token)).await.json();
    assert_eq!(read["expires_at"], "2030-06-01T10:00:00Z");
    assert_eq!(read["status"], "active");

    let listed = context.get("/_/api/v1/links", Some(&token)).await.json();
    assert_eq!(listed["items"][0]["expires_at"], "2030-06-01T10:00:00Z");

    let west = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": "2030-06-01T12:00:00-05:00"}),
    )
    .await;
    assert_eq!(west.status, StatusCode::OK);
    assert_eq!(west.json()["expires_at"], "2030-06-01T17:00:00Z");
}

#[tokio::test]
async fn invalid_expiries_return_422_problem_details_and_change_nothing() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(&context, &token, "valid-expiry").await;
    let id = link_id(&link);
    let uri = format!("/_/api/v1/links/{id}");

    let set = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": "2999-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(set.status, StatusCode::OK);

    for invalid in [
        "tomorrow",
        "",
        "2026-13-01T00:00:00Z",
        "2026-01-01",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00Zjunk",
    ] {
        let response = patch_link(&context, &token, id, json!({"expires_at": invalid})).await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "expiry {invalid:?} was accepted"
        );
        assert_eq!(response.content_type(), "application/problem+json");
        assert_eq!(
            response.json()["code"],
            "invalid_expires_at",
            "expiry: {invalid:?}"
        );
    }

    let wrong_type = patch_link(&context, &token, id, json!({"expires_at": 1_234_567})).await;
    assert_eq!(wrong_type.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(wrong_type.content_type(), "application/problem+json");

    let read = context.get(&uri, Some(&token)).await.json();
    assert_eq!(
        read["expires_at"], "2999-01-01T00:00:00Z",
        "a rejected expiry must not change the Link"
    );
    assert_eq!(read["status"], "active");
}

#[tokio::test]
async fn an_expired_password_protected_link_returns_410_not_the_password_form() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(&context, &token, "guarded").await;
    let id = link_id(&link);

    let protected = patch_link(&context, &token, id, json!({"password": "open sesame"})).await;
    assert_eq!(protected.status, StatusCode::OK);
    let form = context.get("/guarded", None).await;
    assert_eq!(form.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&form.body).contains("<form"));

    let unlocked = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    let cookie = set_cookie(&unlocked);

    let expired = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": "2020-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(expired.status, StatusCode::OK);
    assert_eq!(expired.json()["has_password"], true);

    let page = context.get("/guarded", None).await;
    assert_eq!(
        page.status,
        StatusCode::GONE,
        "an expired Link must return 410 before asking for a password"
    );
    let body = String::from_utf8_lossy(&page.body);
    assert!(
        !body.contains("<form"),
        "the expired page must not reveal the password form: {body}"
    );
    assert!(
        body.to_lowercase().contains("expired"),
        "the page must explain that the Link expired: {body}"
    );

    let with_cookie = context
        .get_with_headers("/guarded", cookie_header(&cookie))
        .await;
    assert_eq!(
        with_cookie.status,
        StatusCode::GONE,
        "an unlock cookie must not bypass the expiry check"
    );

    let submission = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(
        submission.status,
        StatusCode::GONE,
        "submitting the password to an expired Link must not unlock it"
    );
    assert!(
        submission.headers.get(header::SET_COOKIE).is_none(),
        "an expired Link must not issue an unlock cookie"
    );
    assert_eq!(
        click_count(&context).await,
        0,
        "no request to an expired Link may record a Click"
    );

    let extended = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": "2999-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(extended.status, StatusCode::OK);
    assert_eq!(extended.json()["status"], "active");

    let form_again = context.get("/guarded", None).await;
    assert_eq!(
        form_again.status,
        StatusCode::OK,
        "extending the expiry must make the password form available again"
    );
    assert!(String::from_utf8_lossy(&form_again.body).contains("<form"));

    let redirect = context
        .get_with_headers("/guarded", cookie_header(&cookie))
        .await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(location(&redirect), Some("https://example.com/destination"));
    assert_eq!(click_count(&context).await, 1);
}

#[tokio::test]
async fn expired_links_stay_listed_and_keep_their_slug() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let expired = create_link(&context, &token, "kept-slug").await;
    let expired_id = link_id(&expired);
    let active = create_link(&context, &token, "active-slug").await;
    let active_id = link_id(&active);

    patch_link(
        &context,
        &token,
        expired_id,
        json!({"expires_at": "2020-01-01T00:00:00Z"}),
    )
    .await;
    patch_link(
        &context,
        &token,
        active_id,
        json!({"expires_at": "2999-01-01T00:00:00Z"}),
    )
    .await;

    let all = context.get("/_/api/v1/links", Some(&token)).await.json();
    assert_eq!(all["total"], 2, "expired Links remain listed: {all}");
    let expired_entry = all["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["slug"] == "kept-slug")
        .expect("the expired Link is listed");
    assert_eq!(expired_entry["status"], "expired");
    assert_eq!(expired_entry["expires_at"], "2020-01-01T00:00:00Z");

    let expired_only = context
        .get("/_/api/v1/links?status=expired", Some(&token))
        .await
        .json();
    assert_eq!(expired_only["total"], 1);
    assert_eq!(expired_only["items"][0]["slug"], "kept-slug");
    assert_eq!(expired_only["items"][0]["status"], "expired");

    let active_only = context
        .get("/_/api/v1/links?status=active", Some(&token))
        .await
        .json();
    assert_eq!(active_only["total"], 1);
    assert_eq!(active_only["items"][0]["slug"], "active-slug");
    assert_eq!(active_only["items"][0]["status"], "active");

    let read = context
        .get(&format!("/_/api/v1/links/{expired_id}"), Some(&token))
        .await
        .json();
    assert_eq!(read["status"], "expired");
    assert_eq!(read["slug"], "kept-slug");

    let redirect = context.get("/kept-slug", None).await;
    assert_eq!(redirect.status, StatusCode::GONE);

    let renamed = patch_link(
        &context,
        &token,
        expired_id,
        json!({"slug": "renamed-slug"}),
    )
    .await;
    assert_eq!(
        renamed.status,
        StatusCode::OK,
        "an expired Link can still be edited"
    );
    let renamed = renamed.json();
    assert_eq!(renamed["slug"], "renamed-slug");
    assert_eq!(renamed["status"], "expired");
    assert!(
        renamed["warning"].is_string(),
        "a Slug change still warns: {renamed}"
    );

    assert_eq!(
        context.get("/kept-slug", None).await.status,
        StatusCode::NOT_FOUND,
        "the old Slug is released immediately"
    );
    assert_eq!(
        context.get("/renamed-slug", None).await.status,
        StatusCode::GONE,
        "the expired Link keeps its new Slug until it is deleted"
    );

    let deleted = context
        .delete(&format!("/_/api/v1/links/{expired_id}"), Some(&token))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        context.get("/renamed-slug", None).await.status,
        StatusCode::NOT_FOUND,
        "deleting an expired Link releases its Slug"
    );
}

#[tokio::test]
async fn expiry_boundaries_follow_expired_at_or_before_now() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let id = link_id(&create_link(&context, &token, "boundary").await);
    let now = time::OffsetDateTime::now_utc();
    let format = |instant: time::OffsetDateTime| {
        instant
            .to_offset(time::UtcOffset::UTC)
            .format(&time::format_description::well_known::Rfc3339)
            .expect("RFC 3339 timestamp")
    };

    let at_now = patch_link(&context, &token, id, json!({"expires_at": format(now)})).await;
    assert_eq!(at_now.status, StatusCode::OK);
    assert_eq!(
        at_now.json()["status"],
        "expired",
        "an expiry equal to the current time is already expired"
    );
    assert_eq!(
        context.get("/boundary", None).await.status,
        StatusCode::GONE
    );

    let future = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": format(now + time::Duration::hours(1))}),
    )
    .await;
    assert_eq!(future.status, StatusCode::OK);
    assert_eq!(future.json()["status"], "active");
    assert_eq!(
        context.get("/boundary", None).await.status,
        StatusCode::FOUND
    );

    let past = patch_link(
        &context,
        &token,
        id,
        json!({"expires_at": format(now - time::Duration::hours(1))}),
    )
    .await;
    assert_eq!(past.status, StatusCode::OK);
    assert_eq!(past.json()["status"], "expired");
    assert_eq!(
        context.get("/boundary", None).await.status,
        StatusCode::GONE
    );
}

#[tokio::test]
async fn the_status_filter_agrees_with_the_link_status_at_the_boundary() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let id = link_id(&create_link(&context, &token, "same-second").await);
    let now = time::OffsetDateTime::now_utc();
    let whole_second = now.replace_nanosecond(0).expect("a valid timestamp");
    let expiry = whole_second
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 timestamp");

    let response = patch_link(&context, &token, id, json!({"expires_at": expiry})).await;
    assert_eq!(response.status, StatusCode::OK);
    let response = response.json();
    assert_eq!(
        response["status"], "expired",
        "an expiry earlier in the current second is in the past"
    );

    let expired = context
        .get("/_/api/v1/links?status=expired", Some(&token))
        .await
        .json();
    let active = context
        .get("/_/api/v1/links?status=active", Some(&token))
        .await
        .json();
    assert_eq!(
        expired["total"], 1,
        "the status filter must agree with the Link status: expired={expired} active={active}"
    );
    assert_eq!(active["total"], 0);
    assert_eq!(expired["items"][0]["status"], "expired");
}

#[tokio::test]
async fn only_the_owner_or_an_admin_can_set_the_expiry() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let link = create_link(&context, &alice_token, "alice-link").await;
    let id = link_id(&link);
    let uri = format!("/_/api/v1/links/{id}");

    let forbidden = patch_link(
        &context,
        &bob_token,
        id,
        json!({"expires_at": "2020-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.content_type(), "application/problem+json");
    assert_eq!(forbidden.json()["code"], "forbidden");
    let unchanged = context.get(&uri, Some(&alice_token)).await.json();
    assert!(unchanged["expires_at"].is_null());

    let unauthenticated = context
        .request(
            Method::PATCH,
            &uri,
            None,
            Some(json!({"expires_at": "2020-01-01T00:00:00Z"})),
        )
        .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let unknown = patch_link(
        &context,
        &alice_token,
        999_999,
        json!({"expires_at": "2020-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let admin = patch_link(
        &context,
        &admin_token,
        id,
        json!({"expires_at": "2020-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(admin.status, StatusCode::OK);
    assert_eq!(admin.json()["status"], "expired");
}

#[tokio::test]
async fn combined_edits_apply_the_expiry_with_the_other_fields() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(&context, &token, "combo").await;
    let id = link_id(&link);

    let combined = patch_link(
        &context,
        &token,
        id,
        json!({
            "destination_url": "https://example.com/combo",
            "slug": "combo-renamed",
            "password": "open sesame",
            "expires_at": "2020-01-01T00:00:00Z"
        }),
    )
    .await;
    assert_eq!(
        combined.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&combined.body)
    );
    let combined = combined.json();
    assert_eq!(combined["slug"], "combo-renamed");
    assert_eq!(combined["destination_url"], "https://example.com/combo");
    assert_eq!(combined["has_password"], true);
    assert_eq!(combined["expires_at"], "2020-01-01T00:00:00Z");
    assert_eq!(combined["status"], "expired");
    assert!(combined["warning"].is_string());

    let expired_page = context.get("/combo-renamed", None).await;
    assert_eq!(expired_page.status, StatusCode::GONE);
    assert_eq!(
        context.get("/combo", None).await.status,
        StatusCode::NOT_FOUND
    );

    let reactivated = patch_link(
        &context,
        &token,
        id,
        json!({"password": null, "expires_at": null}),
    )
    .await;
    assert_eq!(reactivated.status, StatusCode::OK);
    let reactivated = reactivated.json();
    assert_eq!(reactivated["has_password"], false);
    assert!(reactivated["expires_at"].is_null());
    assert_eq!(reactivated["status"], "active");

    let redirect = context.get("/combo-renamed", None).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(location(&redirect), Some("https://example.com/combo"));
}
