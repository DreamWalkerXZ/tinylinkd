mod common;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use common::{TestContext, TestResponse, create_link, create_user_with_token};
use serde_json::{Value, json};
use tinylinkd::users::Role;

const BASE_URL: &str = "http://localhost:8080";

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

fn assert_no_password_hash(response: &TestResponse) {
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        !body.contains("password_hash"),
        "the response must not mention the password hash: {body}"
    );
    assert!(
        !body.contains("$argon2"),
        "the response must not contain a password hash: {body}"
    );
}

async fn submit_password(context: &TestContext, slug: &str, password: &str) -> TestResponse {
    submit_password_with_headers(context, slug, password, HeaderMap::new()).await
}

async fn submit_password_with_headers(
    context: &TestContext,
    slug: &str,
    password: &str,
    headers: HeaderMap,
) -> TestResponse {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("/{slug}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    let request = builder
        .body(Body::from(format!("password={password}")))
        .expect("request");
    context.send(request).await
}

async fn submit_password_to_uri(context: &TestContext, uri: &str, password: &str) -> TestResponse {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("password={password}")))
        .expect("request");
    context.send(request).await
}

fn location(response: &TestResponse) -> Option<&str> {
    response
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
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

async fn click_count(context: &TestContext) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM clicks")
        .fetch_one(context.db.read_pool())
        .await
        .expect("count clicks")
}

async fn protect_link(context: &TestContext, token: &str, slug: &str, password: &str) -> i64 {
    let link = create_link(
        context,
        token,
        json!({"destination_url": "https://example.com/destination", "slug": slug}),
    )
    .await;
    let id = link_id(&link);
    let response = patch_link(context, token, id, json!({"password": password})).await;
    assert_eq!(response.status, StatusCode::OK);
    id
}

#[tokio::test]
async fn five_failures_rate_limit_further_attempts_per_ip_and_slug() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    protect_link(&context, &token, "guarded", "open sesame").await;
    protect_link(&context, &token, "other-link", "different").await;

    for attempt in 0..5 {
        let response = submit_password(&context, "guarded", "wrong").await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt}"
        );
    }

    let limited = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(
        limited.status,
        StatusCode::TOO_MANY_REQUESTS,
        "even a correct password is rejected once the limit is reached"
    );
    let retry_after = limited
        .headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("missing Retry-After: {:?}", limited.headers));
    let seconds: u64 = retry_after.parse().expect("Retry-After is in seconds");
    assert!(seconds >= 1, "Retry-After: {retry_after}");
    assert!(limited.headers.get(header::SET_COOKIE).is_none());
    assert_eq!(click_count(&context).await, 0, "a 429 records no Click");

    let other_slug = submit_password(&context, "other-link", "different").await;
    assert_eq!(
        other_slug.status,
        StatusCode::SEE_OTHER,
        "the limit is scoped to one IP and one Slug"
    );
}

#[tokio::test]
async fn the_rate_limit_uses_the_forwarded_client_ip_when_trusted() {
    let context = TestContext::with_config(BASE_URL, true).await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    protect_link(&context, &token, "guarded", "open sesame").await;

    let forwarded = |ip: &'static str| {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static(ip));
        headers
    };

    for _ in 0..5 {
        let response =
            submit_password_with_headers(&context, "guarded", "wrong", forwarded("198.51.100.1"))
                .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }
    let limited = submit_password_with_headers(
        &context,
        "guarded",
        "open sesame",
        forwarded("198.51.100.1"),
    )
    .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);

    let other_ip = submit_password_with_headers(
        &context,
        "guarded",
        "open sesame",
        forwarded("198.51.100.2"),
    )
    .await;
    assert_eq!(
        other_ip.status,
        StatusCode::SEE_OTHER,
        "another client IP is not rate-limited"
    );
}

#[tokio::test]
async fn changing_the_password_invalidates_existing_unlock_cookies() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let id = protect_link(&context, &token, "guarded", "old password").await;

    let unlocked = submit_password(&context, "guarded", "old password").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    let old_cookie = set_cookie(&unlocked);

    let before = context
        .get_with_headers("/guarded", cookie_header(&old_cookie))
        .await;
    assert_eq!(before.status, StatusCode::FOUND);

    let change = patch_link(&context, &token, id, json!({"password": "new password"})).await;
    assert_eq!(change.status, StatusCode::OK);

    let after = context
        .get_with_headers("/guarded", cookie_header(&old_cookie))
        .await;
    assert_eq!(
        after.status,
        StatusCode::OK,
        "the old unlock cookie must be invalid after a password change"
    );
    assert!(String::from_utf8_lossy(&after.body).contains("<form"));

    let old_password = submit_password(&context, "guarded", "old password").await;
    assert_eq!(old_password.status, StatusCode::UNAUTHORIZED);

    let new_password = submit_password(&context, "guarded", "new password").await;
    assert_eq!(new_password.status, StatusCode::SEE_OTHER);
    let redirect = context
        .get_with_headers("/guarded", cookie_header(&set_cookie(&new_password)))
        .await;
    assert_eq!(redirect.status, StatusCode::FOUND);
}

#[tokio::test]
async fn clearing_the_password_makes_the_link_public_and_invalidates_unlocks() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let id = protect_link(&context, &token, "guarded", "open sesame").await;

    let unlocked = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    let old_cookie = set_cookie(&unlocked);

    let clear = patch_link(&context, &token, id, json!({"password": null})).await;
    assert_eq!(clear.status, StatusCode::OK);
    assert_eq!(clear.json()["has_password"], false);

    let with_stale_cookie = context
        .get_with_headers("/guarded", cookie_header(&old_cookie))
        .await;
    assert_eq!(with_stale_cookie.status, StatusCode::FOUND);
    assert_eq!(
        location(&with_stale_cookie),
        Some("https://example.com/destination")
    );

    let without_cookie = context.get("/guarded", None).await;
    assert_eq!(
        without_cookie.status,
        StatusCode::FOUND,
        "a Link without a password redirects without the form"
    );
}

#[tokio::test]
async fn the_unlock_cookie_is_secure_when_the_base_url_is_https() {
    let context = TestContext::with_config("https://short.example", false).await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    protect_link(&context, &token, "guarded", "open sesame").await;

    let unlocked = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    let cookie = set_cookie(&unlocked);
    assert!(cookie.contains("Secure"), "cookie: {cookie}");
    assert!(cookie.contains("HttpOnly"), "cookie: {cookie}");
    assert!(cookie.contains("SameSite=Lax"), "cookie: {cookie}");
    assert!(cookie.contains("Path=/"), "cookie: {cookie}");
}

#[tokio::test]
async fn a_tampered_or_foreign_unlock_cookie_does_not_unlock_the_link() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    protect_link(&context, &token, "guarded", "open sesame").await;
    protect_link(&context, &token, "other-link", "different").await;

    let unlocked = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    let cookie = set_cookie(&unlocked);
    let pair = cookie
        .split(';')
        .next()
        .expect("the cookie pair before the attributes")
        .to_string();

    let mut tampered = pair.clone();
    let signature_start = tampered.rfind('.').expect("a signature separator") + 1;
    let first_signature_byte = tampered.as_bytes()[signature_start];
    let replacement = if first_signature_byte == b'A' {
        "B"
    } else {
        "A"
    };
    tampered.replace_range(signature_start..signature_start + 1, replacement);
    let response = context
        .get_with_headers("/guarded", cookie_header(&tampered))
        .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "a tampered cookie is rejected"
    );
    assert!(String::from_utf8_lossy(&response.body).contains("<form"));

    let mut foreign = HeaderMap::new();
    foreign.insert(
        header::COOKIE,
        HeaderValue::from_str(&pair.replace("tld_link_unlock_1", "tld_link_unlock_2"))
            .expect("cookie header"),
    );
    let response = context.get_with_headers("/other-link", foreign).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "a cookie for another Link is rejected"
    );
}

#[tokio::test]
async fn a_post_to_a_link_without_a_password_is_not_a_form_submission() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/", "slug": "open-link"}),
    )
    .await;

    let response = submit_password(&context, "open-link", "anything").await;

    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response
            .headers
            .get(header::ALLOW)
            .and_then(|value| value.to_str().ok()),
        Some("GET, HEAD")
    );
    assert_eq!(click_count(&context).await, 0);
}

#[tokio::test]
async fn a_protected_link_asks_for_a_password_and_unlocks_with_the_cookie() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/destination", "slug": "guarded"}),
    )
    .await;
    let id = link_id(&link);
    let response = patch_link(&context, &token, id, json!({"password": "open sesame"})).await;
    assert_eq!(response.status, StatusCode::OK);

    let form = context.get("/guarded", None).await;
    assert_eq!(form.status, StatusCode::OK);
    assert!(
        form.content_type().starts_with("text/html"),
        "content type: {}",
        form.content_type()
    );
    let body = String::from_utf8_lossy(&form.body);
    assert!(body.contains("<form"), "body: {body}");
    assert!(body.contains("password"), "body: {body}");
    assert!(
        body.contains("/guarded"),
        "the form must submit back to the short URL: {body}"
    );
    assert_eq!(
        click_count(&context).await,
        0,
        "the form must not record a Click"
    );

    let wrong = submit_password(&context, "guarded", "wrong password").await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.headers.get(header::SET_COOKIE).is_none());
    let body = String::from_utf8_lossy(&wrong.body);
    assert!(body.contains("<form"), "body: {body}");
    assert!(
        body.to_lowercase().contains("incorrect"),
        "the wrong-password form must explain the error: {body}"
    );
    assert_eq!(
        click_count(&context).await,
        0,
        "a wrong password must not record a Click"
    );

    let unlocked = submit_password(&context, "guarded", "open sesame").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&unlocked), Some("/guarded"));
    let cookie = set_cookie(&unlocked);
    assert!(cookie.contains("HttpOnly"), "cookie: {cookie}");
    assert!(cookie.contains("SameSite=Lax"), "cookie: {cookie}");
    assert!(cookie.contains("Path=/"), "cookie: {cookie}");
    assert!(cookie.contains("Max-Age=3600"), "cookie: {cookie}");
    assert!(
        !cookie.contains("Secure"),
        "a plain-HTTP base URL must not set Secure: {cookie}"
    );

    let redirect = context
        .get_with_headers("/guarded", cookie_header(&cookie))
        .await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(location(&redirect), Some("https://example.com/destination"));
    assert_eq!(
        click_count(&context).await,
        1,
        "the unlocked redirect records one Click"
    );

    let again = context
        .get_with_headers("/guarded", cookie_header(&cookie))
        .await;
    assert_eq!(again.status, StatusCode::FOUND);
    assert_eq!(click_count(&context).await, 2);
}

#[tokio::test]
async fn the_query_string_survives_the_password_form_and_unlock_redirect() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    protect_link(&context, &token, "guarded", "open sesame").await;
    let uri = "/guarded?utm_source=newsletter&x=1";
    let form_action = "action=\"/guarded?utm_source=newsletter&#38;x=1\"";

    let form = context.get(uri, None).await;
    assert_eq!(form.status, StatusCode::OK);
    let body = String::from_utf8_lossy(&form.body);
    assert!(
        body.contains(form_action),
        "the form must submit back with the query string: {body}"
    );

    let wrong = submit_password_to_uri(&context, uri, "wrong password").await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let body = String::from_utf8_lossy(&wrong.body);
    assert!(
        body.contains(form_action),
        "the retried form must keep the query string: {body}"
    );

    let unlocked = submit_password_to_uri(&context, uri, "open sesame").await;
    assert_eq!(unlocked.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&unlocked), Some(uri));

    let redirect = context
        .get_with_headers(uri, cookie_header(&set_cookie(&unlocked)))
        .await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(
        location(&redirect),
        Some("https://example.com/destination?utm_source=newsletter&x=1")
    );
}

#[tokio::test]
async fn only_the_owner_or_an_admin_can_change_a_link_password() {
    let context = TestContext::new().await;
    let (_, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (_, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let link = create_link(
        &context,
        &alice_token,
        json!({"destination_url": "https://example.com/", "slug": "alice-link"}),
    )
    .await;
    let id = link_id(&link);
    let uri = format!("/_/api/v1/links/{id}");

    let forbidden = patch_link(&context, &bob_token, id, json!({"password": "intruder"})).await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.content_type(), "application/problem+json");
    assert_eq!(forbidden.json()["code"], "forbidden");

    let unchanged = context.get(&uri, Some(&alice_token)).await.json();
    assert_eq!(
        unchanged["has_password"], false,
        "a rejected edit must not set a password: {unchanged}"
    );

    let unauthenticated = context
        .request(
            Method::PATCH,
            &uri,
            None,
            Some(json!({"password": "intruder"})),
        )
        .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let admin = patch_link(&context, &admin_token, id, json!({"password": "admin-set"})).await;
    assert_eq!(admin.status, StatusCode::OK);
    assert_eq!(admin.json()["has_password"], true);

    let unknown = patch_link(
        &context,
        &alice_token,
        999_999,
        json!({"password": "whatever"}),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.json()["code"], "not_found");
}

#[tokio::test]
async fn the_owner_sets_changes_and_clears_a_link_password() {
    let context = TestContext::new().await;
    let (_, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = create_link(
        &context,
        &token,
        json!({"destination_url": "https://example.com/", "slug": "guarded"}),
    )
    .await;
    let id = link_id(&link);
    assert_eq!(link["has_password"], false);
    let uri = format!("/_/api/v1/links/{id}");

    let set = patch_link(&context, &token, id, json!({"password": "open sesame"})).await;
    assert_eq!(
        set.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&set.body)
    );
    assert_eq!(set.json()["has_password"], true);
    assert_no_password_hash(&set);

    let read = context.get(&uri, Some(&token)).await;
    assert_eq!(read.json()["has_password"], true);
    assert_no_password_hash(&read);

    let list = context.get("/_/api/v1/links", Some(&token)).await;
    assert_eq!(list.json()["items"][0]["has_password"], true);
    assert_no_password_hash(&list);

    let change = patch_link(&context, &token, id, json!({"password": "another secret"})).await;
    assert_eq!(change.status, StatusCode::OK);
    assert_eq!(change.json()["has_password"], true);
    assert_no_password_hash(&change);

    let untouched = patch_link(
        &context,
        &token,
        id,
        json!({"destination_url": "https://example.com/moved"}),
    )
    .await;
    assert_eq!(untouched.status, StatusCode::OK);
    assert_eq!(
        untouched.json()["has_password"],
        true,
        "omitting `password` must not clear it"
    );

    let clear = patch_link(&context, &token, id, json!({"password": null})).await;
    assert_eq!(
        clear.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&clear.body)
    );
    assert_eq!(clear.json()["has_password"], false);
    assert_no_password_hash(&clear);

    let read = context.get(&uri, Some(&token)).await;
    assert_eq!(read.json()["has_password"], false);

    let empty = patch_link(&context, &token, id, json!({"password": ""})).await;
    assert_eq!(empty.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(empty.content_type(), "application/problem+json");
    assert_eq!(empty.json()["code"], "invalid_password");
}

#[tokio::test]
async fn api_link_creation_accepts_a_password_like_the_ui() {
    let context = TestContext::new().await;
    let (_user, token) = create_user_with_token(&context, "alice", Role::User).await;

    let response = context
        .post(
            "/_/api/v1/links",
            Some(&token),
            json!({
                "destination_url": "https://example.com/api-created",
                "slug": "api-created",
                "password": "s3cret-pass",
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
    assert_eq!(link["has_password"], true);
    assert_no_password_hash(&response);

    // An API-created Link is indistinguishable from a UI-created one: it asks
    // for the password before redirecting.
    let form = context.get("/api-created", None).await;
    assert_eq!(form.status, StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&form.body).contains("Password required"),
        "expected the password form"
    );

    let wrong = submit_password(&context, "api-created", "not-the-password").await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

    let unlock = submit_password(&context, "api-created", "s3cret-pass").await;
    assert_eq!(unlock.status, StatusCode::SEE_OTHER);

    let redirect = context
        .get_with_headers("/api-created", cookie_header(&set_cookie(&unlock)))
        .await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(location(&redirect), Some("https://example.com/api-created"));
}
