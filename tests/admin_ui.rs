mod common;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use common::{TestContext, TestResponse};
use tinylinkd::users::{self, NewUser, Role, User};

const PASSWORD: &str = "correct horse battery staple";

/// The display form of an RFC 3339 timestamp in the default UTC timezone.
fn utc_display(timestamp: &str) -> String {
    let parsed =
        time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
            .expect("RFC 3339 timestamp");
    let format =
        time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC")
            .expect("format description");
    parsed.format(&format).expect("formatted timestamp")
}

/// The inline error element rendered beneath a named form field. Panics when
/// the page has no element with that id, so a misplaced error fails the test.
fn field_error(page: &str, field: &str) -> String {
    let marker = format!("id=\"{}_error\"", field);
    let start = page
        .find(&marker)
        .unwrap_or_else(|| panic!("no inline error for {field}; body: {page}"));
    let rest = &page[start..];
    let end = rest.find("</p>").expect("the inline error is a paragraph");
    rest[..end].to_string()
}

/// Every `Set-Cookie` header value on a response.
fn set_cookies(response: &TestResponse) -> Vec<String> {
    response
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("Set-Cookie is valid UTF-8")
                .to_string()
        })
        .collect()
}

/// The `Set-Cookie` header for a named cookie.
fn set_cookie(response: &TestResponse, name: &str) -> Option<String> {
    set_cookies(response)
        .into_iter()
        .find(|value| value.starts_with(&format!("{name}=")))
}

/// The `name=value` pair from a `Set-Cookie` value, suitable for a `Cookie`
/// request header.
fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .expect("a Set-Cookie value has a pair")
        .to_string()
}

/// The value of a hidden input rendered by a template.
fn hidden_input(body: &[u8], name: &str) -> String {
    let html = String::from_utf8_lossy(body);
    let needle = format!("name=\"{name}\"");
    let start = html
        .find(&needle)
        .unwrap_or_else(|| panic!("missing hidden input {name}: {html}"));
    let rest = &html[start + needle.len()..];
    let value_start = rest
        .find("value=\"")
        .unwrap_or_else(|| panic!("missing value for {name}"))
        + "value=\"".len();
    let value_end = rest[value_start..]
        .find('"')
        .expect("the value attribute is terminated");
    rest[value_start..value_start + value_end].to_string()
}

fn encode_form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", urlencode(key), urlencode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

async fn post_form(
    context: &TestContext,
    uri: &str,
    cookies: &[String],
    fields: &[(&str, &str)],
) -> TestResponse {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookies.is_empty() {
        builder = builder.header(header::COOKIE, cookies.join("; "));
    }
    let request = builder
        .body(Body::from(encode_form(fields)))
        .expect("form request");
    context.send(request).await
}

async fn get_with_cookies(context: &TestContext, uri: &str, cookies: &[String]) -> TestResponse {
    let mut headers = HeaderMap::new();
    if !cookies.is_empty() {
        headers.insert(
            header::COOKIE,
            cookies.join("; ").parse().expect("cookie header"),
        );
    }
    context.get_with_headers(uri, headers).await
}

async fn create_user(context: &TestContext, username: &str, role: Role) -> User {
    users::create_user(
        &context.db,
        NewUser {
            username: username.into(),
            email: None,
            password: PASSWORD.into(),
            role,
        },
    )
    .await
    .expect("create user")
}

/// Sign in through the HTTP login flow and return the session cookie pair.
async fn login(context: &TestContext, username: &str, password: &str) -> (String, TestResponse) {
    let page = context.get("/_/login", None).await;
    let csrf_cookie = set_cookie(&page, "tld_login_csrf").expect("login CSRF cookie");
    let csrf_token = hidden_input(&page.body, "csrf_token");
    let response = post_form(
        context,
        "/_/login",
        &[cookie_pair(&csrf_cookie)],
        &[
            ("csrf_token", &csrf_token),
            ("username", username),
            ("password", password),
        ],
    )
    .await;
    let session_cookie = set_cookie(&response, "tld_session")
        .map(|cookie| cookie_pair(&cookie))
        .unwrap_or_default();
    (session_cookie, response)
}

#[tokio::test]
async fn the_login_page_renders_a_csrf_protected_form() {
    let context = TestContext::new().await;

    let response = context.get("/_/login", None).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(response.content_type(), "text/html; charset=utf-8");
    assert_eq!(
        response
            .headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("default-src 'self'")
    );
    assert_eq!(
        response
            .headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers
            .get(header::REFERRER_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer")
    );

    let csrf_cookie = set_cookie(&response, "tld_login_csrf").expect("pre-session CSRF cookie");
    assert!(csrf_cookie.contains("HttpOnly"), "cookie: {csrf_cookie}");
    assert!(
        csrf_cookie.contains("SameSite=Lax"),
        "cookie: {csrf_cookie}"
    );
    assert!(csrf_cookie.contains("Path=/"), "cookie: {csrf_cookie}");
    assert!(
        !csrf_cookie.contains("Secure"),
        "a plain-HTTP base URL must not set Secure: {csrf_cookie}"
    );

    let token = hidden_input(&response.body, "csrf_token");
    assert!(!token.is_empty());
    assert_eq!(cookie_pair(&csrf_cookie), format!("tld_login_csrf={token}"));

    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("name=\"username\""), "body: {body}");
    assert!(body.contains("name=\"password\""), "body: {body}");
    assert!(body.contains("method=\"post\""), "body: {body}");
}

async fn session_csrf_token(context: &TestContext) -> String {
    sqlx::query_scalar(
        "SELECT csrf_token FROM sessions WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(context.db.read_pool())
    .await
    .expect("active session CSRF token")
}

/// The CSRF token of one specific session cookie.
async fn session_csrf_for(context: &TestContext, session_cookie: &str) -> String {
    let plaintext = session_cookie
        .strip_prefix("tld_session=")
        .expect("session cookie pair");
    sqlx::query_scalar("SELECT csrf_token FROM sessions WHERE token_hash = ?")
        .bind(tinylinkd::auth::sha256_hex(plaintext.as_bytes()))
        .fetch_one(context.db.read_pool())
        .await
        .expect("session CSRF token")
}

async fn create_link_on_db(
    context: &TestContext,
    owner: &User,
    slug: &str,
    destination: &str,
) -> tinylinkd::links::Link {
    tinylinkd::links::create_link(&context.db, owner.id, destination, Some(slug))
        .await
        .expect("create Link")
}

async fn set_instance_timezone(context: &TestContext, admin: &User, timezone: &str) {
    let token = tinylinkd::tokens::create_token(&context.db, admin.id, "settings", None)
        .await
        .expect("admin token");
    let response = context
        .request(
            Method::PATCH,
            "/_/api/v1/settings",
            Some(&token.plaintext),
            Some(serde_json::json!({"timezone": timezone})),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
}

#[tokio::test]
async fn link_and_click_times_are_shown_in_the_instance_timezone() {
    let context = TestContext::new().await;
    let admin = create_user(&context, "root", Role::Admin).await;
    set_instance_timezone(&context, &admin, "Europe/Berlin").await;
    let link = create_link_on_db(&context, &admin, "timed-link", "https://example.com/timed").await;
    sqlx::query("UPDATE links SET created_at = ?, updated_at = ?, expires_at = ? WHERE id = ?")
        .bind("2030-01-02T03:04:05Z")
        .bind("2030-01-03T04:05:06Z")
        .bind("2030-02-02T03:04:05Z")
        .bind(link.id)
        .execute(context.db.write_pool())
        .await
        .expect("update Link times");
    sqlx::query(
        "INSERT INTO clicks (link_id, clicked_at, ip, user_agent, referer, device, is_bot, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(link.id)
    .bind("2030-01-02T03:04:05.500Z")
    .bind("203.0.113.9")
    .bind("Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0")
    .bind("https://referrer.example/path")
    .bind("desktop")
    .bind(0)
    .bind("2030-01-02T03:04:05Z")
    .execute(context.db.write_pool())
    .await
    .expect("insert Click");

    let (session_cookie, _) = login(&context, "root", PASSWORD).await;
    let detail = get_with_cookies(
        &context,
        &format!("/_/links/{}", link.id),
        std::slice::from_ref(&session_cookie),
    )
    .await;
    assert_eq!(detail.status, StatusCode::OK);
    let html = String::from_utf8_lossy(&detail.body);
    assert!(
        html.contains("2030-01-02 04:04:05 Europe/Berlin"),
        "Link creation and Click times must use the Instance timezone: {html}"
    );
    assert!(
        html.contains("2030-01-03 05:05:06 Europe/Berlin"),
        "Link update time must use the Instance timezone: {html}"
    );
    assert!(
        html.contains("2030-02-02 04:04:05 Europe/Berlin"),
        "Link expiry must use the Instance timezone: {html}"
    );
    assert!(html.contains("203.0.113.9"), "missing Click IP: {html}");
    assert!(
        html.contains("Firefox/120.0"),
        "missing Click User-Agent: {html}"
    );
    assert!(
        html.contains("https://referrer.example/path"),
        "missing Click referrer: {html}"
    );
    assert!(
        !html.contains("2030-01-02T03:04:05Z"),
        "raw UTC timestamps must not be displayed: {html}"
    );

    let list = get_with_cookies(&context, "/_/links", &[session_cookie]).await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&list.body).contains("2030-02-02 04:04:05 Europe/Berlin"),
        "the Link list expiry must use the Instance timezone"
    );
}

#[tokio::test]
async fn user_and_invite_times_are_shown_in_the_instance_timezone() {
    let context = TestContext::new().await;
    let admin = create_user(&context, "root", Role::Admin).await;
    let alice = create_user(&context, "alice", Role::User).await;
    set_instance_timezone(&context, &admin, "America/New_York").await;
    sqlx::query("UPDATE users SET created_at = ?, updated_at = ? WHERE id = ?")
        .bind("2030-01-02T03:04:05Z")
        .bind("2030-01-02T04:04:05Z")
        .bind(alice.id)
        .execute(context.db.write_pool())
        .await
        .expect("update User times");
    let invite = tinylinkd::invites::create_invite(&context.db, admin.id)
        .await
        .expect("create Invite");
    sqlx::query("UPDATE invites SET created_at = ?, expires_at = ? WHERE id = ?")
        .bind("2030-01-02T03:04:05Z")
        .bind("2030-01-09T03:04:05Z")
        .bind(invite.id)
        .execute(context.db.write_pool())
        .await
        .expect("update Invite times");

    let (session_cookie, _) = login(&context, "root", PASSWORD).await;
    let users_page =
        get_with_cookies(&context, "/_/users", std::slice::from_ref(&session_cookie)).await;
    assert_eq!(users_page.status, StatusCode::OK);
    let users_html = String::from_utf8_lossy(&users_page.body);
    assert!(
        users_html.contains("2030-01-01 22:04:05 America/New_York"),
        "User creation time must use the Instance timezone: {users_html}"
    );
    assert!(
        users_html.contains("2030-01-01 23:04:05 America/New_York"),
        "User update time must use the Instance timezone: {users_html}"
    );

    let invites_page = get_with_cookies(&context, "/_/invites", &[session_cookie]).await;
    assert_eq!(invites_page.status, StatusCode::OK);
    let invites_html = String::from_utf8_lossy(&invites_page.body);
    assert!(
        invites_html.contains("2030-01-01 22:04:05 America/New_York"),
        "Invite creation time must use the Instance timezone: {invites_html}"
    );
    assert!(
        invites_html.contains("2030-01-08 22:04:05 America/New_York"),
        "Invite expiry must use the Instance timezone: {invites_html}"
    );
}

#[tokio::test]
async fn the_link_detail_page_shows_summary_and_statistics() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let link = create_link_on_db(
        &context,
        &alice,
        "stats-link",
        "https://example.com/stats-target",
    )
    .await;

    for user_agent in [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile",
        "GPTBot/1.0",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static(user_agent));
        let response = context.get_with_headers("/stats-link", headers).await;
        assert_eq!(response.status, StatusCode::FOUND);
    }

    let (session, _) = login(&context, "alice", PASSWORD).await;
    let response = get_with_cookies(&context, &format!("/_/links/{}", link.id), &[session]).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("stats-link"), "body: {body}");
    assert!(
        body.contains("https://example.com/stats-target"),
        "body: {body}"
    );
    assert!(body.contains("Total clicks"), "body: {body}");
    assert!(body.contains("Human clicks"), "body: {body}");
    assert!(body.contains("Bot clicks"), "body: {body}");
    // 3 Clicks, 1 bot.
    assert!(body.contains(">3<"), "body: {body}");
    assert!(body.contains(">2<"), "body: {body}");
    assert!(body.contains(">1<"), "body: {body}");
    assert!(body.contains("desktop"), "body: {body}");
    assert!(body.contains("mobile"), "body: {body}");
    assert!(body.contains("bot"), "body: {body}");
    let today = tinylinkd::timeutil::local_date(&chrono_tz::UTC, tinylinkd::timeutil::now())
        .expect("today");
    assert!(
        body.contains(&today),
        "the by-day table shows {today}: {body}"
    );
}

#[tokio::test]
async fn the_edit_form_prefills_the_current_link_values() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let link = tinylinkd::links::create_link_with(
        &context.db,
        tinylinkd::links::NewLink {
            owner_id: alice.id,
            destination_url: "https://example.com/old",
            slug: Some("edit-link"),
            password: Some("link secret"),
            expires_at: Some("2030-01-02T03:04:05Z"),
        },
    )
    .await
    .expect("create Link");
    let (session, _) = login(&context, "alice", PASSWORD).await;

    let response =
        get_with_cookies(&context, &format!("/_/links/{}/edit", link.id), &[session]).await;

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        body.contains("value=\"https://example.com/old\""),
        "body: {body}"
    );
    assert!(body.contains("value=\"edit-link\""), "body: {body}");
    assert!(
        body.contains("value=\"2030-01-02T03:04:05Z\""),
        "body: {body}"
    );
    assert!(body.contains("name=\"remove_password\""), "body: {body}");
    assert!(body.contains("name=\"remove_expiry\""), "body: {body}");
}

#[tokio::test]
async fn editing_a_link_updates_fields_and_shows_the_slug_warning() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let link = create_link_on_db(&context, &alice, "edit-link", "https://example.com/old").await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token = session_csrf_token(&context).await;

    let response = post_form(
        &context,
        &format!("/_/links/{}", link.id),
        std::slice::from_ref(&session),
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/new"),
            ("slug", "renamed-link"),
            ("password", "new secret"),
            ("expires_at", "2031-05-06T07:08:09Z"),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        body.contains(tinylinkd::links::SLUG_RELEASE_WARNING),
        "body: {body}"
    );
    assert!(body.contains("renamed-link"), "body: {body}");
    assert!(body.contains("https://example.com/new"), "body: {body}");

    let updated = tinylinkd::links::find_by_id(&context.db, link.id)
        .await
        .expect("read Link")
        .expect("Link exists");
    assert_eq!(updated.slug, "renamed-link");
    assert_eq!(updated.destination_url, "https://example.com/new");
    assert!(updated.has_password);
    assert_eq!(updated.expires_at.as_deref(), Some("2031-05-06T07:08:09Z"));

    let cleared = post_form(
        &context,
        &format!("/_/links/{}", link.id),
        &[session],
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/new"),
            ("slug", "renamed-link"),
            ("remove_password", "1"),
            ("remove_expiry", "1"),
        ],
    )
    .await;
    assert_eq!(
        cleared.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&cleared.body)
    );
    let cleared_link = tinylinkd::links::find_by_id(&context.db, link.id)
        .await
        .expect("read Link")
        .expect("Link exists");
    assert!(!cleared_link.has_password);
    assert_eq!(cleared_link.expires_at, None);
}

#[tokio::test]
async fn edit_validation_errors_render_inline_and_preserve_values() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let link = create_link_on_db(&context, &alice, "edit-link", "https://example.com/old").await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token = session_csrf_token(&context).await;

    let response = post_form(
        &context,
        &format!("/_/links/{}", link.id),
        std::slice::from_ref(&session),
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/new"),
            ("slug", "NO"),
        ],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "slug").contains("Slug must be 3-64 characters"),
        "body: {body}"
    );
    assert!(body.contains("value=\"NO\""), "body: {body}");
    assert!(
        body.contains("value=\"https://example.com/new\""),
        "body: {body}"
    );

    let unchanged = tinylinkd::links::find_by_id(&context.db, link.id)
        .await
        .expect("read Link")
        .expect("Link exists");
    assert_eq!(unchanged.slug, "edit-link");

    let response = post_form(
        &context,
        &format!("/_/links/{}", link.id),
        &[session],
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/new"),
            ("slug", "edit-link"),
            ("expires_at", "not-a-time"),
        ],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "expires_at").contains("must be an RFC 3339 timestamp"),
        "body: {body}"
    );
    assert!(body.contains("value=\"not-a-time\""), "body: {body}");
}

#[tokio::test]
async fn deleting_a_link_requires_confirmation_and_csrf() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let link = create_link_on_db(
        &context,
        &alice,
        "delete-link",
        "https://example.com/delete-me",
    )
    .await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token = session_csrf_token(&context).await;

    let unconfirmed = post_form(
        &context,
        &format!("/_/links/{}/delete", link.id),
        std::slice::from_ref(&session),
        &[("csrf_token", &csrf_token)],
    )
    .await;
    assert_eq!(unconfirmed.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        tinylinkd::links::find_by_id(&context.db, link.id)
            .await
            .expect("read Link")
            .is_some(),
        "an unconfirmed delete must not remove the Link"
    );

    let wrong_csrf = post_form(
        &context,
        &format!("/_/links/{}/delete", link.id),
        std::slice::from_ref(&session),
        &[("csrf_token", "wrong"), ("confirm", "1")],
    )
    .await;
    assert_eq!(wrong_csrf.status, StatusCode::FORBIDDEN);

    let deleted = post_form(
        &context,
        &format!("/_/links/{}/delete", link.id),
        &[session],
        &[("csrf_token", &csrf_token), ("confirm", "1")],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER);
    assert_eq!(
        deleted
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/links")
    );
    assert!(
        tinylinkd::links::find_by_id(&context.db, link.id)
            .await
            .expect("read Link")
            .is_none(),
        "the Link must be deleted"
    );
    assert_eq!(
        context.get("/delete-link", None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn another_users_link_is_hidden_from_the_detail_page() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let bob = create_user(&context, "bob", Role::User).await;
    let bob_link = create_link_on_db(&context, &bob, "bob-link", "https://example.com/bob").await;
    let (session, _) = login(&context, "alice", PASSWORD).await;

    let forbidden = get_with_cookies(
        &context,
        &format!("/_/links/{}", bob_link.id),
        std::slice::from_ref(&session),
    )
    .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);

    let missing = get_with_cookies(&context, "/_/links/99999", &[session]).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let _ = alice;
}

#[tokio::test]
async fn users_see_only_their_own_links_and_admins_see_all_with_an_owner_filter() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let bob = create_user(&context, "bob", Role::User).await;
    create_user(&context, "root", Role::Admin).await;
    create_link_on_db(
        &context,
        &alice,
        "alice-link",
        "https://example.com/alice-target",
    )
    .await;
    create_link_on_db(&context, &bob, "bob-link", "https://example.com/bob-target").await;

    let (alice_session, _) = login(&context, "alice", PASSWORD).await;
    let alice_list = get_with_cookies(&context, "/_/links", &[alice_session]).await;
    assert_eq!(alice_list.status, StatusCode::OK);
    let alice_body = String::from_utf8_lossy(&alice_list.body);
    assert!(alice_body.contains("alice-link"), "body: {alice_body}");
    assert!(
        !alice_body.contains("bob-link"),
        "a User must not see another User's Link: {alice_body}"
    );
    assert!(
        !alice_body.contains(">Owner<"),
        "a User does not get the Admin owner column: {alice_body}"
    );

    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let admin_list =
        get_with_cookies(&context, "/_/links", std::slice::from_ref(&admin_session)).await;
    assert_eq!(admin_list.status, StatusCode::OK);
    let admin_body = String::from_utf8_lossy(&admin_list.body);
    assert!(admin_body.contains("alice-link"), "body: {admin_body}");
    assert!(admin_body.contains("bob-link"), "body: {admin_body}");
    assert!(
        admin_body.contains(">Owner<"),
        "an Admin gets the owner column: {admin_body}"
    );

    let filtered = get_with_cookies(
        &context,
        &format!("/_/links?owner_id={}", alice.id),
        &[admin_session],
    )
    .await;
    assert_eq!(filtered.status, StatusCode::OK);
    let filtered_body = String::from_utf8_lossy(&filtered.body);
    assert!(
        filtered_body.contains("alice-link"),
        "body: {filtered_body}"
    );
    assert!(
        !filtered_body.contains("bob-link"),
        "the owner filter excludes other Users: {filtered_body}"
    );
}

#[tokio::test]
async fn the_create_form_renders_with_a_csrf_token() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token = session_csrf_token(&context).await;

    let response = get_with_cookies(&context, "/_/links/new", &[session]).await;

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("name=\"destination_url\""), "body: {body}");
    assert!(body.contains("name=\"slug\""), "body: {body}");
    assert!(body.contains("name=\"password\""), "body: {body}");
    assert!(body.contains("name=\"expires_at\""), "body: {body}");
    assert!(
        body.contains(&format!("value=\"{csrf_token}\"")),
        "body: {body}"
    );
}

#[tokio::test]
async fn creating_a_link_from_the_ui_uses_the_shared_service() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token = session_csrf_token(&context).await;

    let response = post_form(
        &context,
        "/_/links",
        std::slice::from_ref(&session),
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/target"),
            ("slug", "ui-link"),
            ("password", "link secret"),
            ("expires_at", "2030-01-02T03:04:05Z"),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let location = response
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location");
    let link_id: i64 = location
        .strip_prefix("/_/links/")
        .expect("detail location")
        .parse()
        .expect("Link id");

    let link = tinylinkd::links::find_by_id(&context.db, link_id)
        .await
        .expect("read Link")
        .expect("Link exists");
    assert_eq!(link.owner_id, alice.id);
    assert_eq!(link.slug, "ui-link");
    assert_eq!(link.destination_url, "https://example.com/target");
    assert!(link.has_password);
    assert_eq!(link.expires_at.as_deref(), Some("2030-01-02T03:04:05Z"));
    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM links WHERE id = ?")
        .bind(link_id)
        .fetch_one(context.db.read_pool())
        .await
        .expect("password hash");
    assert!(password_hash.starts_with("$argon2id$"));

    let list = get_with_cookies(&context, "/_/links", &[session]).await;
    let body = String::from_utf8_lossy(&list.body);
    assert!(body.contains("ui-link"), "body: {body}");
    assert!(body.contains("https://example.com/target"), "body: {body}");
    assert!(body.contains("2030-01-02 03:04:05 UTC"), "body: {body}");
}

#[tokio::test]
async fn create_validation_errors_render_inline_and_preserve_values() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token = session_csrf_token(&context).await;

    let response = post_form(
        &context,
        "/_/links",
        std::slice::from_ref(&session),
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "not a url"),
            ("slug", "BAD SLUG"),
            ("expires_at", "not-a-time"),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "destination_url")
            .contains("Destination URL must be an absolute http or https URL"),
        "body: {body}"
    );
    assert!(body.contains("value=\"not a url\""), "body: {body}");
    assert!(body.contains("value=\"BAD SLUG\""), "body: {body}");

    let response = post_form(
        &context,
        "/_/links",
        &[session],
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/valid"),
            ("slug", ""),
            ("expires_at", "not-a-time"),
        ],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "expires_at").contains("must be an RFC 3339 timestamp"),
        "body: {body}"
    );
    assert!(body.contains("value=\"not-a-time\""), "body: {body}");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links")
        .fetch_one(context.db.read_pool())
        .await
        .expect("count Links");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn a_taken_slug_is_reported_on_the_create_form() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    create_link_on_db(&context, &alice, "taken-slug", "https://example.com/one").await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token = session_csrf_token(&context).await;

    let response = post_form(
        &context,
        "/_/links",
        &[session],
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/two"),
            ("slug", "taken-slug"),
        ],
    )
    .await;

    assert_eq!(response.status, StatusCode::CONFLICT);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "slug").contains("Slug is already taken"),
        "body: {body}"
    );
    assert!(body.contains("value=\"taken-slug\""), "body: {body}");
}

#[tokio::test]
async fn a_failed_login_reports_an_error_without_a_session() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;

    let (session_cookie, response) = login(&context, "alice", "the wrong password").await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(session_cookie.is_empty());
    assert_eq!(response.content_type(), "text/html; charset=utf-8");
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        body.contains("Invalid username or password"),
        "body: {body}"
    );
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(context.db.read_pool())
        .await
        .expect("count sessions");
    assert_eq!(sessions, 0);
}

#[tokio::test]
async fn creating_links_from_the_ui_is_rate_limited_per_user() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let (session_cookie, response) = login(&context, "alice", PASSWORD).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let csrf_token = session_csrf_for(&context, &session_cookie).await;

    for index in 0..30 {
        let slug = format!("ui-rate-{index}");
        let response = post_form(
            &context,
            "/_/links",
            std::slice::from_ref(&session_cookie),
            &[
                ("csrf_token", &csrf_token),
                ("destination_url", "https://example.com/target"),
                ("slug", &slug),
            ],
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::SEE_OTHER,
            "request {index}: {}",
            String::from_utf8_lossy(&response.body)
        );
    }

    let limited = post_form(
        &context,
        "/_/links",
        &[session_cookie],
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/target"),
            ("slug", "ui-rate-overflow"),
        ],
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
    assert_eq!(limited.json()["code"], "rate_limited");
}

#[tokio::test]
async fn login_failures_are_rate_limited_per_ip() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let page = context.get("/_/login", None).await;
    let csrf_cookie = cookie_pair(&set_cookie(&page, "tld_login_csrf").expect("CSRF cookie"));
    let csrf_token = hidden_input(&page.body, "csrf_token");

    for _ in 0..10 {
        let response = post_form(
            &context,
            "/_/login",
            std::slice::from_ref(&csrf_cookie),
            &[
                ("csrf_token", &csrf_token),
                ("username", "alice"),
                ("password", "the wrong password"),
            ],
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }

    let limited = post_form(
        &context,
        "/_/login",
        &[csrf_cookie],
        &[
            ("csrf_token", &csrf_token),
            ("username", "alice"),
            ("password", PASSWORD),
        ],
    )
    .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after = limited
        .headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .expect("Retry-After header");
    assert!(
        (1..=60).contains(&retry_after.parse::<u64>().expect("seconds")),
        "unexpected Retry-After: {retry_after}"
    );
    assert!(
        set_cookie(&limited, "tld_session").is_none(),
        "a rate-limited login must not start a session"
    );
}

#[tokio::test]
async fn state_changing_forms_reject_a_missing_or_wrong_csrf_token() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let (session, _) = login(&context, "alice", PASSWORD).await;

    let missing = post_form(&context, "/_/logout", std::slice::from_ref(&session), &[]).await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);

    let wrong = post_form(
        &context,
        "/_/logout",
        std::slice::from_ref(&session),
        &[("csrf_token", "not-the-token")],
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert_eq!(
        wrong
            .headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("default-src 'self'"),
        "CSRF rejections are HTML pages with the admin security headers"
    );

    let still_valid = get_with_cookies(&context, "/_/links", &[session]).await;
    assert_eq!(still_valid.status, StatusCode::OK);
}

#[tokio::test]
async fn logging_out_revokes_the_session() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token: String = sqlx::query_scalar("SELECT csrf_token FROM sessions")
        .fetch_one(context.db.read_pool())
        .await
        .expect("session CSRF token");

    let response = post_form(
        &context,
        "/_/logout",
        std::slice::from_ref(&session),
        &[("csrf_token", &csrf_token)],
    )
    .await;

    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/login")
    );
    let cleared = set_cookie(&response, "tld_session").expect("cleared cookie");
    assert!(cleared.contains("Max-Age=0"), "cookie: {cleared}");
    let revoked: Option<String> =
        sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE revoked_at IS NOT NULL")
            .fetch_optional(context.db.read_pool())
            .await
            .expect("revoked session");
    assert!(revoked.is_some(), "logout must revoke the session row");

    let after = get_with_cookies(&context, "/_/links", &[session]).await;
    assert_eq!(after.status, StatusCode::SEE_OTHER);
    assert_eq!(
        after
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/login")
    );
}

#[tokio::test]
async fn the_root_redirects_to_login_or_the_link_list() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;

    let anonymous = context.get("/", None).await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert_eq!(
        anonymous
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/login")
    );

    let (session, _) = login(&context, "alice", PASSWORD).await;
    let authenticated = get_with_cookies(&context, "/", &[session]).await;
    assert_eq!(authenticated.status, StatusCode::SEE_OTHER);
    assert_eq!(
        authenticated
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/links")
    );
}

#[tokio::test]
async fn protected_pages_redirect_to_login_without_a_session() {
    let context = TestContext::new().await;

    for uri in ["/_/links", "/_/links/new", "/_/links/1", "/_/links/1/edit"] {
        let response = context.get(uri, None).await;
        assert_eq!(response.status, StatusCode::SEE_OTHER, "uri: {uri}");
        assert_eq!(
            response
                .headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/_/login"),
            "uri: {uri}"
        );
    }

    let mut bogus_headers = HeaderMap::new();
    bogus_headers.insert(
        header::COOKIE,
        HeaderValue::from_static("tld_session=not-a-real-session"),
    );
    let bogus = context.get_with_headers("/_/links", bogus_headers).await;
    assert_eq!(bogus.status, StatusCode::SEE_OTHER);
    assert_eq!(
        bogus
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/login")
    );
}

#[tokio::test]
async fn the_link_list_is_available_after_login() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let (session, login) = login(&context, "alice", PASSWORD).await;
    assert_eq!(login.status, StatusCode::SEE_OTHER);

    let response = get_with_cookies(&context, "/_/links", std::slice::from_ref(&session)).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(response.content_type(), "text/html; charset=utf-8");
    assert_eq!(
        response
            .headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("default-src 'self'")
    );
    assert_eq!(
        response
            .headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers
            .get(header::REFERRER_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer")
    );
    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("Links"), "body: {body}");
    assert!(body.contains("alice"), "body: {body}");
    assert!(body.contains("No Links yet"), "body: {body}");
    assert!(body.contains("action=\"/_/logout\""), "body: {body}");
    let csrf_token: String = sqlx::query_scalar("SELECT csrf_token FROM sessions")
        .fetch_one(context.db.read_pool())
        .await
        .expect("stored CSRF token");
    assert!(
        body.contains(&format!("value=\"{csrf_token}\"")),
        "body: {body}"
    );
}

#[tokio::test]
async fn a_valid_login_starts_a_server_side_session() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;

    let (session_cookie, response) = login(&context, "alice", PASSWORD).await;

    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(
        response
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/links")
    );
    let set_cookie = set_cookie(&response, "tld_session").expect("session cookie");
    assert!(set_cookie.contains("HttpOnly"), "cookie: {set_cookie}");
    assert!(set_cookie.contains("SameSite=Lax"), "cookie: {set_cookie}");
    assert!(set_cookie.contains("Path=/"), "cookie: {set_cookie}");
    assert!(
        set_cookie.contains("Max-Age=604800"),
        "cookie: {set_cookie}"
    );
    assert!(
        !set_cookie.contains("Secure"),
        "a plain-HTTP base URL must not set Secure: {set_cookie}"
    );

    let plaintext = session_cookie
        .strip_prefix("tld_session=")
        .expect("session cookie pair");
    assert_eq!(plaintext.len(), 43, "32 random bytes as base64url");

    let stored: String = sqlx::query_scalar("SELECT token_hash FROM sessions")
        .fetch_one(context.db.read_pool())
        .await
        .expect("stored session");
    assert_eq!(stored, tinylinkd::auth::sha256_hex(plaintext.as_bytes()));
    assert_ne!(stored, plaintext, "only the token hash is stored");
    let csrf_token: String = sqlx::query_scalar("SELECT csrf_token FROM sessions")
        .fetch_one(context.db.read_pool())
        .await
        .expect("stored CSRF token");
    assert_eq!(csrf_token.len(), 43);
}

#[tokio::test]
async fn public_password_expired_and_unknown_slugs_still_work() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    tinylinkd::links::create_link_with(
        &context.db,
        tinylinkd::links::NewLink {
            owner_id: alice.id,
            destination_url: "https://example.com/protected",
            slug: Some("protected-link"),
            password: Some("link password"),
            expires_at: None,
        },
    )
    .await
    .expect("create a protected Link");
    tinylinkd::links::create_link_with(
        &context.db,
        tinylinkd::links::NewLink {
            owner_id: alice.id,
            destination_url: "https://example.com/expired",
            slug: Some("expired-link"),
            password: None,
            expires_at: Some("2020-01-01T00:00:00Z"),
        },
    )
    .await
    .expect("create an expired Link");

    let form = context.get("/protected-link", None).await;
    assert_eq!(form.status, StatusCode::OK);
    let body = String::from_utf8_lossy(&form.body);
    assert!(body.contains("name=\"password\""), "body: {body}");

    let unlocked = post_form(
        &context,
        "/protected-link",
        &[],
        &[("password", "link password")],
    )
    .await;
    assert_eq!(
        unlocked.status,
        StatusCode::SEE_OTHER,
        "body: {}",
        String::from_utf8_lossy(&unlocked.body)
    );
    assert_eq!(
        unlocked
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/protected-link")
    );
    assert!(
        set_cookies(&unlocked)
            .iter()
            .any(|cookie| cookie.starts_with("tld_link_unlock_")),
        "a correct password must issue an unlock cookie: {:?}",
        unlocked.headers
    );

    let expired = context.get("/expired-link", None).await;
    assert_eq!(expired.status, StatusCode::GONE);
    assert!(
        String::from_utf8_lossy(&expired.body)
            .to_lowercase()
            .contains("expired"),
        "the 410 page must explain the expiry"
    );

    let missing = context.get("/no-such-link", None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn session_cookies_do_not_authenticate_the_json_api() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let (session, _) = login(&context, "alice", PASSWORD).await;

    let with_cookie = get_with_cookies(&context, "/_/api/v1/links", &[session]).await;
    assert_eq!(
        with_cookie.status,
        StatusCode::UNAUTHORIZED,
        "a session cookie must not authenticate the JSON API: {}",
        String::from_utf8_lossy(&with_cookie.body)
    );

    let token = tinylinkd::tokens::create_token(&context.db, alice.id, "test token", None)
        .await
        .expect("create an API token");
    let with_bearer = context.get("/_/api/v1/links", Some(&token.plaintext)).await;
    assert_eq!(
        with_bearer.status,
        StatusCode::OK,
        "the Bearer token must still work: {}",
        String::from_utf8_lossy(&with_bearer.body)
    );
}

#[tokio::test]
async fn logging_in_again_rotates_the_session_and_the_old_cookie_stops_working() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let (old_session, _) = login(&context, "alice", PASSWORD).await;

    let page = context.get("/_/login", None).await;
    let csrf_cookie = cookie_pair(&set_cookie(&page, "tld_login_csrf").expect("login CSRF cookie"));
    let csrf_token = hidden_input(&page.body, "csrf_token");
    let response = post_form(
        &context,
        "/_/login",
        &[csrf_cookie, old_session.clone()],
        &[
            ("csrf_token", &csrf_token),
            ("username", "alice"),
            ("password", PASSWORD),
        ],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let new_session =
        cookie_pair(&set_cookie(&response, "tld_session").expect("rotated session cookie"));
    assert_ne!(new_session, old_session, "login must rotate the token");

    let old = get_with_cookies(&context, "/_/links", std::slice::from_ref(&old_session)).await;
    assert_eq!(
        old.status,
        StatusCode::SEE_OTHER,
        "the rotated-out cookie must stop working"
    );
    assert_eq!(
        old.headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/login")
    );

    let new = get_with_cookies(&context, "/_/links", std::slice::from_ref(&new_session)).await;
    assert_eq!(new.status, StatusCode::OK);

    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL")
        .fetch_one(context.db.read_pool())
        .await
        .expect("active sessions");
    assert_eq!(active, 1, "only the rotated session may stay active");
}

#[tokio::test]
async fn an_authenticated_request_refreshes_the_session_cookie() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    let (session, login) = login(&context, "alice", PASSWORD).await;
    let initial = set_cookie(&login, "tld_session").expect("session cookie");
    assert!(initial.contains("Max-Age=604800"), "cookie: {initial}");

    let response = get_with_cookies(&context, "/_/links", std::slice::from_ref(&session)).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let refreshed = set_cookie(&response, "tld_session").expect("a refreshed session cookie");
    assert!(
        refreshed.starts_with(&format!("{session};")),
        "the cookie must keep the same session token: {refreshed}"
    );
    assert!(
        refreshed.contains("Max-Age=604800"),
        "the idle timeout must slide: {refreshed}"
    );
    assert!(
        refreshed.contains("Expires=") && refreshed.contains("GMT"),
        "the cookie must carry an expiry: {refreshed}"
    );
    assert!(refreshed.contains("HttpOnly"), "cookie: {refreshed}");
    assert!(refreshed.contains("SameSite=Lax"), "cookie: {refreshed}");
    assert!(refreshed.contains("Path=/"), "cookie: {refreshed}");
    assert!(
        !refreshed.contains("Secure"),
        "a plain-HTTP base URL must not set Secure: {refreshed}"
    );
}

#[tokio::test]
async fn an_unauthenticated_request_does_not_refresh_a_session_cookie() {
    let context = TestContext::new().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("tld_session=not-a-real-session"),
    );
    let response = context.get_with_headers("/_/links", headers).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert!(
        set_cookie(&response, "tld_session").is_none(),
        "an invalid session must not be refreshed: {:?}",
        set_cookies(&response)
    );
}

#[tokio::test]
async fn the_refreshed_session_cookie_is_secure_over_https() {
    let context = TestContext::with_config("https://tinylinkd.example", false).await;
    create_user(&context, "alice", Role::User).await;
    let (session, login) = login(&context, "alice", PASSWORD).await;
    let initial = set_cookie(&login, "tld_session").expect("session cookie");
    assert!(initial.contains("Secure"), "cookie: {initial}");

    let response = get_with_cookies(&context, "/_/links", std::slice::from_ref(&session)).await;
    assert_eq!(response.status, StatusCode::OK);
    let refreshed = set_cookie(&response, "tld_session").expect("a refreshed session cookie");
    assert!(refreshed.contains("Secure"), "cookie: {refreshed}");
}

#[tokio::test]
async fn an_expired_session_redirects_to_login() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let created = tinylinkd::sessions::create_session(&context.db, alice.id, None)
        .await
        .expect("create a session");
    sqlx::query("UPDATE sessions SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?")
        .bind(
            sqlx::query_scalar::<_, i64>("SELECT MAX(id) FROM sessions")
                .fetch_one(context.db.read_pool())
                .await
                .expect("latest session id"),
        )
        .execute(context.db.write_pool())
        .await
        .expect("expire the session");

    let response = get_with_cookies(
        &context,
        "/_/links",
        &[format!("tld_session={}", created.plaintext)],
    )
    .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/login")
    );
}

#[tokio::test]
async fn the_users_page_lists_roles_disabled_status_and_timestamps() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let root = create_user(&context, "root", Role::Admin).await;
    sqlx::query("UPDATE users SET disabled_at = '2026-01-02T03:04:05Z' WHERE id = ?")
        .bind(alice.id)
        .execute(context.db.write_pool())
        .await
        .expect("disable alice");
    let (admin_session, _) = login(&context, "root", PASSWORD).await;

    let response = get_with_cookies(&context, "/_/users", &[admin_session]).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(response.content_type(), "text/html; charset=utf-8");
    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("alice"), "body: {body}");
    assert!(body.contains("root"), "body: {body}");
    assert!(body.contains(">user<"), "role is shown: {body}");
    assert!(body.contains(">admin<"), "role is shown: {body}");
    assert!(body.contains("disabled"), "boundary status: {body}");
    assert!(
        body.contains("2026-01-02 03:04:05 UTC"),
        "disabled timestamp: {body}"
    );
    assert!(
        body.contains(&utc_display(&alice.created_at)),
        "created timestamp: {body}"
    );
    assert!(
        body.contains(&utc_display(&root.created_at)),
        "created timestamp: {body}"
    );
    assert!(body.contains("name=\"csrf_token\""), "CSRF field: {body}");
}

#[tokio::test]
async fn an_admin_disables_and_enables_a_user() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    create_user(&context, "root", Role::Admin).await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &admin_session).await;

    let disabled = post_form(
        &context,
        &format!("/_/users/{}/disable", alice.id),
        std::slice::from_ref(&admin_session),
        &[("csrf_token", &csrf_token)],
    )
    .await;
    assert_eq!(disabled.status, StatusCode::SEE_OTHER);
    assert_eq!(
        disabled
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/users")
    );
    let stored = users::find_by_id(&context.db, alice.id)
        .await
        .expect("read alice")
        .expect("alice exists");
    assert!(stored.disabled_at.is_some(), "alice must be disabled");

    let (session_cookie, login_response) = login(&context, "alice", PASSWORD).await;
    assert_eq!(login_response.status, StatusCode::UNAUTHORIZED);
    assert!(session_cookie.is_empty());

    let page = get_with_cookies(&context, "/_/users", std::slice::from_ref(&admin_session)).await;
    assert!(String::from_utf8_lossy(&page.body).contains("disabled"));

    let enabled = post_form(
        &context,
        &format!("/_/users/{}/enable", alice.id),
        std::slice::from_ref(&admin_session),
        &[("csrf_token", &csrf_token)],
    )
    .await;
    assert_eq!(enabled.status, StatusCode::SEE_OTHER);
    let stored = users::find_by_id(&context.db, alice.id)
        .await
        .expect("read alice")
        .expect("alice exists");
    assert!(stored.disabled_at.is_none(), "alice must be enabled");

    let (_, login_response) = login(&context, "alice", PASSWORD).await;
    assert_eq!(login_response.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn an_admin_deletes_only_users_who_own_no_links() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let bob = create_user(&context, "bob", Role::User).await;
    create_user(&context, "root", Role::Admin).await;
    create_link_on_db(&context, &alice, "owned-link", "https://example.com/owned").await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &admin_session).await;

    let blocked = post_form(
        &context,
        &format!("/_/users/{}/delete", alice.id),
        std::slice::from_ref(&admin_session),
        &[("csrf_token", &csrf_token), ("confirm", "1")],
    )
    .await;
    assert_eq!(
        blocked.status,
        StatusCode::CONFLICT,
        "body: {}",
        String::from_utf8_lossy(&blocked.body)
    );
    let body = String::from_utf8_lossy(&blocked.body);
    assert!(body.contains("owns 1 Link"), "body: {body}");
    assert!(
        body.contains("Delete or transfer them first"),
        "body: {body}"
    );
    assert!(
        users::find_by_id(&context.db, alice.id)
            .await
            .expect("read alice")
            .is_some(),
        "a User who owns Links must not be deleted"
    );

    let deleted = post_form(
        &context,
        &format!("/_/users/{}/delete", bob.id),
        &[admin_session],
        &[("csrf_token", &csrf_token), ("confirm", "1")],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER);
    assert!(
        users::find_by_id(&context.db, bob.id)
            .await
            .expect("read bob")
            .is_none(),
        "a link-less User must be deleted"
    );
}

#[tokio::test]
async fn user_admin_forms_reject_a_missing_or_wrong_csrf_token() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    create_user(&context, "root", Role::Admin).await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;

    let missing = post_form(
        &context,
        &format!("/_/users/{}/disable", alice.id),
        std::slice::from_ref(&admin_session),
        &[],
    )
    .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);

    let wrong = post_form(
        &context,
        &format!("/_/users/{}/delete", alice.id),
        &[admin_session],
        &[("csrf_token", "not-the-token"), ("confirm", "1")],
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);

    let stored = users::find_by_id(&context.db, alice.id)
        .await
        .expect("read alice")
        .expect("alice exists");
    assert!(stored.disabled_at.is_none());
}

#[tokio::test]
async fn admin_pages_are_forbidden_to_non_admins() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    create_user(&context, "root", Role::Admin).await;

    for uri in ["/_/users", "/_/invites", "/_/settings"] {
        let anonymous = context.get(uri, None).await;
        assert_eq!(anonymous.status, StatusCode::SEE_OTHER, "uri: {uri}");
        assert_eq!(
            anonymous
                .headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/_/login"),
            "uri: {uri}"
        );

        let (alice_session, _) = login(&context, "alice", PASSWORD).await;
        let forbidden = get_with_cookies(&context, uri, std::slice::from_ref(&alice_session)).await;
        assert_eq!(
            forbidden.status,
            StatusCode::FORBIDDEN,
            "uri: {uri}, body: {}",
            String::from_utf8_lossy(&forbidden.body)
        );

        let (root_session, _) = login(&context, "root", PASSWORD).await;
        let allowed = get_with_cookies(&context, uri, &[root_session]).await;
        assert_eq!(
            allowed.status,
            StatusCode::OK,
            "uri: {uri}, body: {}",
            String::from_utf8_lossy(&allowed.body)
        );
    }

    let (alice_session, _) = login(&context, "alice", PASSWORD).await;
    let alice_csrf = session_csrf_for(&context, &alice_session).await;
    let denied = post_form(
        &context,
        &format!("/_/users/{}/disable", alice.id),
        &[alice_session],
        &[("csrf_token", &alice_csrf)],
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let stored = users::find_by_id(&context.db, alice.id)
        .await
        .expect("read alice")
        .expect("alice exists");
    assert!(stored.disabled_at.is_none());
}

#[tokio::test]
async fn the_navigation_exposes_admin_pages_only_to_admins() {
    let context = TestContext::new().await;
    create_user(&context, "alice", Role::User).await;
    create_user(&context, "root", Role::Admin).await;

    let (alice_session, _) = login(&context, "alice", PASSWORD).await;
    let alice_page = get_with_cookies(&context, "/_/links", &[alice_session]).await;
    assert_eq!(alice_page.status, StatusCode::OK);
    let alice_body = String::from_utf8_lossy(&alice_page.body);
    for link in ["/_/users", "/_/invites", "/_/settings"] {
        assert!(
            !alice_body.contains(link),
            "a User must not see the {link} navigation entry: {alice_body}"
        );
    }

    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let admin_page = get_with_cookies(&context, "/_/links", &[admin_session]).await;
    assert_eq!(admin_page.status, StatusCode::OK);
    let admin_body = String::from_utf8_lossy(&admin_page.body);
    for link in ["/_/users", "/_/invites", "/_/settings"] {
        assert!(
            admin_body.contains(link),
            "an Admin must see the {link} navigation entry: {admin_body}"
        );
    }
}

/// The first `<code>...</code>` value rendered by a template.
fn first_code(body: &[u8]) -> String {
    let html = String::from_utf8_lossy(body);
    let start = html.find("<code>").expect("a code element") + "<code>".len();
    let end = html[start..]
        .find("</code>")
        .expect("a closed code element")
        + start;
    html[start..end].to_string()
}

#[tokio::test]
async fn an_admin_creates_an_invite_and_sees_the_token_once() {
    let context = TestContext::new().await;
    create_user(&context, "root", Role::Admin).await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &admin_session).await;

    let response = post_form(
        &context,
        "/_/invites",
        std::slice::from_ref(&admin_session),
        &[("csrf_token", &csrf_token)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("shown only once"), "body: {body}");
    let token = first_code(&response.body);
    assert_eq!(token.len(), 43, "32 random bytes as base64url: {token}");
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "the token is base64url: {token}"
    );
    assert_eq!(
        body.matches(&token).count(),
        1,
        "the token must be shown exactly once: {body}"
    );

    let (stored_hash, expires_at): (String, String) =
        sqlx::query_as("SELECT token_hash, expires_at FROM invites")
            .fetch_one(context.db.read_pool())
            .await
            .expect("the stored Invite");
    assert_eq!(stored_hash, tinylinkd::auth::sha256_hex(token.as_bytes()));
    assert_ne!(stored_hash, token, "only the token hash is stored");
    assert!(
        body.contains(&utc_display(&expires_at)),
        "expiry shown: {body}"
    );

    let list = get_with_cookies(&context, "/_/invites", &[admin_session]).await;
    assert_eq!(list.status, StatusCode::OK);
    let list_body = String::from_utf8_lossy(&list.body);
    assert!(
        !list_body.contains(&token),
        "the list must never show the plaintext token: {list_body}"
    );
    assert!(list_body.contains(">pending<"), "body: {list_body}");
}

#[tokio::test]
async fn the_invites_page_lists_every_status_without_tokens() {
    let context = TestContext::new().await;
    let root = create_user(&context, "root", Role::Admin).await;

    let pending = tinylinkd::invites::create_invite(&context.db, root.id)
        .await
        .expect("pending Invite");
    let revoked = tinylinkd::invites::create_invite(&context.db, root.id)
        .await
        .expect("revokable Invite");
    tinylinkd::invites::revoke_invite(&context.db, revoked.id)
        .await
        .expect("revoke the Invite");
    let used = tinylinkd::invites::create_invite(&context.db, root.id)
        .await
        .expect("usable Invite");
    tinylinkd::invites::accept_invite(
        &context.db,
        &used.plaintext,
        tinylinkd::invites::AcceptInvite {
            username: "invitee".into(),
            email: None,
            password: PASSWORD.into(),
        },
    )
    .await
    .expect("accept the Invite");
    let expired = tinylinkd::invites::create_invite(&context.db, root.id)
        .await
        .expect("expiring Invite");
    sqlx::query("UPDATE invites SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?")
        .bind(expired.id)
        .execute(context.db.write_pool())
        .await
        .expect("expire the Invite");

    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let response = get_with_cookies(&context, "/_/invites", &[admin_session]).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body = String::from_utf8_lossy(&response.body);
    for status in ["pending", "revoked", "used", "expired"] {
        assert!(
            body.contains(&format!(">{status}<")),
            "the {status} status is shown: {body}"
        );
    }
    assert!(body.contains("root"), "the creating Admin: {body}");
    assert!(
        body.contains(&utc_display(&pending.expires_at)),
        "expiry: {body}"
    );
    for secret in [&pending.plaintext, &revoked.plaintext, &used.plaintext] {
        assert!(
            !body.contains(secret),
            "the Invite list must never contain a plaintext token: {body}"
        );
    }
}

#[tokio::test]
async fn an_admin_revokes_an_unused_invite() {
    let context = TestContext::new().await;
    let root = create_user(&context, "root", Role::Admin).await;
    let revokable = tinylinkd::invites::create_invite(&context.db, root.id)
        .await
        .expect("create an Invite");
    let used = tinylinkd::invites::create_invite(&context.db, root.id)
        .await
        .expect("create a used Invite");
    tinylinkd::invites::accept_invite(
        &context.db,
        &used.plaintext,
        tinylinkd::invites::AcceptInvite {
            username: "invitee".into(),
            email: None,
            password: PASSWORD.into(),
        },
    )
    .await
    .expect("accept the Invite");
    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &admin_session).await;

    let revoked = post_form(
        &context,
        &format!("/_/invites/{}/revoke", revokable.id),
        std::slice::from_ref(&admin_session),
        &[("csrf_token", &csrf_token)],
    )
    .await;
    assert_eq!(revoked.status, StatusCode::SEE_OTHER);
    assert_eq!(
        revoked
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/invites")
    );
    let revoked_at: Option<String> =
        sqlx::query_scalar("SELECT revoked_at FROM invites WHERE id = ?")
            .bind(revokable.id)
            .fetch_one(context.db.read_pool())
            .await
            .expect("read the Invite");
    assert!(revoked_at.is_some(), "the Invite must be revoked");

    let blocked = post_form(
        &context,
        &format!("/_/invites/{}/revoke", used.id),
        std::slice::from_ref(&admin_session),
        &[("csrf_token", &csrf_token)],
    )
    .await;
    assert_eq!(blocked.status, StatusCode::CONFLICT);
    assert!(
        String::from_utf8_lossy(&blocked.body).contains("already been used"),
        "body: {}",
        String::from_utf8_lossy(&blocked.body)
    );

    let missing = post_form(
        &context,
        "/_/invites/99999/revoke",
        &[admin_session],
        &[("csrf_token", &csrf_token)],
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invite_forms_reject_a_missing_or_wrong_csrf_token() {
    let context = TestContext::new().await;
    let root = create_user(&context, "root", Role::Admin).await;
    let invite = tinylinkd::invites::create_invite(&context.db, root.id)
        .await
        .expect("create an Invite");
    let (admin_session, _) = login(&context, "root", PASSWORD).await;

    let missing = post_form(
        &context,
        "/_/invites",
        std::slice::from_ref(&admin_session),
        &[],
    )
    .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invites")
        .fetch_one(context.db.read_pool())
        .await
        .expect("count Invites");
    assert_eq!(count, 1, "a rejected form must not create an Invite");

    let wrong = post_form(
        &context,
        &format!("/_/invites/{}/revoke", invite.id),
        &[admin_session],
        &[("csrf_token", "not-the-token")],
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    let revoked_at: Option<String> =
        sqlx::query_scalar("SELECT revoked_at FROM invites WHERE id = ?")
            .bind(invite.id)
            .fetch_one(context.db.read_pool())
            .await
            .expect("read the Invite");
    assert!(revoked_at.is_none(), "a rejected form must not revoke");
}

#[tokio::test]
async fn the_settings_page_prefills_the_instance_settings() {
    let context = TestContext::new().await;
    create_user(&context, "root", Role::Admin).await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &admin_session).await;

    let response = get_with_cookies(&context, "/_/settings", &[admin_session]).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(response.content_type(), "text/html; charset=utf-8");
    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("action=\"/_/settings\""), "body: {body}");
    assert!(body.contains("value=\"tinylinkd\""), "body: {body}");
    assert!(body.contains("value=\"UTC\""), "body: {body}");
    assert!(body.contains("value=\"90\""), "body: {body}");
    assert!(body.contains("value=\"3600\""), "body: {body}");
    assert!(
        body.contains(&format!("value=\"{csrf_token}\"")),
        "body: {body}"
    );
    assert!(body.contains("name=\"instance_name\""), "body: {body}");
    assert!(body.contains("name=\"timezone\""), "body: {body}");
    assert!(
        body.contains("name=\"click_retention_days\""),
        "body: {body}"
    );
    assert!(
        body.contains("name=\"password_unlock_ttl_seconds\""),
        "body: {body}"
    );
}

#[tokio::test]
async fn an_admin_updates_the_instance_settings() {
    let context = TestContext::new().await;
    create_user(&context, "root", Role::Admin).await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &admin_session).await;

    let response = post_form(
        &context,
        "/_/settings",
        std::slice::from_ref(&admin_session),
        &[
            ("csrf_token", &csrf_token),
            ("instance_name", "My Links"),
            ("timezone", "Europe/London"),
            ("click_retention_days", "30"),
            ("password_unlock_ttl_seconds", "120"),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(
        response
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/settings")
    );
    let stored = tinylinkd::settings::load(&context.db)
        .await
        .expect("load settings");
    assert_eq!(stored.instance_name, "My Links");
    assert_eq!(stored.timezone, "Europe/London");
    assert_eq!(stored.click_retention_days, 30);
    assert_eq!(stored.password_unlock_ttl_seconds, 120);

    let list = get_with_cookies(&context, "/_/links", &[admin_session]).await;
    assert!(
        String::from_utf8_lossy(&list.body).contains("My Links"),
        "the Instance name is used by the navigation"
    );
}

#[tokio::test]
async fn settings_validation_errors_render_inline_and_preserve_values() {
    let context = TestContext::new().await;
    create_user(&context, "root", Role::Admin).await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &admin_session).await;

    let invalid_timezone = [
        ("csrf_token", csrf_token.as_str()),
        ("instance_name", "Renamed"),
        ("timezone", "Not/AZone"),
        ("click_retention_days", "90"),
        ("password_unlock_ttl_seconds", "3600"),
    ];
    let response = post_form(
        &context,
        "/_/settings",
        std::slice::from_ref(&admin_session),
        &invalid_timezone,
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "timezone").contains("valid IANA timezone name"),
        "body: {body}"
    );
    assert!(body.contains("value=\"Not/AZone\""), "body: {body}");
    assert!(body.contains("value=\"Renamed\""), "body: {body}");
    let unchanged = tinylinkd::settings::load(&context.db)
        .await
        .expect("load settings");
    assert_eq!(unchanged.instance_name, "tinylinkd");
    assert_eq!(unchanged.timezone, "UTC");

    let invalid_days = [
        ("csrf_token", csrf_token.as_str()),
        ("instance_name", "tinylinkd"),
        ("timezone", "UTC"),
        ("click_retention_days", "abc"),
        ("password_unlock_ttl_seconds", "3600"),
    ];
    let response = post_form(
        &context,
        "/_/settings",
        std::slice::from_ref(&admin_session),
        &invalid_days,
    )
    .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "click_retention_days").contains("whole number"),
        "body: {body}"
    );
    assert!(body.contains("value=\"abc\""), "body: {body}");

    let zero_days = [
        ("csrf_token", csrf_token.as_str()),
        ("instance_name", "tinylinkd"),
        ("timezone", "UTC"),
        ("click_retention_days", "0"),
        ("password_unlock_ttl_seconds", "3600"),
    ];
    let response = post_form(
        &context,
        "/_/settings",
        std::slice::from_ref(&admin_session),
        &zero_days,
    )
    .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "click_retention_days").contains("positive number of days"),
        "body: {body}"
    );

    let bad_ttl = [
        ("csrf_token", csrf_token.as_str()),
        ("instance_name", "tinylinkd"),
        ("timezone", "UTC"),
        ("click_retention_days", "90"),
        ("password_unlock_ttl_seconds", "-1"),
    ];
    let response = post_form(
        &context,
        "/_/settings",
        std::slice::from_ref(&admin_session),
        &bad_ttl,
    )
    .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "password_unlock_ttl_seconds").contains("positive number of seconds"),
        "body: {body}"
    );

    let empty_name = [
        ("csrf_token", csrf_token.as_str()),
        ("instance_name", ""),
        ("timezone", "UTC"),
        ("click_retention_days", "90"),
        ("password_unlock_ttl_seconds", "3600"),
    ];
    let response = post_form(&context, "/_/settings", &[admin_session], &empty_name).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8_lossy(&response.body);
    assert!(
        field_error(&body, "instance_name").contains("must not be empty"),
        "body: {body}"
    );
}

#[tokio::test]
async fn settings_forms_reject_a_missing_or_wrong_csrf_token() {
    let context = TestContext::new().await;
    create_user(&context, "root", Role::Admin).await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;

    let fields = [
        ("instance_name", "Hijacked"),
        ("timezone", "UTC"),
        ("click_retention_days", "1"),
        ("password_unlock_ttl_seconds", "1"),
    ];
    let missing = post_form(
        &context,
        "/_/settings",
        std::slice::from_ref(&admin_session),
        &fields,
    )
    .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);

    let mut wrong_fields = vec![("csrf_token", "not-the-token")];
    wrong_fields.extend_from_slice(&fields);
    let wrong = post_form(&context, "/_/settings", &[admin_session], &wrong_fields).await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);

    let unchanged = tinylinkd::settings::load(&context.db)
        .await
        .expect("load settings");
    assert_eq!(unchanged.instance_name, "tinylinkd");
    assert_eq!(unchanged.click_retention_days, 90);
}

#[tokio::test]
async fn an_admin_transfers_a_link_and_access_follows_the_new_owner() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let bob = create_user(&context, "bob", Role::User).await;
    let _admin = create_user(&context, "root", Role::Admin).await;
    let link = create_link_on_db(
        &context,
        &alice,
        "shared-link",
        "https://example.com/target",
    )
    .await;
    let (admin_session, _) = login(&context, "root", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &admin_session).await;

    let edit = get_with_cookies(
        &context,
        &format!("/_/links/{}/edit", link.id),
        std::slice::from_ref(&admin_session),
    )
    .await;
    assert_eq!(
        edit.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&edit.body)
    );
    let body = String::from_utf8_lossy(&edit.body);
    assert!(body.contains("name=\"owner_id\""), "body: {body}");
    assert!(
        body.contains(&format!("value=\"{}\" selected", alice.id)),
        "the current owner is selected: {body}"
    );
    assert!(
        body.contains(&format!("value=\"{}\"", bob.id)),
        "the other User is offered as an owner: {body}"
    );

    let response = post_form(
        &context,
        &format!("/_/links/{}", link.id),
        std::slice::from_ref(&admin_session),
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/target"),
            ("slug", "shared-link"),
            ("owner_id", &bob.id.to_string()),
        ],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let transferred = tinylinkd::links::find_by_id(&context.db, link.id)
        .await
        .expect("read Link")
        .expect("Link exists");
    assert_eq!(transferred.owner_id, bob.id);

    let (bob_session, _) = login(&context, "bob", PASSWORD).await;
    let bob_list = get_with_cookies(&context, "/_/links", std::slice::from_ref(&bob_session)).await;
    assert_eq!(bob_list.status, StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&bob_list.body).contains("shared-link"),
        "the new owner sees the Link in their list"
    );
    let bob_detail = get_with_cookies(
        &context,
        &format!("/_/links/{}", link.id),
        std::slice::from_ref(&bob_session),
    )
    .await;
    assert_eq!(bob_detail.status, StatusCode::OK);
    let bob_edit = get_with_cookies(
        &context,
        &format!("/_/links/{}/edit", link.id),
        std::slice::from_ref(&bob_session),
    )
    .await;
    assert_eq!(bob_edit.status, StatusCode::OK);
    let bob_edit_body = String::from_utf8_lossy(&bob_edit.body);
    assert!(
        !bob_edit_body.contains("name=\"owner_id\""),
        "a non-Admin does not get the owner selector: {bob_edit_body}"
    );

    let (alice_session, _) = login(&context, "alice", PASSWORD).await;
    let alice_list =
        get_with_cookies(&context, "/_/links", std::slice::from_ref(&alice_session)).await;
    assert!(
        !String::from_utf8_lossy(&alice_list.body).contains("shared-link"),
        "the old owner loses the Link in their list"
    );
    let alice_detail = get_with_cookies(
        &context,
        &format!("/_/links/{}", link.id),
        std::slice::from_ref(&alice_session),
    )
    .await;
    assert_eq!(
        alice_detail.status,
        StatusCode::FORBIDDEN,
        "the old owner loses access to the Link"
    );
    let alice_edit = get_with_cookies(
        &context,
        &format!("/_/links/{}/edit", link.id),
        &[alice_session],
    )
    .await;
    assert_eq!(alice_edit.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_non_admin_cannot_transfer_link_ownership() {
    let context = TestContext::new().await;
    let alice = create_user(&context, "alice", Role::User).await;
    let bob = create_user(&context, "bob", Role::User).await;
    let link = create_link_on_db(&context, &alice, "alice-link", "https://example.com/alice").await;
    let (session, _) = login(&context, "alice", PASSWORD).await;
    let csrf_token = session_csrf_for(&context, &session).await;

    let edit = get_with_cookies(
        &context,
        &format!("/_/links/{}/edit", link.id),
        std::slice::from_ref(&session),
    )
    .await;
    assert_eq!(edit.status, StatusCode::OK);
    assert!(
        !String::from_utf8_lossy(&edit.body).contains("name=\"owner_id\""),
        "a non-Admin is not offered the owner selector"
    );

    let response = post_form(
        &context,
        &format!("/_/links/{}", link.id),
        std::slice::from_ref(&session),
        &[
            ("csrf_token", &csrf_token),
            ("destination_url", "https://example.com/alice"),
            ("slug", "alice-link"),
            ("owner_id", &bob.id.to_string()),
        ],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let unchanged = tinylinkd::links::find_by_id(&context.db, link.id)
        .await
        .expect("read Link")
        .expect("Link exists");
    assert_eq!(unchanged.owner_id, alice.id);
}
