mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::json;
use tinylinkd::bootstrap::{BootstrapAdmin, bootstrap_admin};
use tinylinkd::tokens::create_token;

#[tokio::test]
async fn api_requests_are_rate_limited_per_token() {
    let context = TestContext::new().await;
    let admin = bootstrap_test_admin(&context).await;
    let token = create_token(&context.db, admin.id, "rate limited", None)
        .await
        .expect("token");

    for index in 0..120 {
        let response = context.get("/_/api/v1/me", Some(&token.plaintext)).await;
        assert_eq!(response.status, StatusCode::OK, "request {index}");
    }

    let limited = context.get("/_/api/v1/me", Some(&token.plaintext)).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.content_type(), "application/problem+json");
    let retry_after = limited
        .headers
        .get(axum::http::header::RETRY_AFTER)
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
    assert_eq!(problem["instance"], "/_/api/v1/me");

    let unaffected = create_token(&context.db, admin.id, "fresh", None)
        .await
        .expect("second token");
    let fresh = context
        .get("/_/api/v1/me", Some(&unaffected.plaintext))
        .await;
    assert_eq!(
        fresh.status,
        StatusCode::OK,
        "the limit is per token, not per user"
    );
}

#[tokio::test]
async fn json_and_problem_responses_disable_content_type_sniffing() {
    let context = TestContext::new().await;
    let admin = bootstrap_test_admin(&context).await;
    let token = create_token(&context.db, admin.id, "nosniff", None)
        .await
        .expect("token");

    let cases = [
        ("/_/api/v1/me", None),
        ("/_/api/v1/me", Some(token.plaintext.as_str())),
        ("/_/api/v1/unknown", None),
        ("/_/health", None),
    ];
    for (uri, token) in cases {
        let response = context.get(uri, token).await;
        let nosniff = response
            .headers
            .get(axum::http::header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok());
        assert_eq!(nosniff, Some("nosniff"), "missing nosniff on {uri}");
    }
}

#[tokio::test]
async fn unauthenticated_request_to_me_returns_problem_details() {
    let context = TestContext::new().await;

    let response = context.get("/_/api/v1/me", None).await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.content_type(), "application/problem+json");
    let problem = response.json();
    assert_eq!(problem["status"], 401);
    assert_eq!(problem["code"], "authentication_required");
    assert_eq!(problem["instance"], "/_/api/v1/me");
    assert!(problem["title"].is_string(), "missing title: {problem}");
    assert!(problem["detail"].is_string(), "missing detail: {problem}");
}

#[tokio::test]
async fn bootstrapped_admin_reads_their_profile_with_an_api_token() {
    let context = TestContext::new().await;
    let admin = bootstrap_admin(
        &context.db,
        Some(BootstrapAdmin {
            username: "admin".into(),
            password: "correct horse battery staple".into(),
            email: Some("admin@example.com".into()),
        }),
    )
    .await
    .expect("bootstrap admin")
    .expect("admin created");
    let token = create_token(&context.db, admin.id, "test token", None)
        .await
        .expect("create token");

    let response = context.get("/_/api/v1/me", Some(&token.plaintext)).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.content_type(), "application/json");
    let profile = response.json();
    assert_eq!(profile["id"], admin.id);
    assert_eq!(profile["username"], "admin");
    assert_eq!(profile["email"], "admin@example.com");
    assert_eq!(profile["role"], "admin");
    let created_at = profile["created_at"].as_str().expect("created_at");
    assert!(
        time::OffsetDateTime::parse(created_at, &time::format_description::well_known::Rfc3339)
            .is_ok(),
        "created_at is not RFC 3339: {created_at}"
    );
    assert!(profile["updated_at"].is_string());
}

async fn bootstrap_test_admin(context: &TestContext) -> tinylinkd::users::User {
    bootstrap_admin(
        &context.db,
        Some(BootstrapAdmin {
            username: "admin".into(),
            password: "correct horse battery staple".into(),
            email: None,
        }),
    )
    .await
    .expect("bootstrap admin")
    .expect("admin created")
}

#[tokio::test]
async fn created_token_is_returned_once_and_authenticates() {
    let context = TestContext::new().await;
    let admin = bootstrap_test_admin(&context).await;
    let admin_token = create_token(&context.db, admin.id, "admin cli", None)
        .await
        .expect("admin token");

    let response = context
        .post(
            "/_/api/v1/tokens",
            Some(&admin_token.plaintext),
            json!({"name": "deploy key"}),
        )
        .await;

    assert_eq!(response.status, StatusCode::CREATED);
    let created = response.json();
    let plaintext = created["token"].as_str().expect("plaintext token");
    assert!(plaintext.starts_with("tld_"), "{plaintext}");
    assert_eq!(created["name"], "deploy key");
    assert_eq!(created["prefix"], &plaintext[..12]);
    assert!(created["expires_at"].is_null());
    assert!(created["last_used_at"].is_null());
    assert!(created["revoked_at"].is_null());

    let profile = context.get("/_/api/v1/me", Some(plaintext)).await;
    assert_eq!(profile.status, StatusCode::OK);
    assert_eq!(profile.json()["username"], "admin");
}

#[tokio::test]
async fn token_list_reports_metadata_without_plaintext_or_hashes() {
    let context = TestContext::new().await;
    let admin = bootstrap_test_admin(&context).await;
    let admin_token = create_token(&context.db, admin.id, "admin cli", None)
        .await
        .expect("admin token");
    let created = context
        .post(
            "/_/api/v1/tokens",
            Some(&admin_token.plaintext),
            json!({"name": "deploy key"}),
        )
        .await
        .json();

    let response = context
        .get("/_/api/v1/tokens", Some(&admin_token.plaintext))
        .await;

    assert_eq!(response.status, StatusCode::OK);
    let list = response.json();
    assert_eq!(list["total"], 2);
    assert_eq!(list["limit"], 20);
    assert_eq!(list["offset"], 0);
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    for item in items {
        for forbidden in ["token", "token_hash", "hash"] {
            assert!(item.get(forbidden).is_none(), "leaked {forbidden}: {item}");
        }
        for field in [
            "id",
            "name",
            "prefix",
            "expires_at",
            "last_used_at",
            "revoked_at",
            "created_at",
        ] {
            assert!(item.get(field).is_some(), "missing {field}: {item}");
        }
    }
    let deploy_key = items
        .iter()
        .find(|item| item["id"] == created["id"])
        .expect("created token in list");
    assert_eq!(deploy_key["name"], "deploy key");
    assert_eq!(deploy_key["prefix"], created["prefix"]);
    assert!(deploy_key["last_used_at"].is_null());

    let second_page = context
        .get(
            "/_/api/v1/tokens?limit=1&offset=1",
            Some(&admin_token.plaintext),
        )
        .await
        .json();
    assert_eq!(second_page["total"], 2);
    assert_eq!(second_page["limit"], 1);
    assert_eq!(second_page["offset"], 1);
    assert_eq!(second_page["items"].as_array().expect("items").len(), 1);
}

#[tokio::test]
async fn revoked_token_stops_authenticating_and_stays_listed() {
    let context = TestContext::new().await;
    let admin = bootstrap_test_admin(&context).await;
    let admin_token = create_token(&context.db, admin.id, "admin cli", None)
        .await
        .expect("admin token");
    let created = context
        .post(
            "/_/api/v1/tokens",
            Some(&admin_token.plaintext),
            json!({"name": "deploy key"}),
        )
        .await
        .json();
    let token_id = created["id"].as_i64().expect("token id");
    let plaintext = created["token"].as_str().expect("plaintext").to_string();

    let profile = context.get("/_/api/v1/me", Some(&plaintext)).await;
    assert_eq!(profile.status, StatusCode::OK);

    let list = context
        .get("/_/api/v1/tokens", Some(&admin_token.plaintext))
        .await
        .json();
    let item = list["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == token_id)
        .expect("token in list");
    assert!(
        item["last_used_at"].is_string(),
        "last_used_at not recorded: {item}"
    );
    assert!(item["revoked_at"].is_null());

    let response = context
        .delete(
            &format!("/_/api/v1/tokens/{token_id}"),
            Some(&admin_token.plaintext),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(response.body.is_empty(), "204 must have an empty body");

    let rejected = context.get("/_/api/v1/me", Some(&plaintext)).await;
    assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rejected.content_type(), "application/problem+json");
    assert_eq!(rejected.json()["code"], "token_revoked");

    let list = context
        .get("/_/api/v1/tokens", Some(&admin_token.plaintext))
        .await
        .json();
    let item = list["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == token_id)
        .expect("revoked token in list");
    assert!(item["revoked_at"].is_string(), "{item}");

    let again = context
        .delete(
            &format!("/_/api/v1/tokens/{token_id}"),
            Some(&admin_token.plaintext),
        )
        .await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn users_only_see_and_revoke_their_own_tokens() {
    let context = TestContext::new().await;
    let admin = bootstrap_test_admin(&context).await;
    let admin_token = create_token(&context.db, admin.id, "admin cli", None)
        .await
        .expect("admin token");
    let bob = tinylinkd::users::create_user(
        &context.db,
        tinylinkd::users::NewUser {
            username: "bob".into(),
            email: None,
            password: "bob password".into(),
            role: tinylinkd::users::Role::User,
        },
    )
    .await
    .expect("bob");
    let bob_token = create_token(&context.db, bob.id, "bob cli", None)
        .await
        .expect("bob token");
    let bob_created = context
        .post(
            "/_/api/v1/tokens",
            Some(&bob_token.plaintext),
            json!({"name": "bob api token"}),
        )
        .await
        .json();
    let bob_created_id = bob_created["id"].as_i64().expect("bob token id");

    let bob_list = context
        .get("/_/api/v1/tokens", Some(&bob_token.plaintext))
        .await
        .json();
    assert_eq!(bob_list["total"], 2);
    let bob_ids: Vec<i64> = bob_list["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_i64().expect("id"))
        .collect();
    assert!(bob_ids.contains(&bob_created_id));
    assert!(bob_ids.contains(&bob_token.id));
    assert!(!bob_ids.contains(&admin_token.id));

    let admin_list = context
        .get("/_/api/v1/tokens", Some(&admin_token.plaintext))
        .await
        .json();
    let admin_ids: Vec<i64> = admin_list["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_i64().expect("id"))
        .collect();
    assert!(!admin_ids.contains(&bob_token.id));
    assert!(!admin_ids.contains(&bob_created_id));

    let response = context
        .delete(
            &format!("/_/api/v1/tokens/{}", admin_token.id),
            Some(&bob_token.plaintext),
        )
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "not_found");

    let still_valid = context
        .get("/_/api/v1/me", Some(&admin_token.plaintext))
        .await;
    assert_eq!(still_valid.status, StatusCode::OK);
}

#[tokio::test]
async fn invalid_api_tokens_are_rejected_with_problem_details() {
    let context = TestContext::new().await;

    let response = context
        .get("/_/api/v1/me", Some("tld_not-a-real-api-token"))
        .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.content_type(), "application/problem+json");
    let problem = response.json();
    assert_eq!(problem["code"], "invalid_token");
    assert_eq!(problem["status"], 401);
    assert_eq!(problem["instance"], "/_/api/v1/me");
}

#[tokio::test]
async fn expired_api_tokens_are_rejected_and_future_expiry_is_accepted() {
    let context = TestContext::new().await;
    let admin = bootstrap_test_admin(&context).await;
    let admin_token = create_token(&context.db, admin.id, "admin cli", None)
        .await
        .expect("admin token");

    let expired = context
        .post(
            "/_/api/v1/tokens",
            Some(&admin_token.plaintext),
            json!({"name": "old key", "expires_at": "2020-01-01T00:00:00Z"}),
        )
        .await
        .json();
    let expires_at = expired["expires_at"].as_str().expect("expires_at");
    assert_eq!(
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
            .expect("RFC 3339"),
        time::OffsetDateTime::parse(
            "2020-01-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339
        )
        .expect("RFC 3339")
    );

    let rejected = context
        .get(
            "/_/api/v1/me",
            Some(expired["token"].as_str().expect("token")),
        )
        .await;
    assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rejected.json()["code"], "token_expired");

    let future = context
        .post(
            "/_/api/v1/tokens",
            Some(&admin_token.plaintext),
            json!({"name": "future key", "expires_at": "2999-01-01T00:00:00Z"}),
        )
        .await
        .json();
    let accepted = context
        .get(
            "/_/api/v1/me",
            Some(future["token"].as_str().expect("token")),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK);
}

#[tokio::test]
async fn invalid_token_payloads_return_validation_problem_details() {
    let context = TestContext::new().await;
    let admin = bootstrap_test_admin(&context).await;
    let admin_token = create_token(&context.db, admin.id, "admin cli", None)
        .await
        .expect("admin token");

    let empty_name = context
        .post(
            "/_/api/v1/tokens",
            Some(&admin_token.plaintext),
            json!({"name": "  "}),
        )
        .await;
    assert_eq!(empty_name.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(empty_name.content_type(), "application/problem+json");
    assert_eq!(empty_name.json()["code"], "invalid_token_name");

    let bad_expiry = context
        .post(
            "/_/api/v1/tokens",
            Some(&admin_token.plaintext),
            json!({"name": "bad", "expires_at": "tomorrow"}),
        )
        .await;
    assert_eq!(bad_expiry.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad_expiry.json()["code"], "invalid_expires_at");

    let missing_name = context
        .post("/_/api/v1/tokens", Some(&admin_token.plaintext), json!({}))
        .await;
    assert_eq!(missing_name.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(missing_name.content_type(), "application/problem+json");
    assert_eq!(missing_name.json()["code"], "invalid_request");

    let bad_pagination = context
        .get("/_/api/v1/tokens?limit=0", Some(&admin_token.plaintext))
        .await;
    assert_eq!(bad_pagination.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad_pagination.json()["code"], "invalid_pagination");
}

#[tokio::test]
async fn api_tokens_of_disabled_users_are_rejected() {
    let context = TestContext::new().await;
    let bob = tinylinkd::users::create_user(
        &context.db,
        tinylinkd::users::NewUser {
            username: "bob".into(),
            email: None,
            password: "bob password".into(),
            role: tinylinkd::users::Role::User,
        },
    )
    .await
    .expect("bob");
    let bob_token = create_token(&context.db, bob.id, "bob cli", None)
        .await
        .expect("bob token");

    tinylinkd::users::disable_user(&context.db, bob.id)
        .await
        .expect("disable bob");

    let response = context
        .get("/_/api/v1/me", Some(&bob_token.plaintext))
        .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "user_disabled");
}

#[tokio::test]
async fn bootstrap_credentials_are_ignored_once_an_admin_exists() {
    let context = TestContext::new().await;
    let first = bootstrap_admin(
        &context.db,
        Some(BootstrapAdmin {
            username: "first".into(),
            password: "first password".into(),
            email: None,
        }),
    )
    .await
    .expect("bootstrap")
    .expect("first admin");

    let ignored = bootstrap_admin(
        &context.db,
        Some(BootstrapAdmin {
            // Invalid on purpose: ignored credentials must not be validated.
            username: "Not-A-Valid-Admin".into(),
            password: String::new(),
            email: Some("not an email".into()),
        }),
    )
    .await
    .expect("bootstrap is a no-op");
    assert!(ignored.is_none());

    let token = create_token(&context.db, first.id, "first cli", None)
        .await
        .expect("first admin token");
    let profile = context.get("/_/api/v1/me", Some(&token.plaintext)).await;
    assert_eq!(profile.status, StatusCode::OK);
    assert_eq!(profile.json()["username"], "first");

    assert!(
        tinylinkd::users::find_by_username(&context.db, "Not-A-Valid-Admin")
            .await
            .expect("lookup")
            .is_none()
    );
}

#[tokio::test]
async fn instance_starts_without_a_bootstrap_admin() {
    let context = TestContext::new().await;

    let created = bootstrap_admin(&context.db, None)
        .await
        .expect("bootstrap without credentials");
    assert!(created.is_none());

    let health = context.get("/_/health", None).await;
    assert_eq!(health.status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_api_routes_return_problem_details() {
    let context = TestContext::new().await;

    let response = context.get("/_/api/v1/unknown", None).await;

    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.content_type(), "application/problem+json");
    let problem = response.json();
    assert_eq!(problem["code"], "not_found");
    assert_eq!(problem["instance"], "/_/api/v1/unknown");

    // In the admin UI phase the root path redirects to the login page for an
    // unauthenticated browser instead of returning the API-first 404.
    let root = context.get("/", None).await;
    assert_eq!(root.status, StatusCode::SEE_OTHER);
    assert_eq!(
        root.headers
            .get(axum::http::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/_/login")
    );
}
