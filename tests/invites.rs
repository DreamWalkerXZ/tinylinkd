mod common;

use axum::http::{Method, StatusCode};
use common::TestContext;
use serde_json::json;
use sqlx::Row;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tinylinkd::bootstrap::{BootstrapAdmin, bootstrap_admin};
use tinylinkd::tokens::create_token;
use tinylinkd::users::{self, NewUser, Role, User};

async fn bootstrap_admin_with_token(context: &TestContext) -> (User, String) {
    let admin = bootstrap_admin(
        &context.db,
        Some(BootstrapAdmin {
            username: "admin".into(),
            password: "correct horse battery staple".into(),
            email: None,
        }),
    )
    .await
    .expect("bootstrap admin")
    .expect("admin created");
    let token = create_token(&context.db, admin.id, "admin cli", None)
        .await
        .expect("admin token");
    (admin, token.plaintext)
}

async fn create_regular_user_with_token(context: &TestContext, username: &str) -> (User, String) {
    let user = users::create_user(
        &context.db,
        NewUser {
            username: username.into(),
            email: None,
            password: "a regular password".into(),
            role: Role::User,
        },
    )
    .await
    .expect("regular user");
    let token = create_token(&context.db, user.id, "regular cli", None)
        .await
        .expect("regular token");
    (user, token.plaintext)
}

fn parse_rfc3339(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339)
        .unwrap_or_else(|error| panic!("bad timestamp {value}: {error}"))
}

#[tokio::test]
async fn admin_creates_invite_returning_the_plaintext_token_once_and_storing_only_its_hash() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;

    let response = context
        .request(Method::POST, "/_/api/v1/invites", Some(&admin_token), None)
        .await;

    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.content_type(), "application/json");
    let created = response.json();
    let token = created["token"].as_str().expect("plaintext token");
    assert_eq!(token.len(), 43, "32 random bytes as base64url: {token}");
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "token is not base64url: {token}"
    );
    let created_at = parse_rfc3339(created["created_at"].as_str().expect("created_at"));
    let expires_at = parse_rfc3339(created["expires_at"].as_str().expect("expires_at"));
    assert_eq!(
        expires_at - created_at,
        time::Duration::days(7),
        "Invite lifetime must be 7 days"
    );

    // The database stores only the SHA-256 hash of the token.
    let row = sqlx::query("SELECT token_hash FROM invites WHERE id = ?")
        .bind(created["id"].as_i64().expect("invite id"))
        .fetch_one(context.db.read_pool())
        .await
        .expect("stored invite");
    let stored_hash: String = row.try_get("token_hash").expect("token_hash");
    assert_eq!(stored_hash, tinylinkd::auth::hash_token(token));
    assert_ne!(stored_hash, token);
    assert_eq!(stored_hash.len(), 64);
}

#[tokio::test]
async fn admin_lists_invites_with_status_and_without_token_material() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let first = context
        .request(Method::POST, "/_/api/v1/invites", Some(&admin_token), None)
        .await
        .json();
    let second = context
        .request(Method::POST, "/_/api/v1/invites", Some(&admin_token), None)
        .await
        .json();
    let second_id = second["id"].as_i64().expect("second invite id");
    sqlx::query("UPDATE invites SET expires_at = ? WHERE id = ?")
        .bind("2020-01-01T00:00:00Z")
        .bind(second_id)
        .execute(context.db.write_pool())
        .await
        .expect("expire second invite");

    let response = context.get("/_/api/v1/invites", Some(&admin_token)).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.content_type(), "application/json");
    let list = response.json();
    assert_eq!(list["total"], 2);
    assert_eq!(list["limit"], 20);
    assert_eq!(list["offset"], 0);
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    for item in items {
        for forbidden in ["token", "token_hash", "hash", "plaintext"] {
            assert!(item.get(forbidden).is_none(), "leaked {forbidden}: {item}");
        }
        for field in [
            "id",
            "created_by",
            "status",
            "expires_at",
            "used_at",
            "revoked_at",
            "created_at",
        ] {
            assert!(item.get(field).is_some(), "missing {field}: {item}");
        }
    }
    let first_item = items
        .iter()
        .find(|item| item["id"] == first["id"])
        .expect("first invite listed");
    assert_eq!(first_item["status"], "pending");
    assert!(first_item["used_at"].is_null());
    assert!(first_item["revoked_at"].is_null());
    let second_item = items
        .iter()
        .find(|item| item["id"] == second_id)
        .expect("second invite listed");
    assert_eq!(second_item["status"], "expired");

    let page = context
        .get("/_/api/v1/invites?limit=1&offset=1", Some(&admin_token))
        .await
        .json();
    assert_eq!(page["total"], 2);
    assert_eq!(page["limit"], 1);
    assert_eq!(page["offset"], 1);
    assert_eq!(page["items"].as_array().expect("items").len(), 1);
}

#[tokio::test]
async fn admin_revokes_an_unused_invite() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let invite = context
        .request(Method::POST, "/_/api/v1/invites", Some(&admin_token), None)
        .await
        .json();
    let invite_id = invite["id"].as_i64().expect("invite id");

    let response = context
        .delete(
            &format!("/_/api/v1/invites/{invite_id}"),
            Some(&admin_token),
        )
        .await;

    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(response.body.is_empty(), "204 must have an empty body");

    let list = context
        .get("/_/api/v1/invites", Some(&admin_token))
        .await
        .json();
    let item = &list["items"][0];
    assert_eq!(item["status"], "revoked");
    let revoked_at = item["revoked_at"].as_str().expect("revoked_at").to_string();

    // Revoking again is idempotent and does not move the revocation timestamp.
    let again = context
        .delete(
            &format!("/_/api/v1/invites/{invite_id}"),
            Some(&admin_token),
        )
        .await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
    let list = context
        .get("/_/api/v1/invites", Some(&admin_token))
        .await
        .json();
    assert_eq!(list["items"][0]["revoked_at"], revoked_at);

    let unknown = context
        .delete("/_/api/v1/invites/9999", Some(&admin_token))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.content_type(), "application/problem+json");
}

#[tokio::test]
async fn used_invites_cannot_be_revoked() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let invite = context
        .request(Method::POST, "/_/api/v1/invites", Some(&admin_token), None)
        .await
        .json();
    let invite_id = invite["id"].as_i64().expect("invite id");
    sqlx::query("UPDATE invites SET used_at = ? WHERE id = ?")
        .bind("2026-01-01T00:00:00Z")
        .bind(invite_id)
        .execute(context.db.write_pool())
        .await
        .expect("mark used");

    let response = context
        .delete(
            &format!("/_/api/v1/invites/{invite_id}"),
            Some(&admin_token),
        )
        .await;

    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "invite_used");
}

#[tokio::test]
async fn non_admins_receive_403_for_invite_administration() {
    let context = TestContext::new().await;
    let (_user, user_token) = create_regular_user_with_token(&context, "bob").await;

    let create = context
        .request(Method::POST, "/_/api/v1/invites", Some(&user_token), None)
        .await;
    assert_eq!(create.status, StatusCode::FORBIDDEN);
    assert_eq!(create.content_type(), "application/problem+json");
    assert_eq!(create.json()["code"], "forbidden");
    assert_eq!(create.json()["instance"], "/_/api/v1/invites");

    let list = context.get("/_/api/v1/invites", Some(&user_token)).await;
    assert_eq!(list.status, StatusCode::FORBIDDEN);
    assert_eq!(list.json()["code"], "forbidden");

    let revoke = context
        .delete("/_/api/v1/invites/1", Some(&user_token))
        .await;
    assert_eq!(revoke.status, StatusCode::FORBIDDEN);
    assert_eq!(revoke.json()["code"], "forbidden");

    let anonymous = context
        .request(Method::POST, "/_/api/v1/invites", None, None)
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.json()["code"], "authentication_required");
}

async fn create_invite(context: &TestContext, admin_token: &str) -> serde_json::Value {
    context
        .request(Method::POST, "/_/api/v1/invites", Some(admin_token), None)
        .await
        .json()
}

#[tokio::test]
async fn public_invite_validation_reports_every_state() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;

    let valid = create_invite(&context, &admin_token).await;
    let response = context
        .get(
            &format!(
                "/_/api/v1/invites/{}",
                valid["token"].as_str().expect("token")
            ),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.content_type(), "application/json");
    let validation = response.json();
    assert_eq!(validation["status"], "valid");
    assert_eq!(validation["expires_at"], valid["expires_at"]);
    assert!(
        validation.get("token").is_none() && validation.get("token_hash").is_none(),
        "validation leaked token material: {validation}"
    );

    let expired = create_invite(&context, &admin_token).await;
    sqlx::query("UPDATE invites SET expires_at = ? WHERE id = ?")
        .bind("2020-01-01T00:00:00Z")
        .bind(expired["id"].as_i64().expect("expired id"))
        .execute(context.db.write_pool())
        .await
        .expect("expire invite");
    let validation = context
        .get(
            &format!(
                "/_/api/v1/invites/{}",
                expired["token"].as_str().expect("token")
            ),
            None,
        )
        .await
        .json();
    assert_eq!(validation["status"], "expired");

    let used = create_invite(&context, &admin_token).await;
    sqlx::query("UPDATE invites SET used_at = ? WHERE id = ?")
        .bind("2026-01-01T00:00:00Z")
        .bind(used["id"].as_i64().expect("used id"))
        .execute(context.db.write_pool())
        .await
        .expect("mark invite used");
    let validation = context
        .get(
            &format!(
                "/_/api/v1/invites/{}",
                used["token"].as_str().expect("token")
            ),
            None,
        )
        .await
        .json();
    assert_eq!(validation["status"], "used");

    let revoked = create_invite(&context, &admin_token).await;
    context
        .delete(
            &format!("/_/api/v1/invites/{}", revoked["id"].as_i64().expect("id")),
            Some(&admin_token),
        )
        .await;
    let validation = context
        .get(
            &format!(
                "/_/api/v1/invites/{}",
                revoked["token"].as_str().expect("token")
            ),
            None,
        )
        .await
        .json();
    assert_eq!(validation["status"], "revoked");

    let unknown = context
        .get("/_/api/v1/invites/not-a-real-token", None)
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.content_type(), "application/problem+json");
    assert_eq!(unknown.json()["code"], "not_found");
    assert_eq!(
        unknown.json()["instance"],
        "/_/api/v1/invites/not-a-real-token"
    );
}

#[tokio::test]
async fn accepting_a_valid_invite_creates_a_user_and_consumes_the_token() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let invite = create_invite(&context, &admin_token).await;
    let token = invite["token"].as_str().expect("invite token");

    let response = context
        .post(
            &format!("/_/api/v1/invites/{token}/accept"),
            None,
            json!({
                "username": "alice",
                "password": "alice password",
                "email": "alice@example.com"
            }),
        )
        .await;

    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.content_type(), "application/json");
    let user = response.json();
    assert_eq!(user["username"], "alice");
    assert_eq!(user["email"], "alice@example.com");
    assert_eq!(user["role"], "user");
    assert!(user["id"].as_i64().is_some());
    let created_at = user["created_at"].as_str().expect("created_at");
    assert!(parse_rfc3339(created_at) <= OffsetDateTime::now_utc());

    // The invited person's password is stored as an Argon2id PHC string.
    let row = sqlx::query("SELECT password_hash FROM users WHERE username = 'alice'")
        .fetch_one(context.db.read_pool())
        .await
        .expect("alice exists");
    let password_hash: String = row.try_get("password_hash").expect("password_hash");
    assert!(password_hash.starts_with("$argon2id$"), "{password_hash}");
    assert!(tinylinkd::auth::verify_password(
        "alice password",
        &password_hash
    ));
    assert!(!tinylinkd::auth::verify_password(
        "wrong password",
        &password_hash
    ));

    // The token is single-use.
    let reused = context
        .post(
            &format!("/_/api/v1/invites/{token}/accept"),
            None,
            json!({"username": "mallory", "password": "mallory password"}),
        )
        .await;
    assert_eq!(reused.status, StatusCode::CONFLICT);
    assert_eq!(reused.content_type(), "application/problem+json");
    assert_eq!(reused.json()["code"], "invite_used");
    assert!(
        users::find_by_username(&context.db, "mallory")
            .await
            .expect("lookup")
            .is_none()
    );

    let validation = context
        .get(&format!("/_/api/v1/invites/{token}"), None)
        .await
        .json();
    assert_eq!(validation["status"], "used");

    // The new User has the `user` role, not `admin`.
    let alice = users::find_by_username(&context.db, "alice")
        .await
        .expect("lookup")
        .expect("alice");
    let alice_token = create_token(&context.db, alice.id, "alice cli", None)
        .await
        .expect("alice token");
    let profile = context
        .get("/_/api/v1/me", Some(&alice_token.plaintext))
        .await;
    assert_eq!(profile.status, StatusCode::OK);
    assert_eq!(profile.json()["username"], "alice");
    assert_eq!(profile.json()["role"], "user");
    let forbidden = context
        .get("/_/api/v1/invites", Some(&alice_token.plaintext))
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn accepting_an_invite_requires_valid_credentials_and_a_free_username() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let invite = create_invite(&context, &admin_token).await;
    let token = invite["token"].as_str().expect("invite token");

    let bad_username = context
        .post(
            &format!("/_/api/v1/invites/{token}/accept"),
            None,
            json!({"username": "Not Valid", "password": "password"}),
        )
        .await;
    assert_eq!(bad_username.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad_username.json()["code"], "invalid_username");

    let empty_password = context
        .post(
            &format!("/_/api/v1/invites/{token}/accept"),
            None,
            json!({"username": "alice", "password": ""}),
        )
        .await;
    assert_eq!(empty_password.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(empty_password.json()["code"], "invalid_password");

    let taken = context
        .post(
            &format!("/_/api/v1/invites/{token}/accept"),
            None,
            json!({"username": "admin", "password": "password"}),
        )
        .await;
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(taken.json()["code"], "username_taken");

    let invalid_email = context
        .post(
            &format!("/_/api/v1/invites/{token}/accept"),
            None,
            json!({"username": "alice", "password": "password", "email": "not an email"}),
        )
        .await;
    assert_eq!(invalid_email.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid_email.json()["code"], "invalid_email");

    users::create_user(
        &context.db,
        NewUser {
            username: "carol".into(),
            email: Some("carol@example.com".into()),
            password: "carol password".into(),
            role: Role::User,
        },
    )
    .await
    .expect("carol");
    let taken_email = context
        .post(
            &format!("/_/api/v1/invites/{token}/accept"),
            None,
            json!({
                "username": "alice",
                "password": "password",
                "email": "carol@example.com"
            }),
        )
        .await;
    assert_eq!(taken_email.status, StatusCode::CONFLICT);
    assert_eq!(taken_email.json()["code"], "email_taken");

    // Failed acceptance attempts do not consume the Invite.
    let validation = context
        .get(&format!("/_/api/v1/invites/{token}"), None)
        .await
        .json();
    assert_eq!(validation["status"], "valid");
}

#[tokio::test]
async fn expired_and_revoked_invites_cannot_be_accepted() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;

    let expired = create_invite(&context, &admin_token).await;
    sqlx::query("UPDATE invites SET expires_at = ? WHERE id = ?")
        .bind("2020-01-01T00:00:00Z")
        .bind(expired["id"].as_i64().expect("id"))
        .execute(context.db.write_pool())
        .await
        .expect("expire invite");
    let response = context
        .post(
            &format!(
                "/_/api/v1/invites/{}/accept",
                expired["token"].as_str().expect("token")
            ),
            None,
            json!({"username": "alice", "password": "alice password"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::GONE);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "invite_expired");
    assert!(
        users::find_by_username(&context.db, "alice")
            .await
            .expect("lookup")
            .is_none()
    );

    let revoked = create_invite(&context, &admin_token).await;
    context
        .delete(
            &format!("/_/api/v1/invites/{}", revoked["id"].as_i64().expect("id")),
            Some(&admin_token),
        )
        .await;
    let response = context
        .post(
            &format!(
                "/_/api/v1/invites/{}/accept",
                revoked["token"].as_str().expect("token")
            ),
            None,
            json!({"username": "alice", "password": "alice password"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["code"], "invite_revoked");

    let unknown = context
        .post(
            "/_/api/v1/invites/not-a-real-token/accept",
            None,
            json!({"username": "alice", "password": "alice password"}),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.content_type(), "application/problem+json");
}

#[tokio::test]
async fn concurrent_acceptance_of_one_invite_creates_exactly_one_user() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let invite = create_invite(&context, &admin_token).await;
    let token = invite["token"].as_str().expect("invite token").to_string();

    let accept_uri = format!("/_/api/v1/invites/{token}/accept");
    let first = context.post(
        &accept_uri,
        None,
        json!({"username": "alice", "password": "alice password"}),
    );
    let second = context.post(
        &accept_uri,
        None,
        json!({"username": "bob", "password": "bob password"}),
    );
    let (first, second) = tokio::join!(first, second);

    let statuses = [first.status, second.status];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count(),
        1,
        "exactly one acceptance must succeed: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1,
        "the other acceptance must conflict: {statuses:?}"
    );
    let alice = users::find_by_username(&context.db, "alice")
        .await
        .expect("lookup")
        .is_some();
    let bob = users::find_by_username(&context.db, "bob")
        .await
        .expect("lookup")
        .is_some();
    assert!(alice ^ bob, "exactly one User must be created");
}

#[tokio::test]
async fn admin_creates_a_password_reset_token_storing_only_its_hash() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let (bob, bob_token) = create_regular_user_with_token(&context, "bob").await;

    let response = context
        .request(
            Method::POST,
            &format!("/_/api/v1/users/{}/password-reset", bob.id),
            Some(&admin_token),
            None,
        )
        .await;

    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.content_type(), "application/json");
    let created = response.json();
    let token = created["token"].as_str().expect("plaintext token");
    assert_eq!(token.len(), 43, "32 random bytes as base64url: {token}");
    let created_at = parse_rfc3339(created["created_at"].as_str().expect("created_at"));
    let expires_at = parse_rfc3339(created["expires_at"].as_str().expect("expires_at"));
    assert_eq!(
        expires_at - created_at,
        time::Duration::hours(24),
        "password-reset lifetime must be 24 hours"
    );

    let row = sqlx::query("SELECT user_id, token_hash FROM password_resets WHERE id = ?")
        .bind(created["id"].as_i64().expect("reset id"))
        .fetch_one(context.db.read_pool())
        .await
        .expect("stored password reset");
    assert_eq!(row.try_get::<i64, _>("user_id").expect("user_id"), bob.id);
    let stored_hash: String = row.try_get("token_hash").expect("token_hash");
    assert_eq!(stored_hash, tinylinkd::auth::hash_token(token));
    assert_eq!(stored_hash.len(), 64);

    let unknown = context
        .request(
            Method::POST,
            "/_/api/v1/users/9999/password-reset",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.content_type(), "application/problem+json");

    let forbidden = context
        .request(
            Method::POST,
            &format!("/_/api/v1/users/{}/password-reset", bob.id),
            Some(&bob_token),
            None,
        )
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.json()["code"], "forbidden");
}

async fn create_password_reset(
    context: &TestContext,
    admin_token: &str,
    user_id: i64,
) -> serde_json::Value {
    context
        .request(
            Method::POST,
            &format!("/_/api/v1/users/{user_id}/password-reset"),
            Some(admin_token),
            None,
        )
        .await
        .json()
}

#[tokio::test]
async fn public_password_reset_validation_reports_every_state() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let (bob, _bob_token) = create_regular_user_with_token(&context, "bob").await;

    let valid = create_password_reset(&context, &admin_token, bob.id).await;
    let response = context
        .get(
            &format!(
                "/_/api/v1/password-resets/{}",
                valid["token"].as_str().expect("token")
            ),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.content_type(), "application/json");
    let validation = response.json();
    assert_eq!(validation["status"], "valid");
    assert_eq!(validation["expires_at"], valid["expires_at"]);
    assert!(
        validation.get("token").is_none() && validation.get("token_hash").is_none(),
        "validation leaked token material: {validation}"
    );

    let expired = create_password_reset(&context, &admin_token, bob.id).await;
    sqlx::query("UPDATE password_resets SET expires_at = ? WHERE id = ?")
        .bind("2020-01-01T00:00:00Z")
        .bind(expired["id"].as_i64().expect("id"))
        .execute(context.db.write_pool())
        .await
        .expect("expire reset");
    let validation = context
        .get(
            &format!(
                "/_/api/v1/password-resets/{}",
                expired["token"].as_str().expect("token")
            ),
            None,
        )
        .await
        .json();
    assert_eq!(validation["status"], "expired");

    let used = create_password_reset(&context, &admin_token, bob.id).await;
    sqlx::query("UPDATE password_resets SET used_at = ? WHERE id = ?")
        .bind("2026-01-01T00:00:00Z")
        .bind(used["id"].as_i64().expect("id"))
        .execute(context.db.write_pool())
        .await
        .expect("mark reset used");
    let validation = context
        .get(
            &format!(
                "/_/api/v1/password-resets/{}",
                used["token"].as_str().expect("token")
            ),
            None,
        )
        .await
        .json();
    assert_eq!(validation["status"], "used");

    let revoked = create_password_reset(&context, &admin_token, bob.id).await;
    sqlx::query("UPDATE password_resets SET revoked_at = ? WHERE id = ?")
        .bind("2026-01-01T00:00:00Z")
        .bind(revoked["id"].as_i64().expect("id"))
        .execute(context.db.write_pool())
        .await
        .expect("revoke reset");
    let validation = context
        .get(
            &format!(
                "/_/api/v1/password-resets/{}",
                revoked["token"].as_str().expect("token")
            ),
            None,
        )
        .await
        .json();
    assert_eq!(validation["status"], "revoked");

    let unknown = context
        .get("/_/api/v1/password-resets/not-a-real-token", None)
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.content_type(), "application/problem+json");
    assert_eq!(unknown.json()["code"], "not_found");
}

async fn user_password_hash(context: &TestContext, user_id: i64) -> String {
    let row = sqlx::query("SELECT password_hash FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(context.db.read_pool())
        .await
        .expect("stored User");
    row.try_get("password_hash").expect("password_hash")
}

#[tokio::test]
async fn accepting_a_password_reset_changes_the_password_and_consumes_the_token() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let (bob, _bob_token) = create_regular_user_with_token(&context, "bob").await;
    let original_hash = user_password_hash(&context, bob.id).await;
    let reset = create_password_reset(&context, &admin_token, bob.id).await;
    let token = reset["token"].as_str().expect("reset token");

    let response = context
        .post(
            &format!("/_/api/v1/password-resets/{token}/accept"),
            None,
            json!({"password": "a brand new password"}),
        )
        .await;

    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(response.body.is_empty(), "204 must have an empty body");

    let new_hash = user_password_hash(&context, bob.id).await;
    assert_ne!(new_hash, original_hash);
    assert!(new_hash.starts_with("$argon2id$"), "{new_hash}");
    assert!(tinylinkd::auth::verify_password(
        "a brand new password",
        &new_hash
    ));
    assert!(!tinylinkd::auth::verify_password(
        "a regular password",
        &new_hash
    ));

    // The token is single-use.
    let reused = context
        .post(
            &format!("/_/api/v1/password-resets/{token}/accept"),
            None,
            json!({"password": "another password"}),
        )
        .await;
    assert_eq!(reused.status, StatusCode::CONFLICT);
    assert_eq!(reused.content_type(), "application/problem+json");
    assert_eq!(reused.json()["code"], "password_reset_used");
    assert!(tinylinkd::auth::verify_password(
        "a brand new password",
        &user_password_hash(&context, bob.id).await
    ));

    let validation = context
        .get(&format!("/_/api/v1/password-resets/{token}"), None)
        .await
        .json();
    assert_eq!(validation["status"], "used");

    // An invalid new password is rejected without consuming a fresh token.
    let fresh = create_password_reset(&context, &admin_token, bob.id).await;
    let fresh_token = fresh["token"].as_str().expect("reset token");
    let empty = context
        .post(
            &format!("/_/api/v1/password-resets/{fresh_token}/accept"),
            None,
            json!({"password": ""}),
        )
        .await;
    assert_eq!(empty.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(empty.json()["code"], "invalid_password");
    let validation = context
        .get(&format!("/_/api/v1/password-resets/{fresh_token}"), None)
        .await
        .json();
    assert_eq!(validation["status"], "valid");
}

#[tokio::test]
async fn expired_revoked_and_unknown_password_resets_cannot_be_accepted() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let (bob, _bob_token) = create_regular_user_with_token(&context, "bob").await;
    let original_hash = user_password_hash(&context, bob.id).await;

    let expired = create_password_reset(&context, &admin_token, bob.id).await;
    sqlx::query("UPDATE password_resets SET expires_at = ? WHERE id = ?")
        .bind("2020-01-01T00:00:00Z")
        .bind(expired["id"].as_i64().expect("id"))
        .execute(context.db.write_pool())
        .await
        .expect("expire reset");
    let response = context
        .post(
            &format!(
                "/_/api/v1/password-resets/{}/accept",
                expired["token"].as_str().expect("token")
            ),
            None,
            json!({"password": "expired password"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::GONE);
    assert_eq!(response.content_type(), "application/problem+json");
    assert_eq!(response.json()["code"], "password_reset_expired");

    let revoked = create_password_reset(&context, &admin_token, bob.id).await;
    sqlx::query("UPDATE password_resets SET revoked_at = ? WHERE id = ?")
        .bind("2026-01-01T00:00:00Z")
        .bind(revoked["id"].as_i64().expect("id"))
        .execute(context.db.write_pool())
        .await
        .expect("revoke reset");
    let response = context
        .post(
            &format!(
                "/_/api/v1/password-resets/{}/accept",
                revoked["token"].as_str().expect("token")
            ),
            None,
            json!({"password": "revoked password"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["code"], "password_reset_revoked");

    let unknown = context
        .post(
            "/_/api/v1/password-resets/not-a-real-token/accept",
            None,
            json!({"password": "unknown password"}),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.content_type(), "application/problem+json");

    assert_eq!(user_password_hash(&context, bob.id).await, original_hash);
}

#[tokio::test]
async fn concurrent_password_reset_acceptance_applies_exactly_one_password() {
    let context = TestContext::new().await;
    let (_admin, admin_token) = bootstrap_admin_with_token(&context).await;
    let (bob, _bob_token) = create_regular_user_with_token(&context, "bob").await;
    let reset = create_password_reset(&context, &admin_token, bob.id).await;
    let token = reset["token"].as_str().expect("reset token").to_string();

    let uri = format!("/_/api/v1/password-resets/{token}/accept");
    let first = context.post(&uri, None, json!({"password": "first password"}));
    let second = context.post(&uri, None, json!({"password": "second password"}));
    let (first, second) = tokio::join!(first, second);

    let statuses = [first.status, second.status];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::NO_CONTENT)
            .count(),
        1,
        "exactly one acceptance must succeed: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1,
        "the other acceptance must conflict: {statuses:?}"
    );
    let hash = user_password_hash(&context, bob.id).await;
    let first_applied = tinylinkd::auth::verify_password("first password", &hash);
    let second_applied = tinylinkd::auth::verify_password("second password", &hash);
    assert!(
        first_applied ^ second_applied,
        "exactly one new password must be stored"
    );
}
