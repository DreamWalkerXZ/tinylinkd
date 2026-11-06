mod common;

use axum::http::{Method, StatusCode};
use common::{TestContext, TestResponse, create_user_with_token};
use serde_json::{Value, json};
use tinylinkd::tokens::create_token;
use tinylinkd::users::{NewUser, Role};

const PASSWORD: &str = "correct horse battery staple";

async fn request(
    context: &TestContext,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> TestResponse {
    context.request(method, uri, token, body).await
}

async fn patch_me(context: &TestContext, token: &str, body: Value) -> TestResponse {
    request(
        context,
        Method::PATCH,
        "/_/api/v1/me",
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn users_edit_and_clear_their_optional_email() {
    let context = TestContext::new().await;
    let (alice, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    tinylinkd::users::create_user(
        &context.db,
        NewUser {
            username: "bob".into(),
            email: Some("bob@example.com".into()),
            password: PASSWORD.into(),
            role: Role::User,
        },
    )
    .await
    .expect("create bob");

    let response = patch_me(
        &context,
        &alice_token,
        json!({"email": "alice@example.com"}),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(response.content_type(), "application/json");
    let profile = response.json();
    assert_eq!(profile["id"], alice.id);
    assert_eq!(profile["username"], "alice");
    assert_eq!(profile["email"], "alice@example.com");

    let unchanged = patch_me(&context, &alice_token, json!({})).await;
    assert_eq!(unchanged.status, StatusCode::OK);
    assert_eq!(
        unchanged.json()["email"],
        "alice@example.com",
        "an omitted email must leave the profile unchanged"
    );

    let cleared = patch_me(&context, &alice_token, json!({"email": null})).await;
    assert_eq!(cleared.status, StatusCode::OK);
    assert!(
        cleared.json()["email"].is_null(),
        "null must clear the optional email: {}",
        cleared.json()
    );

    let invalid = patch_me(&context, &alice_token, json!({"email": "not an email"})).await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid.content_type(), "application/problem+json");
    assert_eq!(invalid.json()["code"], "invalid_email");

    let taken = patch_me(&context, &alice_token, json!({"email": "bob@example.com"})).await;
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(taken.content_type(), "application/problem+json");
    assert_eq!(taken.json()["code"], "email_taken");

    let unauthenticated = request(
        &context,
        Method::PATCH,
        "/_/api/v1/me",
        None,
        Some(json!({"email": "x@example.com"})),
    )
    .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthenticated.json()["code"], "authentication_required");
}

async fn change_password(context: &TestContext, token: &str, body: Value) -> TestResponse {
    request(
        context,
        Method::POST,
        "/_/api/v1/me/password",
        Some(token),
        Some(body),
    )
    .await
}

async fn delete_me(context: &TestContext, token: &str, body: Value) -> TestResponse {
    request(
        context,
        Method::DELETE,
        "/_/api/v1/me",
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn users_change_their_password_by_proving_the_current_password() {
    let context = TestContext::new().await;
    let (_alice, token) = create_user_with_token(&context, "alice", Role::User).await;

    let wrong = change_password(
        &context,
        &token,
        json!({"current_password": "wrong password", "new_password": "a new password"}),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.content_type(), "application/problem+json");
    assert_eq!(wrong.json()["code"], "invalid_password");

    let missing = change_password(&context, &token, json!({})).await;
    assert_eq!(missing.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(missing.json()["code"], "invalid_request");

    let empty = change_password(
        &context,
        &token,
        json!({"current_password": PASSWORD, "new_password": ""}),
    )
    .await;
    assert_eq!(empty.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(empty.json()["code"], "invalid_password");

    let changed = change_password(
        &context,
        &token,
        json!({"current_password": PASSWORD, "new_password": "a new password"}),
    )
    .await;
    assert_eq!(
        changed.status,
        StatusCode::NO_CONTENT,
        "body: {}",
        String::from_utf8_lossy(&changed.body)
    );
    assert!(changed.body.is_empty(), "204 must have an empty body");

    let stale = change_password(
        &context,
        &token,
        json!({"current_password": PASSWORD, "new_password": "another password"}),
    )
    .await;
    assert_eq!(
        stale.status,
        StatusCode::UNAUTHORIZED,
        "the old password must stop working"
    );

    let replaced = change_password(
        &context,
        &token,
        json!({"current_password": "a new password", "new_password": "another password"}),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::NO_CONTENT);

    let stored: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE username = 'alice'")
            .fetch_one(context.db.read_pool())
            .await
            .expect("password hash");
    assert!(
        tinylinkd::auth::verify_password("another password", &stored),
        "the new password must be stored as an Argon2id hash"
    );
    assert!(!tinylinkd::auth::verify_password(PASSWORD, &stored));
}

#[tokio::test]
async fn users_delete_their_own_account_only_with_the_current_password_and_no_links() {
    let context = TestContext::new().await;
    let (alice, token) = create_user_with_token(&context, "alice", Role::User).await;
    let link = context
        .post(
            "/_/api/v1/links",
            Some(&token),
            json!({"destination_url": "https://example.com/", "slug": "alice-link"}),
        )
        .await;
    assert_eq!(link.status, StatusCode::CREATED);
    let link_id = link.json()["id"].as_i64().expect("link id");

    let wrong = delete_me(&context, &token, json!({"password": "wrong password"})).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.content_type(), "application/problem+json");
    assert_eq!(wrong.json()["code"], "invalid_password");

    let blocked = delete_me(&context, &token, json!({"password": PASSWORD})).await;
    assert_eq!(blocked.status, StatusCode::CONFLICT);
    assert_eq!(blocked.content_type(), "application/problem+json");
    assert_eq!(blocked.json()["code"], "user_owns_links");
    let detail = blocked.json()["detail"]
        .as_str()
        .expect("detail")
        .to_string();
    assert!(
        detail.contains('1'),
        "the detail must tell the User how many Links block deletion: {detail}"
    );

    let still_there = context.get("/_/api/v1/me", Some(&token)).await;
    assert_eq!(still_there.status, StatusCode::OK);
    assert_eq!(still_there.json()["id"], alice.id);

    assert_eq!(
        context
            .delete(&format!("/_/api/v1/links/{link_id}"), Some(&token))
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    let missing = delete_me(&context, &token, json!({})).await;
    assert_eq!(missing.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(missing.json()["code"], "invalid_request");

    let deleted = delete_me(&context, &token, json!({"password": PASSWORD})).await;
    assert_eq!(
        deleted.status,
        StatusCode::NO_CONTENT,
        "body: {}",
        String::from_utf8_lossy(&deleted.body)
    );
    assert!(deleted.body.is_empty(), "204 must have an empty body");

    let rejected = context.get("/_/api/v1/me", Some(&token)).await;
    assert_eq!(
        rejected.status,
        StatusCode::UNAUTHORIZED,
        "the deleted User's API tokens must stop authenticating"
    );
    assert!(
        tinylinkd::users::find_by_username(&context.db, "alice")
            .await
            .expect("lookup")
            .is_none()
    );
}

async fn patch_user(context: &TestContext, token: &str, user_id: i64, body: Value) -> TestResponse {
    request(
        context,
        Method::PATCH,
        &format!("/_/api/v1/users/{user_id}"),
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn admins_list_and_read_users_while_non_admins_are_forbidden() {
    let context = TestContext::new().await;
    let (admin, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let (alice, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (bob, _) = create_user_with_token(&context, "bob", Role::User).await;

    let listed = context.get("/_/api/v1/users", Some(&admin_token)).await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.content_type(), "application/json");
    let list = listed.json();
    assert_eq!(list["total"], 3);
    assert_eq!(list["limit"], 20);
    assert_eq!(list["offset"], 0);
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    for item in items {
        for field in [
            "id",
            "username",
            "email",
            "role",
            "disabled",
            "created_at",
            "updated_at",
        ] {
            assert!(item.get(field).is_some(), "missing {field}: {item}");
        }
    }
    let admin_item = items
        .iter()
        .find(|item| item["id"] == admin.id)
        .expect("admin in list");
    assert_eq!(admin_item["role"], "admin");
    assert_eq!(admin_item["disabled"], false);

    let page = context
        .get("/_/api/v1/users?limit=1&offset=1", Some(&admin_token))
        .await
        .json();
    assert_eq!(page["total"], 3);
    assert_eq!(page["limit"], 1);
    assert_eq!(page["offset"], 1);
    assert_eq!(page["items"].as_array().expect("items").len(), 1);

    let read = context
        .get(&format!("/_/api/v1/users/{}", alice.id), Some(&admin_token))
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let profile = read.json();
    assert_eq!(profile["id"], alice.id);
    assert_eq!(profile["username"], "alice");
    assert_eq!(profile["role"], "user");
    assert_eq!(profile["disabled"], false);

    let unknown = context
        .get("/_/api/v1/users/999999", Some(&admin_token))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.content_type(), "application/problem+json");
    assert_eq!(unknown.json()["code"], "not_found");

    let forbidden_list = context.get("/_/api/v1/users", Some(&alice_token)).await;
    assert_eq!(forbidden_list.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden_list.content_type(), "application/problem+json");
    assert_eq!(forbidden_list.json()["code"], "forbidden");

    let forbidden_read = context
        .get(&format!("/_/api/v1/users/{}", bob.id), Some(&alice_token))
        .await;
    assert_eq!(forbidden_read.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden_read.json()["code"], "forbidden");

    let unauthenticated = context.get("/_/api/v1/users", None).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthenticated.json()["code"], "authentication_required");
}

#[tokio::test]
async fn admins_edit_email_and_disabled_status_and_disabling_revokes_tokens() {
    let context = TestContext::new().await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let (alice, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (bob, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let bob_with_email = patch_user(
        &context,
        &admin_token,
        bob.id,
        json!({"email": "bob@example.com"}),
    )
    .await;
    assert_eq!(bob_with_email.status, StatusCode::OK);
    assert_eq!(bob_with_email.json()["email"], "bob@example.com");

    let edited = patch_user(
        &context,
        &admin_token,
        alice.id,
        json!({"email": "alice@example.com"}),
    )
    .await;
    assert_eq!(
        edited.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&edited.body)
    );
    assert_eq!(edited.json()["email"], "alice@example.com");
    assert_eq!(edited.json()["id"], alice.id);

    let duplicate = patch_user(
        &context,
        &admin_token,
        alice.id,
        json!({"email": "bob@example.com"}),
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    assert_eq!(duplicate.json()["code"], "email_taken");

    let disabled = patch_user(&context, &admin_token, alice.id, json!({"disabled": true})).await;
    assert_eq!(
        disabled.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&disabled.body)
    );
    assert_eq!(disabled.json()["disabled"], true);

    let rejected = context.get("/_/api/v1/me", Some(&alice_token)).await;
    assert_eq!(
        rejected.status,
        StatusCode::UNAUTHORIZED,
        "a disabled User must not authenticate"
    );
    let code = rejected.json()["code"].as_str().expect("code").to_string();
    assert!(
        code == "token_revoked" || code == "user_disabled",
        "unexpected code: {code}"
    );

    let enabled = patch_user(&context, &admin_token, alice.id, json!({"disabled": false})).await;
    assert_eq!(enabled.status, StatusCode::OK);
    assert_eq!(enabled.json()["disabled"], false);

    let still_revoked = context.get("/_/api/v1/me", Some(&alice_token)).await;
    assert_eq!(
        still_revoked.status,
        StatusCode::UNAUTHORIZED,
        "enabling must not restore revoked API tokens"
    );
    assert_eq!(still_revoked.json()["code"], "token_revoked");

    let field_types =
        patch_user(&context, &admin_token, alice.id, json!({"disabled": "yes"})).await;
    assert_eq!(field_types.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(field_types.json()["code"], "invalid_request");

    let unknown = patch_user(&context, &admin_token, 999999, json!({"disabled": true})).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let forbidden = patch_user(&context, &bob_token, alice.id, json!({"disabled": true})).await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.json()["code"], "forbidden");
}

fn user_tokens_uri(user_id: i64) -> String {
    format!("/_/api/v1/users/{user_id}/tokens")
}

#[tokio::test]
async fn admins_manage_api_tokens_for_another_user() {
    let context = TestContext::new().await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let (alice, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (bob, _) = create_user_with_token(&context, "bob", Role::User).await;
    let bob_token = create_token(&context.db, bob.id, "bob token", None)
        .await
        .expect("bob token");

    let listed = context
        .get(&user_tokens_uri(alice.id), Some(&admin_token))
        .await;
    assert_eq!(
        listed.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&listed.body)
    );
    let list = listed.json();
    assert_eq!(list["total"], 1);
    assert_eq!(list["limit"], 20);
    assert_eq!(list["offset"], 0);
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert!(items[0].get("token").is_none(), "plaintext leaked: {list}");

    let created = context
        .post(
            &user_tokens_uri(alice.id),
            Some(&admin_token),
            json!({"name": "support token"}),
        )
        .await;
    assert_eq!(
        created.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&created.body)
    );
    let created = created.json();
    let plaintext = created["token"].as_str().expect("plaintext").to_string();
    let token_id = created["id"].as_i64().expect("token id");
    assert_eq!(created["name"], "support token");
    assert_eq!(created["prefix"], &plaintext[..12]);

    let me = context.get("/_/api/v1/me", Some(&plaintext)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["id"], alice.id);
    assert_eq!(me.json()["username"], "alice");

    let revoked = context
        .delete(
            &format!("/_/api/v1/users/{}/tokens/{token_id}", alice.id),
            Some(&admin_token),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    assert!(revoked.body.is_empty(), "204 must have an empty body");

    let rejected = context.get("/_/api/v1/me", Some(&plaintext)).await;
    assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rejected.json()["code"], "token_revoked");

    let list = context
        .get(&user_tokens_uri(alice.id), Some(&admin_token))
        .await
        .json();
    let revoked_item = list["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == token_id)
        .expect("revoked token in list");
    assert!(revoked_item["revoked_at"].is_string(), "{revoked_item}");

    let unknown_token = context
        .delete(
            &format!("/_/api/v1/users/{}/tokens/999999", alice.id),
            Some(&admin_token),
        )
        .await;
    assert_eq!(unknown_token.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown_token.json()["code"], "not_found");

    let foreign_token = context
        .delete(
            &format!("/_/api/v1/users/{}/tokens/{}", alice.id, bob_token.id),
            Some(&admin_token),
        )
        .await;
    assert_eq!(
        foreign_token.status,
        StatusCode::NOT_FOUND,
        "a token belonging to another User must not be found under this User"
    );

    let forbidden_revoke = context
        .delete(
            &format!("/_/api/v1/users/{}/tokens/1", alice.id),
            Some(&alice_token),
        )
        .await;
    assert_eq!(forbidden_revoke.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden_revoke.json()["code"], "forbidden");
    let forbidden_list = context
        .get(&user_tokens_uri(alice.id), Some(&alice_token))
        .await;
    assert_eq!(forbidden_list.status, StatusCode::FORBIDDEN);
    let forbidden_create = context
        .post(
            &user_tokens_uri(alice.id),
            Some(&alice_token),
            json!({"name": "nope"}),
        )
        .await;
    assert_eq!(forbidden_create.status, StatusCode::FORBIDDEN);

    for method in [Method::GET, Method::POST] {
        let unknown = request(
            &context,
            method.clone(),
            "/_/api/v1/users/999999/tokens",
            Some(&admin_token),
            (method == Method::POST).then(|| json!({"name": "x"})),
        )
        .await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND, "method {method}");
    }
    let unknown_revoke = context
        .delete("/_/api/v1/users/999999/tokens/1", Some(&admin_token))
        .await;
    assert_eq!(unknown_revoke.status, StatusCode::NOT_FOUND);

    let disabled = patch_user(&context, &admin_token, alice.id, json!({"disabled": true})).await;
    assert_eq!(disabled.status, StatusCode::OK);
    let disabled_create = context
        .post(
            &user_tokens_uri(alice.id),
            Some(&admin_token),
            json!({"name": "disabled user token"}),
        )
        .await;
    assert_eq!(disabled_create.status, StatusCode::CONFLICT);
    assert_eq!(disabled_create.json()["code"], "user_disabled");

    let enabled = patch_user(&context, &admin_token, alice.id, json!({"disabled": false})).await;
    assert_eq!(enabled.status, StatusCode::OK);
    let recreated = context
        .post(
            &user_tokens_uri(alice.id),
            Some(&admin_token),
            json!({"name": "after enable"}),
        )
        .await;
    assert_eq!(recreated.status, StatusCode::CREATED);
}

#[tokio::test]
async fn admins_delete_users_only_when_they_own_no_links() {
    let context = TestContext::new().await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let (alice, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (bob, _) = create_user_with_token(&context, "bob", Role::User).await;
    let link = context
        .post(
            "/_/api/v1/links",
            Some(&alice_token),
            json!({"destination_url": "https://example.com/", "slug": "alice-owned"}),
        )
        .await;
    assert_eq!(link.status, StatusCode::CREATED);
    let link_id = link.json()["id"].as_i64().expect("link id");

    let blocked = context
        .delete(&format!("/_/api/v1/users/{}", alice.id), Some(&admin_token))
        .await;
    assert_eq!(blocked.status, StatusCode::CONFLICT);
    assert_eq!(blocked.content_type(), "application/problem+json");
    assert_eq!(blocked.json()["code"], "user_owns_links");
    let detail = blocked.json()["detail"]
        .as_str()
        .expect("detail")
        .to_string();
    assert!(
        detail.contains('1'),
        "detail must report the Link count: {detail}"
    );
    assert!(
        tinylinkd::users::find_by_id(&context.db, alice.id)
            .await
            .expect("lookup")
            .is_some()
    );

    let deleted = context
        .delete(&format!("/_/api/v1/users/{}", bob.id), Some(&admin_token))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert!(deleted.body.is_empty(), "204 must have an empty body");
    assert!(
        tinylinkd::users::find_by_username(&context.db, "bob")
            .await
            .expect("lookup")
            .is_none()
    );

    assert_eq!(
        context
            .delete(&format!("/_/api/v1/links/{link_id}"), Some(&alice_token))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let deleted = context
        .delete(&format!("/_/api/v1/users/{}", alice.id), Some(&admin_token))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let rejected = context.get("/_/api/v1/me", Some(&alice_token)).await;
    assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);

    let unknown = context
        .delete("/_/api/v1/users/999999", Some(&admin_token))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let (_, carol_token) = create_user_with_token(&context, "carol", Role::User).await;
    let forbidden = context
        .delete("/_/api/v1/users/999999", Some(&carol_token))
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.json()["code"], "forbidden");
}

async fn patch_link(context: &TestContext, token: &str, link_id: i64, body: Value) -> TestResponse {
    request(
        context,
        Method::PATCH,
        &format!("/_/api/v1/links/{link_id}"),
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn admins_transfer_link_ownership_and_access_follows_the_owner() {
    let context = TestContext::new().await;
    let (_, admin_token) = create_user_with_token(&context, "admin", Role::Admin).await;
    let (alice, alice_token) = create_user_with_token(&context, "alice", Role::User).await;
    let (bob, bob_token) = create_user_with_token(&context, "bob", Role::User).await;
    let link = context
        .post(
            "/_/api/v1/links",
            Some(&alice_token),
            json!({"destination_url": "https://example.com/transfer", "slug": "transfer-me"}),
        )
        .await;
    assert_eq!(link.status, StatusCode::CREATED);
    let link = link.json();
    let link_id = link["id"].as_i64().expect("link id");
    assert_eq!(link["owner_id"], alice.id);

    let forbidden = patch_link(&context, &alice_token, link_id, json!({"owner_id": bob.id})).await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.content_type(), "application/problem+json");
    assert_eq!(forbidden.json()["code"], "forbidden");
    let unchanged = context
        .get(&format!("/_/api/v1/links/{link_id}"), Some(&alice_token))
        .await
        .json();
    assert_eq!(unchanged["owner_id"], alice.id);

    let transferred =
        patch_link(&context, &admin_token, link_id, json!({"owner_id": bob.id})).await;
    assert_eq!(
        transferred.status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&transferred.body)
    );
    assert_eq!(transferred.json()["owner_id"], bob.id);
    assert_eq!(transferred.json()["slug"], "transfer-me");

    let bob_read = context
        .get(&format!("/_/api/v1/links/{link_id}"), Some(&bob_token))
        .await;
    assert_eq!(bob_read.status, StatusCode::OK);
    assert_eq!(bob_read.json()["owner_id"], bob.id);

    let alice_read = context
        .get(&format!("/_/api/v1/links/{link_id}"), Some(&alice_token))
        .await;
    assert_eq!(
        alice_read.status,
        StatusCode::FORBIDDEN,
        "the old owner must lose read access"
    );
    let alice_edit = patch_link(
        &context,
        &alice_token,
        link_id,
        json!({"destination_url": "https://example.com/old-owner"}),
    )
    .await;
    assert_eq!(alice_edit.status, StatusCode::FORBIDDEN);
    let alice_delete = context
        .delete(&format!("/_/api/v1/links/{link_id}"), Some(&alice_token))
        .await;
    assert_eq!(alice_delete.status, StatusCode::FORBIDDEN);

    let bob_edit = patch_link(
        &context,
        &bob_token,
        link_id,
        json!({"destination_url": "https://example.com/new-owner"}),
    )
    .await;
    assert_eq!(bob_edit.status, StatusCode::OK);
    assert_eq!(
        bob_edit.json()["destination_url"],
        "https://example.com/new-owner"
    );

    let bob_list = context
        .get("/_/api/v1/links", Some(&bob_token))
        .await
        .json();
    assert_eq!(bob_list["total"], 1);
    assert_eq!(bob_list["items"][0]["id"], link_id);
    let alice_list = context
        .get("/_/api/v1/links", Some(&alice_token))
        .await
        .json();
    assert_eq!(alice_list["total"], 0);

    let unknown_owner =
        patch_link(&context, &admin_token, link_id, json!({"owner_id": 999999})).await;
    assert_eq!(unknown_owner.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown_owner.json()["code"], "not_found");
    let still_bob = context
        .get(&format!("/_/api/v1/links/{link_id}"), Some(&bob_token))
        .await
        .json();
    assert_eq!(still_bob["owner_id"], bob.id);

    let redirect = context.get("/transfer-me", None).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(
        redirect
            .headers
            .get(axum::http::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://example.com/new-owner")
    );
}
