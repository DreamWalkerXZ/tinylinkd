use serde::Serialize;
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::auth::{hash_password, verify_password};
use crate::db::Database;
use crate::error::ApiError;
use crate::timeutil;

pub const USERNAME_MIN_LEN: usize = 3;
pub const USERNAME_MAX_LEN: usize = 32;
pub const EMAIL_MAX_LEN: usize = 254;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub role: Role,
    pub disabled_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub role: Role,
}

pub fn validate_username(username: &str) -> Result<(), ApiError> {
    let valid_length = (USERNAME_MIN_LEN..=USERNAME_MAX_LEN).contains(&username.len());
    let valid_characters = username.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    });
    if !valid_length || !valid_characters {
        return Err(ApiError::validation(
            "invalid_username",
            "Username must be 3-32 characters using ASCII lowercase letters, digits, '-' or '_'.",
        ));
    }
    Ok(())
}

fn normalize_email(email: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(email) = email.map(|email| email.trim().to_string()) else {
        return Ok(None);
    };
    if email.is_empty() {
        return Ok(None);
    }
    let valid = email.len() <= EMAIL_MAX_LEN
        && !email.contains(char::is_whitespace)
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty());
    if !valid {
        return Err(ApiError::validation(
            "invalid_email",
            "Email must be a single address of at most 254 characters.",
        ));
    }
    Ok(Some(email))
}

pub(crate) fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.is_empty() {
        return Err(ApiError::validation(
            "invalid_password",
            "Password must not be empty.",
        ));
    }
    Ok(())
}

pub(crate) struct PreparedUser {
    username: String,
    email: Option<String>,
    password_hash: String,
    role: Role,
    created_at: String,
}

pub(crate) fn prepare_user(new: NewUser) -> Result<PreparedUser, ApiError> {
    validate_username(&new.username)?;
    let email = normalize_email(new.email)?;
    validate_password(&new.password)?;
    let password_hash = hash_password(&new.password)
        .map_err(|error| ApiError::internal(format!("failed to hash password: {error}")))?;
    Ok(PreparedUser {
        username: new.username,
        email,
        password_hash,
        role: new.role,
        created_at: timeutil::now_rfc3339(),
    })
}

pub(crate) async fn insert_user(
    connection: &mut SqliteConnection,
    prepared: &PreparedUser,
) -> Result<User, ApiError> {
    let existing_username: Option<i64> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
            .bind(&prepared.username)
            .fetch_optional(&mut *connection)
            .await?;
    if existing_username.is_some() {
        return Err(ApiError::conflict(
            "username_taken",
            "Username is already taken.",
        ));
    }

    if let Some(email) = &prepared.email {
        let existing_email: Option<i64> =
            sqlx::query_scalar("SELECT id FROM users WHERE email = ?")
                .bind(email)
                .fetch_optional(&mut *connection)
                .await?;
        if existing_email.is_some() {
            return Err(ApiError::conflict(
                "email_taken",
                "Email is already in use.",
            ));
        }
    }

    let result = sqlx::query(
        "INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&prepared.username)
    .bind(&prepared.email)
    .bind(&prepared.password_hash)
    .bind(prepared.role.as_str())
    .bind(&prepared.created_at)
    .bind(&prepared.created_at)
    .execute(&mut *connection)
    .await?;

    Ok(User {
        id: result.last_insert_rowid(),
        username: prepared.username.clone(),
        email: prepared.email.clone(),
        role: prepared.role,
        disabled_at: None,
        created_at: prepared.created_at.clone(),
        updated_at: prepared.created_at.clone(),
    })
}

pub async fn create_user(db: &Database, new: NewUser) -> Result<User, ApiError> {
    let prepared = prepare_user(new)?;
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let user = insert_user(&mut transaction, &prepared).await?;
    transaction.commit().await?;
    Ok(user)
}

/// List Users ordered by id for the Admin user list.
pub async fn list_users(
    db: &Database,
    limit: i64,
    offset: i64,
) -> Result<(Vec<User>, i64), ApiError> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db.read_pool())
        .await?;
    let rows = sqlx::query(&format!(
        "SELECT {USER_SELECT} FROM users ORDER BY id LIMIT ? OFFSET ?"
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(db.read_pool())
    .await?;
    let users = rows
        .iter()
        .map(user_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((users, total))
}

#[derive(Debug, Clone)]
pub struct UserChanges {
    /// `None` leaves the email unchanged; `Some(None)` clears it.
    pub email: Option<Option<String>>,
    /// `None` leaves the disabled status unchanged.
    pub disabled: Option<bool>,
}

/// Admin edit of a User's email and disabled status.
///
/// Disabling a User and revoking every one of their API tokens share one
/// `BEGIN IMMEDIATE` transaction, so access ends atomically. Enabling clears
/// the disabled timestamp but never restores revoked tokens.
pub async fn update_user(
    db: &Database,
    user_id: i64,
    changes: UserChanges,
) -> Result<User, ApiError> {
    let email = changes.email.map(normalize_email).transpose()?;
    let now = timeutil::now_rfc3339();

    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    if find_by_id_on(&mut transaction, user_id).await?.is_none() {
        transaction.rollback().await?;
        return Err(ApiError::not_found("User not found."));
    }
    if let Some(Some(email)) = &email {
        if let Err(error) = ensure_email_available(&mut transaction, user_id, email).await {
            transaction.rollback().await?;
            return Err(error);
        }
    }
    match changes.disabled {
        Some(true) => {
            sqlx::query(
                "UPDATE users SET disabled_at = COALESCE(disabled_at, ?), updated_at = ?
                 WHERE id = ?",
            )
            .bind(&now)
            .bind(&now)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ?",
            )
            .bind(&now)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        }
        Some(false) => {
            sqlx::query("UPDATE users SET disabled_at = NULL, updated_at = ? WHERE id = ?")
                .bind(&now)
                .bind(user_id)
                .execute(&mut *transaction)
                .await?;
        }
        None => {}
    }
    if let Some(email) = &email {
        sqlx::query("UPDATE users SET email = ?, updated_at = ? WHERE id = ?")
            .bind(email)
            .bind(&now)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
    }
    let user = find_by_id_on(&mut transaction, user_id)
        .await?
        .ok_or_else(|| ApiError::internal("the edited User disappeared"))?;
    transaction.commit().await?;
    Ok(user)
}

/// Create an Admin only when the Instance has no Admin yet.
///
/// The check and insert share one `BEGIN IMMEDIATE` transaction so two
/// concurrent bootstraps can never create two first Admins.
pub async fn create_admin_if_none(db: &Database, new: NewUser) -> Result<Option<User>, ApiError> {
    let prepared = prepare_user(new)?;
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    if admin_exists_on(&mut transaction).await? {
        transaction.rollback().await?;
        return Ok(None);
    }
    let user = insert_user(&mut transaction, &prepared).await?;
    transaction.commit().await?;
    Ok(Some(user))
}

async fn admin_exists_on(connection: &mut SqliteConnection) -> Result<bool, ApiError> {
    let exists: i64 =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')")
            .fetch_one(&mut *connection)
            .await?;
    Ok(exists != 0)
}

pub async fn admin_exists(db: &Database) -> Result<bool, ApiError> {
    let exists: i64 =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')")
            .fetch_one(db.read_pool())
            .await?;
    Ok(exists != 0)
}

/// The User columns exposed by the API. Password hashes are never selected.
pub(crate) const USER_SELECT: &str =
    "id, username, email, role, disabled_at, created_at, updated_at";

pub async fn find_by_username(db: &Database, username: &str) -> Result<Option<User>, ApiError> {
    let row = sqlx::query(&format!(
        "SELECT {USER_SELECT} FROM users WHERE username = ?"
    ))
    .bind(username)
    .fetch_optional(db.read_pool())
    .await?;
    row.map(|row| user_from_row(&row)).transpose()
}

pub async fn find_by_id(db: &Database, id: i64) -> Result<Option<User>, ApiError> {
    let row = sqlx::query(&format!("SELECT {USER_SELECT} FROM users WHERE id = ?"))
        .bind(id)
        .fetch_optional(db.read_pool())
        .await?;
    row.map(|row| user_from_row(&row)).transpose()
}

async fn find_by_id_on(
    connection: &mut SqliteConnection,
    id: i64,
) -> Result<Option<User>, ApiError> {
    let row = sqlx::query(&format!("SELECT {USER_SELECT} FROM users WHERE id = ?"))
        .bind(id)
        .fetch_optional(&mut *connection)
        .await?;
    row.map(|row| user_from_row(&row)).transpose()
}

async fn ensure_email_available(
    connection: &mut SqliteConnection,
    user_id: i64,
    email: &str,
) -> Result<(), ApiError> {
    let existing: Option<i64> =
        sqlx::query_scalar("SELECT id FROM users WHERE email = ? AND id != ?")
            .bind(email)
            .bind(user_id)
            .fetch_optional(&mut *connection)
            .await?;
    if existing.is_some() {
        return Err(ApiError::conflict(
            "email_taken",
            "Email is already in use.",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct EmailChange {
    /// `None` leaves the email unchanged; `Some(None)` clears it.
    pub email: Option<Option<String>>,
}

/// Edit the optional email of a User. The uniqueness check and the update
/// share one `BEGIN IMMEDIATE` transaction.
pub async fn update_email(
    db: &Database,
    user_id: i64,
    change: EmailChange,
) -> Result<User, ApiError> {
    let Some(email) = change.email else {
        let user = find_by_id(db, user_id).await?;
        return user.ok_or_else(|| ApiError::not_found("User not found."));
    };
    let email = normalize_email(email)?;

    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    if find_by_id_on(&mut transaction, user_id).await?.is_none() {
        transaction.rollback().await?;
        return Err(ApiError::not_found("User not found."));
    }
    if let Some(email) = &email {
        if let Err(error) = ensure_email_available(&mut transaction, user_id, email).await {
            transaction.rollback().await?;
            return Err(error);
        }
    }
    let now = timeutil::now_rfc3339();
    sqlx::query("UPDATE users SET email = ?, updated_at = ? WHERE id = ?")
        .bind(&email)
        .bind(&now)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    let user = find_by_id_on(&mut transaction, user_id)
        .await?
        .ok_or_else(|| ApiError::internal("the edited User disappeared"))?;
    transaction.commit().await?;
    Ok(user)
}

pub async fn disable_user(db: &Database, id: i64) -> Result<(), ApiError> {
    let now = timeutil::now_rfc3339();
    let result = sqlx::query("UPDATE users SET disabled_at = ?, updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&now)
        .bind(id)
        .execute(db.write_pool())
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("User not found."));
    }
    Ok(())
}

fn user_owns_links(count: i64) -> ApiError {
    let noun = if count == 1 { "Link" } else { "Links" };
    ApiError::conflict(
        "user_owns_links",
        format!("The User owns {count} {noun}. Delete or transfer them first."),
    )
}

/// Delete a User that owns no Links.
///
/// The Link count and the delete share one `BEGIN IMMEDIATE` transaction so a
/// concurrent Link creation cannot orphan a Link.
pub async fn delete_user(db: &Database, user_id: i64) -> Result<(), ApiError> {
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    if find_by_id_on(&mut transaction, user_id).await?.is_none() {
        transaction.rollback().await?;
        return Err(ApiError::not_found("User not found."));
    }
    let owned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE owner_id = ?")
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await?;
    if owned > 0 {
        transaction.rollback().await?;
        return Err(user_owns_links(owned));
    }
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

async fn verify_current_password(
    db: &Database,
    user_id: i64,
    current_password: &str,
) -> Result<(), ApiError> {
    let stored: Option<String> = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(db.read_pool())
        .await?;
    let Some(stored) = stored else {
        return Err(ApiError::not_found("User not found."));
    };
    if !verify_password(current_password, &stored) {
        return Err(ApiError::unauthorized(
            "invalid_password",
            "The current password is incorrect.",
        ));
    }
    Ok(())
}

/// Delete the current User's own account after proving the current password.
/// The same no-Links rule applies as for an Admin deleting a User.
pub async fn delete_own_account(
    db: &Database,
    user_id: i64,
    current_password: &str,
) -> Result<(), ApiError> {
    verify_current_password(db, user_id, current_password).await?;
    delete_user(db, user_id).await
}

/// Change a User's password after proving the current password. The new
/// password is hashed with Argon2id before the update.
pub async fn change_password(
    db: &Database,
    user_id: i64,
    current_password: &str,
    new_password: &str,
) -> Result<(), ApiError> {
    validate_password(new_password)?;
    verify_current_password(db, user_id, current_password).await?;
    let password_hash = hash_password(new_password)
        .map_err(|error| ApiError::internal(format!("failed to hash password: {error}")))?;
    let now = timeutil::now_rfc3339();
    let result = sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(&password_hash)
        .bind(&now)
        .bind(user_id)
        .execute(db.write_pool())
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("User not found."));
    }
    Ok(())
}

pub fn user_from_row(row: &SqliteRow) -> Result<User, ApiError> {
    let role: String = row.try_get("role")?;
    let role = Role::parse(&role)
        .ok_or_else(|| ApiError::internal(format!("unknown User role in database: {role}")))?;
    Ok(User {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        email: row.try_get("email")?,
        role,
        disabled_at: row.try_get("disabled_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
