use sqlx::Row;

use crate::auth::{self, constant_time_eq, generate_one_time_token, hash_token};
use crate::db::Database;
use crate::error::ApiError;
use crate::timeutil;
use crate::users;

/// Password-reset tokens are valid for 24 hours.
pub const PASSWORD_RESET_LIFETIME: time::Duration = time::Duration::hours(24);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordResetStatus {
    Valid,
    Used,
    Expired,
    Revoked,
}

impl PasswordResetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

fn status_from_columns(
    expires_at: &str,
    used_at: Option<&str>,
    revoked_at: Option<&str>,
) -> Result<PasswordResetStatus, ApiError> {
    if revoked_at.is_some() {
        return Ok(PasswordResetStatus::Revoked);
    }
    if used_at.is_some() {
        return Ok(PasswordResetStatus::Used);
    }
    let expires_at = timeutil::parse_rfc3339(expires_at).map_err(|error| {
        ApiError::internal(format!(
            "stored password-reset expiry is not RFC 3339: {error}"
        ))
    })?;
    if expires_at <= timeutil::now() {
        Ok(PasswordResetStatus::Expired)
    } else {
        Ok(PasswordResetStatus::Valid)
    }
}

#[derive(Debug, Clone)]
pub struct PasswordResetValidation {
    pub status: PasswordResetStatus,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct CreatedPasswordReset {
    pub id: i64,
    pub plaintext: String,
    pub expires_at: String,
    pub created_at: String,
}

pub async fn create_password_reset(
    db: &Database,
    user_id: i64,
) -> Result<CreatedPasswordReset, ApiError> {
    let user: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(db.read_pool())
        .await?;
    if user.is_none() {
        return Err(ApiError::not_found("User not found."));
    }

    let generated = generate_one_time_token().map_err(|error| {
        ApiError::internal(format!("failed to generate password-reset token: {error}"))
    })?;
    let created_at = timeutil::now();
    let expires_at = created_at + PASSWORD_RESET_LIFETIME;
    let created_at = timeutil::format_rfc3339(created_at);
    let expires_at = timeutil::format_rfc3339(expires_at);

    let result = sqlx::query(
        "INSERT INTO password_resets (user_id, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&generated.hash)
    .bind(&expires_at)
    .bind(&created_at)
    .execute(db.write_pool())
    .await?;

    Ok(CreatedPasswordReset {
        id: result.last_insert_rowid(),
        plaintext: generated.plaintext,
        expires_at,
        created_at,
    })
}

/// Look up a password-reset token by its plaintext value.
///
/// The stored hash is compared in constant time, like Invite tokens.
pub async fn validate_password_reset(
    db: &Database,
    plaintext: &str,
) -> Result<PasswordResetValidation, ApiError> {
    let expected_hash = hash_token(plaintext);
    let row = sqlx::query(
        "SELECT token_hash, expires_at, used_at, revoked_at
         FROM password_resets WHERE token_hash = ?",
    )
    .bind(&expected_hash)
    .fetch_optional(db.read_pool())
    .await?;
    let Some(row) = row else {
        return Err(ApiError::not_found("Password-reset token not found."));
    };
    let stored_hash: String = row.try_get("token_hash")?;
    if !constant_time_eq(stored_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err(ApiError::not_found("Password-reset token not found."));
    }

    let expires_at: String = row.try_get("expires_at")?;
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    let status = status_from_columns(&expires_at, used_at.as_deref(), revoked_at.as_deref())?;
    Ok(PasswordResetValidation { status, expires_at })
}

/// Set a new password from a valid password-reset token and consume the token.
///
/// The password is hashed before the write transaction starts. The token is
/// claimed with a single conditional `UPDATE`, so a concurrent acceptance can
/// never apply two passwords.
pub async fn accept_password_reset(
    db: &Database,
    plaintext: &str,
    new_password: &str,
) -> Result<(), ApiError> {
    users::validate_password(new_password)?;
    let password_hash = auth::hash_password(new_password)
        .map_err(|error| ApiError::internal(format!("failed to hash password: {error}")))?;
    let expected_hash = hash_token(plaintext);

    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let row = sqlx::query(
        "SELECT id, user_id, token_hash, expires_at, used_at, revoked_at
         FROM password_resets WHERE token_hash = ?",
    )
    .bind(&expected_hash)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Err(ApiError::not_found("Password-reset token not found."));
    };
    let stored_hash: String = row.try_get("token_hash")?;
    if !constant_time_eq(stored_hash.as_bytes(), expected_hash.as_bytes()) {
        transaction.rollback().await?;
        return Err(ApiError::not_found("Password-reset token not found."));
    }
    let reset_id: i64 = row.try_get("id")?;
    let user_id: i64 = row.try_get("user_id")?;
    let expires_at: String = row.try_get("expires_at")?;
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    match status_from_columns(&expires_at, used_at.as_deref(), revoked_at.as_deref())? {
        PasswordResetStatus::Valid => {}
        PasswordResetStatus::Expired => {
            transaction.rollback().await?;
            return Err(ApiError::gone(
                "password_reset_expired",
                "The password-reset token has expired.",
            ));
        }
        PasswordResetStatus::Used => {
            transaction.rollback().await?;
            return Err(ApiError::conflict(
                "password_reset_used",
                "The password-reset token has already been used.",
            ));
        }
        PasswordResetStatus::Revoked => {
            transaction.rollback().await?;
            return Err(ApiError::conflict(
                "password_reset_revoked",
                "The password-reset token has been revoked.",
            ));
        }
    }

    let now = timeutil::now_rfc3339();
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(&password_hash)
        .bind(&now)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    let claimed = sqlx::query(
        "UPDATE password_resets SET used_at = ?
         WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(reset_id)
    .execute(&mut *transaction)
    .await?;
    if claimed.rows_affected() != 1 {
        transaction.rollback().await?;
        return Err(ApiError::conflict(
            "password_reset_used",
            "The password-reset token is no longer available.",
        ));
    }

    transaction.commit().await?;
    Ok(())
}
