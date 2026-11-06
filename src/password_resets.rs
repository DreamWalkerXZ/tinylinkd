use sqlx::Row;

use crate::auth::{self, constant_time_eq, hash_token};
use crate::db::Database;
use crate::error::ApiError;
use crate::one_time_tokens::{self, TokenKind};
use crate::timeutil;
use crate::users;

pub use crate::one_time_tokens::{
    CreatedToken as CreatedPasswordReset, TokenStatus as PasswordResetStatus,
    TokenValidation as PasswordResetValidation,
};

/// Password-reset tokens are valid for 24 hours.
pub const PASSWORD_RESET_LIFETIME: time::Duration = time::Duration::hours(24);

const KIND: TokenKind = TokenKind {
    table: "password_resets",
    label: "password-reset",
    not_found: "Password-reset token not found.",
    expired_code: "password_reset_expired",
    expired_detail: "The password-reset token has expired.",
    used_code: "password_reset_used",
    used_detail: "The password-reset token has already been used.",
    revoked_code: "password_reset_revoked",
    revoked_detail: "The password-reset token has been revoked.",
    revoke_unavailable_code: "password_reset_unavailable",
    revoke_unavailable_detail: "The password-reset token can no longer be revoked.",
    claim_unavailable_code: "password_reset_used",
    claim_unavailable_detail: "The password-reset token is no longer available.",
};

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

    let generated = one_time_tokens::generate_token(PASSWORD_RESET_LIFETIME, KIND.label)?;

    let result = sqlx::query(
        "INSERT INTO password_resets (user_id, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&generated.hash)
    .bind(&generated.expires_at)
    .bind(&generated.created_at)
    .execute(db.write_pool())
    .await?;

    Ok(CreatedPasswordReset {
        id: result.last_insert_rowid(),
        plaintext: generated.plaintext,
        expires_at: generated.expires_at,
        created_at: generated.created_at,
    })
}

/// Look up a password-reset token by its plaintext value.
///
/// The stored hash is compared in constant time, like Invite tokens.
pub async fn validate_password_reset(
    db: &Database,
    plaintext: &str,
) -> Result<PasswordResetValidation, ApiError> {
    one_time_tokens::validate(db, &KIND, plaintext).await
}

/// Revoke a password-reset token so it can no longer be validated or used.
///
/// Used tokens cannot be revoked. Revoking an already revoked token is a
/// no-op, mirroring Invite revocation.
pub async fn revoke_password_reset(db: &Database, reset_id: i64) -> Result<(), ApiError> {
    one_time_tokens::revoke(db, &KIND, reset_id).await
}

/// Apply a new password for a valid password-reset token and consume it.
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
        return Err(ApiError::not_found(KIND.not_found));
    };
    let stored_hash: String = row.try_get("token_hash")?;
    if !constant_time_eq(stored_hash.as_bytes(), expected_hash.as_bytes()) {
        transaction.rollback().await?;
        return Err(ApiError::not_found(KIND.not_found));
    }
    let reset_id: i64 = row.try_get("id")?;
    let user_id: i64 = row.try_get("user_id")?;
    let expires_at: String = row.try_get("expires_at")?;
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    let status = one_time_tokens::status_from_columns(
        &expires_at,
        used_at.as_deref(),
        revoked_at.as_deref(),
        KIND.label,
    )?;
    if let Err(error) = status.ensure_pending(&KIND) {
        transaction.rollback().await?;
        return Err(error);
    }

    let now = timeutil::now_rfc3339();
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(&password_hash)
        .bind(&now)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    if !one_time_tokens::claim(&mut transaction, &KIND, reset_id, &now).await? {
        transaction.rollback().await?;
        return Err(ApiError::conflict(
            KIND.claim_unavailable_code,
            KIND.claim_unavailable_detail,
        ));
    }

    transaction.commit().await?;
    Ok(())
}
