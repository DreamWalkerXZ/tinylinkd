use sqlx::Row;
use sqlx::{Sqlite, Transaction};

use crate::auth::{constant_time_eq, generate_one_time_token, hash_token};
use crate::db::Database;
use crate::error::ApiError;
use crate::timeutil;

/// The lifecycle state shared by one-time Invite and password-reset tokens.
///
/// Status precedence is `revoked`, then `used`, then `expired`, then pending.
/// Both token kinds render a pending token differently depending on the
/// endpoint: the Admin list shows `pending`; the public validation page shows
/// `valid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStatus {
    Pending,
    Used,
    Expired,
    Revoked,
}

impl TokenStatus {
    /// The Admin-facing status name. A pending token is `pending`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    /// The public acceptance-page status name. A pending token is `valid`.
    pub fn as_validation_str(self) -> &'static str {
        match self {
            Self::Pending => "valid",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    /// Fail with the kind-specific error unless the token can still be used.
    pub(crate) fn ensure_pending(self, kind: &TokenKind) -> Result<(), ApiError> {
        match self {
            Self::Pending => Ok(()),
            Self::Expired => Err(ApiError::gone(kind.expired_code, kind.expired_detail)),
            Self::Used => Err(ApiError::conflict(kind.used_code, kind.used_detail)),
            Self::Revoked => Err(ApiError::conflict(kind.revoked_code, kind.revoked_detail)),
        }
    }
}

/// The table name, human label, and error text that distinguish the two
/// one-time token kinds. The state machine is shared; these are the only
/// table-specific differences.
pub(crate) struct TokenKind {
    pub(crate) table: &'static str,
    pub(crate) label: &'static str,
    pub(crate) not_found: &'static str,
    pub(crate) expired_code: &'static str,
    pub(crate) expired_detail: &'static str,
    pub(crate) used_code: &'static str,
    pub(crate) used_detail: &'static str,
    pub(crate) revoked_code: &'static str,
    pub(crate) revoked_detail: &'static str,
    pub(crate) revoke_unavailable_code: &'static str,
    pub(crate) revoke_unavailable_detail: &'static str,
    pub(crate) claim_unavailable_code: &'static str,
    pub(crate) claim_unavailable_detail: &'static str,
}

/// A one-time token as returned by the public validation endpoints.
#[derive(Debug, Clone)]
pub struct TokenValidation {
    pub status: TokenStatus,
    pub expires_at: String,
}

/// A one-time token created by an Admin. The plaintext is returned only once.
#[derive(Debug, Clone)]
pub struct CreatedToken {
    pub id: i64,
    pub plaintext: String,
    pub expires_at: String,
    pub created_at: String,
}

/// A freshly generated token plus its storage hash and lifetime window.
pub(crate) struct GeneratedToken {
    pub(crate) plaintext: String,
    pub(crate) hash: String,
    pub(crate) expires_at: String,
    pub(crate) created_at: String,
}

/// Generate a one-time token that expires `lifetime` from now.
pub(crate) fn generate_token(
    lifetime: time::Duration,
    label: &str,
) -> Result<GeneratedToken, ApiError> {
    let generated = generate_one_time_token().map_err(|error| {
        ApiError::internal(format!("failed to generate {label} token: {error}"))
    })?;
    let created_at = timeutil::now();
    let expires_at = created_at + lifetime;
    Ok(GeneratedToken {
        plaintext: generated.plaintext,
        hash: generated.hash,
        created_at: timeutil::format_rfc3339(created_at),
        expires_at: timeutil::format_rfc3339(expires_at),
    })
}

/// Resolve a token's status from its stored timestamp columns.
pub(crate) fn status_from_columns(
    expires_at: &str,
    used_at: Option<&str>,
    revoked_at: Option<&str>,
    label: &str,
) -> Result<TokenStatus, ApiError> {
    if revoked_at.is_some() {
        return Ok(TokenStatus::Revoked);
    }
    if used_at.is_some() {
        return Ok(TokenStatus::Used);
    }
    let expires_at = timeutil::parse_rfc3339(expires_at).map_err(|error| {
        ApiError::internal(format!("stored {label} expiry is not RFC 3339: {error}"))
    })?;
    if expires_at <= timeutil::now() {
        Ok(TokenStatus::Expired)
    } else {
        Ok(TokenStatus::Pending)
    }
}

/// Look up a token by its plaintext value.
///
/// The lookup is by hash; the stored hash is compared in constant time so a
/// mismatched token cannot be distinguished by timing.
pub(crate) async fn validate(
    db: &Database,
    kind: &TokenKind,
    plaintext: &str,
) -> Result<TokenValidation, ApiError> {
    let expected_hash = hash_token(plaintext);
    let select = format!(
        "SELECT token_hash, expires_at, used_at, revoked_at
         FROM {} WHERE token_hash = ?",
        kind.table
    );
    let row = sqlx::query(&select)
        .bind(&expected_hash)
        .fetch_optional(db.read_pool())
        .await?;
    let Some(row) = row else {
        return Err(ApiError::not_found(kind.not_found));
    };
    let stored_hash: String = row.try_get("token_hash")?;
    if !constant_time_eq(stored_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err(ApiError::not_found(kind.not_found));
    }

    let expires_at: String = row.try_get("expires_at")?;
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    let status = status_from_columns(
        &expires_at,
        used_at.as_deref(),
        revoked_at.as_deref(),
        kind.label,
    )?;
    Ok(TokenValidation { status, expires_at })
}

/// Revoke a token. Revoking an already revoked token is a no-op, so the
/// endpoint is idempotent. A used token cannot be revoked.
pub(crate) async fn revoke(db: &Database, kind: &TokenKind, id: i64) -> Result<(), ApiError> {
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let select = format!(
        "SELECT used_at, revoked_at FROM {} WHERE id = ?",
        kind.table
    );
    let row = sqlx::query(&select)
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Err(ApiError::not_found(kind.not_found));
    };
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    if used_at.is_some() {
        transaction.rollback().await?;
        return Err(ApiError::conflict(kind.used_code, kind.used_detail));
    }
    if revoked_at.is_some() {
        transaction.commit().await?;
        return Ok(());
    }

    let update = format!(
        "UPDATE {} SET revoked_at = ?
         WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
        kind.table
    );
    let revoked = sqlx::query(&update)
        .bind(timeutil::now_rfc3339())
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    if revoked.rows_affected() == 0 {
        transaction.rollback().await?;
        return Err(ApiError::conflict(
            kind.revoke_unavailable_code,
            kind.revoke_unavailable_detail,
        ));
    }

    transaction.commit().await?;
    Ok(())
}

/// Mark a token used with a single conditional `UPDATE`, so a concurrent
/// acceptance can never apply it twice. Returns `false` when the token was
/// claimed by another request.
pub(crate) async fn claim(
    transaction: &mut Transaction<'_, Sqlite>,
    kind: &TokenKind,
    id: i64,
    used_at: &str,
) -> Result<bool, ApiError> {
    let update = format!(
        "UPDATE {} SET used_at = ?
         WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
        kind.table
    );
    let claimed = sqlx::query(&update)
        .bind(used_at)
        .bind(id)
        .execute(&mut **transaction)
        .await?;
    Ok(claimed.rows_affected() == 1)
}
