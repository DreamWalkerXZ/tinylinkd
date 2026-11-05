use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use crate::auth::{constant_time_eq, generate_one_time_token, hash_token};
use crate::db::Database;
use crate::error::ApiError;
use crate::timeutil;
use crate::users::{self, NewUser, Role, User};

/// Invite tokens are valid for seven days.
pub const INVITE_LIFETIME: time::Duration = time::Duration::days(7);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteStatus {
    Pending,
    Used,
    Expired,
    Revoked,
}

impl InviteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    /// The public acceptance page calls a pending Invite `valid`.
    pub fn as_validation_str(self) -> &'static str {
        match self {
            Self::Pending => "valid",
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
) -> Result<InviteStatus, ApiError> {
    if revoked_at.is_some() {
        return Ok(InviteStatus::Revoked);
    }
    if used_at.is_some() {
        return Ok(InviteStatus::Used);
    }
    let expires_at = timeutil::parse_rfc3339(expires_at).map_err(|error| {
        ApiError::internal(format!("stored Invite expiry is not RFC 3339: {error}"))
    })?;
    if expires_at <= timeutil::now() {
        Ok(InviteStatus::Expired)
    } else {
        Ok(InviteStatus::Pending)
    }
}

#[derive(Debug, Clone)]
pub struct InviteSummary {
    pub id: i64,
    pub created_by: i64,
    pub status: InviteStatus,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct CreatedInvite {
    pub id: i64,
    pub plaintext: String,
    pub expires_at: String,
    pub created_at: String,
}

pub async fn create_invite(db: &Database, admin_id: i64) -> Result<CreatedInvite, ApiError> {
    let generated = generate_one_time_token()
        .map_err(|error| ApiError::internal(format!("failed to generate Invite token: {error}")))?;
    let created_at = timeutil::now();
    let expires_at = created_at + INVITE_LIFETIME;
    let created_at = timeutil::format_rfc3339(created_at);
    let expires_at = timeutil::format_rfc3339(expires_at);

    let result = sqlx::query(
        "INSERT INTO invites (token_hash, created_by, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&generated.hash)
    .bind(admin_id)
    .bind(&expires_at)
    .bind(&created_at)
    .execute(db.write_pool())
    .await?;

    Ok(CreatedInvite {
        id: result.last_insert_rowid(),
        plaintext: generated.plaintext,
        expires_at,
        created_at,
    })
}

pub async fn list_invites(
    db: &Database,
    limit: i64,
    offset: i64,
) -> Result<(Vec<InviteSummary>, i64), ApiError> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invites")
        .fetch_one(db.read_pool())
        .await?;

    let rows = sqlx::query(
        "SELECT id, created_by, expires_at, used_at, revoked_at, created_at
         FROM invites ORDER BY id LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db.read_pool())
    .await?;

    let invites = rows
        .iter()
        .map(invite_summary_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((invites, total))
}

fn invite_summary_from_row(row: &SqliteRow) -> Result<InviteSummary, ApiError> {
    let expires_at: String = row.try_get("expires_at")?;
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    let status = status_from_columns(&expires_at, used_at.as_deref(), revoked_at.as_deref())?;
    Ok(InviteSummary {
        id: row.try_get("id")?,
        created_by: row.try_get("created_by")?,
        status,
        expires_at,
        used_at,
        revoked_at,
        created_at: row.try_get("created_at")?,
    })
}

/// Revoke an unused Invite.
/// Revoking an already revoked Invite is a no-op, so the endpoint is
/// idempotent. A used Invite cannot be revoked.
pub async fn revoke_invite(db: &Database, invite_id: i64) -> Result<(), ApiError> {
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let row = sqlx::query("SELECT used_at, revoked_at FROM invites WHERE id = ?")
        .bind(invite_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Err(ApiError::not_found("Invite not found."));
    };
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    if used_at.is_some() {
        transaction.rollback().await?;
        return Err(ApiError::conflict(
            "invite_used",
            "The Invite has already been used.",
        ));
    }
    if revoked_at.is_some() {
        transaction.commit().await?;
        return Ok(());
    }

    let revoked = sqlx::query(
        "UPDATE invites SET revoked_at = ?
         WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(timeutil::now_rfc3339())
    .bind(invite_id)
    .execute(&mut *transaction)
    .await?;
    if revoked.rows_affected() == 0 {
        transaction.rollback().await?;
        return Err(ApiError::conflict(
            "invite_unavailable",
            "The Invite can no longer be revoked.",
        ));
    }

    transaction.commit().await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct InviteValidation {
    pub status: InviteStatus,
    pub expires_at: String,
}

/// Look up an Invite by its plaintext token.
///
/// The lookup is by hash; the stored hash is compared in constant time so a
/// mismatched token cannot be distinguished by timing.
pub async fn validate_invite(db: &Database, plaintext: &str) -> Result<InviteValidation, ApiError> {
    let expected_hash = hash_token(plaintext);
    let row = sqlx::query(
        "SELECT token_hash, expires_at, used_at, revoked_at
         FROM invites WHERE token_hash = ?",
    )
    .bind(&expected_hash)
    .fetch_optional(db.read_pool())
    .await?;
    let Some(row) = row else {
        return Err(ApiError::not_found("Invite not found."));
    };
    let stored_hash: String = row.try_get("token_hash")?;
    if !constant_time_eq(stored_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err(ApiError::not_found("Invite not found."));
    }

    let expires_at: String = row.try_get("expires_at")?;
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    let status = status_from_columns(&expires_at, used_at.as_deref(), revoked_at.as_deref())?;
    Ok(InviteValidation { status, expires_at })
}

#[derive(Debug, Clone)]
pub struct AcceptInvite {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
}

/// Create a User from a valid Invite and consume the Invite atomically.
///
/// The password is hashed before the write transaction starts. The Invite is
/// claimed with a single conditional `UPDATE`, so a concurrent acceptance can
/// never create a second User.
pub async fn accept_invite(
    db: &Database,
    plaintext: &str,
    request: AcceptInvite,
) -> Result<User, ApiError> {
    let prepared = users::prepare_user(NewUser {
        username: request.username,
        email: request.email,
        password: request.password,
        role: Role::User,
    })?;
    let expected_hash = hash_token(plaintext);

    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let row = sqlx::query(
        "SELECT id, token_hash, expires_at, used_at, revoked_at
         FROM invites WHERE token_hash = ?",
    )
    .bind(&expected_hash)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Err(ApiError::not_found("Invite not found."));
    };
    let stored_hash: String = row.try_get("token_hash")?;
    if !constant_time_eq(stored_hash.as_bytes(), expected_hash.as_bytes()) {
        transaction.rollback().await?;
        return Err(ApiError::not_found("Invite not found."));
    }
    let invite_id: i64 = row.try_get("id")?;
    let expires_at: String = row.try_get("expires_at")?;
    let used_at: Option<String> = row.try_get("used_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    match status_from_columns(&expires_at, used_at.as_deref(), revoked_at.as_deref())? {
        InviteStatus::Pending => {}
        InviteStatus::Expired => {
            transaction.rollback().await?;
            return Err(ApiError::gone("invite_expired", "The Invite has expired."));
        }
        InviteStatus::Used => {
            transaction.rollback().await?;
            return Err(ApiError::conflict(
                "invite_used",
                "The Invite has already been used.",
            ));
        }
        InviteStatus::Revoked => {
            transaction.rollback().await?;
            return Err(ApiError::conflict(
                "invite_revoked",
                "The Invite has been revoked.",
            ));
        }
    }

    let user = match users::insert_user(&mut transaction, &prepared).await {
        Ok(user) => user,
        Err(error) => {
            if let Err(rollback_error) = transaction.rollback().await {
                tracing::warn!(error = %rollback_error, "failed to roll back Invite acceptance");
            }
            return Err(error);
        }
    };

    let claimed = sqlx::query(
        "UPDATE invites SET used_at = ?
         WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(timeutil::now_rfc3339())
    .bind(invite_id)
    .execute(&mut *transaction)
    .await?;
    if claimed.rows_affected() != 1 {
        transaction.rollback().await?;
        return Err(ApiError::conflict(
            "invite_used",
            "The Invite is no longer available.",
        ));
    }

    transaction.commit().await?;
    Ok(user)
}
