use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use crate::auth::{constant_time_eq, hash_token};
use crate::db::Database;
use crate::error::ApiError;
use crate::one_time_tokens::{self, TokenKind};
use crate::timeutil;
use crate::users::{self, NewUser, Role, User};

pub use crate::one_time_tokens::{
    CreatedToken as CreatedInvite, TokenStatus as InviteStatus, TokenValidation as InviteValidation,
};

/// Invite tokens are valid for seven days.
pub const INVITE_LIFETIME: time::Duration = time::Duration::days(7);

const KIND: TokenKind = TokenKind {
    table: "invites",
    label: "Invite",
    not_found: "Invite not found.",
    expired_code: "invite_expired",
    expired_detail: "The Invite has expired.",
    used_code: "invite_used",
    used_detail: "The Invite has already been used.",
    revoked_code: "invite_revoked",
    revoked_detail: "The Invite has been revoked.",
    revoke_unavailable_code: "invite_unavailable",
    revoke_unavailable_detail: "The Invite can no longer be revoked.",
    claim_unavailable_code: "invite_used",
    claim_unavailable_detail: "The Invite is no longer available.",
};

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

pub async fn create_invite(db: &Database, admin_id: i64) -> Result<CreatedInvite, ApiError> {
    let generated = one_time_tokens::generate_token(INVITE_LIFETIME, KIND.label)?;

    let result = sqlx::query(
        "INSERT INTO invites (token_hash, created_by, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&generated.hash)
    .bind(admin_id)
    .bind(&generated.expires_at)
    .bind(&generated.created_at)
    .execute(db.write_pool())
    .await?;

    Ok(CreatedInvite {
        id: result.last_insert_rowid(),
        plaintext: generated.plaintext,
        expires_at: generated.expires_at,
        created_at: generated.created_at,
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
    let status = one_time_tokens::status_from_columns(
        &expires_at,
        used_at.as_deref(),
        revoked_at.as_deref(),
        KIND.label,
    )?;
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
    one_time_tokens::revoke(db, &KIND, invite_id).await
}

/// Look up an Invite by its plaintext token.
///
/// The lookup is by hash; the stored hash is compared in constant time so a
/// mismatched token cannot be distinguished by timing.
pub async fn validate_invite(db: &Database, plaintext: &str) -> Result<InviteValidation, ApiError> {
    one_time_tokens::validate(db, &KIND, plaintext).await
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
        return Err(ApiError::not_found(KIND.not_found));
    };
    let stored_hash: String = row.try_get("token_hash")?;
    if !constant_time_eq(stored_hash.as_bytes(), expected_hash.as_bytes()) {
        transaction.rollback().await?;
        return Err(ApiError::not_found(KIND.not_found));
    }
    let invite_id: i64 = row.try_get("id")?;
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

    let user = match users::insert_user(&mut transaction, &prepared).await {
        Ok(user) => user,
        Err(error) => {
            if let Err(rollback_error) = transaction.rollback().await {
                tracing::warn!(error = %rollback_error, "failed to roll back Invite acceptance");
            }
            return Err(error);
        }
    };

    if !one_time_tokens::claim(&mut transaction, &KIND, invite_id, &timeutil::now_rfc3339()).await?
    {
        transaction.rollback().await?;
        return Err(ApiError::conflict(
            KIND.claim_unavailable_code,
            KIND.claim_unavailable_detail,
        ));
    }

    transaction.commit().await?;
    Ok(user)
}
