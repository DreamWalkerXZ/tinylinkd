use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection};

use crate::auth::generate_api_token;
use crate::db::Database;
use crate::error::ApiError;
use crate::timeutil;

pub const TOKEN_NAME_MAX_LEN: usize = 100;

#[derive(Debug, Clone)]
pub struct TokenSummary {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct CreatedToken {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub plaintext: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

fn normalize_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > TOKEN_NAME_MAX_LEN {
        return Err(ApiError::validation(
            "invalid_token_name",
            format!("Token name must be 1-{TOKEN_NAME_MAX_LEN} characters."),
        ));
    }
    Ok(name.to_string())
}

fn normalize_expiry(expires_at: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(expires_at) = expires_at else {
        return Ok(None);
    };
    let parsed = timeutil::parse_rfc3339(expires_at).map_err(|_| {
        ApiError::validation(
            "invalid_expires_at",
            "expires_at must be an RFC 3339 timestamp.",
        )
    })?;
    Ok(Some(timeutil::format_rfc3339(parsed)))
}

pub async fn create_token(
    db: &Database,
    user_id: i64,
    name: &str,
    expires_at: Option<&str>,
) -> Result<CreatedToken, ApiError> {
    let name = normalize_name(name)?;
    let expires_at = normalize_expiry(expires_at)?;

    let user = sqlx::query("SELECT disabled_at FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(db.read_pool())
        .await?;
    let Some(user) = user else {
        return Err(ApiError::not_found("User not found."));
    };
    let disabled_at: Option<String> = user.try_get("disabled_at")?;
    if disabled_at.is_some() {
        return Err(ApiError::conflict(
            "user_disabled",
            "Cannot create an API token for a disabled User.",
        ));
    }

    let generated = generate_api_token()
        .map_err(|error| ApiError::internal(format!("failed to generate API token: {error}")))?;
    let created_at = timeutil::now_rfc3339();

    let result = sqlx::query(
        "INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&name)
    .bind(&generated.hash)
    .bind(&generated.prefix)
    .bind(&expires_at)
    .bind(&created_at)
    .execute(db.write_pool())
    .await?;

    Ok(CreatedToken {
        id: result.last_insert_rowid(),
        name,
        prefix: generated.prefix,
        plaintext: generated.plaintext,
        expires_at,
        last_used_at: None,
        revoked_at: None,
        created_at,
    })
}

pub async fn list_tokens(
    db: &Database,
    user_id: i64,
    limit: i64,
    offset: i64,
) -> Result<(Vec<TokenSummary>, i64), ApiError> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(db.read_pool())
        .await?;

    let rows = sqlx::query(
        "SELECT id, name, token_prefix, expires_at, last_used_at, revoked_at, created_at
         FROM api_tokens WHERE user_id = ? ORDER BY id LIMIT ? OFFSET ?",
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.read_pool())
    .await?;

    let tokens = rows
        .iter()
        .map(token_summary_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((tokens, total))
}

pub async fn revoke_token(db: &Database, user_id: i64, token_id: i64) -> Result<(), ApiError> {
    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT id FROM api_tokens WHERE id = ? AND user_id = ?")
            .bind(token_id)
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?;
    if exists.is_none() {
        transaction.rollback().await?;
        return Err(ApiError::not_found("API token not found."));
    }
    sqlx::query("UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?")
        .bind(timeutil::now_rfc3339())
        .bind(token_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn authenticate(
    connection: &mut SqliteConnection,
    token_hash: &str,
) -> Result<Option<(TokenSummary, crate::users::User)>, ApiError> {
    let row = sqlx::query(
        "SELECT t.id AS token_id, t.name AS token_name, t.token_prefix, t.expires_at,
                t.last_used_at, t.revoked_at, t.created_at AS token_created_at,
                u.id, u.username, u.email, u.role, u.disabled_at, u.created_at, u.updated_at
         FROM api_tokens t JOIN users u ON u.id = t.user_id
         WHERE t.token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let summary = TokenSummary {
        id: row.try_get("token_id")?,
        name: row.try_get("token_name")?,
        prefix: row.try_get("token_prefix")?,
        expires_at: row.try_get("expires_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
        created_at: row.try_get("token_created_at")?,
    };
    let user = crate::users::user_from_row(&row)?;
    Ok(Some((summary, user)))
}

pub fn token_summary_from_row(row: &SqliteRow) -> Result<TokenSummary, ApiError> {
    Ok(TokenSummary {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        prefix: row.try_get("token_prefix")?,
        expires_at: row.try_get("expires_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
        created_at: row.try_get("created_at")?,
    })
}
