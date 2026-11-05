use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::db::Database;
use crate::error::ApiError;

/// The `secrets` key holding the HMAC signing key for password-unlock cookies.
pub const UNLOCK_COOKIE_SIGNING_KEY: &str = "unlock_cookie_signing_key";

/// Unlock cookies are signed with a 32-byte key generated on first need.
pub const SIGNING_KEY_LEN: usize = 32;

/// Read the unlock-cookie signing key, generating and persisting it on first
/// need.
///
/// The key lives in the `secrets` table so it survives restarts, is included in
/// backups, and is never exposed through the API or logs. Concurrent first
/// uses are safe: `INSERT OR IGNORE` lets one key win and every caller then
/// reads the stored winner.
pub async fn unlock_cookie_signing_key(db: &Database) -> Result<Vec<u8>, ApiError> {
    if let Some(encoded) = read_secret(db, UNLOCK_COOKIE_SIGNING_KEY).await? {
        return decode_key(&encoded);
    }

    let mut key = [0u8; SIGNING_KEY_LEN];
    getrandom::fill(&mut key).map_err(|error| {
        ApiError::internal(format!(
            "failed to generate the unlock signing key: {error}"
        ))
    })?;
    let encoded = URL_SAFE_NO_PAD.encode(key);
    sqlx::query("INSERT OR IGNORE INTO secrets (key, value) VALUES (?, ?)")
        .bind(UNLOCK_COOKIE_SIGNING_KEY)
        .bind(&encoded)
        .execute(db.write_pool())
        .await?;

    let encoded = read_secret(db, UNLOCK_COOKIE_SIGNING_KEY)
        .await?
        .ok_or_else(|| ApiError::internal("the unlock signing key disappeared"))?;
    decode_key(&encoded)
}

async fn read_secret(db: &Database, key: &str) -> Result<Option<String>, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT value FROM secrets WHERE key = ?")
            .bind(key)
            .fetch_optional(db.read_pool())
            .await?,
    )
}

fn decode_key(encoded: &str) -> Result<Vec<u8>, ApiError> {
    let key = URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        ApiError::internal(format!("the stored unlock signing key is invalid: {error}"))
    })?;
    if key.len() != SIGNING_KEY_LEN {
        return Err(ApiError::internal(
            "the stored unlock signing key has the wrong length",
        ));
    }
    Ok(key)
}
