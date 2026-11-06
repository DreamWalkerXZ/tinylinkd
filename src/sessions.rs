use std::time::Duration;

use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sqlx::Row;

use crate::auth::{constant_time_eq, hash_token};
use crate::db::Database;
use crate::error::ApiError;
use crate::ratelimit::RateLimiter;
use crate::timeutil;

/// The browser session cookie for the admin UI.
pub const SESSION_COOKIE_NAME: &str = "tld_session";

/// The pre-session double-submit cookie for the login form.
pub const LOGIN_CSRF_COOKIE_NAME: &str = "tld_login_csrf";

/// Sessions expire after 7 days without a request.
pub const SESSION_IDLE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// The login CSRF cookie only has to survive until the form is submitted.
pub const LOGIN_CSRF_COOKIE_TTL_SECONDS: i64 = 10 * 60;

/// Failed browser logins allowed per IP within [`LOGIN_FAILURE_WINDOW`].
pub const LOGIN_FAILURE_LIMIT: usize = 10;

/// The sliding window for [`LOGIN_FAILURE_LIMIT`].
pub const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// Generate a session token or CSRF token: 32 random bytes as base64url.
pub fn generate_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The `Set-Cookie` header for the login form's double-submit CSRF token.
pub fn login_csrf_set_cookie(value: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{LOGIN_CSRF_COOKIE_NAME}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={LOGIN_CSRF_COOKIE_TTL_SECONDS}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// The `Set-Cookie` header that stores a browser session.
///
/// The `Expires` attribute mirrors the `Max-Age` idle timeout so browsers that
/// ignore `Max-Age` expire the cookie at the same time. Every authenticated
/// response re-issues this cookie, so the timeout slides with activity.
pub fn session_set_cookie(value: &str, secure: bool) -> String {
    let expires_at = http_cookie_expires(SESSION_IDLE_TTL_SECONDS);
    let mut cookie = format!(
        "{SESSION_COOKIE_NAME}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_IDLE_TTL_SECONDS}; Expires={expires_at}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// An IMF-fixdate timestamp `seconds` from now, as used by cookie `Expires`.
fn http_cookie_expires(seconds: i64) -> String {
    use chrono::{DateTime, Utc};
    let when = std::time::SystemTime::now() + std::time::Duration::from_secs(seconds.max(0) as u64);
    let when: DateTime<Utc> = when.into();
    when.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// The `Set-Cookie` header that removes the browser session cookie.
pub fn clear_session_cookie(secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Compare a submitted CSRF token with the session's token in constant time.
pub fn csrf_matches(expected: &str, submitted: &str) -> bool {
    constant_time_eq(expected.as_bytes(), submitted.as_bytes())
}

/// A newly created browser session. The plaintext token is returned once and
/// only its SHA-256 hash is stored.
#[derive(Debug, Clone)]
pub struct CreatedSession {
    pub plaintext: String,
    pub csrf_token: String,
}

/// Create a session for a User, rotating out `previous_token` when the browser
/// presented one. The revoke and insert share one `BEGIN IMMEDIATE`
/// transaction so a failed login cannot leave two live sessions behind.
pub async fn create_session(
    db: &Database,
    user_id: i64,
    previous_token: Option<&str>,
) -> Result<CreatedSession, ApiError> {
    let plaintext = generate_token().map_err(|error| {
        ApiError::internal(format!("failed to generate a session token: {error}"))
    })?;
    let csrf_token = generate_token()
        .map_err(|error| ApiError::internal(format!("failed to generate a CSRF token: {error}")))?;
    let token_hash = hash_token(&plaintext);
    let now = timeutil::now_rfc3339();
    let expires_at = timeutil::format_rfc3339(
        timeutil::now() + time::Duration::seconds(SESSION_IDLE_TTL_SECONDS),
    );

    let mut transaction = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    if let Some(previous_token) = previous_token {
        sqlx::query(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(&now)
        .bind(hash_token(previous_token))
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "INSERT INTO sessions
         (user_id, token_hash, csrf_token, created_at, last_seen_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&token_hash)
    .bind(&csrf_token)
    .bind(&now)
    .bind(&now)
    .bind(&expires_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(CreatedSession {
        plaintext,
        csrf_token,
    })
}

/// Revoke a session so its cookie can no longer authenticate.
pub async fn revoke(db: &Database, session_id: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
        .bind(timeutil::now_rfc3339())
        .bind(session_id)
        .execute(db.write_pool())
        .await?;
    Ok(())
}

/// Find a cookie value by name across all `Cookie` headers.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    crate::cookies::cookie_value(headers, name)
}

/// An authenticated browser session.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub csrf_token: String,
}

impl Session {
    /// Whether a submitted form token matches this session's CSRF token.
    pub fn csrf_matches(&self, submitted: &str) -> bool {
        csrf_matches(&self.csrf_token, submitted)
    }
}

/// Resolve a plaintext session token to its Session and User. Expired,
/// revoked, or disabled-User sessions are rejected. A valid lookup updates the
/// sliding 7-day idle expiry.
pub async fn authenticate(
    db: &Database,
    plaintext: &str,
) -> Result<Option<(Session, crate::users::User)>, ApiError> {
    let row = sqlx::query(
        "SELECT s.id AS session_id, s.user_id AS session_user_id, s.csrf_token,
                s.expires_at AS session_expires_at, s.revoked_at AS session_revoked_at,
                u.id, u.username, u.email, u.role, u.disabled_at, u.created_at, u.updated_at
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?",
    )
    .bind(hash_token(plaintext))
    .fetch_optional(db.read_pool())
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let revoked_at: Option<String> = row.try_get("session_revoked_at")?;
    if revoked_at.is_some() {
        return Ok(None);
    }
    let expires_at: String = row.try_get("session_expires_at")?;
    let Ok(expires_at) = timeutil::parse_rfc3339(&expires_at) else {
        tracing::error!("stored session expiry is not RFC 3339");
        return Ok(None);
    };
    let now = timeutil::now();
    if expires_at <= now {
        return Ok(None);
    }
    let user = crate::users::user_from_row(&row)?;
    if user.disabled_at.is_some() {
        return Ok(None);
    }

    let session = Session {
        id: row.try_get("session_id")?,
        user_id: row.try_get("session_user_id")?,
        csrf_token: row.try_get("csrf_token")?,
    };

    let now = timeutil::format_rfc3339(now);
    let expires_at = timeutil::format_rfc3339(
        timeutil::now() + time::Duration::seconds(SESSION_IDLE_TTL_SECONDS),
    );
    if let Err(error) = sqlx::query(
        "UPDATE sessions SET last_seen_at = ?, expires_at = ?
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(&expires_at)
    .bind(session.id)
    .execute(db.write_pool())
    .await
    {
        tracing::warn!(error = %error, session_id = session.id, "failed to refresh a session");
    }

    Ok(Some((session, user)))
}

/// Whether a plaintext session token still authenticates, without sliding its
/// idle expiry. Response middleware uses this to decide whether to re-issue
/// the browser cookie; [`authenticate`] performs the sliding update itself.
pub async fn is_valid(db: &Database, plaintext: &str) -> Result<bool, ApiError> {
    let row = sqlx::query(
        "SELECT s.expires_at, s.revoked_at, u.disabled_at
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?",
    )
    .bind(hash_token(plaintext))
    .fetch_optional(db.read_pool())
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    if revoked_at.is_some() {
        return Ok(false);
    }
    let disabled_at: Option<String> = row.try_get("disabled_at")?;
    if disabled_at.is_some() {
        return Ok(false);
    }
    let expires_at: String = row.try_get("expires_at")?;
    match timeutil::parse_rfc3339(&expires_at) {
        Ok(expires_at) => Ok(expires_at > timeutil::now()),
        Err(error) => {
            tracing::error!(error = %error, "stored session expiry is not RFC 3339");
            Ok(false)
        }
    }
}

/// Process-local failed-login limiter keyed by client IP. A single-instance
/// deployment needs no external store; expired failures are pruned whenever a
/// new one is recorded.
#[derive(Debug)]
pub struct LoginAttemptLimiter {
    failures: RateLimiter<String>,
}

impl LoginAttemptLimiter {
    pub fn new() -> Self {
        Self {
            failures: RateLimiter::new(LOGIN_FAILURE_LIMIT, LOGIN_FAILURE_WINDOW),
        }
    }

    /// When this IP is rate-limited, returns the seconds to advertise in
    /// `Retry-After`.
    pub fn check(&self, ip: &str) -> Option<u64> {
        self.failures.check(&ip.to_string())
    }

    /// Record a failed login attempt.
    pub fn record_failure(&self, ip: &str) {
        self.failures.record(&ip.to_string());
    }
}

impl Default for LoginAttemptLimiter {
    fn default() -> Self {
        Self::new()
    }
}
