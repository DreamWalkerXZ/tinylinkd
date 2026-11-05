use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use axum::http::header;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use time::OffsetDateTime;

/// How long a password unlock lasts by default. T10 makes this an Instance
/// setting; until then every unlock cookie uses this TTL.
pub const UNLOCK_COOKIE_TTL_SECONDS: i64 = 3600;

/// Failed password attempts allowed per IP and Link within
/// [`PASSWORD_FAILURE_WINDOW`] before further attempts are rejected.
pub const PASSWORD_FAILURE_LIMIT: usize = 5;

/// The sliding window for [`PASSWORD_FAILURE_LIMIT`].
pub const PASSWORD_FAILURE_WINDOW: Duration = Duration::from_secs(60);

const COOKIE_NAME_PREFIX: &str = "tld_link_unlock_";
const PAYLOAD_VERSION: &str = "v1";

fn hmac(secret: &[u8]) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts keys of any length")
}

fn sign(secret: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac(secret);
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn verify(secret: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let mut mac = hmac(secret);
    mac.update(message);
    mac.verify_slice(signature).is_ok()
}

/// The cookie name for one Link. Each Link gets its own cookie so a browser
/// can stay unlocked on several Links at once.
pub fn cookie_name(link_id: i64) -> String {
    format!("{COOKIE_NAME_PREFIX}{link_id}")
}

fn payload(link_id: i64, password_version: i64, expires_at_unix: i64) -> String {
    format!("{PAYLOAD_VERSION}.{link_id}.{password_version}.{expires_at_unix}")
}

/// Build a signed unlock cookie value for a Link and password version.
pub fn issue_cookie(
    secret: &[u8],
    link_id: i64,
    password_version: i64,
    now: OffsetDateTime,
) -> String {
    let expires_at_unix =
        (now + time::Duration::seconds(UNLOCK_COOKIE_TTL_SECONDS)).unix_timestamp();
    let payload = payload(link_id, password_version, expires_at_unix);
    let signature = URL_SAFE_NO_PAD.encode(sign(secret, payload.as_bytes()));
    format!("{payload}.{signature}")
}

/// Verify an unlock cookie value for the given Link. The signature is checked
/// in constant time, and the Link id, password version, and expiry must match.
pub fn cookie_is_valid(
    secret: &[u8],
    value: &str,
    link_id: i64,
    password_version: i64,
    now: OffsetDateTime,
) -> bool {
    let mut parts = value.split('.');
    let (
        Some(version),
        Some(cookie_link_id),
        Some(cookie_password_version),
        Some(expires_at),
        Some(signature),
        None,
    ) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    )
    else {
        return false;
    };
    if version != PAYLOAD_VERSION {
        return false;
    }
    let (Ok(cookie_link_id), Ok(cookie_password_version), Ok(expires_at)) = (
        cookie_link_id.parse::<i64>(),
        cookie_password_version.parse::<i64>(),
        expires_at.parse::<i64>(),
    ) else {
        return false;
    };
    if cookie_link_id != link_id
        || cookie_password_version != password_version
        || expires_at <= now.unix_timestamp()
    {
        return false;
    }
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let expected = payload(cookie_link_id, cookie_password_version, expires_at);
    verify(secret, expected.as_bytes(), &signature)
}

/// The `Set-Cookie` header value that stores an unlock cookie.
pub fn set_cookie_header(link_id: i64, value: &str, secure: bool) -> String {
    let mut header = format!(
        "{}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={UNLOCK_COOKIE_TTL_SECONDS}",
        cookie_name(link_id)
    );
    if secure {
        header.push_str("; Secure");
    }
    header
}

/// Find a Link's unlock cookie in the request's `Cookie` headers.
pub fn cookie_from_headers(headers: &HeaderMap, link_id: i64) -> Option<String> {
    let name = cookie_name(link_id);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key.trim() == name).then(|| value.to_string()))
}

/// Process-local failed-password rate limiter keyed by client IP and Link.
///
/// A single-instance deployment needs no external store; the state is bounded
/// by pruning expired failures whenever a new one is recorded.
#[derive(Debug, Default)]
pub struct PasswordAttemptLimiter {
    failures: Mutex<HashMap<(String, i64), VecDeque<Instant>>>,
}

impl PasswordAttemptLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(String, i64), VecDeque<Instant>>> {
        self.failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// When the Link is rate-limited for this IP, returns the number of
    /// seconds the caller should advertise in `Retry-After`.
    pub fn check(&self, ip: &str, link_id: i64) -> Option<u64> {
        let key = (ip.to_string(), link_id);
        let now = Instant::now();
        let mut failures = self.lock();
        let entry = failures.get_mut(&key)?;
        while entry
            .front()
            .is_some_and(|oldest| now.duration_since(*oldest) >= PASSWORD_FAILURE_WINDOW)
        {
            entry.pop_front();
        }
        if entry.len() < PASSWORD_FAILURE_LIMIT {
            return None;
        }
        let oldest = *entry.front().expect("a limited entry has failures");
        Some(
            PASSWORD_FAILURE_WINDOW
                .saturating_sub(now.duration_since(oldest))
                .as_secs()
                .max(1),
        )
    }

    /// Record a failed password attempt.
    pub fn record_failure(&self, ip: &str, link_id: i64) {
        let now = Instant::now();
        let mut failures = self.lock();
        failures.retain(|_, times| {
            while times
                .front()
                .is_some_and(|oldest| now.duration_since(*oldest) >= PASSWORD_FAILURE_WINDOW)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        failures
            .entry((ip.to_string(), link_id))
            .or_default()
            .push_back(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a-test-signing-key-of-32-bytes!!!";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid timestamp")
    }

    #[test]
    fn issued_cookies_verify_for_the_same_link_and_version() {
        let cookie = issue_cookie(SECRET, 7, 3, now());
        assert!(cookie_is_valid(SECRET, &cookie, 7, 3, now()));
        assert!(!cookie_is_valid(SECRET, &cookie, 8, 3, now()));
        assert!(!cookie_is_valid(SECRET, &cookie, 7, 4, now()));
    }

    #[test]
    fn cookies_expire_after_the_ttl() {
        let cookie = issue_cookie(SECRET, 7, 3, now());
        let later = now() + time::Duration::seconds(UNLOCK_COOKIE_TTL_SECONDS + 1);
        assert!(!cookie_is_valid(SECRET, &cookie, 7, 3, later));
    }

    #[test]
    fn tampered_or_foreign_cookies_are_rejected() {
        let cookie = issue_cookie(SECRET, 7, 3, now());
        assert!(!cookie_is_valid(b"another-secret", &cookie, 7, 3, now()));

        let mut parts: Vec<&str> = cookie.split('.').collect();
        parts[2] = "4";
        let tampered = parts.join(".");
        assert!(!cookie_is_valid(SECRET, &tampered, 7, 4, now()));

        assert!(!cookie_is_valid(SECRET, "", 7, 3, now()));
        assert!(!cookie_is_valid(SECRET, "v2.7.3.1.abc", 7, 3, now()));
        assert!(!cookie_is_valid(SECRET, "v1.7.3.1", 7, 3, now()));
    }

    #[test]
    fn the_limiter_rejects_the_sixth_failure_and_forgets_old_ones() {
        let limiter = PasswordAttemptLimiter::new();
        let ip = "203.0.113.7";
        for _ in 0..PASSWORD_FAILURE_LIMIT {
            assert_eq!(limiter.check(ip, 1), None);
            limiter.record_failure(ip, 1);
        }
        let retry_after = limiter
            .check(ip, 1)
            .expect("the sixth failure is rate-limited");
        assert!(
            (58..=60).contains(&retry_after),
            "unexpected Retry-After: {retry_after}"
        );
        assert_eq!(limiter.check(ip, 2), None, "another Link is unaffected");
        assert_eq!(
            limiter.check("203.0.113.8", 1),
            None,
            "another IP is unaffected"
        );
    }
}
