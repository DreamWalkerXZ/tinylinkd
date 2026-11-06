use chrono::TimeZone;
use chrono_tz::Tz;
use time::OffsetDateTime;
use time::UtcOffset;
use time::format_description::well_known::Rfc3339;

use crate::error::ApiError;

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn now_rfc3339() -> String {
    format_rfc3339(now())
}

pub fn format_rfc3339(timestamp: OffsetDateTime) -> String {
    timestamp
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .expect("a valid timestamp always formats as RFC 3339")
}

pub fn parse_rfc3339(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}

/// Validate an RFC 3339 expiry and normalize it to UTC with the `Z`
/// designator.
pub fn normalize_expiry(value: &str) -> Result<String, ApiError> {
    let parsed = parse_rfc3339(value).map_err(|_| {
        ApiError::validation(
            "invalid_expires_at",
            "expires_at must be an RFC 3339 timestamp.",
        )
    })?;
    Ok(format_rfc3339(parsed))
}

/// The calendar date of a UTC instant in an IANA timezone, as `YYYY-MM-DD`.
///
/// The conversion uses the timezone's offset for that instant, so it follows
/// daylight-saving transitions. Returns `None` only for instants outside the
/// range that the timezone database can represent.
pub fn local_date(timezone: &Tz, timestamp: OffsetDateTime) -> Option<String> {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp.unix_timestamp(), 0)?;
    Some(utc.with_timezone(timezone).date_naive().to_string())
}

/// The wall-clock time of a stored RFC 3339 instant in an IANA timezone.
fn local_naive(timezone: &Tz, value: &str) -> Option<chrono::NaiveDateTime> {
    let parsed = parse_rfc3339(value).ok()?;
    let instant = chrono::DateTime::<chrono::Utc>::from_timestamp(parsed.unix_timestamp(), 0)?;
    Some(instant.with_timezone(timezone).naive_local())
}

/// Format a stored RFC 3339 instant for display in an IANA timezone.
///
/// The result is `YYYY-MM-DD HH:MM:SS <IANA name>`, using the timezone's
/// offset at that instant so daylight-saving transitions are respected.
/// Unparseable values are returned unchanged rather than hidden.
pub fn format_in_timezone(timezone: &Tz, value: &str) -> String {
    match local_naive(timezone, value) {
        Some(local) => format!("{} {}", local.format("%Y-%m-%d %H:%M:%S"), timezone.name()),
        None => value.to_string(),
    }
}

/// Format a stored RFC 3339 instant as `YYYY-MM-DD HH:MM:SS` in an IANA
/// timezone, without the timezone name. This is the round-trippable form the
/// admin UI uses for editable expiry times. Unparseable values are returned
/// unchanged rather than hidden.
pub fn format_local_datetime(timezone: &Tz, value: &str) -> String {
    match local_naive(timezone, value) {
        Some(local) => local.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => value.to_string(),
    }
}

/// Parse a `YYYY-MM-DD HH:MM:SS` wall-clock time in an IANA timezone into a UTC
/// instant. A time that occurs twice during a daylight-saving fall-back
/// resolves to the earlier occurrence; a skipped time is rejected.
pub fn parse_local_datetime(timezone: &Tz, value: &str) -> Option<OffsetDateTime> {
    let naive = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok()?;
    let instant = timezone.from_local_datetime(&naive).earliest()?;
    OffsetDateTime::from_unix_timestamp(instant.timestamp()).ok()
}
