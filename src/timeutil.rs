use chrono_tz::Tz;
use time::OffsetDateTime;
use time::UtcOffset;
use time::format_description::well_known::Rfc3339;

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

/// The calendar date of a UTC instant in an IANA timezone, as `YYYY-MM-DD`.
///
/// The conversion uses the timezone's offset for that instant, so it follows
/// daylight-saving transitions. Returns `None` only for instants outside the
/// range that the timezone database can represent.
pub fn local_date(timezone: &Tz, timestamp: OffsetDateTime) -> Option<String> {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp.unix_timestamp(), 0)?;
    Some(utc.with_timezone(timezone).date_naive().to_string())
}

/// Format a stored RFC 3339 instant for display in an IANA timezone.
///
/// The result is `YYYY-MM-DD HH:MM:SS <IANA name>`, using the timezone's
/// offset at that instant so daylight-saving transitions are respected.
/// Unparseable values are returned unchanged rather than hidden.
pub fn format_in_timezone(timezone: &Tz, value: &str) -> String {
    let Ok(parsed) = parse_rfc3339(value) else {
        return value.to_string();
    };
    let Some(instant) = chrono::DateTime::<chrono::Utc>::from_timestamp(parsed.unix_timestamp(), 0)
    else {
        return value.to_string();
    };
    format!(
        "{} {}",
        instant.with_timezone(timezone).format("%Y-%m-%d %H:%M:%S"),
        timezone.name()
    )
}
