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
