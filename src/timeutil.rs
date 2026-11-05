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
