use std::collections::BTreeMap;
use std::str::FromStr;

use futures_util::TryStreamExt;
use sqlx::{QueryBuilder, Row, Sqlite};
use time::OffsetDateTime;

use crate::db::Database;
use crate::error::ApiError;
use crate::timeutil;

/// The default v1 Click retention window in days. The running Instance uses
/// the mutable `click_retention_days` setting instead of this constant.
pub const CLICK_RETENTION_DAYS: i64 = crate::settings::DEFAULT_CLICK_RETENTION_DAYS;

/// The interval between Click retention runs.
pub const RETENTION_CHECK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// An inclusive range of UTC timestamps. `None` means unbounded on that side.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeRange {
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
}

impl TimeRange {
    fn bounds(self) -> (Option<String>, Option<String>) {
        (
            self.from.map(timeutil::format_rfc3339),
            self.to.map(timeutil::format_rfc3339),
        )
    }
}

/// One recorded Click as stored for analytics.
#[derive(Debug, Clone)]
pub struct Click {
    pub id: i64,
    pub clicked_at: String,
    pub ip: String,
    pub user_agent: String,
    pub referer: Option<String>,
    pub device: String,
    pub is_bot: bool,
}

fn click_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Click, ApiError> {
    Ok(Click {
        id: row.try_get("id")?,
        clicked_at: row.try_get("clicked_at")?,
        ip: row.try_get("ip")?,
        user_agent: row.try_get("user_agent")?,
        referer: row.try_get("referer")?,
        device: row.try_get("device")?,
        is_bot: row.try_get::<i64, _>("is_bot")? != 0,
    })
}

fn push_time_range<'a>(
    builder: &mut QueryBuilder<'a, Sqlite>,
    from: Option<&'a str>,
    to: Option<&'a str>,
) {
    // Stored timestamps may or may not carry fractional seconds, so a text
    // comparison would misorder Clicks at a whole-second boundary. Compare
    // the instants instead; both bounds are inclusive.
    if let Some(from) = from {
        builder
            .push(" AND julianday(clicked_at) >= julianday(")
            .push_bind(from)
            .push(")");
    }
    if let Some(to) = to {
        builder
            .push(" AND julianday(clicked_at) <= julianday(")
            .push_bind(to)
            .push(")");
    }
}

/// List a Link's Clicks newest first, within an optional UTC time range.
/// `total` counts every matching Click, ignoring `limit`/`offset`.
pub async fn list_clicks(
    db: &Database,
    link_id: i64,
    range: TimeRange,
    limit: i64,
    offset: i64,
) -> Result<(Vec<Click>, i64), ApiError> {
    let (from, to) = range.bounds();

    let mut count = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM clicks WHERE link_id = ");
    count.push_bind(link_id);
    push_time_range(&mut count, from.as_deref(), to.as_deref());
    let total: i64 = count.build_query_scalar().fetch_one(db.read_pool()).await?;

    let mut select = QueryBuilder::<Sqlite>::new(
        "SELECT id, clicked_at, ip, user_agent, referer, device, is_bot
         FROM clicks WHERE link_id = ",
    );
    select.push_bind(link_id);
    push_time_range(&mut select, from.as_deref(), to.as_deref());
    select
        .push(" ORDER BY clicked_at DESC, id DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = select.build().fetch_all(db.read_pool()).await?;

    let clicks = rows.iter().map(click_from_row).collect::<Result<_, _>>()?;
    Ok((clicks, total))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayStats {
    pub date: String,
    pub total_clicks: i64,
    pub human_clicks: i64,
    pub bot_clicks: i64,
}

/// Aggregate statistics for one Link over an optional UTC time range.
///
/// Day buckets use the Instance's IANA `timezone`, while stored timestamps and
/// the range bounds remain UTC. Only days with at least one Click appear,
/// oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClickStats {
    pub total_clicks: i64,
    pub human_clicks: i64,
    pub bot_clicks: i64,
    /// Every Click counted once per device, including bot-device Clicks.
    pub by_device: BTreeMap<String, i64>,
    /// Only days with at least one Click appear, oldest first.
    pub by_day: Vec<DayStats>,
}

pub async fn click_stats(
    db: &Database,
    link_id: i64,
    range: TimeRange,
    timezone: &str,
) -> Result<ClickStats, ApiError> {
    let timezone = chrono_tz::Tz::from_str(timezone)
        .map_err(|_| ApiError::internal("the Instance timezone is invalid"))?;
    let (from, to) = range.bounds();

    let mut totals = QueryBuilder::<Sqlite>::new(
        "SELECT COUNT(*) AS total_clicks,
                COUNT(*) - COALESCE(SUM(is_bot), 0) AS human_clicks,
                COALESCE(SUM(is_bot), 0) AS bot_clicks
         FROM clicks WHERE link_id = ",
    );
    totals.push_bind(link_id);
    push_time_range(&mut totals, from.as_deref(), to.as_deref());
    let row = totals.build().fetch_one(db.read_pool()).await?;
    let total_clicks: i64 = row.try_get("total_clicks")?;
    let human_clicks: i64 = row.try_get("human_clicks")?;
    let bot_clicks: i64 = row.try_get("bot_clicks")?;

    let mut devices = QueryBuilder::<Sqlite>::new(
        "SELECT device, COUNT(*) AS clicks FROM clicks WHERE link_id = ",
    );
    devices.push_bind(link_id);
    push_time_range(&mut devices, from.as_deref(), to.as_deref());
    devices.push(" GROUP BY device");
    let rows = devices.build().fetch_all(db.read_pool()).await?;
    let mut by_device = BTreeMap::new();
    for row in &rows {
        by_device.insert(
            row.try_get::<String, _>("device")?,
            row.try_get::<i64, _>("clicks")?,
        );
    }

    let mut days =
        QueryBuilder::<Sqlite>::new("SELECT clicked_at, is_bot FROM clicks WHERE link_id = ");
    days.push_bind(link_id);
    push_time_range(&mut days, from.as_deref(), to.as_deref());
    let mut rows = days.build().fetch(db.read_pool());
    let mut by_day: BTreeMap<String, DayStats> = BTreeMap::new();
    while let Some(row) = rows.try_next().await? {
        let clicked_at: String = row.try_get("clicked_at")?;
        let is_bot = row.try_get::<i64, _>("is_bot")? != 0;
        let timestamp = timeutil::parse_rfc3339(&clicked_at).map_err(|error| {
            ApiError::internal(format!("a stored Click timestamp is invalid: {error}"))
        })?;
        let date = timeutil::local_date(&timezone, timestamp).ok_or_else(|| {
            ApiError::internal("a Click timestamp is outside the representable range")
        })?;
        let day = by_day.entry(date.clone()).or_insert_with(|| DayStats {
            date,
            total_clicks: 0,
            human_clicks: 0,
            bot_clicks: 0,
        });
        day.total_clicks += 1;
        if is_bot {
            day.bot_clicks += 1;
        } else {
            day.human_clicks += 1;
        }
    }
    let by_day = by_day.into_values().collect();

    Ok(ClickStats {
        total_clicks,
        human_clicks,
        bot_clicks,
        by_device,
        by_day,
    })
}

/// Delete every Click recorded before `now - retention_days`.
///
/// A Click exactly `retention_days` old is kept: only Clicks *older* than the
/// window are pruned. Returns the number of deleted rows.
pub async fn cleanup_old_clicks(
    db: &Database,
    retention_days: i64,
    now: OffsetDateTime,
) -> Result<u64, ApiError> {
    let cutoff_seconds = now
        .unix_timestamp()
        .saturating_sub(retention_days.saturating_mul(86_400));
    let Ok(cutoff) = OffsetDateTime::from_unix_timestamp(cutoff_seconds) else {
        // A retention window beyond the representable range keeps every Click.
        return Ok(0);
    };
    let cutoff = timeutil::format_rfc3339(cutoff);
    let result = sqlx::query("DELETE FROM clicks WHERE clicked_at < ?")
        .bind(cutoff)
        .execute(db.write_pool())
        .await?;
    Ok(result.rows_affected())
}

/// Read the Instance's current `click_retention_days` setting and prune Clicks
/// older than that window. Reading the setting on every run means a changed
/// retention takes effect without a restart.
pub async fn cleanup_old_clicks_for_instance(
    db: &Database,
    now: OffsetDateTime,
) -> Result<u64, ApiError> {
    let instance_settings = crate::settings::load(db).await?;
    cleanup_old_clicks(db, instance_settings.click_retention_days, now).await
}

/// Start the detached Click retention task. It prunes expired Clicks
/// immediately at startup (Tokio's interval fires its first tick at once) and
/// then every [`RETENTION_CHECK_INTERVAL`], without blocking server startup.
/// Each run reads the current Instance retention setting.
pub fn spawn_click_retention(db: Database) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RETENTION_CHECK_INTERVAL);
        loop {
            interval.tick().await;
            match cleanup_old_clicks_for_instance(&db, timeutil::now()).await {
                Ok(0) => {}
                Ok(deleted) => tracing::info!(deleted, "pruned old Clicks"),
                Err(error) => {
                    tracing::error!(error = %error, "Click retention cleanup failed");
                }
            }
        }
    });
}
