use std::collections::BTreeMap;

use sqlx::{QueryBuilder, Row, Sqlite};
use time::OffsetDateTime;

use crate::db::Database;
use crate::error::ApiError;
use crate::timeutil;

/// The v1 Click retention window. T10 replaces this constant with the mutable
/// Instance setting; the periodic task already takes the window as a parameter.
pub const CLICK_RETENTION_DAYS: i64 = 90;

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
    if let Some(from) = from {
        builder.push(" AND clicked_at >= ").push_bind(from);
    }
    if let Some(to) = to {
        builder.push(" AND clicked_at <= ").push_bind(to);
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
/// Day buckets use UTC in this ticket: stored timestamps are UTC RFC 3339, so
/// their first ten characters are the UTC calendar date. T10 switches the
/// buckets to the Instance timezone.
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
) -> Result<ClickStats, ApiError> {
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

    let mut days = QueryBuilder::<Sqlite>::new(
        "SELECT substr(clicked_at, 1, 10) AS day,
                COUNT(*) AS total_clicks,
                COUNT(*) - COALESCE(SUM(is_bot), 0) AS human_clicks,
                COALESCE(SUM(is_bot), 0) AS bot_clicks
         FROM clicks WHERE link_id = ",
    );
    days.push_bind(link_id);
    push_time_range(&mut days, from.as_deref(), to.as_deref());
    days.push(" GROUP BY day ORDER BY day");
    let rows = days.build().fetch_all(db.read_pool()).await?;
    let by_day = rows
        .iter()
        .map(|row| {
            Ok(DayStats {
                date: row.try_get("day")?,
                total_clicks: row.try_get("total_clicks")?,
                human_clicks: row.try_get("human_clicks")?,
                bot_clicks: row.try_get("bot_clicks")?,
            })
        })
        .collect::<Result<_, ApiError>>()?;

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
    let cutoff = timeutil::format_rfc3339(now - time::Duration::days(retention_days));
    let result = sqlx::query("DELETE FROM clicks WHERE clicked_at < ?")
        .bind(cutoff)
        .execute(db.write_pool())
        .await?;
    Ok(result.rows_affected())
}

/// Start the detached Click retention task. It prunes expired Clicks
/// immediately at startup (Tokio's interval fires its first tick at once) and
/// then every [`RETENTION_CHECK_INTERVAL`], without blocking server startup.
pub fn spawn_click_retention(db: Database) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RETENTION_CHECK_INTERVAL);
        loop {
            interval.tick().await;
            match cleanup_old_clicks(&db, CLICK_RETENTION_DAYS, timeutil::now()).await {
                Ok(0) => {}
                Ok(deleted) => tracing::info!(deleted, "pruned old Clicks"),
                Err(error) => {
                    tracing::error!(error = %error, "Click retention cleanup failed");
                }
            }
        }
    });
}
