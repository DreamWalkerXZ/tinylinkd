use std::str::FromStr;

use chrono_tz::Tz;
use sqlx::SqlitePool;

use crate::db::Database;
use crate::error::ApiError;

/// The default Instance name, used until an Admin changes it.
pub const DEFAULT_INSTANCE_NAME: &str = "tinylinkd";

/// The default IANA timezone. All storage remains UTC; this controls display
/// and daily Click buckets.
pub const DEFAULT_TIMEZONE: &str = "UTC";

/// The default Click retention window in days.
pub const DEFAULT_CLICK_RETENTION_DAYS: i64 = 90;

/// The default lifetime of a password-unlock cookie in seconds.
pub const DEFAULT_PASSWORD_UNLOCK_TTL_SECONDS: i64 = 3600;

pub const INSTANCE_NAME_KEY: &str = "instance_name";
pub const TIMEZONE_KEY: &str = "timezone";
pub const CLICK_RETENTION_DAYS_KEY: &str = "click_retention_days";
pub const PASSWORD_UNLOCK_TTL_SECONDS_KEY: &str = "password_unlock_ttl_seconds";

/// The mutable Instance settings stored in the `settings` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSettings {
    pub instance_name: String,
    /// An IANA timezone name, already validated when written through the API.
    pub timezone: String,
    pub click_retention_days: i64,
    pub password_unlock_ttl_seconds: i64,
}

impl Default for InstanceSettings {
    fn default() -> Self {
        Self {
            instance_name: DEFAULT_INSTANCE_NAME.to_string(),
            timezone: DEFAULT_TIMEZONE.to_string(),
            click_retention_days: DEFAULT_CLICK_RETENTION_DAYS,
            password_unlock_ttl_seconds: DEFAULT_PASSWORD_UNLOCK_TTL_SECONDS,
        }
    }
}

impl InstanceSettings {
    /// The Instance timezone, falling back to UTC if the stored value is not a
    /// valid IANA name. The API prevents storing an invalid name.
    pub fn timezone_tz(&self) -> Tz {
        parse_timezone(&self.timezone).unwrap_or(chrono_tz::UTC)
    }
}

/// Validate an IANA timezone name.
pub fn parse_timezone(value: &str) -> Option<Tz> {
    Tz::from_str(value).ok()
}

/// A partial update to the mutable Instance settings.
#[derive(Debug, Clone, Default)]
pub struct SettingsChanges {
    pub instance_name: Option<String>,
    pub timezone: Option<String>,
    pub click_retention_days: Option<i64>,
    pub password_unlock_ttl_seconds: Option<i64>,
}

fn default_rows() -> [(&'static str, String); 4] {
    [
        (INSTANCE_NAME_KEY, DEFAULT_INSTANCE_NAME.to_string()),
        (TIMEZONE_KEY, DEFAULT_TIMEZONE.to_string()),
        (
            CLICK_RETENTION_DAYS_KEY,
            DEFAULT_CLICK_RETENTION_DAYS.to_string(),
        ),
        (
            PASSWORD_UNLOCK_TTL_SECONDS_KEY,
            DEFAULT_PASSWORD_UNLOCK_TTL_SECONDS.to_string(),
        ),
    ]
}

/// Insert any missing default settings rows. Existing values are never
/// overwritten, so this is safe to run on every start and upgrade.
pub async fn ensure_defaults(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    for (key, value) in default_rows() {
        sqlx::query("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await
}

fn stored_positive(value: &str, key: &str) -> Option<i64> {
    match value.trim().parse::<i64>() {
        Ok(parsed) if parsed > 0 => Some(parsed),
        _ => {
            tracing::warn!(key, value, "ignoring an invalid stored Instance setting");
            None
        }
    }
}

/// Read the mutable Instance settings, falling back to documented defaults
/// when a row is missing or a stored value is invalid.
pub async fn load(db: &Database) -> Result<InstanceSettings, ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM settings")
        .fetch_all(db.read_pool())
        .await?;

    let mut settings = InstanceSettings::default();
    for (key, value) in rows {
        match key.as_str() {
            INSTANCE_NAME_KEY => {
                if value.trim().is_empty() {
                    tracing::warn!(key, "ignoring an empty stored Instance name");
                } else {
                    settings.instance_name = value;
                }
            }
            TIMEZONE_KEY => {
                if parse_timezone(value.trim()).is_some() {
                    settings.timezone = value;
                } else {
                    tracing::warn!(key, value, "ignoring an invalid stored Instance timezone");
                }
            }
            CLICK_RETENTION_DAYS_KEY => {
                if let Some(days) = stored_positive(&value, &key) {
                    settings.click_retention_days = days;
                }
            }
            PASSWORD_UNLOCK_TTL_SECONDS_KEY => {
                if let Some(seconds) = stored_positive(&value, &key) {
                    settings.password_unlock_ttl_seconds = seconds;
                }
            }
            _ => {}
        }
    }
    Ok(settings)
}

/// Validate and persist a partial update, returning the complete settings.
///
/// Every field is validated before any row is written, so an invalid field
/// never leaves a partial update behind.
pub async fn update(db: &Database, changes: SettingsChanges) -> Result<InstanceSettings, ApiError> {
    let mut validated: Vec<(&'static str, String)> = Vec::new();

    if let Some(instance_name) = changes.instance_name {
        let instance_name = instance_name.trim();
        if instance_name.is_empty() {
            return Err(ApiError::validation(
                "invalid_instance_name",
                "instance_name must not be empty.",
            ));
        }
        validated.push((INSTANCE_NAME_KEY, instance_name.to_string()));
    }

    if let Some(timezone) = changes.timezone {
        let timezone = timezone.trim();
        if parse_timezone(timezone).is_none() {
            return Err(ApiError::validation(
                "invalid_timezone",
                "timezone must be a valid IANA timezone name, such as 'Europe/London'.",
            ));
        }
        validated.push((TIMEZONE_KEY, timezone.to_string()));
    }

    if let Some(days) = changes.click_retention_days {
        if days <= 0 {
            return Err(ApiError::validation(
                "invalid_click_retention_days",
                "click_retention_days must be a positive number of days.",
            ));
        }
        validated.push((CLICK_RETENTION_DAYS_KEY, days.to_string()));
    }

    if let Some(seconds) = changes.password_unlock_ttl_seconds {
        if seconds <= 0 {
            return Err(ApiError::validation(
                "invalid_password_unlock_ttl",
                "password_unlock_ttl_seconds must be a positive number of seconds.",
            ));
        }
        validated.push((PASSWORD_UNLOCK_TTL_SECONDS_KEY, seconds.to_string()));
    }

    if !validated.is_empty() {
        let mut transaction = db.write_pool().begin().await?;
        for (key, value) in validated {
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES (?, ?)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            )
            .bind(key)
            .bind(value)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
    }

    load(db).await
}
