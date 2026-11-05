use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

#[derive(Clone)]
pub struct Database {
    read_pool: SqlitePool,
    write_pool: SqlitePool,
    path: PathBuf,
}

impl Database {
    pub async fn connect(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("failed to create data directory {}", data_dir.display()))?;

        let path = data_dir.join("tinylinkd.db");

        let write_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(connect_options(&path))
            .await
            .with_context(|| format!("failed to open SQLite database {}", path.display()))?;

        sqlx::migrate!("./migrations")
            .run(&write_pool)
            .await
            .context("failed to run database migrations")?;

        crate::settings::ensure_defaults(&write_pool)
            .await
            .context("failed to insert the default Instance settings")?;

        let read_pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connect_options(&path))
            .await
            .with_context(|| format!("failed to open SQLite database {}", path.display()))?;

        Ok(Self {
            read_pool,
            write_pool,
            path,
        })
    }

    pub fn read_pool(&self) -> &SqlitePool {
        &self.read_pool
    }

    pub fn write_pool(&self) -> &SqlitePool {
        &self.write_pool
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn ping(&self) -> Result<()> {
        if !self.path.exists() {
            bail!("database file {} does not exist", self.path.display());
        }

        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM settings")
            .fetch_one(&self.read_pool)
            .await
            .context("database health check failed")?;
        Ok(())
    }
}

fn connect_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
}

/// Create a consistent snapshot of the SQLite database with `VACUUM INTO`.
///
/// The live database must already exist; unlike [`Database::connect`], this
/// does not create or migrate it, so a backup never changes the source.
pub async fn backup(data_dir: &Path, output: &Path) -> Result<()> {
    let source = data_dir.join("tinylinkd.db");
    if !source.exists() {
        bail!(
            "database file {} does not exist; run `tld migrate` or start the server first",
            source.display()
        );
    }
    if output.exists() {
        bail!(
            "refusing to overwrite existing file {}; choose a new backup path",
            output.display()
        );
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options(&source))
        .await
        .with_context(|| format!("failed to open SQLite database {}", source.display()))?;

    let destination = output
        .to_str()
        .context("backup output path must be valid UTF-8")?;
    let result = sqlx::query("VACUUM INTO ?")
        .bind(destination)
        .execute(&pool)
        .await;
    pool.close().await;

    result.map_err(|error| {
        anyhow::anyhow!("failed to write backup to {}: {error}", output.display())
    })?;
    Ok(())
}
