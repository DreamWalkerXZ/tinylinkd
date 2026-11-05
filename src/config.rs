use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "tld", version, about = "A small, self-hosted URL shortener")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the HTTP server.
    Serve(ServeArgs),
    /// Apply embedded database migrations and exit.
    Migrate(MigrateArgs),
}

impl Command {
    pub fn log_format(&self) -> LogFormat {
        match self {
            Self::Serve(args) => args.common.log_format,
            Self::Migrate(args) => args.common.log_format,
        }
    }
}

#[derive(Debug, Args)]
pub struct CommonArgs {
    /// Directory holding the SQLite database.
    #[arg(long, env = "TLD_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Log output format.
    #[arg(long, env = "TLD_LOG_FORMAT", value_enum, default_value = "text")]
    pub log_format: LogFormat,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Public base URL used to build short links.
    #[arg(long, env = "TLD_BASE_URL")]
    pub base_url: String,

    /// Address to listen on.
    #[arg(long, env = "TLD_LISTEN_ADDR", default_value = "127.0.0.1:8080")]
    pub listen_addr: SocketAddr,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Args)]
pub struct MigrateArgs {
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub base_url: Url,
    pub listen_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub log_format: LogFormat,
}

impl Config {
    pub fn from_args(args: ServeArgs) -> Result<Self> {
        Ok(Self {
            base_url: validate_base_url(&args.base_url)?,
            listen_addr: args.listen_addr,
            data_dir: args.common.data_dir,
            log_format: args.common.log_format,
        })
    }
}

pub fn validate_base_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("TLD_BASE_URL must be a valid absolute URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("TLD_BASE_URL must use http or https");
    }
    if url.host_str().is_none() {
        bail!("TLD_BASE_URL must include a host");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_absolute_http_and_https_base_urls() {
        assert!(validate_base_url("http://localhost:8080").is_ok());
        assert!(validate_base_url("https://tld.example.com").is_ok());
        assert!(validate_base_url("https://example.com/?x=1").is_ok());
        assert!(validate_base_url("https://example.com/#x").is_ok());
    }

    #[test]
    fn rejects_non_http_base_urls() {
        assert!(validate_base_url("ftp://example.com").is_err());
        assert!(validate_base_url("not a url").is_err());
    }
}
