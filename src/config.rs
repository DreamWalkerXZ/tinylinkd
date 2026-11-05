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
    /// Manage Users.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Manage API tokens.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

impl Command {
    pub fn log_format(&self) -> LogFormat {
        match self {
            Self::Serve(args) => args.common.log_format,
            Self::Migrate(args) => args.common.log_format,
            Self::Admin { command } => match command {
                AdminCommand::Create(args) => args.common.log_format,
            },
            Self::Token { command } => match command {
                TokenCommand::Create(args) => args.common.log_format,
            },
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Create a User with the Admin role.
    Create(AdminCreateArgs),
}

#[derive(Debug, Args)]
pub struct AdminCreateArgs {
    /// Username for the new Admin. Prompted when omitted.
    #[arg(long)]
    pub username: Option<String>,

    /// Optional email address for the new Admin.
    #[arg(long)]
    pub email: Option<String>,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Create an API token and print the plaintext once.
    Create(TokenCreateArgs),
}

#[derive(Debug, Args)]
pub struct TokenCreateArgs {
    /// Username of the User who will own the API token.
    #[arg(long)]
    pub user: String,

    /// Display name for the API token.
    #[arg(long, default_value = "cli")]
    pub name: String,

    /// RFC 3339 timestamp at which the API token expires.
    #[arg(long)]
    pub expires_at: Option<String>,

    #[command(flatten)]
    pub common: CommonArgs,
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

    /// Trust the first address in X-Forwarded-For as the client IP.
    #[arg(
        long,
        env = "TLD_TRUST_PROXY",
        action = clap::ArgAction::Set,
        default_value_t = false
    )]
    pub trust_proxy: bool,

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
    pub trust_proxy: bool,
}

impl Config {
    pub fn from_args(args: ServeArgs) -> Result<Self> {
        Ok(Self {
            base_url: validate_base_url(&args.base_url)?,
            listen_addr: args.listen_addr,
            data_dir: args.common.data_dir,
            log_format: args.common.log_format,
            trust_proxy: args.trust_proxy,
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

    #[test]
    fn trust_proxy_defaults_to_false_and_accepts_a_value() {
        let default = Cli::try_parse_from(["tld", "serve", "--base-url", "http://localhost:8080"])
            .expect("parse");
        let Command::Serve(args) = default.command else {
            panic!("expected serve");
        };
        assert!(!args.trust_proxy);

        let enabled = Cli::try_parse_from([
            "tld",
            "serve",
            "--base-url",
            "http://localhost:8080",
            "--trust-proxy",
            "true",
        ])
        .expect("parse");
        let Command::Serve(args) = enabled.command else {
            panic!("expected serve");
        };
        assert!(args.trust_proxy);
    }
}
