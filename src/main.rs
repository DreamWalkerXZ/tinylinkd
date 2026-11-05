use std::io::{BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;

use tinylinkd::analytics;
use tinylinkd::app::{AppConfig, build_router_with_config};
use tinylinkd::bootstrap::{BootstrapAdmin, bootstrap_admin};
use tinylinkd::config::{AdminCommand, Cli, Command, Config, TokenCommand};
use tinylinkd::db::Database;
use tinylinkd::logging;
use tinylinkd::secrets;
use tinylinkd::tokens;
use tinylinkd::users::{self, NewUser, Role};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(error) = logging::init(cli.command.log_format()) {
        eprintln!("error: {error:#}");
        return ExitCode::FAILURE;
    }

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "fatal error");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve(args) => {
            let config = Config::from_args(args)?;
            serve(config).await
        }
        Command::Migrate(args) => {
            let db = Database::connect(&args.common.data_dir).await?;
            info!(path = %db.path().display(), "migrations applied");
            Ok(())
        }
        Command::Admin { command } => admin(command).await,
        Command::Token { command } => token(command).await,
    }
}

async fn admin(command: AdminCommand) -> Result<()> {
    match command {
        AdminCommand::Create(args) => {
            let db = Database::connect(&args.common.data_dir).await?;
            let username = match args.username {
                Some(username) => username,
                None => prompt_line("Username: ")?,
            };
            let password = read_password()?;
            let user = users::create_user(
                &db,
                NewUser {
                    username,
                    email: args.email,
                    password,
                    role: Role::Admin,
                },
            )
            .await?;
            info!(user_id = user.id, username = %user.username, "created Admin User");
            Ok(())
        }
    }
}

async fn token(command: TokenCommand) -> Result<()> {
    match command {
        TokenCommand::Create(args) => {
            let db = Database::connect(&args.common.data_dir).await?;
            let user = users::find_by_username(&db, &args.user)
                .await?
                .with_context(|| format!("User '{}' not found", args.user))?;
            let created =
                tokens::create_token(&db, user.id, &args.name, args.expires_at.as_deref()).await?;
            println!("{}", created.plaintext);
            info!(token_id = created.id, username = %user.username, "created API token");
            Ok(())
        }
    }
}

fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line)?;
    if read == 0 {
        bail!("no value provided on standard input");
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn read_password() -> Result<String> {
    if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password("Password: ")?)
    } else {
        eprint!("Password: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line)?;
        if read == 0 {
            bail!("no password provided on standard input");
        }
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }
}

async fn serve(config: Config) -> Result<()> {
    let db = Database::connect(&config.data_dir).await?;
    bootstrap_admin(&db, BootstrapAdmin::from_env()).await?;
    // Generate the HMAC signing key on the first run and persist it in the
    // `secrets` table so unlock cookies survive restarts and backups.
    secrets::unlock_cookie_signing_key(&db)
        .await
        .context("failed to initialize the password-unlock signing key")?;
    analytics::spawn_click_retention(db.clone());
    let app = build_router_with_config(
        db,
        AppConfig::new(config.base_url.clone(), config.trust_proxy),
    );
    let shutdown = shutdown_signal();
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(
        addr = %listener.local_addr()?,
        base_url = %config.base_url,
        trust_proxy = config.trust_proxy,
        "tinylinkd listening"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

#[cfg(unix)]
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("failed to install SIGINT handler");
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    async move {
        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }
        info!("shutdown signal received");
    }
}

#[cfg(not(unix))]
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    let ctrl_c = tokio::signal::ctrl_c();

    async move {
        ctrl_c.await.expect("failed to install Ctrl+C handler");
        info!("shutdown signal received");
    }
}
