use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;

use tinylinkd::app::build_router;
use tinylinkd::config::{Cli, Command, Config};
use tinylinkd::db::Database;
use tinylinkd::logging;

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
    }
}

async fn serve(config: Config) -> Result<()> {
    let db = Database::connect(&config.data_dir).await?;
    let app = build_router(db);
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(
        addr = %listener.local_addr()?,
        base_url = %config.base_url,
        "tinylinkd listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}
