use anyhow::{Result, anyhow};
use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

pub fn init(format: LogFormat) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);

    match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    }
    .map_err(|error| anyhow!("failed to initialize logging: {error}"))
}
