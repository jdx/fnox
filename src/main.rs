use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth_prompt;
mod commands;
mod config;
mod env;
mod error;
mod hook_env;
mod providers;
mod secret_resolver;
mod settings;
mod shell;

#[cfg(test)]
mod clap_sort;

use commands::Cli;

#[tokio::main]
async fn main() -> miette::Result<()> {
    miette::set_panic_hook();

    // Initialize rustls crypto provider for GCP SDKs
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();

    // Set CLI snapshot for settings system
    settings::Settings::set_cli_snapshot(settings::CliSnapshot {
        age_key_file: cli.age_key_file.clone(),
        profile: cli.profile.clone(),
        if_missing: cli.if_missing.clone(),
    });

    // Handle --no-color flag
    if cli.no_color {
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
    }

    // Initialize tracing
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("fnox={}", log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::debug!("Using config file: {}", cli.config.display());

    cli.command.run(&cli).await.map_err(miette::Report::new)
}
