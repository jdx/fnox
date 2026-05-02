use clap::Parser;
use fnox::commands::Cli;
use fnox::settings;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
        no_defaults: cli.no_defaults,
    });

    // Handle --no-color flag
    if cli.no_color {
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
    }

    // Initialize tracing
    //
    // Cover both the binary crate (`fnox`) and the library crate (`fnox_core`,
    // which holds providers / config / secret resolver / lease backends / http).
    // Without `fnox_core` in the filter, `--verbose` would silently drop debug
    // and warn output from the bulk of the codebase.
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("fnox={level},fnox_core={level}", level = log_level).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::debug!("Using config file: {}", cli.config.display());

    cli.command.run(&cli).await.map_err(miette::Report::new)
}
