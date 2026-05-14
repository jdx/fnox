use clap::Parser;
use fnox::commands::Cli;
use fnox::settings;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> miette::Result<()> {
    // Restore the default SIGPIPE handler. Rust inherits SIG_IGN from libc,
    // so writes to a closed pipe return EPIPE and `println!` panics — e.g.
    // `fnox get FOO | head -c 0` would crash with "failed printing to stdout".
    // SIG_DFL makes the process exit on the signal like a normal Unix tool.
    #[cfg(unix)]
    unsafe {
        let _ = nix::sys::signal::sigaction(
            nix::sys::signal::Signal::SIGPIPE,
            &nix::sys::signal::SigAction::new(
                nix::sys::signal::SigHandler::SigDfl,
                nix::sys::signal::SaFlags::empty(),
                nix::sys::signal::SigSet::empty(),
            ),
        );
    }

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
