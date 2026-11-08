use fnox::commands::Cli;
use fnox::settings;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> miette::Result<()> {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "macos")]
    {
        match argv.first().and_then(|argument| argument.to_str()) {
            Some("__touch-id-read") => return run_touch_id_read(&argv),
            Some("__touch-id-set") => return run_touch_id_set(&argv),
            Some("__touch-id-delete") => return run_touch_id_delete(&argv),
            _ => {}
        }
    }
    if fnox::hook_env::can_exit_before_startup(&argv) {
        return Ok(());
    }
    run(argv)
}

#[cfg(target_os = "macos")]
fn run_touch_id_read(argv: &[std::ffi::OsString]) -> miette::Result<()> {
    use std::io::Write;

    if argv.len() != 7 {
        miette::bail!("Invalid internal Touch ID request");
    }
    await_touch_id_helper_approval()?;
    validate_touch_id_helper_parent()?;
    let values = argv[1..].iter().map(|value| value.to_string_lossy());
    let values: Vec<_> = values.collect();
    match fnox::providers::keychain::read_touch_id_for_helper(
        &values[0], &values[1], &values[2], &values[3], &values[4], &values[5],
    ) {
        Ok(secret) => std::io::stdout()
            .lock()
            .write_all(secret.as_bytes())
            .map_err(|error| miette::miette!("Unable to return Keychain value: {error}")),
        Err((status, details)) => {
            eprintln!("{status}\n{details}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "macos")]
fn run_touch_id_set(argv: &[std::ffi::OsString]) -> miette::Result<()> {
    use std::io::Read;

    if argv.len() != 4 {
        miette::bail!("Invalid internal Touch ID write request");
    }
    await_touch_id_helper_approval()?;
    validate_touch_id_helper_parent()?;
    let values: Vec<_> = argv[1..]
        .iter()
        .map(|value| value.to_string_lossy())
        .collect();
    let mut secret = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut secret)
        .map_err(|error| miette::miette!("Unable to read protected Keychain value: {error}"))?;
    match fnox::providers::keychain::write_touch_id_for_helper(
        &values[0], &values[1], &secret, &values[2],
    ) {
        Ok(()) => Ok(()),
        Err((status, details)) => {
            eprintln!("{status}\n{details}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "macos")]
fn run_touch_id_delete(argv: &[std::ffi::OsString]) -> miette::Result<()> {
    if argv.len() != 3 {
        miette::bail!("Invalid internal Touch ID cleanup request");
    }
    await_touch_id_helper_approval()?;
    validate_touch_id_helper_parent()?;
    let values: Vec<_> = argv[1..]
        .iter()
        .map(|value| value.to_string_lossy())
        .collect();
    match fnox::providers::keychain::delete_touch_id_for_helper(&values[0], &values[1]) {
        Ok(()) => Ok(()),
        Err((status, details)) => {
            eprintln!("{status}\n{details}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "macos")]
fn validate_touch_id_helper_parent() -> miette::Result<()> {
    fnox::providers::keychain::validate_touch_id_helper_parent().map_err(|(status, details)| {
        miette::miette!("Untrusted Touch ID helper caller (status {status}): {details}")
    })
}

#[cfg(target_os = "macos")]
fn await_touch_id_helper_approval() -> miette::Result<()> {
    read_touch_id_helper_approval(&mut std::io::stdin().lock())
        .map_err(|error| miette::miette!("Fnox did not approve the Touch ID helper: {error}"))
}

#[cfg(target_os = "macos")]
fn read_touch_id_helper_approval(reader: &mut impl std::io::Read) -> std::io::Result<()> {
    let mut approval = [0];
    reader.read_exact(&mut approval)?;
    if approval[0] == fnox::providers::keychain::TOUCH_ID_HELPER_APPROVAL {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid helper approval",
        ))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod touch_id_helper_tests {
    use super::read_touch_id_helper_approval;
    use std::io::Cursor;

    #[test]
    fn helper_waits_for_the_parent_approval_byte() {
        assert!(
            read_touch_id_helper_approval(&mut Cursor::new([
                fnox::providers::keychain::TOUCH_ID_HELPER_APPROVAL,
            ]))
            .is_ok()
        );
        assert!(read_touch_id_helper_approval(&mut Cursor::new([0])).is_err());
        assert!(read_touch_id_helper_approval(&mut Cursor::new([])).is_err());
    }
}

#[tokio::main]
async fn run(argv: Vec<std::ffi::OsString>) -> miette::Result<()> {
    // Restore the default SIGPIPE handler. Rust inherits SIG_IGN from libc,
    // so writes to a closed pipe return EPIPE and `println!` panics — e.g.
    // `fnox get FOO | head -c 0` would crash with "failed printing to stdout".
    // SIG_DFL makes the process exit on the signal like a normal Unix tool.
    #[cfg(unix)]
    set_sigpipe(nix::sys::signal::SigHandler::SigDfl);

    miette::set_panic_hook();

    if let Some(answer) = fnox::commands::completion_app()
        .completion_request(&argv)
        .await
    {
        print!("{answer}");
        return Ok(());
    }

    // Initialize rustls crypto provider for GCP SDKs
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (cli, settings_layer) = Cli::parse_with_settings();

    // A server must outlive a client that hangs up before its reply is
    // written: `writev` on a closed socket raises SIGPIPE, which would kill
    // `fnox proxy run` and leave its child pointed at a dead proxy. Ignored,
    // the write fails with EPIPE and only that connection ends. Children still
    // start with SIG_DFL, because std resets SIGPIPE when it spawns them.
    #[cfg(unix)]
    if cli.command.serves_connections() {
        set_sigpipe(nix::sys::signal::SigHandler::SigIgn);
    }

    // Hand the settings system the command line as the parser saw it: what was given
    // contributes, what was left off does not, and nothing here copies fields by hand.
    settings::Settings::set_cli_layer(settings_layer);
    fnox::env::set_non_interactive(cli.non_interactive);

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

#[cfg(unix)]
fn set_sigpipe(handler: nix::sys::signal::SigHandler) {
    // SAFETY: SIG_DFL and SIG_IGN are not handler functions, so no code runs
    // in signal context.
    unsafe {
        let _ = nix::sys::signal::sigaction(
            nix::sys::signal::Signal::SIGPIPE,
            &nix::sys::signal::SigAction::new(
                handler,
                nix::sys::signal::SaFlags::empty(),
                nix::sys::signal::SigSet::empty(),
            ),
        );
    }
}
