//! Open a URL in the user's default browser.

/// Detach the launcher's stdio so a browser cannot write to, or hold open, the
/// caller's pipes (`fnox env --json` promises a pure stdout).
fn silence(cmd: &mut std::process::Command) -> &mut std::process::Command {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
}

/// Launch the platform's URL opener for `url`.
pub fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        silence(std::process::Command::new("open").arg(url)).status()?;
    }
    #[cfg(target_os = "windows")]
    {
        // Not `cmd /C start`: cmd would treat `&` in the URL as a command separator
        silence(std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]))
            .status()?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        silence(std::process::Command::new("xdg-open").arg(url)).status()?;
    }
    Ok(())
}
