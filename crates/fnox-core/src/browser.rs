//! Open a URL in the user's default browser.

/// Detach the launcher's stdio so a browser cannot write to, or hold open, the
/// caller's pipes (`fnox env --json` promises a pure stdout).
fn silence(cmd: &mut std::process::Command) -> &mut std::process::Command {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
}

fn opener(url: &str) -> std::process::Command {
    #[cfg(target_os = "macos")]
    {
        let mut cmd = std::process::Command::new("open");
        cmd.arg(url);
        cmd
    }
    #[cfg(target_os = "windows")]
    {
        // Not `cmd /C start`: cmd would treat `&` in the URL as a command separator
        let mut cmd = std::process::Command::new("rundll32");
        cmd.args(["url.dll,FileProtocolHandler", url]);
        cmd
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let mut cmd = std::process::Command::new("xdg-open");
        cmd.arg(url);
        cmd
    }
}

/// Launch the platform's URL opener for `url` without waiting for it, so a
/// launcher that stays alive until the browser closes cannot block the caller.
/// A background thread reaps the child.
pub fn open_browser(url: &str) -> std::io::Result<()> {
    let mut child = silence(&mut opener(url)).spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
