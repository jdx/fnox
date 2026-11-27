//! Run a target's CLI with the secret value on stdin, so the value never
//! appears in a process listing.

use crate::error::{FnoxError, Result};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

pub(super) struct Cli {
    /// Config `type` of the target, used in error messages
    pub target_type: &'static str,
    pub program: &'static str,
    pub install_hint: &'static str,
    /// What to check when the command fails
    pub hint: &'static str,
}

impl Cli {
    /// Run the command, failing with its stderr if it exits non-zero
    pub async fn run(&self, args: &[String], stdin: &str) -> Result<()> {
        self.try_run(args, stdin).await?.map_err(|stderr| {
            let command: Vec<&str> = args.iter().take(2).map(String::as_str).collect();
            self.failed(format!(
                "{} {} failed: {stderr}",
                self.program,
                command.join(" ")
            ))
        })
    }

    /// Run the command. A non-zero exit is `Ok(Err(stderr))`, so a caller can
    /// try something else; failing to run it at all is an error.
    pub async fn try_run(
        &self,
        args: &[String],
        stdin: &str,
    ) -> Result<std::result::Result<(), String>> {
        let mut child = tokio::process::Command::new(self.program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    FnoxError::ProviderCliNotFound {
                        provider: self.target_type.to_string(),
                        cli: self.program.to_string(),
                        install_hint: self.install_hint.to_string(),
                        url: super::docs_url(self.target_type),
                    }
                } else {
                    self.failed(format!("failed to run {}: {e}", self.program))
                }
            })?;

        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| self.failed(format!("{} did not expose a piped stdin", self.program)))?;
        // A CLI that fails early, say on a rejected token, can exit without
        // reading stdin. The write then hits a closed pipe; its exit status
        // and stderr below say what went wrong, so carry on to them.
        let written = {
            #[cfg(unix)]
            let _ignore = IgnoreSigpipe::new();
            pipe.write_all(stdin.as_bytes()).await
        };
        match written {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => {
                return Err(self.failed(format!(
                    "failed to write the value to {}: {e}",
                    self.program
                )));
            }
        }
        // Closing stdin marks the end of the value
        drop(pipe);

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| self.failed(format!("failed to wait for {}: {e}", self.program)))?;
        if output.status.success() {
            Ok(Ok(()))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Ok(Err(if stderr.is_empty() {
                format!("exited with {}", output.status)
            } else {
                stderr
            }))
        }
    }

    pub fn failed(&self, details: String) -> FnoxError {
        FnoxError::ProviderCliFailed {
            provider: self.target_type.to_string(),
            details,
            hint: self.hint.to_string(),
            url: super::docs_url(self.target_type),
        }
    }
}

/// Append `--flag value` when `value` is set
pub(super) fn opt(args: &mut Vec<String>, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.extend([flag.to_string(), value.to_string()]);
    }
}

/// Ignores SIGPIPE while any guard is alive, so a write to a CLI that exited
/// without reading its stdin fails with EPIPE instead of killing fnox.
///
/// fnox runs with SIGPIPE at SIG_DFL so that a closed stdout ends it quietly
/// (see `main.rs`). The guard covers only the write to the child, and the
/// last guard to drop puts back what was there before, so output that fnox
/// prints afterwards still behaves that way.
#[cfg(unix)]
struct IgnoreSigpipe;

/// Live guards, and the disposition the first one replaced
#[cfg(unix)]
static IGNORE_SIGPIPE: std::sync::Mutex<(usize, libc::sighandler_t)> =
    std::sync::Mutex::new((0, libc::SIG_DFL));

#[cfg(unix)]
impl IgnoreSigpipe {
    fn new() -> Self {
        let mut state = IGNORE_SIGPIPE.lock().unwrap_or_else(|e| e.into_inner());
        if state.0 == 0 {
            // SAFETY: SIG_IGN is not a handler function, so no code runs in
            // signal context.
            let previous = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
            if previous != libc::SIG_ERR {
                state.1 = previous;
            }
        }
        state.0 += 1;
        Self
    }
}

#[cfg(unix)]
impl Drop for IgnoreSigpipe {
    fn drop(&mut self) {
        let mut state = IGNORE_SIGPIPE.lock().unwrap_or_else(|e| e.into_inner());
        state.0 -= 1;
        if state.0 == 0 {
            // SAFETY: the disposition was SIG_DFL, SIG_IGN or a handler that
            // was installed before, so putting it back is as safe as it was.
            unsafe { libc::signal(libc::SIGPIPE, state.1) };
        }
    }
}
