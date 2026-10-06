use crate::child_env::{self, EnvScope, Roots};
use crate::error::{FnoxError, Result};
use crate::temp_file_secrets::create_ephemeral_secret_file;
use crate::{commands::Cli, config::Config};
use std::process::Command;
use tempfile::NamedTempFile;

#[derive(Debug, usage_rs::Args)]
#[usage(alias = "x", alias_hidden = "run")]
pub struct ExecCommand {
    /// Re-resolve this secret from its provider instead of serving it from the
    /// daemon cache, and cache the new value. Other secrets are still served from
    /// the cache. Repeat to refresh several keys
    #[usage(long, value_name = "KEY")]
    pub refresh: Vec<String>,

    /// Replace the fnox process with the command so it keeps the same PID and receives
    /// signals directly. Rejected when the command's environment would carry an as_file
    /// secret, or when the profile configures credential leases, since fnox must clean
    /// those up after the command exits. Unix only
    #[cfg(unix)]
    #[usage(long)]
    pub replace: bool,

    /// Command to run
    #[usage(
        arg,
        double_dash = "automatic",
        value_hint = usage_rs::ValueHint::CommandWithArguments
    )]
    pub command: Vec<String>,
}

impl ExecCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if self.command.is_empty() {
            return Err(FnoxError::CommandNotSpecified);
        }

        #[cfg(unix)]
        if self.replace {
            install_replace_signal_handlers()?;
        }

        let profile = Config::get_profiles(cli.profile.as_slice());
        tracing::debug!(
            "Running command with secrets from profiles '{}'",
            Config::display_profiles(&profile)
        );

        // Get the profile secrets
        let profile_secrets = config.get_secrets(&profile)?;
        let leases = config.get_leases(&profile)?;

        #[cfg(unix)]
        if self.replace {
            let file_secrets = profile_secrets
                .iter()
                .filter(|(_, secret)| secret.as_file && secret.env_mode().in_exec())
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>();
            if !file_secrets.is_empty() {
                return Err(FnoxError::ExecReplaceFileSecrets {
                    secrets: file_secrets.join(", "),
                });
            }
            if !leases.is_empty() {
                return Err(FnoxError::ExecReplaceLeases);
            }
        }

        let cmd_name = &self.command[0];

        #[cfg(windows)]
        let cmd_path = which::which(cmd_name).unwrap_or_else(|_| cmd_name.into());
        #[cfg(not(windows))]
        let cmd_path = cmd_name;

        let mut cmd = Command::new(cmd_path);

        if self.command.len() > 1 {
            cmd.args(&self.command[1..]);
        }

        for key in &self.refresh {
            if !profile_secrets.contains_key(key) {
                tracing::warn!("--refresh {key}: no such secret in the current profile");
            }
        }
        crate::daemon::refresh(cli, &config, &self.refresh).await?;

        let (plan, lease_files) = child_env::plan(
            cli,
            &config,
            &profile,
            EnvScope::Exec,
            Roots::AllProfile,
            "exec",
        )
        .await?;

        // Apply in order: remove, then set, then files. Explicit secrets and
        // lease credentials win over the ambient scrub because `remove` never
        // lists a key that is also set.
        for key in &plan.remove {
            cmd.env_remove(key);
        }
        for (key, value) in &plan.set {
            cmd.env(key, value);
        }
        // Keep temp files alive for the duration of the command
        let mut _temp_files: Vec<NamedTempFile> = lease_files;
        for (key, value) in &plan.files {
            let temp_file = create_ephemeral_secret_file(key, value)?;
            tracing::debug!(
                "Created temporary file for secret '{}' at '{}'",
                key,
                temp_file.path().display()
            );
            cmd.env(key, temp_file.path());
            _temp_files.push(temp_file);
        }

        #[cfg(unix)]
        if self.replace {
            use std::os::unix::process::CommandExt;

            let source = cmd.exec();
            return Err(FnoxError::CommandExecutionFailed {
                command: self.command.join(" "),
                source,
            });
        }

        let mut child = cmd.spawn().map_err(|e| FnoxError::CommandExecutionFailed {
            command: self.command.join(" "),
            source: e,
        })?;

        // Forward SIGINT/SIGTERM to the child so Ctrl-C and `kill` reach it.
        #[cfg(unix)]
        {
            let child_pid = nix::unistd::Pid::from_raw(child.id() as i32);
            unsafe {
                // Ignore signals in the parent — the child handles them.
                // When the child exits we propagate its exit code below.
                signal_hook::low_level::register(signal_hook::consts::SIGINT, move || {
                    nix::sys::signal::kill(child_pid, nix::sys::signal::SIGINT).ok();
                })
                .ok();
                signal_hook::low_level::register(signal_hook::consts::SIGTERM, move || {
                    nix::sys::signal::kill(child_pid, nix::sys::signal::SIGTERM).ok();
                })
                .ok();
            }
        }

        let status = child
            .wait()
            .map_err(|e| FnoxError::CommandExecutionFailed {
                command: self.command.join(" "),
                source: e,
            })?;

        // Temp files are cleaned up when _temp_files drops here
        drop(_temp_files);

        if !status.success() {
            // Exit silently — the child already printed its own errors.
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                // If killed by signal, exit with 128+signal (standard convention)
                if let Some(sig) = status.signal() {
                    std::process::exit(128 + sig);
                }
            }
            std::process::exit(status.code().unwrap_or(1));
        }

        Ok(())
    }
}

#[cfg(unix)]
/// Installs temporary SIGINT and SIGTERM handlers while fnox resolves secrets before replacement.
fn install_replace_signal_handlers() -> Result<()> {
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        if !signal_uses_default_action(signal)? {
            continue;
        }
        unsafe { signal_hook::low_level::register(signal, move || libc::_exit(128 + signal)) }
            .map_err(|source| FnoxError::ExecReplaceSignalSetup { source })?;
    }

    Ok(())
}

#[cfg(unix)]
/// Reports whether a signal currently uses its default disposition.
fn signal_uses_default_action(signal: libc::c_int) -> Result<bool> {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    if unsafe { libc::sigaction(signal, std::ptr::null(), action.as_mut_ptr()) } == -1 {
        return Err(FnoxError::ExecReplaceSignalSetup {
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(unsafe { action.assume_init() }.sa_sigaction == libc::SIG_DFL)
}
