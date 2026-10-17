use crate::child_env::{self, EnvScope, Roots};
use crate::error::{FnoxError, Result};
use crate::temp_file_secrets::create_ephemeral_secret_file;
use crate::{commands::Cli, config::Config};
use std::process::Command;
use tempfile::NamedTempFile;

/// Run a command with secrets in its environment
///
/// Resolves the active profile's secrets and runs COMMAND with them set as
/// environment variables. Secrets with `env = true` (the default) or
/// `env = "exec"` are set; `env = false` secrets are not, and are removed if the
/// parent environment has them. An `as_file` secret is written to a private
/// temporary file whose path becomes the variable's value; the file is deleted
/// when the command exits. Configured lease backends add short-lived
/// credentials.
///
/// fnox also removes `FNOX_AGE_KEY`, `FNOX_AGE_KEY_FILE`, and the Enpass master
/// password from the inherited environment, forwards Ctrl-C and `SIGTERM` to the
/// command, and exits with the command's exit status. Put fnox options before
/// `--`; everything after it is the command.
#[derive(Debug, usage_rs::Args)]
#[usage(alias = "x", alias_hidden = "run")]
#[usage(
    example("fnox exec -- npm start", header = "Run a command"),
    example(
        "fnox exec -P production --if-missing error -- ./deploy.sh",
        header = "Use the production profile and fail on any missing secret"
    ),
    example(
        "fnox exec -- sh -c 'test -n \"$DATABASE_URL\"'",
        header = "Expand a secret in a shell expression (single quotes defer expansion)"
    ),
    example(
        "fnox exec --refresh API_TOKEN -- ./script.sh",
        header = "Re-fetch one secret instead of using the daemon cache"
    ),
    after_long_help = "See also:\n- Running commands: https://fnox.jdx.dev/guide/running-commands\n- Profiles: https://fnox.jdx.dev/guide/profiles"
)]
pub struct ExecCommand {
    /// Re-fetch KEY from its provider instead of the daemon cache; repeatable
    ///
    /// The fresh value replaces the cached one. Other secrets are still served
    /// from the cache.
    #[usage(long, value_name = "KEY")]
    pub refresh: Vec<String>,

    /// Replace the fnox process with the command (Unix only)
    ///
    /// The command keeps fnox's process ID and receives signals directly. Not
    /// allowed when the command would receive an `as_file` secret or the profile
    /// configures lease backends, because fnox must clean those up after the
    /// command exits.
    #[cfg(unix)]
    #[usage(long)]
    pub replace: bool,

    /// Command to run, with its arguments
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

        let (plan, lease_files) =
            child_env::plan(cli, &config, &profile, EnvScope::Exec, Roots::Scope, "exec").await?;

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
