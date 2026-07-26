use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger};
use crate::temp_file_secrets::create_ephemeral_secret_file;
use crate::{commands::Cli, config::Config};
use clap::{Args, ValueHint};
use std::collections::HashSet;
use std::process::Command;
use tempfile::NamedTempFile;

#[derive(Debug, Args)]
#[command(visible_alias = "x", alias = "run")]
pub struct ExecCommand {
    /// Run the command in fnox's process, keeping the same PID and receiving signals
    /// directly; supports environment-only secrets without leases and does not inherit
    /// ambient FNOX_AGE_KEY or FNOX_AGE_KEY_FILE values. Available on Linux,
    /// macOS, and other Unix-like systems
    #[cfg(unix)]
    #[arg(long)]
    pub replace: bool,

    /// Command to run
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_hint = ValueHint::CommandWithArguments)]
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
        let leases = config.get_leases(&profile);

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

        // Resolve secrets using batch resolution first
        let resolved_secrets = crate::daemon::resolve_batch(
            cli,
            &config,
            &profile,
            &profile_secrets,
            crate::daemon::Purpose::Exec,
            true,
        )
        .await?;

        // Keep temp files alive for the duration of the command
        let mut _temp_files: Vec<NamedTempFile> = Vec::new();

        // Track which env var keys are set by lease backends so regular secrets
        // don't overwrite short-lived lease credentials with long-lived master ones
        let mut lease_keys: HashSet<String> = HashSet::new();

        // Resolve leases if configured.
        // Temporarily set resolved secrets as process env vars so lease backend
        // SDKs (AWS, GCP, Azure) can find master credentials during lease creation.
        // The TempEnvGuard ensures cleanup on all exit paths (including errors).
        let mut _temp_env_guard = lease::TempEnvGuard::default();
        if !leases.is_empty() {
            _temp_files.extend(lease::set_secrets_as_env(
                &resolved_secrets,
                &profile_secrets,
                &mut _temp_env_guard,
            )?);
            let project_dir = lease::project_dir_from_config(&config, &cli.config);
            // Each resolve_lease call manages its own short-lived ledger locks.
            // Leases are processed sequentially; no shared lock is needed.
            for (name, lease_config) in &leases {
                // Check prerequisites before attempting to create/use a lease
                let prereq_missing = lease_config.check_prerequisites();
                if let Some(ref missing) = prereq_missing {
                    // Check if there's a cached lease we can still use (short lock).
                    let has_cache = {
                        let _lock = LeaseLedger::lock(&project_dir)?;
                        let ledger = LeaseLedger::load(&project_dir)?;
                        let config_hash = lease_config.config_hash();
                        ledger
                            .find_reusable(name, &config_hash)
                            .is_some_and(|r| r.cached_credentials.is_some())
                    };
                    if !has_cache {
                        tracing::warn!(
                            "Skipping lease '{}': {}\nRun 'fnox lease create -i {}' to set up credentials interactively.",
                            name,
                            missing,
                            name
                        );
                        continue;
                    }
                }
                // Intentionally hard-fail: if prerequisites pass but lease
                // creation fails (network, permissions, etc.), abort rather
                // than silently running the subprocess without expected creds.
                // resolve_lease manages its own ledger locks with minimal scope.
                let creds = lease::resolve_lease(
                    name,
                    lease_config,
                    &config,
                    &profile,
                    &project_dir,
                    prereq_missing.as_deref(),
                    "exec",
                    false,
                )
                .await?;
                for (cred_key, cred_value) in creds {
                    lease_keys.insert(cred_key.clone());
                    cmd.env(cred_key, cred_value);
                }
            }
        }

        // The target should receive resolved secrets, not the age identity that
        // decrypts other values in the configuration. Explicitly configured
        // secrets with these names are added back by the loop below.
        #[cfg(unix)]
        if self.replace {
            cmd.env_remove("FNOX_AGE_KEY");
            cmd.env_remove("FNOX_AGE_KEY_FILE");
        }

        // Add resolved secrets as environment variables
        for (key, value) in resolved_secrets {
            // Skip secrets whose keys were already set by lease backends.
            // This MUST come before env=false: if a master credential has
            // env=false and the lease backend produced a short-lived credential
            // under the same key (e.g., AWS_ACCESS_KEY_ID), calling env_remove
            // here would strip the lease credential that cmd.env() already set.
            if lease_keys.contains(&key) {
                tracing::debug!("Skipping secret '{}': already set by lease backend", key);
                continue;
            }
            // Strip env=false secrets from child environment regardless of whether
            // resolution succeeded — a stale inherited env var must not leak through.
            // env="exec" secrets ARE injected here: exec subprocesses are their
            // intended destination.
            if let Some(secret_config) = profile_secrets.get(&key)
                && !secret_config.env_mode().in_exec()
            {
                cmd.env_remove(&key);
                continue;
            }
            if let Some(value) = value {
                // Check if this secret should be written to a file
                if let Some(secret_config) = profile_secrets.get(&key) {
                    if secret_config.as_file {
                        // Create a temporary file and write the secret to it
                        let temp_file = create_ephemeral_secret_file(&key, &value)?;
                        let file_path = temp_file.path().to_string_lossy().to_string();

                        tracing::debug!(
                            "Created temporary file for secret '{}' at '{}'",
                            key,
                            file_path
                        );

                        // Set env var to the file path
                        cmd.env(key, file_path);

                        // Keep the temp file alive
                        _temp_files.push(temp_file);
                    } else {
                        // Set env var to the secret value directly
                        cmd.env(key, value);
                    }
                } else {
                    cmd.env(key, value);
                }
            }
        }

        // Drop the temp env guard BEFORE spawning the child process.
        // This removes temporary secrets (including env=false master credentials)
        // from the parent process environment so the child doesn't inherit them.
        drop(_temp_env_guard);

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
fn signal_uses_default_action(signal: libc::c_int) -> Result<bool> {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    if unsafe { libc::sigaction(signal, std::ptr::null(), action.as_mut_ptr()) } == -1 {
        return Err(FnoxError::ExecReplaceSignalSetup {
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(unsafe { action.assume_init() }.sa_sigaction == libc::SIG_DFL)
}
