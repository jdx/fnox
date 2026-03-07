use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger, LeaseRecord};
use crate::lease_backends::LeaseBackendConfig;
use crate::secret_resolver::resolve_secrets_batch;
use crate::settings::Settings;
use crate::temp_file_secrets::create_ephemeral_secret_file;
use crate::{commands::Cli, config::Config};
use chrono::Utc;
use clap::{Args, ValueHint};
use std::process::Command;
use tempfile::NamedTempFile;

#[derive(Debug, Args)]
#[command(visible_alias = "x", alias = "run")]
pub struct ExecCommand {
    /// Command to run
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_hint = ValueHint::CommandWithArguments)]
    pub command: Vec<String>,
}

impl ExecCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if self.command.is_empty() {
            return Err(FnoxError::CommandNotSpecified);
        }

        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Running command with secrets from profile '{}'", profile);

        // Get the profile secrets
        let profile_secrets = config.get_secrets(&profile)?;

        let mut cmd = Command::new(&self.command[0]);
        if self.command.len() > 1 {
            cmd.args(&self.command[1..]);
        }

        // Handle lease backends (experimental)
        let leases = config.get_leases(&profile);
        if !leases.is_empty() {
            if let Err(e) = Settings::ensure_experimental("lease in exec") {
                tracing::warn!("Skipping leases: {}", e);
            } else {
                for (name, lease_config) in &leases {
                    let creds = resolve_lease(name, lease_config).await?;
                    for (cred_key, cred_value) in creds {
                        cmd.env(cred_key, cred_value);
                    }
                }
            }
        }

        // Resolve secrets using batch resolution
        let resolved_secrets = resolve_secrets_batch(&config, &profile, &profile_secrets).await?;

        // Keep temp files alive for the duration of the command
        let mut _temp_files: Vec<NamedTempFile> = Vec::new();

        // Add resolved secrets as environment variables
        for (key, value) in resolved_secrets {
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

        let status = cmd
            .status()
            .map_err(|e| FnoxError::CommandExecutionFailed {
                command: self.command.join(" "),
                source: e,
            })?;

        if !status.success()
            && let Some(code) = status.code()
        {
            return Err(FnoxError::CommandExitFailed {
                command: self.command.join(" "),
                status: code,
            });
        }

        // Temp files are automatically deleted when _temp_files goes out of scope
        Ok(())
    }
}

/// Resolve a lease backend into credentials
async fn resolve_lease(
    name: &str,
    lease_config: &LeaseBackendConfig,
) -> Result<std::collections::HashMap<String, String>> {
    let backend = lease_config.create_backend()?;

    let duration_str = lease_config
        .duration()
        .unwrap_or(lease::DEFAULT_LEASE_DURATION);
    let duration = lease::parse_duration(duration_str)?;

    let max_duration = backend.max_lease_duration();
    if duration > max_duration {
        return Err(FnoxError::Config(format!(
            "Lease duration '{}' for '{}' exceeds maximum {:?}",
            duration_str, name, max_duration
        )));
    }

    let label = format!("fnox-exec-{}", name);
    let result = backend.create_lease(duration, &label).await?;

    // Record in ledger
    let mut ledger = LeaseLedger::load()?;
    ledger.add(LeaseRecord {
        lease_id: result.lease_id.clone(),
        backend_name: name.to_string(),
        label: label.clone(),
        created_at: Utc::now(),
        expires_at: result.expires_at,
        revoked: false,
    });
    ledger.save()?;

    tracing::debug!(
        "Created lease '{}' for backend '{}' (expires {:?})",
        result.lease_id,
        name,
        result.expires_at
    );

    Ok(result.credentials)
}
