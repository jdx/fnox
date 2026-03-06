use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger, LeaseRecord};
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

        // Handle lease-enabled secrets first (experimental)
        let mut lease_keys: Vec<String> = Vec::new();
        for (key, secret_config) in &profile_secrets {
            if secret_config.lease.is_some() {
                if let Err(e) = Settings::ensure_experimental("lease in exec") {
                    tracing::warn!("Skipping lease for '{}': {}", key, e);
                    continue;
                }
                lease_keys.push(key.clone());
            }
        }

        // Resolve leased secrets
        for key in &lease_keys {
            let secret_config = &profile_secrets[key];
            if let Some(creds) = resolve_lease_secret(&config, &profile, key, secret_config).await?
            {
                for (cred_key, cred_value) in creds {
                    cmd.env(cred_key, cred_value);
                }
            }
        }

        // Resolve remaining (non-leased) secrets using batch resolution
        let non_lease_secrets: indexmap::IndexMap<_, _> = profile_secrets
            .iter()
            .filter(|(k, _)| !lease_keys.contains(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let resolved_secrets =
            resolve_secrets_batch(&config, &profile, &non_lease_secrets).await?;

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

/// Resolve a secret via credential leasing instead of direct retrieval
async fn resolve_lease_secret(
    config: &Config,
    profile: &str,
    key: &str,
    secret_config: &crate::config::SecretConfig,
) -> Result<Option<std::collections::HashMap<String, String>>> {
    let backend_name = match secret_config.lease.as_deref() {
        Some(name) => name,
        None => return Ok(None),
    };

    let leases = config.get_leases(profile);
    let backend_config = leases.get(backend_name).ok_or_else(|| {
        FnoxError::Config(format!(
            "Lease backend '{}' for secret '{}' not found. Define it in [leases.{}] in fnox.toml.",
            backend_name, key, backend_name
        ))
    })?;

    let backend = backend_config.create_backend()?;

    let duration_str = secret_config
        .lease_duration
        .as_deref()
        .unwrap_or(lease::DEFAULT_LEASE_DURATION);
    let duration = lease::parse_duration(duration_str)?;

    let value = secret_config.value().ok_or_else(|| {
        FnoxError::Config(format!(
            "Secret '{}' has no value configured for leasing",
            key
        ))
    })?;

    let result = backend
        .create_lease(value, duration, &format!("fnox-exec-{}", key))
        .await?;

    // Record in ledger
    let mut ledger = LeaseLedger::load()?;
    ledger.add(LeaseRecord {
        lease_id: result.lease_id.clone(),
        backend_name: backend_name.to_string(),
        secret_name: key.to_string(),
        label: format!("fnox-exec-{}", key),
        created_at: Utc::now(),
        expires_at: result.expires_at,
        revoked: false,
    });
    ledger.save()?;

    tracing::debug!(
        "Created lease '{}' for secret '{}' (expires {:?})",
        result.lease_id,
        key,
        result.expires_at
    );

    Ok(Some(result.credentials))
}
