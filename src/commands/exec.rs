use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger, LeaseRecord};
use crate::lease_backends::LeaseBackendConfig;
use crate::providers::{self, ProviderCapability};
use crate::secret_resolver::resolve_secrets_batch;
use crate::settings::Settings;
use crate::temp_file_secrets::create_ephemeral_secret_file;
use crate::{commands::Cli, config::Config};
use chrono::Utc;
use clap::{Args, ValueHint};
use std::collections::HashMap;
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
                let project_dir = lease::project_dir_from_config(&cli.config);
                for (name, lease_config) in &leases {
                    let creds =
                        resolve_lease(name, lease_config, &config, &profile, &project_dir).await?;
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

/// Find an encryption provider if one is configured (default_provider with Encryption capability)
async fn find_encryption_provider(
    config: &Config,
    profile: &str,
) -> Option<(String, Box<dyn providers::Provider>)> {
    let provider_name = match config.get_default_provider(profile) {
        Ok(Some(name)) => name,
        _ => return None,
    };

    let providers_map = config.get_providers(profile);
    let provider_config = providers_map.get(&provider_name)?;

    let provider =
        match providers::get_provider_resolved(config, profile, &provider_name, provider_config)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "Could not instantiate encryption provider '{}': {}",
                    provider_name,
                    e
                );
                return None;
            }
        };

    if provider
        .capabilities()
        .contains(&ProviderCapability::Encryption)
    {
        Some((provider_name, provider))
    } else {
        None
    }
}

/// Encrypt credential values using an encryption provider
async fn encrypt_credentials(
    provider: &dyn providers::Provider,
    credentials: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut encrypted = HashMap::new();
    for (key, value) in credentials {
        let enc = provider.encrypt(value).await?;
        encrypted.insert(key.clone(), enc);
    }
    Ok(encrypted)
}

/// Decrypt cached credential values using an encryption provider
async fn decrypt_credentials(
    provider: &dyn providers::Provider,
    cached: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut decrypted = HashMap::new();
    for (key, value) in cached {
        let dec = provider.get_secret(value).await?;
        decrypted.insert(key.clone(), dec);
    }
    Ok(decrypted)
}

/// Resolve a lease backend into credentials, reusing cached credentials when available
async fn resolve_lease(
    name: &str,
    lease_config: &LeaseBackendConfig,
    config: &Config,
    profile: &str,
    project_dir: &std::path::Path,
) -> Result<HashMap<String, String>> {
    // Load ledger once as mutable to avoid race window with concurrent invocations
    let mut ledger = LeaseLedger::load(project_dir)?;

    // Check for a reusable cached lease
    if let Some(cached_lease) = ledger.find_reusable(name)
        && let Some(ref cached_creds) = cached_lease.cached_credentials {
            // If encrypted, decrypt
            if let Some(ref enc_provider_name) = cached_lease.encryption_provider {
                match find_encryption_provider(config, profile).await {
                    Some((found_name, provider)) if found_name == *enc_provider_name => {
                        match decrypt_credentials(provider.as_ref(), cached_creds).await {
                            Ok(decrypted) => {
                                tracing::debug!(
                                    "Reusing cached encrypted lease '{}' for backend '{}'",
                                    cached_lease.lease_id,
                                    name
                                );
                                return Ok(decrypted);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to decrypt cached lease '{}': {}, creating fresh lease",
                                    cached_lease.lease_id,
                                    e
                                );
                            }
                        }
                    }
                    _ => {
                        tracing::warn!(
                            "Encryption provider '{}' not available for cached lease '{}', creating fresh lease",
                            enc_provider_name,
                            cached_lease.lease_id
                        );
                    }
                }
            } else {
                // Plaintext cached credentials
                tracing::debug!(
                    "Reusing cached plaintext lease '{}' for backend '{}'",
                    cached_lease.lease_id,
                    name
                );
                return Ok(cached_creds.clone());
            }
        }

    // No reusable cache — create fresh lease
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

    // Try to cache credentials (optionally encrypted)
    let (cached_credentials, encryption_provider) =
        match find_encryption_provider(config, profile).await {
            Some((enc_name, provider)) => {
                match encrypt_credentials(provider.as_ref(), &result.credentials).await {
                    Ok(encrypted) => {
                        tracing::debug!(
                            "Caching encrypted credentials for lease '{}'",
                            result.lease_id
                        );
                        (Some(encrypted), Some(enc_name))
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to encrypt credentials for caching: {}, storing plaintext",
                            e
                        );
                        (Some(result.credentials.clone()), None)
                    }
                }
            }
            None => {
                tracing::debug!(
                    "No encryption provider, caching plaintext credentials for lease '{}'",
                    result.lease_id
                );
                (Some(result.credentials.clone()), None)
            }
        };

    // Record in ledger
    ledger.add(LeaseRecord {
        lease_id: result.lease_id.clone(),
        backend_name: name.to_string(),
        label: label.clone(),
        created_at: Utc::now(),
        expires_at: result.expires_at,
        revoked: false,
        cached_credentials,
        encryption_provider,
    });
    ledger.save(project_dir)?;

    tracing::debug!(
        "Created lease '{}' for backend '{}' (expires {:?})",
        result.lease_id,
        name,
        result.expires_at
    );

    Ok(result.credentials)
}
