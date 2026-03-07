use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger, LeaseRecord};
use crate::lease_backends::LeaseBackendConfig;
use crate::secret_resolver::resolve_secrets_batch;
use crate::settings::Settings;
use crate::temp_file_secrets::create_ephemeral_secret_file;
use crate::{commands::Cli, config::Config};
use chrono::Utc;
use clap::{Args, ValueHint};
use indexmap::IndexMap;
use std::collections::HashSet;
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

        // Resolve secrets using batch resolution first
        let resolved_secrets = resolve_secrets_batch(&config, &profile, &profile_secrets).await?;

        // Keep temp files alive for the duration of the command
        let mut _temp_files: Vec<NamedTempFile> = Vec::new();

        // Track which env var keys are set by lease backends so regular secrets
        // don't overwrite short-lived lease credentials with long-lived master ones
        let mut lease_keys: HashSet<String> = HashSet::new();

        // Resolve leases if configured and experimental mode is enabled.
        // Temporarily set resolved secrets as process env vars so lease backend
        // SDKs (AWS, GCP, Azure) can find master credentials during lease creation.
        // The TempEnvGuard ensures cleanup on all exit paths (including errors).
        let leases = config.get_leases(&profile);
        let mut _temp_env_guard = lease::TempEnvGuard::default();
        if !leases.is_empty() {
            Settings::ensure_experimental("lease in exec")?;
            for (key, value) in &resolved_secrets {
                if let Some(value) = value
                    && std::env::var(key).is_err()
                {
                    // TODO: unsafe set_var on a multi-threaded Tokio runtime is technically
                    // UB. Refactor to pass credentials explicitly to lease backend SDKs
                    // instead of mutating the process environment.
                    unsafe { std::env::set_var(key, value) };
                    _temp_env_guard.keys.push(key.clone());
                }
            }
            let project_dir = lease::project_dir_from_config(&config, &cli.config);
            // Load ledger once to avoid TOCTTOU race with concurrent invocations
            let mut ledger = LeaseLedger::load(&project_dir)?;
            for (name, lease_config) in &leases {
                // Check prerequisites before attempting to create/use a lease
                let prereq_missing = lease_config.check_prerequisites();
                if let Some(ref missing) = prereq_missing {
                    // Check if there's a cached lease we can still use
                    let config_hash = lease_config.config_hash();
                    if let Some(cached) = ledger.find_reusable(name, &config_hash)
                        && cached.cached_credentials.is_some()
                    {
                        // Fall through to resolve_lease which will use the cache
                    } else {
                        eprintln!(
                            "Skipping lease '{}': {}\nRun 'fnox lease create -i {}' to set up credentials interactively.",
                            name, missing, name
                        );
                        continue;
                    }
                }
                // Intentionally hard-fail: if prerequisites pass but lease
                // creation fails (network, permissions, etc.), abort rather
                // than silently running the subprocess without expected creds.
                let creds = resolve_lease(
                    name,
                    lease_config,
                    &config,
                    &profile,
                    &project_dir,
                    &mut ledger,
                    prereq_missing.as_deref(),
                )
                .await?;
                for (cred_key, cred_value) in creds {
                    lease_keys.insert(cred_key.clone());
                    cmd.env(cred_key, cred_value);
                }
            }
        }

        // Add resolved secrets as environment variables
        for (key, value) in resolved_secrets {
            if let Some(value) = value {
                // Skip secrets with env = false (only accessible via `fnox get`)
                if let Some(secret_config) = profile_secrets.get(&key)
                    && !secret_config.env
                {
                    continue;
                }
                // Skip secrets whose keys were already set by lease backends —
                // lease credentials (short-lived) must not be overwritten by
                // regular secrets (which may be long-lived master credentials)
                if lease_keys.contains(&key) {
                    tracing::debug!("Skipping secret '{}': already set by lease backend", key);
                    continue;
                }
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

/// Resolve a lease backend into credentials, reusing cached credentials when available.
/// Takes a mutable reference to the ledger to avoid double-load TOCTTOU races.
async fn resolve_lease(
    name: &str,
    lease_config: &LeaseBackendConfig,
    config: &Config,
    profile: &str,
    project_dir: &std::path::Path,
    ledger: &mut LeaseLedger,
    prereq_missing: Option<&str>,
) -> Result<IndexMap<String, String>> {
    // Check for a reusable cached lease (config_hash ensures stale creds
    // are not returned after backend config changes like role ARN rotation)
    let config_hash = lease_config.config_hash();
    if let Some(cached_lease) = ledger.find_reusable(name, &config_hash)
        && let Some(ref cached_creds) = cached_lease.cached_credentials
    {
        // If encrypted, decrypt
        if let Some(ref enc_provider_name) = cached_lease.encryption_provider {
            match lease::find_encryption_provider(config, profile).await {
                lease::EncryptionProviderResult::Available(found_name, provider)
                    if found_name == *enc_provider_name =>
                {
                    match lease::decrypt_credentials(provider.as_ref(), cached_creds).await {
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

    // No reusable cache — create fresh lease.
    // If prerequisites were already known to be missing, fail now with a clear
    // message instead of letting the SDK produce a confusing auth error.
    if let Some(missing) = prereq_missing {
        return Err(FnoxError::Config(format!(
            "Cached lease for '{}' could not be used and prerequisites are missing: {}\n\
             Run 'fnox lease create -i {}' to set up credentials interactively.",
            name, missing, name
        )));
    }
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
        lease::cache_credentials(config, profile, &result.credentials, &result.lease_id).await;

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
        config_hash: Some(config_hash),
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
