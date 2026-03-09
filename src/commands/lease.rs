use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger, LeaseRecord, TempEnvGuard};
use crate::secret_resolver::resolve_secrets_batch;
use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use indexmap::IndexMap;

#[derive(Debug, Args)]
#[command(about = "Manage ephemeral credential leases")]
pub struct LeaseCommand {
    #[command(subcommand)]
    pub subcommand: Option<LeaseSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum LeaseSubcommand {
    /// Revoke all expired leases that need manual cleanup
    Cleanup(LeaseCleanupCommand),
    /// Create a short-lived credential lease from a secret
    Create(LeaseCreateCommand),
    /// List tracked leases
    List(LeaseListCommand),
    /// Revoke a lease by ID
    Revoke(LeaseRevokeCommand),
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Shell,
    Json,
    Env,
}

#[derive(Debug, Args)]
pub struct LeaseCreateCommand {
    /// Lease backend name (from `[leases.<name>]` config). Creates all backends if omitted.
    pub backend_name: Option<String>,

    /// Create leases for all configured backends
    #[arg(short, long, conflicts_with = "backend_name")]
    pub all: bool,

    /// Lease duration (e.g., "15m", "1h", "2h30m"); overrides config duration
    #[arg(short, long)]
    pub duration: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "shell")]
    pub format: OutputFormat,

    /// Prompt interactively for missing credentials
    #[arg(short, long)]
    pub interactive: bool,

    /// Label for the lease (e.g., session purpose)
    #[arg(short, long, default_value = "fnox-lease")]
    pub label: String,
}

#[derive(Debug, Args)]
pub struct LeaseListCommand {
    /// Show only active (non-expired, non-revoked) leases
    #[arg(long)]
    pub active: bool,

    /// Show only expired leases
    #[arg(long)]
    pub expired: bool,
}

#[derive(Debug, Args)]
pub struct LeaseRevokeCommand {
    /// Lease ID to revoke
    pub lease_id: String,
}

#[derive(Debug, Args)]
pub struct LeaseCleanupCommand;

impl LeaseCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        match &self.subcommand {
            Some(LeaseSubcommand::Create(cmd)) => cmd.run(cli, config).await,
            Some(LeaseSubcommand::List(cmd)) => cmd.run(cli, &config).await,
            Some(LeaseSubcommand::Revoke(cmd)) => cmd.run(cli, config).await,
            Some(LeaseSubcommand::Cleanup(cmd)) => cmd.run(cli, config).await,
            // `fnox lease` with no subcommand defaults to creating all leases
            None => {
                let cmd = LeaseCreateCommand {
                    backend_name: None,
                    all: true,
                    duration: None,
                    format: OutputFormat::Shell,
                    interactive: false,
                    label: "fnox-lease".to_string(),
                };
                cmd.run(cli, config).await
            }
        }
    }
}

impl LeaseCreateCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        let project_dir = lease::project_dir_from_config(&config, &cli.config);
        let leases = config.get_leases(&profile);

        // Resolve secrets once upfront (shared across all backends)
        let profile_secrets = config.get_secrets(&profile)?;
        let resolved_secrets = resolve_secrets_batch(&config, &profile, &profile_secrets).await?;

        let mut _temp_env_guard = TempEnvGuard::default();
        let _temp_files =
            lease::set_secrets_as_env(&resolved_secrets, &profile_secrets, &mut _temp_env_guard)?;

        let create_all = self.all || self.backend_name.is_none();

        if create_all {
            if leases.is_empty() {
                return Err(FnoxError::Config(
                    "No lease backends configured. Define them in [leases.<name>] in fnox.toml."
                        .to_string(),
                ));
            }
            self.run_all(
                cli,
                &config,
                &profile,
                &project_dir,
                &leases,
                &resolved_secrets,
                &mut _temp_env_guard,
            )
            .await
        } else {
            let backend_name = self.backend_name.as_deref().unwrap();
            let backend_config = leases.get(backend_name).ok_or_else(|| {
                FnoxError::Config(format!(
                    "Lease backend '{}' not found. Define it in [leases.{}] in fnox.toml.",
                    backend_name, backend_name
                ))
            })?;
            self.create_single(
                backend_name,
                backend_config,
                &config,
                &profile,
                &project_dir,
                &resolved_secrets,
                &mut _temp_env_guard,
            )
            .await
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_all(
        &self,
        _cli: &Cli,
        config: &Config,
        profile: &str,
        project_dir: &std::path::Path,
        leases: &IndexMap<String, crate::lease_backends::LeaseBackendConfig>,
        resolved_secrets: &indexmap::IndexMap<String, Option<String>>,
        temp_env_guard: &mut TempEnvGuard,
    ) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        for (backend_name, backend_config) in leases {
            match self
                .create_single(
                    backend_name,
                    backend_config,
                    config,
                    profile,
                    project_dir,
                    resolved_secrets,
                    temp_env_guard,
                )
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    eprintln!(
                        "{} Failed to create lease for '{}': {}",
                        console::style("✗").red(),
                        backend_name,
                        e
                    );
                    errors.push(format!("{}: {}", backend_name, e));
                }
            }
        }

        if !errors.is_empty() {
            return Err(FnoxError::Config(format!(
                "{} of {} lease backends failed:\n{}",
                errors.len(),
                leases.len(),
                errors.join("\n")
            )));
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_single(
        &self,
        backend_name: &str,
        backend_config: &crate::lease_backends::LeaseBackendConfig,
        config: &Config,
        profile: &str,
        project_dir: &std::path::Path,
        resolved_secrets: &indexmap::IndexMap<String, Option<String>>,
        temp_env_guard: &mut TempEnvGuard,
    ) -> Result<()> {
        // Hard-fail if any secret required by this lease backend failed to resolve.
        // resolve_secrets_batch respects if_missing (default: "warn"), which would
        // silently swallow auth errors (e.g. FIDO2 PIN failure) and produce a
        // misleading "token not found" error later in check_prerequisites.
        let required: std::collections::HashSet<&str> = backend_config
            .required_env_vars()
            .iter()
            .map(|(k, _)| *k)
            .collect();
        let failed: Vec<_> = resolved_secrets
            .iter()
            .filter(|(k, v)| v.is_none() && required.contains(k.as_str()))
            .map(|(k, _)| k.as_str())
            .collect();
        if !failed.is_empty() {
            return Err(FnoxError::Config(format!(
                "Failed to resolve secrets required by lease backend '{}': {}",
                backend_name,
                failed.join(", "),
            )));
        }

        // Check prerequisites and prompt for missing env vars if --interactive
        if let Some(missing) = backend_config.check_prerequisites() {
            let required_vars = backend_config.required_env_vars();
            if self.interactive && !required_vars.is_empty() {
                eprintln!("{}", missing);
                eprintln!();
                for (var, description) in &required_vars {
                    if std::env::var(var).is_err() {
                        let value = demand::Input::new(format!("{var} ({description})"))
                            .placeholder("paste value here")
                            .run()
                            .map_err(|e| {
                                FnoxError::Config(format!("Failed to read input: {}", e))
                            })?;
                        if !value.is_empty() {
                            // TODO: unsafe set_var on a multi-threaded Tokio runtime is
                            // technically UB. Refactor to pass credentials explicitly.
                            unsafe { std::env::set_var(var, &value) };
                            temp_env_guard.keys.push(var.to_string());
                        }
                    }
                }
                // Re-check after prompting
                if let Some(still_missing) = backend_config.check_prerequisites() {
                    return Err(FnoxError::Config(still_missing));
                }
            } else {
                return Err(FnoxError::Config(missing));
            }
        }

        let duration_str = self
            .duration
            .as_deref()
            .or(backend_config.duration())
            .unwrap_or(lease::DEFAULT_LEASE_DURATION);
        let duration = lease::parse_duration(duration_str)?;

        let backend = backend_config.create_backend()?;

        // Check duration against max
        let max_duration = backend.max_lease_duration();
        if duration > max_duration {
            return Err(FnoxError::Config(format!(
                "Requested duration {:?} exceeds maximum {:?} for lease backend '{}'",
                duration, max_duration, backend_name
            )));
        }

        // Create the lease, cache credentials, and record in ledger
        let _ledger_lock = LeaseLedger::lock(project_dir)?;
        let mut ledger = LeaseLedger::load(project_dir)?;
        let result = lease::create_and_record_lease(
            backend.as_ref(),
            backend_name,
            &self.label,
            duration,
            backend_config.config_hash(),
            config,
            profile,
            &mut ledger,
            project_dir,
        )
        .await?;

        // Output in requested format
        match self.format {
            OutputFormat::Shell => {
                println!(
                    "{} Lease '{}' created (expires {})",
                    console::style("✓").green(),
                    backend_name,
                    format_expiry(result.expires_at)
                );
                for (key, value) in &result.credentials {
                    let display = mask_credential(value);
                    println!("  {:<25} {}", key, display);
                }
                if let Some(exp) = result.expires_at {
                    println!("  {:<25} {}", "Expires", exp.to_rfc3339());
                }
            }
            OutputFormat::Json => {
                let mut output = serde_json::Map::new();
                output.insert(
                    "backend".to_string(),
                    serde_json::Value::String(backend_name.to_string()),
                );
                for (key, value) in &result.credentials {
                    output.insert(key.clone(), serde_json::Value::String(value.clone()));
                }
                if let Some(exp) = result.expires_at {
                    output.insert(
                        "expires_at".to_string(),
                        serde_json::Value::String(exp.to_rfc3339()),
                    );
                }
                output.insert(
                    "lease_id".to_string(),
                    serde_json::Value::String(result.lease_id),
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output)
                        .map_err(|e| FnoxError::Json { source: e })?
                );
            }
            OutputFormat::Env => {
                for (key, value) in &result.credentials {
                    println!(
                        "export {}={}",
                        key,
                        shlex::try_quote(value).map_err(|_| {
                            FnoxError::Config(format!(
                                "Credential value for '{key}' contains characters that cannot be shell-quoted"
                            ))
                        })?
                    );
                }
            }
        }

        Ok(())
    }
}

impl LeaseListCommand {
    pub async fn run(&self, cli: &Cli, config: &Config) -> Result<()> {
        let project_dir = lease::project_dir_from_config(config, &cli.config);
        let ledger = LeaseLedger::load(&project_dir)?;

        let records: Vec<&LeaseRecord> = if self.active {
            ledger.active_leases()
        } else if self.expired {
            ledger.expired_leases()
        } else {
            ledger.leases.iter().collect()
        };

        if records.is_empty() {
            println!("No leases found.");
            return Ok(());
        }

        println!(
            "{:<20} {:<15} {:<15} {:<8}",
            "LEASE ID", "BACKEND", "EXPIRES", "STATUS"
        );
        for record in records {
            let status = if record.revoked {
                "revoked"
            } else if record.expires_at.is_some_and(|exp| exp <= Utc::now()) {
                "expired"
            } else {
                "active"
            };
            let expires = record
                .expires_at
                .map(|exp: chrono::DateTime<chrono::Utc>| exp.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "never".to_string());
            let id_short = if record.lease_id.chars().count() > 18 {
                let truncated: String = record.lease_id.chars().take(15).collect();
                format!("{truncated}...")
            } else {
                record.lease_id.clone()
            };
            println!(
                "{:<20} {:<15} {:<15} {:<8}",
                id_short, record.backend_name, expires, status
            );
        }

        Ok(())
    }
}

impl LeaseRevokeCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let project_dir = lease::project_dir_from_config(&config, &cli.config);
        let _ledger_lock = LeaseLedger::lock(&project_dir)?;
        let mut ledger = LeaseLedger::load(&project_dir)?;

        let record = ledger
            .find(&self.lease_id)
            .ok_or_else(|| FnoxError::Config(format!("Lease '{}' not found", self.lease_id)))?;

        if record.revoked {
            println!("Lease '{}' is already revoked.", self.lease_id);
            return Ok(());
        }

        let backend_name = record.backend_name.clone();
        let cached_credentials = record.cached_credentials.clone();
        let encryption_provider_name = record.encryption_provider.clone();
        let profile = Config::get_profile(cli.profile.as_deref());
        let leases = config.get_leases(&profile);

        // Decrypt cached credentials (if encrypted) so backends can use
        // credential values for revocation (e.g. GitHub App needs the token).
        let decrypted_credentials = match (&cached_credentials, &encryption_provider_name) {
            (Some(creds), Some(enc_name)) => {
                match lease::find_encryption_provider(&config, &profile).await {
                    lease::EncryptionProviderResult::Available(found_name, provider)
                        if found_name == *enc_name =>
                    {
                        match lease::decrypt_credentials(provider.as_ref(), creds).await {
                            Ok(decrypted) => Some(decrypted),
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to decrypt cached credentials for revocation: {e}"
                                );
                                None
                            }
                        }
                    }
                    _ => {
                        tracing::warn!(
                            "Encryption provider '{enc_name}' not available for credential decryption"
                        );
                        None
                    }
                }
            }
            (Some(creds), None) => Some(creds.clone()),
            _ => None,
        };

        if let Some(backend_config) = leases.get(&backend_name) {
            match backend_config.create_backend() {
                Ok(backend) => {
                    if let Err(e) = backend
                        .revoke_lease(&self.lease_id, decrypted_credentials.as_ref())
                        .await
                    {
                        tracing::warn!("Backend revocation failed for '{}': {}", self.lease_id, e);
                        eprintln!(
                            "Warning: backend revocation failed; only the local ledger entry will be revoked."
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to create backend '{}' for revocation: {}",
                        backend_name,
                        e
                    );
                    eprintln!(
                        "Warning: could not initialize backend '{}'; only the local ledger entry was revoked.",
                        backend_name
                    );
                }
            }
        } else {
            tracing::warn!(
                "Lease backend '{}' not found in config; backend revocation skipped",
                backend_name
            );
            eprintln!(
                "Warning: backend '{}' not found in config; only the local ledger entry was revoked.",
                backend_name
            );
        }

        ledger.mark_revoked(&self.lease_id);
        ledger.save(&project_dir)?;
        println!("Lease '{}' revoked.", self.lease_id);

        Ok(())
    }
}

impl LeaseCleanupCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let project_dir = lease::project_dir_from_config(&config, &cli.config);
        let _ledger_lock = LeaseLedger::lock(&project_dir)?;
        let mut ledger = LeaseLedger::load(&project_dir)?;
        let expired: Vec<LeaseRecord> = ledger
            .expired_leases()
            .iter()
            .map(|r| (*r).clone())
            .collect();

        if expired.is_empty() {
            println!("No expired leases to clean up.");
            return Ok(());
        }

        let profile = Config::get_profile(cli.profile.as_deref());
        let leases = config.get_leases(&profile);
        let mut cleaned = 0;

        for record in &expired {
            // Try to revoke via the backend if available (best-effort)
            if let Some(backend_config) = leases.get(&record.backend_name) {
                match backend_config.create_backend() {
                    Ok(backend) => {
                        // Expired leases: pass None for credentials since the
                        // token has expired and can't be revoked server-side anyway.
                        if let Err(e) = backend.revoke_lease(&record.lease_id, None).await {
                            tracing::warn!("Failed to revoke lease '{}': {}", record.lease_id, e);
                            // Still mark revoked locally — the credential has expired anyway
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to create backend '{}' for lease '{}': {}",
                            record.backend_name,
                            record.lease_id,
                            e
                        );
                        // Fall through to mark_revoked — don't leave stale entries
                    }
                }
            } else {
                // Backend not in current profile config — skip remote revocation
                // but still mark as revoked locally to clean up the ledger
                tracing::debug!(
                    "Lease backend '{}' not found for lease '{}', marking revoked locally",
                    record.backend_name,
                    record.lease_id
                );
            }
            ledger.mark_revoked(&record.lease_id);
            cleaned += 1;
        }

        ledger.save(&project_dir)?;
        println!("Cleaned up {} expired lease(s).", cleaned);

        Ok(())
    }
}

fn mask_credential(value: &str) -> String {
    if value.chars().count() > 12 {
        let prefix: String = value.chars().take(4).collect();
        let suffix: String = value
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{prefix}...{suffix}")
    } else {
        "****".to_string()
    }
}

fn format_expiry(expires_at: Option<chrono::DateTime<chrono::Utc>>) -> String {
    match expires_at {
        Some(exp) => {
            let remaining = exp - Utc::now();
            if remaining.num_seconds() <= 0 {
                "expired".to_string()
            } else if remaining.num_hours() > 0 {
                format!(
                    "in {}h{}m",
                    remaining.num_hours(),
                    remaining.num_minutes() % 60
                )
            } else if remaining.num_minutes() > 0 {
                format!("in {}m", remaining.num_minutes())
            } else {
                format!("in {}s", remaining.num_seconds())
            }
        }
        None => "never".to_string(),
    }
}
