use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger, LeaseRecord};
use crate::settings::Settings;
use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Args)]
#[command(about = "Manage ephemeral credential leases (experimental)")]
pub struct LeaseCommand {
    #[command(subcommand)]
    pub subcommand: LeaseSubcommand,
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
    /// Secret name to lease credentials for
    pub secret_name: String,

    /// Lease duration (e.g., "15m", "1h", "2h30m")
    #[arg(short, long, default_value = crate::lease::DEFAULT_LEASE_DURATION)]
    pub duration: String,

    /// Output format
    #[arg(short, long, default_value = "shell")]
    pub format: OutputFormat,

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
        Settings::ensure_experimental("fnox lease")?;

        match &self.subcommand {
            LeaseSubcommand::Create(cmd) => cmd.run(cli, config).await,
            LeaseSubcommand::List(cmd) => cmd.run().await,
            LeaseSubcommand::Revoke(cmd) => cmd.run(cli, config).await,
            LeaseSubcommand::Cleanup(cmd) => cmd.run(cli, config).await,
        }
    }
}

impl LeaseCreateCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let duration = lease::parse_duration(&self.duration)?;

        let profile = Config::get_profile(cli.profile.as_deref());
        let secrets = config.get_secrets(&profile)?;

        // Find the secret config
        let secret_config =
            secrets
                .get(&self.secret_name)
                .ok_or_else(|| FnoxError::SecretNotFound {
                    key: self.secret_name.clone(),
                    profile: profile.clone(),
                    config_path: None,
                    suggestion: None,
                })?;

        // Resolve the lease backend
        let backend_name = secret_config.lease.as_deref().ok_or_else(|| {
            FnoxError::Config(format!(
                "Secret '{}' has no lease backend configured. Set `lease = \"<backend_name>\"` in the secret config.",
                self.secret_name
            ))
        })?;

        let leases = config.get_leases(&profile);
        let backend_config = leases.get(backend_name).ok_or_else(|| {
            FnoxError::Config(format!(
                "Lease backend '{}' not found. Define it in [leases.{}] in fnox.toml.",
                backend_name, backend_name
            ))
        })?;

        let backend = backend_config.create_backend()?;

        // Check duration against max
        let max_duration = backend.max_lease_duration();
        if duration > max_duration {
            return Err(FnoxError::Config(format!(
                "Requested duration {:?} exceeds maximum {:?} for lease backend '{}'",
                duration, max_duration, backend_name
            )));
        }

        let value = secret_config.value().ok_or_else(|| {
            FnoxError::Config(format!(
                "Secret '{}' has no value configured",
                self.secret_name
            ))
        })?;

        // Create the lease
        let result = backend.create_lease(value, duration, &self.label).await?;

        // Record in ledger
        let mut ledger = LeaseLedger::load()?;
        ledger.add(LeaseRecord {
            lease_id: result.lease_id.clone(),
            backend_name: backend_name.to_string(),
            secret_name: self.secret_name.clone(),
            label: self.label.clone(),
            created_at: Utc::now(),
            expires_at: result.expires_at,
            revoked: false,
        });
        ledger.save()?;

        // Output in requested format
        match self.format {
            OutputFormat::Shell => {
                println!(
                    "Lease created (expires {})",
                    format_expiry(result.expires_at)
                );
                println!();
                for (key, value) in &result.credentials {
                    let display = if value.len() > 12 {
                        format!("{}...{}", &value[..4], &value[value.len() - 4..])
                    } else {
                        "****".to_string()
                    };
                    println!("{:<25} {}", key, display);
                }
                if let Some(exp) = result.expires_at {
                    println!("{:<25} {}", "Expires", exp.to_rfc3339());
                }
            }
            OutputFormat::Json => {
                let mut output = serde_json::Map::new();
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
                    println!("export {}={}", key, shell_escape(value));
                }
            }
        }

        Ok(())
    }
}

impl LeaseListCommand {
    pub async fn run(&self) -> Result<()> {
        let ledger = LeaseLedger::load()?;

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
            "{:<20} {:<15} {:<20} {:<15} {:<8}",
            "LEASE ID", "BACKEND", "SECRET", "EXPIRES", "STATUS"
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
            let id_short = if record.lease_id.len() > 18 {
                format!("{}...", &record.lease_id[..15])
            } else {
                record.lease_id.clone()
            };
            println!(
                "{:<20} {:<15} {:<20} {:<15} {:<8}",
                id_short, record.backend_name, record.secret_name, expires, status
            );
        }

        Ok(())
    }
}

impl LeaseRevokeCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let mut ledger = LeaseLedger::load()?;

        let record = ledger
            .find(&self.lease_id)
            .ok_or_else(|| FnoxError::Config(format!("Lease '{}' not found", self.lease_id)))?;

        if record.revoked {
            println!("Lease '{}' is already revoked.", self.lease_id);
            return Ok(());
        }

        let backend_name = record.backend_name.clone();
        let profile = Config::get_profile(cli.profile.as_deref());
        let leases = config.get_leases(&profile);

        if let Some(backend_config) = leases.get(&backend_name)
            && let Ok(backend) = backend_config.create_backend()
        {
            backend.revoke_lease(&self.lease_id).await?;
        }

        ledger.mark_revoked(&self.lease_id);
        ledger.save()?;
        println!("Lease '{}' revoked.", self.lease_id);

        Ok(())
    }
}

impl LeaseCleanupCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let mut ledger = LeaseLedger::load()?;
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
            let Some(backend_config) = leases.get(&record.backend_name) else {
                tracing::warn!(
                    "Lease backend '{}' not found for lease '{}', skipping",
                    record.backend_name,
                    record.lease_id
                );
                continue;
            };
            let backend = match backend_config.create_backend() {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        "Failed to create backend '{}' for lease '{}': {}",
                        record.backend_name,
                        record.lease_id,
                        e
                    );
                    continue;
                }
            };
            if let Err(e) = backend.revoke_lease(&record.lease_id).await {
                tracing::warn!("Failed to revoke lease '{}': {}", record.lease_id, e);
                continue;
            }
            ledger.mark_revoked(&record.lease_id);
            cleaned += 1;
        }

        ledger.save()?;
        println!("Cleaned up {} expired lease(s).", cleaned);

        Ok(())
    }
}

fn format_expiry(expires_at: Option<chrono::DateTime<chrono::Utc>>) -> String {
    match expires_at {
        Some(exp) => {
            let remaining = exp - Utc::now();
            if remaining.num_hours() > 0 {
                format!(
                    "in {}h{}m",
                    remaining.num_hours(),
                    remaining.num_minutes() % 60
                )
            } else {
                format!("in {}m", remaining.num_minutes())
            }
        }
        None => "never".to_string(),
    }
}

fn shell_escape(s: &str) -> String {
    if s.contains('\'') {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        format!("'{}'", s)
    }
}
