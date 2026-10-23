use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger, LeaseRecord, TempEnvGuard};
use crate::secret_resolver::resolve_secrets_batch;
use chrono::Utc;
use indexmap::IndexMap;
use strum::EnumString;

/// Create and manage short-lived credentials from lease backends
///
/// Lease backends, defined under `[leases.<name>]`, mint temporary credentials
/// such as AWS STS sessions or Vault tokens. `fnox exec` creates or reuses
/// leases automatically; these commands manage them by hand. fnox records each
/// lease in a per-project ledger. Without a subcommand, `fnox lease` creates
/// leases for every configured backend.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox lease list --active", header = "List active leases"),
    example(
        "fnox exec -- aws s3 ls",
        header = "Let fnox exec create or reuse a lease"
    ),
    after_long_help = "See also:\n- Credential leases: https://fnox.jdx.dev/guide/leases"
)]
pub struct LeaseCommand {
    #[usage(subcommand)]
    pub subcommand: Option<LeaseSubcommand>,
}

#[derive(Debug, usage_rs::Subcommands)]
pub enum LeaseSubcommand {
    Cleanup(LeaseCleanupCommand),
    Create(LeaseCreateCommand),
    List(LeaseListCommand),
    Revoke(LeaseRevokeCommand),
}

#[derive(Debug, Clone, usage_rs::ValueEnum, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum OutputFormat {
    /// Summary with masked credential values
    Shell,
    /// JSON object with the credentials, `lease_id`, and `expires_at`
    Json,
    /// `export KEY=value` lines with the real credentials
    Env,
}

/// Create short-lived credentials from a lease backend
///
/// Creates a lease from BACKEND_NAME, or from every configured backend when you
/// omit it, records it in the project's lease ledger, and prints the
/// credentials. The default `shell` format shows a summary with masked values;
/// `json` and `env` print the real credentials, so keep that output out of logs.
///
/// The lease lasts for `--duration`, else the backend's `duration` setting,
/// else 15 minutes, and cannot exceed the backend's maximum.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example(
        "fnox lease create aws --duration 30m",
        header = "Create a 30-minute lease"
    ),
    example(
        "eval \"$(fnox lease create aws --format env)\"",
        header = "Export the credentials into the current shell"
    ),
    example(
        "fnox lease create aws --interactive",
        header = "Prompt for missing backend credentials"
    ),
    after_long_help = "See also:\n- Credential leases: https://fnox.jdx.dev/guide/leases"
)]
pub struct LeaseCreateCommand {
    /// Lease backend from `[leases.<name>]` (default: every configured backend)
    pub backend_name: Option<String>,

    /// Create leases for every configured backend
    #[usage(short, long)]
    pub all: bool,

    /// Lease length, such as `15m`, `1h`, or `2h30m`; overrides the backend's
    /// `duration`
    #[usage(short, long)]
    pub duration: Option<String>,

    /// Output format
    #[usage(short, long, default = "shell", value_enum)]
    pub format: OutputFormat,

    /// Prompt for backend credentials that are missing from the environment
    #[usage(short, long)]
    pub interactive: bool,

    /// Label recorded with the lease, such as its purpose
    #[usage(short, long, default = "fnox-lease")]
    pub label: String,
}

/// List leases recorded for this project
///
/// Prints the ID, backend, label, expiry, and status (`active`, `expired`, or
/// `revoked`) of each lease in the project's ledger. Long IDs are shortened in
/// the table; `fnox lease revoke` accepts the shortened form as a prefix, and
/// `--json` prints full IDs. The ledger tracks leases fnox created; it is not an
/// inventory of credentials at the provider.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox lease list", header = "List every recorded lease"),
    example(
        "fnox lease list --active",
        header = "List leases that are still valid"
    ),
    example(
        "fnox lease list --json",
        header = "Print full lease IDs and metadata as JSON"
    ),
    after_long_help = "See also:\n- Credential leases: https://fnox.jdx.dev/guide/leases"
)]
pub struct LeaseListCommand {
    /// Show only leases that have not expired or been revoked
    #[usage(long)]
    pub active: bool,

    /// Show only expired leases
    #[usage(long)]
    pub expired: bool,

    /// Print leases as a JSON array with full IDs, labels, and timestamps;
    /// cached credentials are never included
    #[usage(long)]
    pub json: bool,
}

/// Revoke leases by ID, ID prefix, or backend
///
/// Asks the lease backend to revoke each matching lease, then marks it revoked
/// in the project's ledger. If the backend cannot revoke a lease, for example
/// because its credentials only expire on their own, fnox warns and revokes
/// only the ledger entry.
///
/// TARGET is a lease ID, a unique prefix of one (as shown by `fnox lease list`),
/// or a backend name from `[leases.<name>]`, which revokes every active lease of
/// that backend. Use `--all` to revoke every active lease in the project.
/// Expired leases are handled by `fnox lease cleanup`.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox lease revoke LEASE_ID", header = "Revoke a lease"),
    example(
        "fnox lease revoke aws-1a2b3c",
        header = "Revoke a lease by a unique ID prefix"
    ),
    example(
        "fnox lease revoke aws",
        header = "Revoke every active lease of the aws backend"
    ),
    example("fnox lease revoke --all", header = "Revoke every active lease"),
    after_long_help = "See also:\n- Credential leases: https://fnox.jdx.dev/guide/leases"
)]
pub struct LeaseRevokeCommand {
    /// Lease ID, unique ID prefix, or backend name
    pub target: Option<String>,

    /// Revoke every active lease in this project
    #[usage(short, long)]
    pub all: bool,
}

/// Revoke expired leases and mark them revoked in the ledger
///
/// For each expired lease in the project's ledger that is not yet marked
/// revoked, asks its backend to revoke it and then marks it revoked. A backend
/// failure is logged and the entry is still marked. Backends may need their
/// credentials and network access.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox lease cleanup", header = "Clean up expired leases"),
    after_long_help = "See also:\n- Credential leases: https://fnox.jdx.dev/guide/leases"
)]
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
        if self.all && self.backend_name.is_some() {
            return Err(FnoxError::Config(
                "--all cannot be used with a lease backend name".to_string(),
            ));
        }
        let profile = Config::get_profiles(cli.profile.as_slice());
        let project_dir = lease::project_dir_from_config(&config, &cli.config);
        let leases = config.get_leases(&profile)?;

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
        profile: &[String],
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
        profile: &[String],
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

fn lease_status(record: &LeaseRecord) -> &'static str {
    if record.revoked {
        "revoked"
    } else if record.expires_at.is_some_and(|exp| exp <= Utc::now()) {
        "expired"
    } else {
        "active"
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

        if self.json {
            let entries: Vec<serde_json::Value> = records
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "lease_id": r.lease_id,
                        "backend": r.backend_name,
                        "label": r.label,
                        "status": lease_status(r),
                        "created_at": r.created_at.to_rfc3339(),
                        "expires_at": r.expires_at.map(|exp| exp.to_rfc3339()),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&entries)
                    .map_err(|e| FnoxError::Json { source: e })?
            );
            return Ok(());
        }

        if records.is_empty() {
            println!("No leases found.");
            return Ok(());
        }

        println!(
            "{:<20} {:<15} {:<20} {:<16} {:<8}",
            "LEASE ID", "BACKEND", "LABEL", "EXPIRES", "STATUS"
        );
        for record in records {
            let expires = record
                .expires_at
                .map(|exp: chrono::DateTime<chrono::Utc>| exp.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "never".to_string());
            println!(
                "{:<20} {:<15} {:<20} {:<16} {:<8}",
                shorten(&record.lease_id, 18),
                record.backend_name,
                shorten(&record.label, 20),
                expires,
                lease_status(record)
            );
        }

        Ok(())
    }
}

/// Shorten `value` to at most `max` characters, ending in `...` when cut.
/// `LeaseRevokeCommand` strips that suffix, so the shortened form works as a prefix.
fn shorten(value: &str, max: usize) -> String {
    if value.chars().count() > max {
        let truncated: String = value.chars().take(max - 3).collect();
        format!("{truncated}...")
    } else {
        value.to_string()
    }
}

impl LeaseRevokeCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        match (&self.target, self.all) {
            (Some(_), true) => {
                return Err(FnoxError::Config(
                    "--all cannot be used with a lease ID or backend name".to_string(),
                ));
            }
            (None, false) => {
                return Err(FnoxError::Config(
                    "Specify a lease ID, ID prefix, or backend name to revoke, or use --all"
                        .to_string(),
                ));
            }
            _ => {}
        }

        let project_dir = lease::project_dir_from_config(&config, &cli.config);
        let _ledger_lock = LeaseLedger::lock(&project_dir)?;
        let mut ledger = LeaseLedger::load(&project_dir)?;
        let profile = Config::get_profiles(cli.profile.as_slice());
        let leases = config.get_leases(&profile)?;

        // Records are addressed by ledger position: lease IDs are not
        // guaranteed unique, so marking by ID could revoke the wrong entry.
        let selected: Vec<usize> = match &self.target {
            None => Self::active_indices(&ledger, |_| true),
            Some(target) => {
                Self::resolve_target(&ledger, target, leases.contains_key(target.as_str()))?
            }
        };

        if selected.is_empty() {
            println!("No active leases to revoke.");
            return Ok(());
        }

        let mut revoked = 0;
        for &index in &selected {
            let record = ledger.leases[index].clone();
            if record.revoked {
                println!("Lease '{}' is already revoked.", record.lease_id);
                continue;
            }
            Self::revoke_record(&config, &profile, &leases, &record).await;
            ledger.mark_revoked_at(index);
            // Save after each lease so a later failure or interrupt doesn't
            // forget that the backend already revoked this one.
            ledger.save(&project_dir)?;
            println!("Lease '{}' revoked.", record.lease_id);
            revoked += 1;
        }
        if selected.len() > 1 {
            println!("Revoked {revoked} lease(s).");
        }

        Ok(())
    }

    /// Ledger positions of active (non-revoked, non-expired) records matching `filter`.
    fn active_indices(ledger: &LeaseLedger, filter: impl Fn(&LeaseRecord) -> bool) -> Vec<usize> {
        let now = Utc::now();
        ledger
            .leases
            .iter()
            .enumerate()
            .filter(|(_, r)| !r.revoked && r.expires_at.is_none_or(|exp| exp > now) && filter(r))
            .map(|(i, _)| i)
            .collect()
    }

    /// Match `target` against the ledger and return the positions of the
    /// records to revoke: every record with that exact lease ID, then a backend
    /// name (active leases only), then a unique ID prefix.
    fn resolve_target(
        ledger: &LeaseLedger,
        target: &str,
        configured_backend: bool,
    ) -> Result<Vec<usize>> {
        let with_id = |id: &str| -> Vec<usize> {
            ledger
                .leases
                .iter()
                .enumerate()
                .filter(|(_, r)| r.lease_id == id)
                .map(|(i, _)| i)
                .collect()
        };

        let exact = with_id(target);
        if !exact.is_empty() {
            return Ok(exact);
        }

        let known_backend =
            configured_backend || ledger.leases.iter().any(|r| r.backend_name == target);
        if known_backend {
            return Ok(Self::active_indices(ledger, |r| r.backend_name == target));
        }

        // `lease list` shortens IDs with a trailing "...", so accept that form.
        let prefix = target.trim_end_matches("...");
        let mut ids: Vec<&str> = Vec::new();
        if !prefix.is_empty() {
            for r in &ledger.leases {
                if r.lease_id.starts_with(prefix) && !ids.contains(&r.lease_id.as_str()) {
                    ids.push(&r.lease_id);
                }
            }
        }
        match ids.as_slice() {
            [] => Err(FnoxError::Config(format!(
                "Lease '{target}' not found. Use a lease ID or unique prefix from `fnox lease list`, or a backend name."
            ))),
            [id] => Ok(with_id(id)),
            many => Err(FnoxError::Config(format!(
                "'{target}' matches {} leases; use a longer prefix or the full ID:\n{}",
                many.len(),
                many.iter()
                    .map(|id| format!("  {id}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))),
        }
    }

    /// Ask the backend to revoke `record`. Failures are reported as warnings;
    /// the caller still marks the ledger entry revoked.
    async fn revoke_record(
        config: &Config,
        profile: &[String],
        leases: &IndexMap<String, crate::lease_backends::LeaseBackendConfig>,
        record: &LeaseRecord,
    ) {
        // Decrypt cached credentials (if encrypted) so backends can use
        // credential values for revocation (e.g. GitHub App needs the token).
        let decrypted_credentials = match (&record.cached_credentials, &record.encryption_provider)
        {
            (Some(creds), Some(enc_name)) => {
                match lease::find_encryption_provider(config, profile).await {
                    lease::EncryptionProviderResult::Available(found_name, provider)
                        if found_name == *enc_name =>
                    {
                        match crate::providers::age::with_decrypt_scope(lease::decrypt_credentials(
                            provider.as_ref(),
                            creds,
                        ))
                        .await
                        {
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

        let backend_name = &record.backend_name;
        if let Some(backend_config) = leases.get(backend_name) {
            match backend_config.create_backend() {
                Ok(backend) => {
                    if let Err(e) = backend
                        .revoke_lease(&record.lease_id, decrypted_credentials.as_ref())
                        .await
                    {
                        tracing::warn!(
                            "Backend revocation failed for '{}': {}",
                            record.lease_id,
                            e
                        );
                        eprintln!(
                            "Warning: backend revocation failed for '{}'; only the local ledger entry will be revoked.",
                            record.lease_id
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

        let profile = Config::get_profiles(cli.profile.as_slice());
        let leases = config.get_leases(&profile)?;
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
