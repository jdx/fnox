use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger};
use crate::secret_resolver::resolve_secret;
use crate::suggest::{find_similar, format_suggestions};
use crate::temp_file_secrets::create_persistent_secret_file;
use crate::{commands::Cli, config::Config};
use clap::Args;

#[derive(Debug, Args)]
pub struct GetCommand {
    /// Secret key to retrieve
    pub key: String,

    /// Base64 decode the secret
    #[arg(long)]
    pub base64_decode: bool,
}

impl GetCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Getting secret '{}' from profile '{}'", self.key, profile);

        // Validate the configuration first
        config.validate()?;

        // Check if the requested key is produced by a lease backend
        if let Some(value) = self.resolve_from_lease(cli, &config, &profile).await? {
            let value = self.maybe_base64_decode(value)?;
            println!("{}", value);
            return Ok(());
        }

        // Get the profile secrets
        let profile_secrets = config.get_secrets(&profile)?;

        // Get the secret config
        let secret_config = profile_secrets.get(&self.key).ok_or_else(|| {
            // Find similar secret names for suggestion
            let available_keys: Vec<_> = profile_secrets.keys().map(|s| s.as_str()).collect();
            let similar = find_similar(&self.key, available_keys);
            let suggestion = format_suggestions(&similar);

            FnoxError::SecretNotFound {
                key: self.key.clone(),
                profile: profile.clone(),
                config_path: config.secret_sources.get(&self.key).cloned(),
                suggestion,
            }
        })?;

        // Resolve the secret using centralized resolver
        match resolve_secret(&config, &profile, &self.key, secret_config).await {
            Ok(Some(value)) => {
                let value = self.maybe_base64_decode(value)?;

                // Check if this secret should be written to a file
                if secret_config.as_file {
                    let file_path = create_persistent_secret_file("fnox-", &self.key, &value)?;
                    println!("{}", file_path);
                } else {
                    println!("{}", value);
                }
                Ok(())
            }
            Ok(None) => {
                // Secret not found but if_missing allows it
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn maybe_base64_decode(&self, value: String) -> Result<String> {
        if self.base64_decode {
            let decoded_bytes = data_encoding::BASE64
                .decode(value.as_bytes())
                .map_err(|e| FnoxError::SecretDecodeFailed {
                    details: format!("Failed to base64 decode secret: {}", e),
                })?;
            Ok(str::from_utf8(&decoded_bytes)
                .map_err(|e| FnoxError::SecretDecodeFailed {
                    details: format!("decoded secret is not valid UTF-8: {}", e),
                })?
                .to_string())
        } else {
            Ok(value)
        }
    }

    /// Check if the requested key is produced by a lease backend.
    /// If so, resolve the lease and return the credential value.
    async fn resolve_from_lease(
        &self,
        cli: &Cli,
        config: &Config,
        profile: &str,
    ) -> Result<Option<String>> {
        let leases = config.get_leases(profile);

        // Fast path: check if any lease backend produces this key (pure config
        // lookup — no network calls or backend instantiation needed).
        let matching_lease = leases
            .iter()
            .find(|(_, lease_config)| lease_config.produced_env_vars().contains(&self.key));

        let Some((name, lease_config)) = matching_lease else {
            return Ok(None);
        };

        // Only resolve the secrets the lease backend actually needs (e.g.
        // CLOUDFLARE_API_TOKEN, VAULT_ADDR) rather than all profile secrets.
        // This avoids spurious failures from unrelated unreachable secrets.
        let required: std::collections::HashSet<&str> = lease_config
            .required_env_vars()
            .iter()
            .map(|(k, _)| *k)
            .collect();
        let all_secrets = config.get_secrets(profile)?;
        let needed_secrets: indexmap::IndexMap<_, _> = all_secrets
            .iter()
            .filter(|(k, _)| required.contains(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let resolved_secrets =
            crate::secret_resolver::resolve_secrets_batch(config, profile, &needed_secrets).await?;
        let mut temp_env_guard = lease::TempEnvGuard::default();
        let _temp_files =
            lease::set_secrets_as_env(&resolved_secrets, &needed_secrets, &mut temp_env_guard)?;

        let project_dir = lease::project_dir_from_config(config, &cli.config);
        let _ledger_lock = LeaseLedger::lock(&project_dir)?;
        let mut ledger = LeaseLedger::load(&project_dir)?;

        let prereq_missing = lease_config.check_prerequisites();
        if let Some(ref missing) = prereq_missing {
            let config_hash = lease_config.config_hash();
            if ledger
                .find_reusable(name, &config_hash)
                .and_then(|c| c.cached_credentials.as_ref())
                .is_none()
            {
                return Err(FnoxError::Config(format!(
                    "Lease '{}': {}\nRun 'fnox lease create -i {}' to set up credentials interactively.",
                    name, missing, name
                )));
            }
        }

        let creds = lease::resolve_lease(
            name,
            lease_config,
            config,
            profile,
            &project_dir,
            &mut ledger,
            prereq_missing.as_deref(),
            "get",
        )
        .await?;

        Ok(creds.get(&self.key).cloned())
    }
}
