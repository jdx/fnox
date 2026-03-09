use crate::config::SecretConfig;
use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger};
use crate::secret_resolver::resolve_secret;
use crate::suggest::{find_similar, format_suggestions};
use crate::temp_file_secrets::create_persistent_secret_file;
use crate::{commands::Cli, config::Config};
use clap::Args;
use indexmap::IndexMap;

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
        if let Some((value, profile_secrets)) =
            self.resolve_from_lease(cli, &config, &profile).await?
        {
            let value = self.maybe_base64_decode(value)?;
            // Respect as_file from the profile secret config when present
            if let Some(sc) = profile_secrets.get(&self.key)
                && sc.as_file
            {
                let file_path = create_persistent_secret_file("fnox-", &self.key, &value)?;
                println!("{}", file_path);
                return Ok(());
            }
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
    /// If so, resolve the lease and return the credential value alongside
    /// the profile secrets map (to avoid a redundant `get_secrets` call).
    async fn resolve_from_lease(
        &self,
        cli: &Cli,
        config: &Config,
        profile: &str,
    ) -> Result<Option<(String, IndexMap<String, SecretConfig>)>> {
        let leases = config.get_leases(profile);

        // Fast path: check if any lease backend produces this key (pure config
        // lookup — no network calls or backend instantiation needed).
        // Use rfind to match exec's last-wins semantics when multiple leases
        // produce the same key.
        let matching_lease = leases
            .iter()
            .rfind(|(_, lease_config)| lease_config.produces_env_var(&self.key));

        let Some((name, lease_config)) = matching_lease else {
            return Ok(None);
        };

        let project_dir = lease::project_dir_from_config(config, &cli.config);
        let config_hash = lease_config.config_hash();

        // Cache-first fast path for plaintext cached entries: no secret
        // resolution or env injection needed, so we can return immediately.
        // Encrypted entries are deferred until after secret injection below,
        // since the encryption provider may need credentials from profile
        // secrets (e.g. VAULT_TOKEN stored as a secret).
        let cached_entry = {
            let _lock = LeaseLedger::lock(&project_dir)?;
            let ledger = LeaseLedger::load(&project_dir)?;
            lease::find_cached_entry(&ledger, name, &config_hash)
        };

        if let Some(ref entry) = cached_entry
            && entry.encryption_provider.is_none()
        {
            tracing::debug!(
                "Reusing cached plaintext lease '{}' for backend '{}'",
                entry.lease_id,
                name
            );
            let all_secrets = config.get_secrets(profile).unwrap_or_default();
            return self.extract_key_from_creds(name, entry.credentials.clone(), all_secrets);
        }

        // Resolve consumed secrets and inject them as env vars so that:
        // 1. The encryption provider can initialize (e.g. VAULT_TOKEN)
        // 2. The backend SDK can authenticate for fresh lease creation
        let mut consumed: std::collections::HashSet<&str> =
            lease_config.consumed_env_vars().iter().copied().collect();

        // Always include the default encryption provider's env deps so that
        // create_and_record_lease can encrypt cached credentials even on a cold
        // start (no cached_entry). Without this, the provider's credentials
        // (e.g. VAULT_TOKEN) would never be injected and encryption would fail
        // permanently, forcing a fresh API call on every invocation.
        if let Ok(Some(ref default_provider_name)) = config.get_default_provider(profile) {
            let providers_map = config.get_providers(profile);
            if let Some(provider_config) = providers_map.get(default_provider_name) {
                for dep in provider_config.env_dependencies() {
                    consumed.insert(dep);
                }
            }
        }

        // When consumed is empty the backend needs no profile secrets (e.g. it
        // authenticates via instance metadata). Avoid aborting on a transient
        // secrets-config read error that would be irrelevant in that case.
        let all_secrets = if consumed.is_empty() {
            config.get_secrets(profile).unwrap_or_default()
        } else {
            config.get_secrets(profile)?
        };
        let needed_secrets: indexmap::IndexMap<_, _> = all_secrets
            .iter()
            .filter(|(k, _)| consumed.contains(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let resolved_secrets =
            crate::secret_resolver::resolve_secrets_batch(config, profile, &needed_secrets).await?;

        let mut temp_env_guard = lease::TempEnvGuard::default();
        let _temp_files =
            lease::set_secrets_as_env(&resolved_secrets, &needed_secrets, &mut temp_env_guard)?;

        // Now that credentials are in the environment, attempt encrypted cache
        // decryption. This must happen after set_secrets_as_env so the
        // encryption provider (e.g. Vault) can find its credentials.
        // On failure, fall through to create a fresh lease — matching exec's
        // behaviour. create_and_record_lease handles encryption failure
        // gracefully by storing (None, None) for cached credentials.
        if let Some(entry) = cached_entry {
            // entry.encryption_provider is guaranteed Some here (plaintext
            // was handled above), so resolve_cached_entry will attempt decrypt.
            if let Some(creds) = lease::resolve_cached_entry(entry, config, profile, name).await {
                return self.extract_key_from_creds(name, creds, all_secrets.clone());
            }
        }

        // check_prerequisites is intentionally called after set_secrets_as_env:
        // profile secrets (e.g. AWS_ACCESS_KEY_ID) are already injected into the
        // process env, so prerequisites that are met via profile secrets will pass.
        // This matches exec.rs behaviour.
        let prereq_missing = lease_config.check_prerequisites();

        let creds = lease::resolve_lease(
            name,
            lease_config,
            config,
            profile,
            &project_dir,
            prereq_missing.as_deref(),
            "get",
        )
        .await?;

        self.extract_key_from_creds(name, creds, all_secrets)
    }

    fn extract_key_from_creds(
        &self,
        name: &str,
        creds: IndexMap<String, String>,
        all_secrets: IndexMap<String, SecretConfig>,
    ) -> Result<Option<(String, IndexMap<String, SecretConfig>)>> {
        match creds.get(&self.key) {
            Some(value) => Ok(Some((value.clone(), all_secrets))),
            None => Err(FnoxError::LeaseContractViolation {
                lease: name.to_string(),
                key: self.key.clone(),
            }),
        }
    }
}
