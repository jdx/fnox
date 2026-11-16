use crate::config::{Config, ProviderConfig, SecretConfig};
use crate::error::Result;
use crate::secret_resolver;
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};

use crate::commands::Cli;

/// Verify that the active profile's secrets resolve, without printing them
///
/// Validates the config, then resolves each secret that uses a provider and
/// whose `if_missing` is `error`. References to unknown providers are reported
/// as well. Values are never printed.
///
/// Secrets without a provider are not resolved. One with no default is
/// reported only when its own `if_missing` is `error` or `warn`; `--if-missing`
/// and `FNOX_IF_MISSING` do not apply to it, so an environment-only secret that
/// is unset can still pass.
///
/// A provider whose own settings do not resolve, such as an `endpoint` that takes
/// its value from an unset secret, is reported whatever the secret's `if_missing`.
/// It is an error when the secret's `if_missing` is `error` and a warning
/// otherwise.
///
/// `--all` also resolves secrets whose `if_missing` is `warn` or `ignore`; their
/// failures are reported as warnings, or not at all for `ignore`. `--strict`
/// reports every warning as an error. Problems go to stderr, and fnox exits 1
/// when any error is found.
#[derive(Debug, usage_rs::Args)]
#[usage(alias = "c")]
#[usage(
    example(
        "fnox check --all",
        header = "Resolve every secret in the active profile"
    ),
    example(
        "fnox check --if-missing error",
        header = "Treat every provider-backed secret as required"
    ),
    example(
        "fnox check --strict",
        header = "Fail on warnings, such as a provider that cannot be configured"
    ),
    example("fnox -P production check --all", header = "Check another profile"),
    after_long_help = "See also:\n- Troubleshooting: https://fnox.jdx.dev/guide/troubleshooting\n- Missing secrets: https://fnox.jdx.dev/guide/missing-secrets"
)]
pub struct CheckCommand {
    /// Also resolve secrets whose `if_missing` is `warn` or `ignore`
    #[usage(short = 'a', long)]
    all: bool,

    /// Treat warnings as errors and exit 1
    #[usage(long)]
    strict: bool,
}

impl CheckCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        crate::providers::age::with_decrypt_scope(self.run_in_scope(cli, config)).await
    }

    async fn run_in_scope(&self, cli: &Cli, config: Config) -> Result<()> {
        config.validate()?;
        let profile = Config::get_profiles(cli.profile.as_slice());
        let profile_display = Config::display_profiles(&profile);

        // Load config
        println!("Checking configuration for profile(s): {}", profile_display);

        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        // Check secrets
        if let Ok(secrets) = config.get_secrets(&profile) {
            if secrets.is_empty() {
                warnings.push("No secrets defined in profile(s)".to_string());
            } else {
                println!("Found {} secret(s) in profile(s)", secrets.len());
                let providers = config.get_providers(&profile)?;
                // Looked up once, and only for a secret that needs it
                let mut default_provider: Option<std::result::Result<Option<String>, String>> =
                    None;
                let mut age_batches: IndexMap<String, IndexMap<String, SecretConfig>> =
                    IndexMap::new();
                // Whether each provider's own settings resolve, checked once per provider
                let mut provider_config_errors: HashMap<String, Option<String>> = HashMap::new();
                let mut reported_errors: HashSet<String> = HashSet::new();
                let mut reported_warnings: HashSet<String> = HashSet::new();

                for (name, secret_config) in secrets {
                    // Check if secret has a value source
                    if !secret_config.has_value() {
                        match secret_config.if_missing {
                            Some(crate::config::IfMissing::Error) => {
                                issues.push(format!(
                                    "Secret '{}' is required but has no value source",
                                    name
                                ));
                            }
                            Some(crate::config::IfMissing::Warn) => {
                                warnings.push(format!("Secret '{}' has no value source", name));
                            }
                            _ => {
                                // Ignore is fine
                            }
                        }
                    }

                    // Check provider configuration
                    //
                    // The provider is the one resolution uses: the secret's own, else
                    // the sync cache's, else the default provider for a secret that
                    // has a value.
                    let serving_provider = match secret_config.provider() {
                        Some(provider) => Some(provider.to_string()),
                        None => match secret_config.sync.as_ref() {
                            Some(sync) => Some(sync.provider.clone()),
                            None if secret_config.value().is_some() => {
                                match default_provider
                                    .get_or_insert_with(|| {
                                        config
                                            .get_default_provider(&profile)
                                            .map_err(|err| err.to_string())
                                    })
                                    .clone()
                                {
                                    Ok(provider) => provider,
                                    Err(error) => {
                                        // A required secret can't be served, so say why. For
                                        // the others, "No providers configured" below covers
                                        // the common cause and `--strict` reports it.
                                        let if_missing =
                                            secret_resolver::resolve_if_missing_behavior(
                                                &secret_config,
                                                &config,
                                            );
                                        if matches!(if_missing, crate::config::IfMissing::Error)
                                            && secret_config.default.is_none()
                                        {
                                            issues.push(format!(
                                                "Secret '{}' needs the default provider, which is not usable: {}",
                                                name, error
                                            ));
                                        }
                                        None
                                    }
                                }
                            }
                            None => None,
                        },
                    };
                    if let Some(provider) = serving_provider.as_deref() {
                        // Determine if we should check this secret
                        let if_missing =
                            secret_resolver::resolve_if_missing_behavior(&secret_config, &config);

                        if !providers.contains_key(provider) {
                            let message = format!(
                                "Secret '{}' references unknown provider '{}'",
                                name, provider
                            );
                            if matches!(if_missing, crate::config::IfMissing::Error) {
                                issues.push(message);
                            } else {
                                warnings.push(message);
                            }
                        } else {
                            let resolution_provider = secret_config
                                .sync
                                .as_ref()
                                .map(|sync| sync.provider.as_str())
                                .unwrap_or(provider);

                            // The sync provider serves the secret at run time, so a
                            // missing one is reported like a missing `provider`.
                            if !providers.contains_key(resolution_provider) {
                                let message = format!(
                                    "Secret '{}' references unknown sync provider '{}'",
                                    name, resolution_provider
                                );
                                if matches!(if_missing, crate::config::IfMissing::Error) {
                                    issues.push(message);
                                } else {
                                    warnings.push(message);
                                }
                                continue;
                            }

                            // A provider whose own settings don't resolve can't serve
                            // its secrets, so report it whatever their `if_missing` is
                            // and without relying on resolving the secret, which a
                            // `default` can satisfy. A required secret without a
                            // `default` reports the same failure when it resolves
                            // below, so it skips this check and the settings are only
                            // fetched once.
                            let reports_own_failure =
                                matches!(if_missing, crate::config::IfMissing::Error)
                                    && secret_config.default.is_none();
                            if !reports_own_failure
                                && let Some(resolution_config) = providers.get(resolution_provider)
                            {
                                if !provider_config_errors.contains_key(resolution_provider) {
                                    let error = crate::providers::resolve_provider_config(
                                        &config,
                                        &profile,
                                        resolution_provider,
                                        resolution_config,
                                    )
                                    .await
                                    .err()
                                    .map(|err| err.to_string());
                                    provider_config_errors
                                        .insert(resolution_provider.to_string(), error);
                                }
                                if let Some(error) = &provider_config_errors[resolution_provider] {
                                    let message = format!(
                                        "Provider '{}' could not be configured (used by secret '{}'): {}",
                                        resolution_provider, name, error
                                    );
                                    if matches!(if_missing, crate::config::IfMissing::Error) {
                                        if reported_errors.insert(resolution_provider.to_string()) {
                                            issues.push(message);
                                        }
                                    } else if reported_warnings
                                        .insert(resolution_provider.to_string())
                                    {
                                        warnings.push(message);
                                    }
                                    continue;
                                }
                            }

                            // Skip checking if not --all and if_missing is not Error
                            if !self.all
                                && matches!(
                                    if_missing,
                                    crate::config::IfMissing::Warn
                                        | crate::config::IfMissing::Ignore
                                )
                            {
                                continue;
                            }

                            let has_provider_value =
                                secret_config.sync.is_some() || secret_config.value().is_some();
                            if matches!(if_missing, crate::config::IfMissing::Error)
                                && secret_config.default.is_none()
                                && secret_config.json_path.is_none()
                                && secret_config.line.is_none()
                                && has_provider_value
                                && matches!(
                                    providers.get(resolution_provider),
                                    Some(ProviderConfig::AgeEncryption { .. })
                                )
                            {
                                age_batches
                                    .entry(resolution_provider.to_string())
                                    .or_default()
                                    .insert(name, secret_config);
                                continue;
                            }

                            // Try to actually resolve the secret from the provider
                            match crate::daemon::resolve_one(
                                cli,
                                &config,
                                &profile,
                                &name,
                                &secret_config,
                                crate::daemon::Purpose::Check,
                            )
                            .await
                            {
                                Ok(Some(_)) => {
                                    // Secret resolved successfully
                                }
                                Ok(None) => {
                                    // No value found, but that might be OK depending on if_missing
                                    match if_missing {
                                        crate::config::IfMissing::Error => {
                                            issues.push(format!(
                                                "Secret '{}' could not be resolved from provider '{}'",
                                                name, provider
                                            ));
                                        }
                                        crate::config::IfMissing::Warn => {
                                            warnings.push(format!(
                                                "Secret '{}' could not be resolved from provider '{}'",
                                                name, provider
                                            ));
                                        }
                                        crate::config::IfMissing::Ignore => {
                                            // Silently ignore
                                        }
                                    }
                                }
                                Err(err) => {
                                    // Error resolving secret
                                    match if_missing {
                                        crate::config::IfMissing::Error => {
                                            issues.push(format!(
                                                "Secret '{}' failed to resolve: {}",
                                                name, err
                                            ));
                                        }
                                        crate::config::IfMissing::Warn => {
                                            warnings.push(format!(
                                                "Secret '{}' failed to resolve: {}",
                                                name, err
                                            ));
                                        }
                                        crate::config::IfMissing::Ignore => {
                                            // Silently ignore
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                for (provider, batch) in age_batches {
                    let provider_secrets = batch
                        .iter()
                        .map(|(name, secret_config)| {
                            let value = secret_config
                                .sync
                                .as_ref()
                                .map(|sync| sync.value.clone())
                                .or_else(|| secret_config.value().map(ToOwned::to_owned))
                                .expect("batched secrets have a provider value");
                            (name.clone(), value)
                        })
                        .collect::<Vec<_>>();
                    let provider_config = providers
                        .get(&provider)
                        .expect("batched secrets use a configured age provider");
                    match crate::providers::get_provider_resolved(
                        &config,
                        &profile,
                        &provider,
                        provider_config,
                    )
                    .await
                    {
                        Ok(age_provider) => {
                            let mut values =
                                age_provider.get_secrets_batch(&provider_secrets).await;
                            for name in batch.keys() {
                                match values.remove(name) {
                                    Some(Ok(_)) => {}
                                    Some(Err(err)) => issues.push(format!(
                                        "Secret '{}' failed to resolve: {}",
                                        name, err
                                    )),
                                    None => issues.push(format!(
                                        "Secret '{}' could not be resolved from provider '{}'",
                                        name, provider
                                    )),
                                }
                            }
                        }
                        Err(err) => {
                            for name in batch.keys() {
                                issues
                                    .push(format!("Secret '{}' failed to resolve: {}", name, err));
                            }
                        }
                    }
                }
            }
        } else {
            issues.push(format!("Profile(s) '{}' not found", profile_display));
        }

        // Check providers
        let providers = config.get_providers(&profile)?;
        if providers.is_empty() {
            warnings.push("No providers configured".to_string());
        } else {
            println!("Found {} provider(s) in profile", providers.len());
        }

        if self.strict {
            issues.append(&mut warnings);
        }

        // Report results
        if !issues.is_empty() {
            eprintln!("Found {} error(s):", issues.len());
            for issue in &issues {
                eprintln!("  {}", issue);
            }
        }

        if !warnings.is_empty() {
            eprintln!("Found {} warning(s):", warnings.len());
            for warning in &warnings {
                eprintln!("  {}", warning);
            }
        }

        if issues.is_empty() && warnings.is_empty() {
            println!("✓ Configuration is healthy");
        } else if issues.is_empty() {
            println!("✓ Configuration is OK (with warnings)");
        }

        if !issues.is_empty() {
            std::process::exit(1);
        }

        Ok(())
    }
}
