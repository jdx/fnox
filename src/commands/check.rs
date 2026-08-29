use crate::config::{Config, ProviderConfig, SecretConfig};
use crate::error::Result;
use crate::secret_resolver;
use indexmap::IndexMap;

use crate::commands::Cli;

#[derive(Debug, usage_rs::Args)]
#[usage(alias = "c")]
pub struct CheckCommand {
    /// Check all secrets including those with if_missing=warn or if_missing=ignore
    #[usage(short = 'a', long)]
    all: bool,
}

impl CheckCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
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
                let mut age_batches: IndexMap<String, IndexMap<String, SecretConfig>> =
                    IndexMap::new();

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
                    if let Some(provider) = secret_config.provider() {
                        if !providers.contains_key(provider) {
                            warnings.push(format!(
                                "Secret '{}' references unknown provider '{}'",
                                name, provider
                            ));
                        } else {
                            // Determine if we should check this secret
                            let if_missing = secret_resolver::resolve_if_missing_behavior(
                                &secret_config,
                                &config,
                            );

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

                            let resolution_provider = secret_config
                                .sync
                                .as_ref()
                                .map(|sync| sync.provider.as_str())
                                .unwrap_or(provider);
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
