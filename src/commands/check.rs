use crate::config::Config;
use crate::error::Result;
use crate::secret_resolver;
use clap::Args;

use crate::commands::Cli;

#[derive(Debug, Args)]
#[command(visible_alias = "c")]
pub struct CheckCommand {
    /// Check all secrets including those with if_missing=warn or if_missing=ignore
    #[arg(short = 'a', long)]
    all: bool,
}

impl CheckCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        config.validate()?;
        let profile = Config::get_profile(cli.profile.as_deref());

        // Load config
        println!("Checking configuration for profile: {}", profile);

        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        // Check secrets
        if let Ok(secrets) = config.get_secrets(&profile) {
            if secrets.is_empty() {
                warnings.push("No secrets defined in profile".to_string());
            } else {
                println!("Found {} secret(s) in profile", secrets.len());

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
                    if let Some(provider) = &secret_config.provider {
                        let providers = config.get_providers(&profile);
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

                            // Try to actually resolve the secret from the provider
                            match secret_resolver::resolve_secret(
                                &config,
                                &profile,
                                &name,
                                &secret_config,
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
            }
        } else {
            issues.push(format!("Profile '{}' not found", profile));
        }

        // Check providers
        let providers = config.get_providers(&profile);
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
