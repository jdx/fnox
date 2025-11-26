use crate::error::{FnoxError, Result};
use crate::secret_resolver::{handle_provider_error, resolve_if_missing_behavior, resolve_secret};
use crate::{commands::Cli, config::Config};
use clap::Args;

type MaskFn = Box<dyn Fn(&str, &str)>;

#[derive(Debug, Args)]
pub struct CiRedactCommand {}

impl CiRedactCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Redacting secrets from profile '{}'", profile);

        // Check if we're in CI and get the vendor
        let ci_info = ci_info::get();
        if !ci_info.ci {
            return Err(FnoxError::Config(
                "Not running in a CI environment. The ci-redact command is only for CI/CD pipelines.".to_string()
            ));
        }

        // Determine the masking format based on CI vendor
        let mask_fn: MaskFn = match ci_info.vendor {
            Some(ci_info::types::Vendor::GitHubActions) => {
                Box::new(|key: &str, value: &str| {
                    // GitHub Actions doesn't properly handle multiline secrets
                    // Warn the user instead of attempting to mask
                    if value.contains('\n') {
                        tracing::warn!(
                            "Secret '{}' contains newlines and cannot be fully redacted in CI logs. \
                            Consider using a secret manager or storing multiline secrets outside fnox config.",
                            key
                        );
                    } else {
                        println!("::add-mask::{}", value);
                    }
                })
            }
            Some(ci_info::types::Vendor::GitLabCI) => {
                // GitLab CI doesn't have a built-in mask command
                // Instead, you need to configure masked variables in the UI
                return Err(FnoxError::Config(
                    "GitLab CI does not support runtime secret masking. Configure masked variables in GitLab CI/CD settings.".to_string()
                ));
            }
            Some(ci_info::types::Vendor::CircleCI) => {
                // CircleCI doesn't have a built-in mask command
                return Err(FnoxError::Config(
                    "CircleCI does not support runtime secret masking. Use CircleCI context secrets or project environment variables.".to_string()
                ));
            }
            Some(ci_info::types::Vendor::Unknown) => {
                return Err(FnoxError::Config(
                    "Running in CI but vendor is unknown. Cannot determine masking format."
                        .to_string(),
                ));
            }
            Some(vendor) => {
                return Err(FnoxError::Config(format!(
                    "CI vendor '{:?}' does not have known secret masking support. Please configure secrets through your CI provider's settings.",
                    vendor
                )));
            }
            None => {
                return Err(FnoxError::Config(
                    "Running in CI but vendor is None. Cannot determine masking format."
                        .to_string(),
                ));
            }
        };

        // Get the profile secrets
        let profile_secrets = config.get_secrets(&profile)?;

        // Resolve and redact each secret
        for (key, secret_config) in &profile_secrets {
            match resolve_secret(&config, &profile, key, secret_config).await {
                Ok(Some(value)) => {
                    // Output CI-specific mask command
                    mask_fn(key, &value);
                }
                Ok(None) => {
                    // Secret not found, ignore based on if_missing setting
                }
                Err(e) => {
                    // Provider error - respect if_missing to decide whether to fail or continue
                    let if_missing = resolve_if_missing_behavior(secret_config, &config);

                    if let Some(error) = handle_provider_error(key, e, if_missing, false) {
                        return Err(error);
                    }
                }
            }
        }

        Ok(())
    }
}
