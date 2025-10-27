use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secret;
use crate::{
    commands::Cli,
    config::{Config, IfMissing},
};
use clap::Args;

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
        let mask_fn: Box<dyn Fn(&str)> = match ci_info.vendor {
            Some(ci_info::types::Vendor::GitHubActions) => {
                Box::new(|value: &str| println!("::add-mask::{}", value))
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

        if profile_secrets.is_empty() && profile != "default" {
            let available_profiles = config.list_profiles();
            return Err(FnoxError::ProfileNotFound {
                profile: profile.clone(),
                available_profiles,
            });
        }

        // Resolve and redact each secret
        for (key, secret_config) in &profile_secrets {
            match resolve_secret(
                &config,
                &profile,
                key,
                secret_config,
                cli.age_key_file.as_deref(),
            )
            .await
            {
                Ok(Some(value)) => {
                    // Output CI-specific mask command
                    mask_fn(&value);
                }
                Ok(None) => {
                    // Secret not found, ignore based on if_missing setting
                }
                Err(e) => {
                    eprintln!("Error resolving secret '{}': {}", key, e);
                    if matches!(secret_config.if_missing, Some(IfMissing::Error) | None) {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }
}
