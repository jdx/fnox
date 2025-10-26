use crate::config::{Config, IfMissing, SecretConfig};
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::get_provider;

/// Resolves a secret value using the correct priority order:
/// 1. Provider (if specified)
/// 2. Default value (if specified)
/// 3. Environment variable
///
/// The raw `value` field is NEVER used directly - it's only used as input to providers.
pub async fn resolve_secret(
    config: &Config,
    profile: &str,
    key: &str,
    secret_config: &SecretConfig,
    age_key_file: Option<&std::path::Path>,
) -> Result<Option<String>> {
    // Priority 1: Provider (if specified and has a value)
    if let Some(value) =
        try_resolve_from_provider(config, profile, secret_config, age_key_file).await?
    {
        return Ok(Some(value));
    }

    // Priority 2: Default value
    if let Some(default) = &secret_config.default {
        tracing::debug!("Using default value for secret '{}'", key);
        return Ok(Some(default.clone()));
    }

    // Priority 3: Environment variable
    if let Ok(env_value) = env::var(key) {
        tracing::debug!("Found secret '{}' in current environment", key);
        return Ok(Some(env_value));
    }

    // No value found - handle based on if_missing
    handle_missing_secret(key, secret_config)
}

async fn try_resolve_from_provider(
    config: &Config,
    profile: &str,
    secret_config: &SecretConfig,
    age_key_file: Option<&std::path::Path>,
) -> Result<Option<String>> {
    // Only try provider if we have a value to pass to it
    let Some(provider_value) = &secret_config.value else {
        return Ok(None);
    };

    // Determine which provider to use
    let provider_name = if let Some(ref provider_name) = secret_config.provider {
        // Explicit provider specified
        provider_name.clone()
    } else if let Some(default_provider) = config.get_default_provider(profile)? {
        // Use default provider
        default_provider
    } else {
        // No provider configured, can't resolve
        return Ok(None);
    };

    // Get the provider config
    let providers = config.get_providers(profile);
    let provider_config =
        providers
            .get(&provider_name)
            .ok_or_else(|| FnoxError::ProviderNotConfigured {
                provider: provider_name.clone(),
                profile: profile.to_string(),
                config_path: config.provider_sources.get(&provider_name).cloned(),
            })?;

    // Resolve from provider
    let provider = get_provider(provider_config)?;
    let value = provider.get_secret(provider_value, age_key_file).await?;
    Ok(Some(value))
}

fn handle_missing_secret(key: &str, secret_config: &SecretConfig) -> Result<Option<String>> {
    match secret_config.if_missing {
        Some(IfMissing::Error) => Err(FnoxError::Config(format!(
            "Secret '{}' not found and no default provided",
            key
        ))),
        Some(IfMissing::Warn) | None => {
            // Default to warn when if_missing is not specified
            eprintln!(
                "Warning: Secret '{}' not found and no default provided",
                key
            );
            Ok(None)
        }
        Some(IfMissing::Ignore) => Ok(None),
    }
}
