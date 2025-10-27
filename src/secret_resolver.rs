use crate::config::{Config, IfMissing, SecretConfig};
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::get_provider;
use crate::settings::Settings;

/// Resolves the if_missing behavior using the complete priority chain:
/// 1. CLI flag (--if-missing) via Settings
/// 2. Environment variable (FNOX_IF_MISSING) via Settings  
/// 3. Secret-level if_missing
/// 4. Top-level config if_missing
/// 5. Base default environment variable (FNOX_IF_MISSING_DEFAULT) via Settings
/// 6. Hard-coded default (warn)
pub fn resolve_if_missing_behavior(secret_config: &SecretConfig, config: &Config) -> IfMissing {
    Settings::try_get()
        .ok()
        .and_then(|s| {
            // CLI flag or FNOX_IF_MISSING env var (highest priority)
            s.if_missing
                .as_ref()
                .map(|value| match value.to_lowercase().as_str() {
                    "error" => IfMissing::Error,
                    "warn" => IfMissing::Warn,
                    "ignore" => IfMissing::Ignore,
                    _ => {
                        eprintln!(
                            "Warning: Invalid if_missing value '{}', using 'warn'",
                            value
                        );
                        IfMissing::Warn
                    }
                })
        })
        .or(secret_config.if_missing)
        .or(config.if_missing)
        .or_else(|| {
            // FNOX_IF_MISSING_DEFAULT fallback before hard-coded default
            Settings::try_get().ok().and_then(|s| {
                s.if_missing_default
                    .as_ref()
                    .map(|value| match value.to_lowercase().as_str() {
                        "error" => IfMissing::Error,
                        "warn" => IfMissing::Warn,
                        "ignore" => IfMissing::Ignore,
                        _ => {
                            eprintln!(
                                "Warning: Invalid FNOX_IF_MISSING_DEFAULT value '{}', using 'warn'",
                                value
                            );
                            IfMissing::Warn
                        }
                    })
            })
        })
        .unwrap_or(IfMissing::Warn)
}

/// Handles provider errors according to if_missing behavior.
/// Returns Some(err) if the error should be propagated, None if it should be ignored.
pub fn handle_provider_error(
    key: &str,
    error: FnoxError,
    if_missing: IfMissing,
    use_tracing: bool,
) -> Option<FnoxError> {
    match if_missing {
        IfMissing::Error => {
            if use_tracing {
                tracing::error!("Error resolving secret '{}': {}", key, error);
            } else {
                eprintln!("Error resolving secret '{}': {}", key, error);
            }
            Some(error)
        }
        IfMissing::Warn => {
            if use_tracing {
                tracing::warn!("Error resolving secret '{}': {}", key, error);
            } else {
                eprintln!("Warning: Error resolving secret '{}': {}", key, error);
            }
            None
        }
        IfMissing::Ignore => {
            // Silently skip
            None
        }
    }
}

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

    // No value found - handle based on if_missing with priority chain
    handle_missing_secret(key, secret_config, config)
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

fn handle_missing_secret(
    key: &str,
    secret_config: &SecretConfig,
    config: &Config,
) -> Result<Option<String>> {
    let if_missing = resolve_if_missing_behavior(secret_config, config);

    match if_missing {
        IfMissing::Error => Err(FnoxError::Config(format!(
            "Secret '{}' not found and no default provided",
            key
        ))),
        IfMissing::Warn => {
            eprintln!(
                "Warning: Secret '{}' not found and no default provided",
                key
            );
            Ok(None)
        }
        IfMissing::Ignore => Ok(None),
    }
}
