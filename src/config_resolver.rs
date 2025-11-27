//! Configuration value resolution for provider configs.
//!
//! This module handles resolving `ConfigValue` fields in provider configurations,
//! which may be either plain values or references to secrets.

use crate::config::{Config, ConfigValue, SecretConfig};
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers;

/// Resolve a ConfigValue to a plain string.
///
/// Resolution priority:
/// 1. Plain value - return immediately
/// 2. Secret reference:
///    a. Check environment variable with the secret name
///    b. Look up secret in config and resolve via provider
///
/// # Bootstrap Provider Requirement
///
/// Secrets used in provider configs must be stored using "bootstrap" providers -
/// providers that don't have secret references in their own config. This includes:
/// - `keychain` - uses OS-level authentication
/// - `age` - uses FNOX_AGE_KEY env var or key file path
/// - `password-store` - uses GPG
/// - `plain` - no authentication
///
/// If a secret references a non-bootstrap provider, an error is returned.
pub async fn resolve_config_value(
    value: &ConfigValue,
    config: &Config,
    profile: &str,
) -> Result<String> {
    match value {
        ConfigValue::Plain(s) => Ok(s.clone()),
        ConfigValue::SecretRef(secret_ref) => {
            resolve_secret_ref(&secret_ref.secret, config, profile).await
        }
    }
}

/// Resolve an optional ConfigValue.
pub async fn resolve_config_value_optional(
    value: &Option<ConfigValue>,
    config: &Config,
    profile: &str,
) -> Result<Option<String>> {
    match value {
        Some(v) => Ok(Some(resolve_config_value(v, config, profile).await?)),
        None => Ok(None),
    }
}

/// Resolve a secret reference by name.
///
/// Priority:
/// 1. Environment variable with the secret name
/// 2. Secret defined in config (resolved via its provider)
async fn resolve_secret_ref(secret_name: &str, config: &Config, profile: &str) -> Result<String> {
    // Priority 1: Check environment variable
    if let Ok(env_value) = env::var(secret_name) {
        tracing::debug!(
            "Resolved secret '{}' from environment variable",
            secret_name
        );
        return Ok(env_value);
    }

    // Priority 2: Look up secret in config
    let secrets = config.get_secrets(profile)?;
    let secret_config = secrets.get(secret_name).ok_or_else(|| {
        FnoxError::Config(format!(
            "Secret '{}' not found in config or environment. \
            Provider config secrets must be defined in [secrets] or available as environment variables.",
            secret_name
        ))
    })?;

    // Resolve the secret using its provider (must be a bootstrap provider)
    resolve_secret_for_provider_config(secret_name, secret_config, config, profile).await
}

/// Resolve a secret specifically for use in provider config.
///
/// This is a restricted version of secret resolution that only works with
/// bootstrap providers to avoid circular dependencies.
async fn resolve_secret_for_provider_config(
    secret_name: &str,
    secret_config: &SecretConfig,
    config: &Config,
    profile: &str,
) -> Result<String> {
    // Check if secret has a provider and value
    let Some(provider_value) = &secret_config.value else {
        // No provider value - check for default
        if let Some(default) = &secret_config.default {
            return Ok(default.clone());
        }
        return Err(FnoxError::Config(format!(
            "Secret '{}' has no value or default configured",
            secret_name
        )));
    };

    // Get the provider name
    let provider_name = if let Some(ref name) = secret_config.provider {
        name.clone()
    } else if let Some(default) = config.get_default_provider(profile)? {
        default
    } else {
        return Err(FnoxError::Config(format!(
            "Secret '{}' has no provider specified and no default provider configured",
            secret_name
        )));
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

    // Ensure this is a bootstrap provider (no secret refs in its config)
    if provider_config.has_secret_refs() {
        return Err(FnoxError::Config(format!(
            "Cannot resolve secret '{}': provider '{}' has secret references in its config. \
            Secrets used in provider configurations must use bootstrap providers \
            (keychain, age, password-store, plain) that don't have secret references.",
            secret_name, provider_name
        )));
    }

    // Create the provider using the simple (non-resolving) path
    let provider = providers::get_provider_simple(provider_config)?;

    // Resolve the secret
    let value = provider.get_secret(provider_value).await?;
    tracing::debug!(
        "Resolved secret '{}' from provider '{}'",
        secret_name,
        provider_name
    );
    Ok(value)
}
