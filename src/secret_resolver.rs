use crate::auth_prompt::prompt_and_run_auth;
use crate::config::{Config, IfMissing, SecretConfig};
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::{ProviderConfig, get_provider_resolved};
use crate::settings::Settings;
use indexmap::IndexMap;
use std::collections::HashMap; // Used only for internal grouping by provider

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
) -> Result<Option<String>> {
    // Priority 1: Provider (if specified and has a value)
    if let Some(value) = try_resolve_from_provider(config, profile, secret_config).await? {
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

    // Try to resolve the secret, with auth retry on failure
    try_resolve_with_auth_retry(
        config,
        profile,
        &provider_name,
        provider_config,
        provider_value,
    )
    .await
}

/// Attempts to resolve a secret from a provider, with optional auth retry.
/// If the initial attempt fails and we're in a TTY with auth prompting enabled,
/// prompts the user to run the auth command and retries once.
async fn try_resolve_with_auth_retry(
    config: &Config,
    profile: &str,
    provider_name: &str,
    provider_config: &ProviderConfig,
    provider_value: &str,
) -> Result<Option<String>> {
    // Initial secret retrieval attempt before any authentication retry logic
    match try_get_secret(
        config,
        profile,
        provider_name,
        provider_config,
        provider_value,
    )
    .await
    {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            // Try auth prompt and retry
            if prompt_and_run_auth(config, provider_config, provider_name, &error)? {
                // Auth command ran successfully, retry
                try_get_secret(
                    config,
                    profile,
                    provider_name,
                    provider_config,
                    provider_value,
                )
                .await
                .map(Some)
            } else {
                // No auth prompt or user declined
                Err(error)
            }
        }
    }
}

/// Helper to get a single secret from a provider without auth retry logic.
/// Creates the provider instance and calls `get_secret`.
async fn try_get_secret(
    config: &Config,
    profile: &str,
    provider_name: &str,
    provider_config: &ProviderConfig,
    provider_value: &str,
) -> Result<String> {
    let provider = get_provider_resolved(config, profile, provider_name, provider_config).await?;
    provider.get_secret(provider_value).await
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

/// Resolves multiple secrets efficiently using batch operations when possible.
///
/// This groups secrets by provider and uses `get_secrets_batch` to minimize
/// external API calls. Providers are processed in parallel for maximum efficiency.
///
/// Returns an error immediately if any secret with `if_missing = "error"` fails to resolve.
pub async fn resolve_secrets_batch(
    config: &Config,
    profile: &str,
    secrets: &IndexMap<String, SecretConfig>,
) -> Result<IndexMap<String, Option<String>>> {
    use futures::stream::{self, StreamExt};

    // Group secrets by provider
    let mut by_provider: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut no_provider = Vec::new();

    for (key, secret_config) in secrets {
        // Check if we can resolve from provider
        if let Some(ref provider_value) = secret_config.value {
            // Determine which provider to use
            let provider_name = if let Some(ref provider_name) = secret_config.provider {
                provider_name.clone()
            } else if let Ok(Some(default_provider)) = config.get_default_provider(profile) {
                default_provider
            } else {
                // No provider, fall back to individual resolution
                no_provider.push(key.clone());
                continue;
            };

            by_provider
                .entry(provider_name)
                .or_default()
                .push((key.clone(), provider_value.clone()));
        } else {
            // No value for provider, use individual resolution
            no_provider.push(key.clone());
        }
    }

    // Resolve secrets grouped by provider in parallel
    let provider_results: Vec<_> = stream::iter(by_provider)
        .map(|(provider_name, provider_secrets)| async move {
            resolve_provider_batch(config, profile, secrets, &provider_name, provider_secrets).await
        })
        .buffer_unordered(10)
        .collect()
        .await;

    // Combine results from all providers into a temporary HashMap, failing fast on errors
    let mut temp_results = HashMap::new();
    for provider_result in provider_results {
        temp_results.extend(provider_result?);
    }

    // Resolve secrets that couldn't be batched using individual resolution in parallel
    let no_provider_results: Vec<_> = stream::iter(no_provider)
        .map(|key| async move {
            let secret_config = &secrets[&key];
            match resolve_secret(config, profile, &key, secret_config).await {
                Ok(value) => Ok((key, value)),
                Err(e) => {
                    let if_missing = resolve_if_missing_behavior(secret_config, config);
                    if let Some(error) = handle_provider_error(&key, e, if_missing, true) {
                        // Error should fail fast - return the error
                        Err(error)
                    } else {
                        // Warn or ignore - continue with None
                        Ok((key, None))
                    }
                }
            }
        })
        .buffer_unordered(10)
        .collect()
        .await;

    // Add no-provider results to temporary HashMap, failing fast on errors
    for result in no_provider_results {
        let (key, value) = result?;
        temp_results.insert(key, value);
    }

    // Build final results in the original order from the input secrets IndexMap
    let mut results = IndexMap::new();
    for (key, _secret_config) in secrets {
        if let Some(value) = temp_results.remove(key) {
            results.insert(key.clone(), value);
        }
    }

    Ok(results)
}

/// Resolve all secrets for a single provider using batch operations
async fn resolve_provider_batch(
    config: &Config,
    profile: &str,
    secrets: &IndexMap<String, SecretConfig>,
    provider_name: &str,
    provider_secrets: Vec<(String, String)>,
) -> Result<HashMap<String, Option<String>>> {
    let mut results = HashMap::new();

    tracing::debug!(
        "Resolving {} secrets from provider '{}' using batch",
        provider_secrets.len(),
        provider_name
    );

    // Get the provider config
    let providers = config.get_providers(profile);
    let provider_config = match providers.get(provider_name) {
        Some(config) => config,
        None => {
            // Provider not configured, handle errors for all secrets
            for (key, _) in &provider_secrets {
                let secret_config = &secrets[key];
                let if_missing = resolve_if_missing_behavior(secret_config, config);
                let error = FnoxError::ProviderNotConfigured {
                    provider: provider_name.to_string(),
                    profile: profile.to_string(),
                    config_path: config.provider_sources.get(provider_name).cloned(),
                };
                if let Some(error) = handle_provider_error(key, error, if_missing, true) {
                    // Fail fast if if_missing is error
                    return Err(error);
                }
                results.insert(key.clone(), None);
            }
            return Ok(results);
        }
    };

    // Try to get secrets with auth retry on failure
    try_batch_with_auth_retry(
        config,
        profile,
        secrets,
        provider_name,
        provider_config,
        &provider_secrets,
        &mut results,
    )
    .await
}

/// Attempts to resolve secrets in batch with optional auth retry.
/// If the initial attempt fails and we're in a TTY with auth prompting enabled,
/// prompts the user to run the auth command and retries once.
async fn try_batch_with_auth_retry(
    config: &Config,
    profile: &str,
    secrets: &IndexMap<String, SecretConfig>,
    provider_name: &str,
    provider_config: &ProviderConfig,
    provider_secrets: &[(String, String)],
    results: &mut HashMap<String, Option<String>>,
) -> Result<HashMap<String, Option<String>>> {
    // Initial batch secret retrieval attempt before any authentication retry logic
    match try_get_secrets_batch(
        config,
        profile,
        provider_name,
        provider_config,
        provider_secrets,
    )
    .await
    {
        Ok(batch_results) => {
            process_batch_results(secrets, config, batch_results, results)?;
            Ok(std::mem::take(results))
        }
        Err(error) => {
            // Try auth prompt and retry
            if prompt_and_run_auth(config, provider_config, provider_name, &error)? {
                // Auth command ran successfully, retry
                match try_get_secrets_batch(
                    config,
                    profile,
                    provider_name,
                    provider_config,
                    provider_secrets,
                )
                .await
                {
                    Ok(batch_results) => {
                        process_batch_results(secrets, config, batch_results, results)?;
                        Ok(std::mem::take(results))
                    }
                    Err(retry_error) => Err(retry_error),
                }
            } else {
                // No auth prompt or user declined - apply if_missing handling per secret
                handle_batch_error(secrets, config, provider_secrets, &error, results)
            }
        }
    }
}

/// Handle a batch error by applying if_missing logic to each secret
fn handle_batch_error(
    secrets: &IndexMap<String, SecretConfig>,
    config: &Config,
    provider_secrets: &[(String, String)],
    error: &FnoxError,
    results: &mut HashMap<String, Option<String>>,
) -> Result<HashMap<String, Option<String>>> {
    for (key, _) in provider_secrets {
        let secret_config = &secrets[key];
        let if_missing = resolve_if_missing_behavior(secret_config, config);
        let provider_error = FnoxError::Provider(error.to_string());
        if let Some(err) = handle_provider_error(key, provider_error, if_missing, true) {
            // Fail fast if if_missing is error
            return Err(err);
        }
        results.insert(key.clone(), None);
    }
    Ok(std::mem::take(results))
}

/// Helper to get multiple secrets in batch from a provider without auth retry logic.
/// Creates the provider instance and calls `get_secrets_batch` on it.
async fn try_get_secrets_batch(
    config: &Config,
    profile: &str,
    provider_name: &str,
    provider_config: &ProviderConfig,
    provider_secrets: &[(String, String)],
) -> Result<HashMap<String, Result<String>>> {
    let provider = get_provider_resolved(config, profile, provider_name, provider_config).await?;
    Ok(provider.get_secrets_batch(provider_secrets).await)
}

/// Process batch results and populate the results map
fn process_batch_results(
    secrets: &IndexMap<String, SecretConfig>,
    config: &Config,
    batch_results: HashMap<String, Result<String>>,
    results: &mut HashMap<String, Option<String>>,
) -> Result<()> {
    for (key, result) in batch_results {
        let secret_config = &secrets[&key];
        match result {
            Ok(value) => {
                results.insert(key, Some(value));
            }
            Err(e) => {
                let if_missing = resolve_if_missing_behavior(secret_config, config);
                if let Some(error) = handle_provider_error(&key, e, if_missing, true) {
                    // Fail fast if if_missing is error
                    return Err(error);
                }
                results.insert(key, None);
            }
        }
    }
    Ok(())
}
