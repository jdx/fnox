use crate::auth_prompt::prompt_and_run_auth;
use crate::config::{Config, IfMissing, SecretConfig};
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::{ProviderConfig, get_provider_resolved};
use crate::settings::Settings;
use crate::source_registry;
use crate::suggest::{find_similar, format_suggestions};
use indexmap::IndexMap;
use miette::SourceSpan;
use std::collections::{HashMap, HashSet};

/// Creates a ProviderNotConfigured error, using source spans when available for better error display.
fn create_provider_not_configured_error(
    provider_name: &str,
    profile: &str,
    secret_config: &SecretConfig,
    config: &Config,
) -> FnoxError {
    // Find similar provider names for suggestion
    let providers = config.get_providers(profile);
    let available_providers: Vec<_> = providers.keys().map(|s| s.as_str()).collect();
    let similar = find_similar(provider_name, available_providers);
    let suggestion = format_suggestions(&similar);

    // Try to create a source-aware error if we have both source path and span
    if let (Some(path), Some(span)) = (&secret_config.source_path, secret_config.provider_span())
        && let Some(src) = source_registry::get_named_source(path)
    {
        return FnoxError::ProviderNotConfiguredWithSource {
            provider: provider_name.to_string(),
            profile: profile.to_string(),
            suggestion,
            src,
            span: SourceSpan::new(span.start.into(), span.end - span.start),
        };
    }

    // Fall back to the basic error without source highlighting
    FnoxError::ProviderNotConfigured {
        provider: provider_name.to_string(),
        profile: profile.to_string(),
        config_path: secret_config.source_path.clone(),
        suggestion,
    }
}

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
    let Some(provider_value) = secret_config.value() else {
        return Ok(None);
    };

    // Determine which provider to use
    let provider_name = if let Some(provider_name) = secret_config.provider() {
        // Explicit provider specified
        provider_name.to_string()
    } else if let Some(default_provider) = config.get_default_provider(profile)? {
        // Use default provider
        default_provider
    } else {
        // No provider configured, can't resolve
        return Ok(None);
    };

    // Get the provider config
    let providers = config.get_providers(profile);
    let provider_config = providers.get(&provider_name).ok_or_else(|| {
        create_provider_not_configured_error(&provider_name, profile, secret_config, config)
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
/// Secrets are resolved in dependency order using Kahn's algorithm. If a provider
/// declares env var dependencies (e.g., 1Password needs `OP_SERVICE_ACCOUNT_TOKEN`),
/// and another secret provides that env var (e.g., an age-encrypted secret named
/// `OP_SERVICE_ACCOUNT_TOKEN`), the dependency is resolved first. Between resolution
/// levels, resolved values are set as environment variables so subsequent providers
/// can read them.
///
/// Returns an error immediately if any secret with `if_missing = "error"` fails to resolve.
pub async fn resolve_secrets_batch(
    config: &Config,
    profile: &str,
    secrets: &IndexMap<String, SecretConfig>,
) -> Result<IndexMap<String, Option<String>>> {
    // Classify each secret: provider-backed vs no-provider
    let mut secret_provider: HashMap<String, (String, String)> = HashMap::new(); // key -> (provider_name, provider_value)
    let mut no_provider = Vec::new();

    let providers = config.get_providers(profile);

    for (key, secret_config) in secrets {
        if let Some(provider_value) = secret_config.value() {
            let provider_name = if let Some(provider_name) = secret_config.provider() {
                provider_name.to_string()
            } else if let Ok(Some(default_provider)) = config.get_default_provider(profile) {
                default_provider
            } else {
                no_provider.push(key.clone());
                continue;
            };

            secret_provider.insert(key.clone(), (provider_name, provider_value.to_string()));
        } else {
            no_provider.push(key.clone());
        }
    }

    // Build dependency graph and compute resolution levels using Kahn's algorithm.
    let env_deps_for_secret: HashMap<String, &[&str]> = secret_provider
        .iter()
        .map(|(key, (provider_name, _))| {
            let deps = providers
                .get(provider_name)
                .map(|pc| pc.env_dependencies())
                .unwrap_or(&[]);
            (key.clone(), deps)
        })
        .collect();

    let all_keys: Vec<String> = secrets.keys().cloned().collect();
    let no_provider_set: HashSet<&str> = no_provider.iter().map(|s| s.as_str()).collect();
    let (levels, cycle) =
        compute_resolution_levels(&all_keys, &env_deps_for_secret, &no_provider_set);

    // Resolve each level in order
    let mut temp_results: HashMap<String, Option<String>> = HashMap::new();

    for ready in &levels {
        let level_results = resolve_level(
            config,
            profile,
            secrets,
            &secret_provider,
            &no_provider,
            ready,
        )
        .await?;

        // Set resolved env vars so next level's providers can see them
        for (key, value) in &level_results {
            if let Some(val) = value {
                env::set_var(key, val);
            }
        }

        temp_results.extend(level_results);
    }

    // Handle any remaining secrets (cycles) - resolve best-effort
    if !cycle.is_empty() {
        tracing::warn!(
            "Detected dependency cycle among secrets: {}. Resolving best-effort.",
            cycle.join(", ")
        );
        let level_results = resolve_level(
            config,
            profile,
            secrets,
            &secret_provider,
            &no_provider,
            &cycle,
        )
        .await?;
        temp_results.extend(level_results);
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

/// Build a dependency graph and compute resolution levels using Kahn's algorithm.
///
/// Returns `(levels, cycle)` where `levels` is a vec of vecs (each inner vec is a set of
/// secrets that can be resolved in parallel), and `cycle` contains any secrets involved
/// in dependency cycles that couldn't be ordered.
///
/// A secret S depends on secret D if S's provider declares an env var dependency
/// (via `env_dependencies()`) that matches D's key name.
fn compute_resolution_levels(
    all_keys: &[String],
    env_deps_for_secret: &HashMap<String, &[&str]>,
    no_provider: &HashSet<&str>,
) -> (Vec<Vec<String>>, Vec<String>) {
    let secret_keys: HashSet<&str> = all_keys.iter().map(|k| k.as_str()).collect();
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

    for (key, deps) in env_deps_for_secret {
        let mut degree = 0usize;
        for dep_env in *deps {
            if secret_keys.contains(dep_env) && *dep_env != key.as_str() {
                degree += 1;
                dependents
                    .entry(dep_env.to_string())
                    .or_default()
                    .push(key.clone());
            }
        }
        in_degree.insert(key.clone(), degree);
    }

    // No-provider secrets always have in_degree 0
    for key in all_keys {
        if no_provider.contains(key.as_str()) {
            in_degree.insert(key.clone(), 0);
        }
    }

    let mut remaining: std::collections::HashSet<String> = in_degree.keys().cloned().collect();
    let mut levels = Vec::new();

    loop {
        let ready: Vec<String> = remaining
            .iter()
            .filter(|k| in_degree.get(*k).copied().unwrap_or(0) == 0)
            .cloned()
            .collect();

        if ready.is_empty() {
            break;
        }

        for k in &ready {
            remaining.remove(k);
        }

        // Decrement in-degrees for dependents of this level
        for key in &ready {
            if let Some(deps) = dependents.get(key) {
                for dep in deps {
                    if let Some(d) = in_degree.get_mut(dep) {
                        *d = d.saturating_sub(1);
                    }
                }
            }
        }

        levels.push(ready);
    }

    let cycle: Vec<String> = remaining.into_iter().collect();
    (levels, cycle)
}

/// Resolve a single level of secrets (all can be resolved in parallel).
async fn resolve_level(
    config: &Config,
    profile: &str,
    secrets: &IndexMap<String, SecretConfig>,
    secret_provider: &HashMap<String, (String, String)>,
    no_provider: &[String],
    ready: &[String],
) -> Result<HashMap<String, Option<String>>> {
    use futures::stream::{self, StreamExt};

    // Split ready keys into provider-backed and no-provider
    let mut by_provider: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut level_no_provider = Vec::new();

    for key in ready {
        if let Some((provider_name, provider_value)) = secret_provider.get(key) {
            by_provider
                .entry(provider_name.clone())
                .or_default()
                .push((key.clone(), provider_value.clone()));
        } else if no_provider.contains(key) {
            level_no_provider.push(key.clone());
        }
    }

    let mut temp_results = HashMap::new();

    // Resolve provider-backed secrets in parallel by provider
    let provider_results: Vec<_> = stream::iter(by_provider)
        .map(|(provider_name, provider_secrets)| async move {
            resolve_provider_batch(config, profile, secrets, &provider_name, provider_secrets).await
        })
        .buffer_unordered(10)
        .collect()
        .await;

    for provider_result in provider_results {
        temp_results.extend(provider_result?);
    }

    // Resolve no-provider secrets in parallel
    let no_provider_results: Vec<_> = stream::iter(level_no_provider)
        .map(|key| async move {
            let secret_config = &secrets[&key];
            match resolve_secret(config, profile, &key, secret_config).await {
                Ok(value) => Ok((key, value)),
                Err(e) => {
                    let if_missing = resolve_if_missing_behavior(secret_config, config);
                    if let Some(error) = handle_provider_error(&key, e, if_missing, true) {
                        Err(error)
                    } else {
                        Ok((key, None))
                    }
                }
            }
        })
        .buffer_unordered(10)
        .collect()
        .await;

    for result in no_provider_results {
        let (key, value) = result?;
        temp_results.insert(key, value);
    }

    Ok(temp_results)
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
            // Find similar provider names for suggestion
            let available_providers: Vec<_> = providers.keys().map(|s| s.as_str()).collect();
            let similar = find_similar(provider_name, available_providers);
            let suggestion = format_suggestions(&similar);

            // Provider not configured, handle errors for all secrets
            for (key, _) in &provider_secrets {
                let secret_config = &secrets[key];
                let if_missing = resolve_if_missing_behavior(secret_config, config);
                let error = FnoxError::ProviderNotConfigured {
                    provider: provider_name.to_string(),
                    profile: profile.to_string(),
                    config_path: config.provider_sources.get(provider_name).cloned(),
                    suggestion: suggestion.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to call compute_resolution_levels and sort each level for deterministic assertions.
    fn compute_sorted(
        all_keys: &[&str],
        env_deps: &[(&str, &[&str])],
        no_provider: &[&str],
    ) -> (Vec<Vec<String>>, Vec<String>) {
        let all: Vec<String> = all_keys.iter().map(|s| s.to_string()).collect();
        let deps: HashMap<String, &[&str]> =
            env_deps.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        let np: HashSet<&str> = no_provider.iter().copied().collect();
        let (mut levels, mut cycle) = compute_resolution_levels(&all, &deps, &np);
        for level in &mut levels {
            level.sort();
        }
        cycle.sort();
        (levels, cycle)
    }

    #[test]
    fn test_no_dependencies() {
        // All secrets independent — resolved in a single level.
        let (levels, cycle) =
            compute_sorted(&["A", "B", "C"], &[("A", &[]), ("B", &[]), ("C", &[])], &[]);
        assert!(cycle.is_empty());
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], vec!["A", "B", "C"]);
    }

    #[test]
    fn test_linear_dependency_chain() {
        // A has no deps, B depends on A, C depends on B.
        let (levels, cycle) = compute_sorted(
            &["A", "B", "C"],
            &[("A", &[]), ("B", &["A"]), ("C", &["B"])],
            &[],
        );
        assert!(cycle.is_empty());
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["A"]);
        assert_eq!(levels[1], vec!["B"]);
        assert_eq!(levels[2], vec!["C"]);
    }

    #[test]
    fn test_diamond_dependency() {
        // A has no deps, B and C both depend on A, D depends on B and C.
        let (levels, cycle) = compute_sorted(
            &["A", "B", "C", "D"],
            &[("A", &[]), ("B", &["A"]), ("C", &["A"]), ("D", &["B", "C"])],
            &[],
        );
        assert!(cycle.is_empty());
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["A"]);
        assert_eq!(levels[1], vec!["B", "C"]);
        assert_eq!(levels[2], vec!["D"]);
    }

    #[test]
    fn test_cycle_detection() {
        // A depends on B, B depends on A — cycle.
        let (levels, cycle) = compute_sorted(&["A", "B"], &[("A", &["B"]), ("B", &["A"])], &[]);
        assert!(levels.is_empty());
        assert_eq!(cycle, vec!["A", "B"]);
    }

    #[test]
    fn test_partial_cycle() {
        // A has no deps, B depends on C, C depends on B — B/C cycle, A resolves fine.
        let (levels, cycle) = compute_sorted(
            &["A", "B", "C"],
            &[("A", &[]), ("B", &["C"]), ("C", &["B"])],
            &[],
        );
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], vec!["A"]);
        assert_eq!(cycle, vec!["B", "C"]);
    }

    #[test]
    fn test_no_provider_secrets_at_level_zero() {
        // NO_PROV has no provider (env-only), OP_SECRET depends on it via env.
        let (levels, cycle) = compute_sorted(
            &["NO_PROV", "OP_SECRET"],
            &[("OP_SECRET", &["NO_PROV"])],
            &["NO_PROV"],
        );
        assert!(cycle.is_empty());
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], vec!["NO_PROV"]);
        assert_eq!(levels[1], vec!["OP_SECRET"]);
    }

    #[test]
    fn test_dep_on_nonexistent_key_ignored() {
        // B declares a dependency on "MISSING" which isn't a secret key — ignored.
        let (levels, cycle) = compute_sorted(&["A", "B"], &[("A", &[]), ("B", &["MISSING"])], &[]);
        assert!(cycle.is_empty());
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], vec!["A", "B"]);
    }

    #[test]
    fn test_self_dependency_ignored() {
        // A declares itself as a dependency — should be ignored (not a cycle).
        let (levels, cycle) = compute_sorted(&["A"], &[("A", &["A"])], &[]);
        assert!(cycle.is_empty());
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], vec!["A"]);
    }

    #[test]
    fn test_real_world_scenario() {
        // OP_SERVICE_ACCOUNT_TOKEN is age-encrypted (no env deps).
        // TUNNEL_TOKEN uses 1Password provider which depends on OP_SERVICE_ACCOUNT_TOKEN.
        // DB_PASSWORD also uses 1Password.
        // PLAIN_VAR has no provider.
        let (levels, cycle) = compute_sorted(
            &[
                "OP_SERVICE_ACCOUNT_TOKEN",
                "TUNNEL_TOKEN",
                "DB_PASSWORD",
                "PLAIN_VAR",
            ],
            &[
                ("OP_SERVICE_ACCOUNT_TOKEN", &[]), // age provider
                (
                    "TUNNEL_TOKEN",
                    &["OP_SERVICE_ACCOUNT_TOKEN", "FNOX_OP_SERVICE_ACCOUNT_TOKEN"],
                ), // 1password
                (
                    "DB_PASSWORD",
                    &["OP_SERVICE_ACCOUNT_TOKEN", "FNOX_OP_SERVICE_ACCOUNT_TOKEN"],
                ), // 1password
            ],
            &["PLAIN_VAR"],
        );
        assert!(cycle.is_empty());
        assert_eq!(levels.len(), 2);
        // Level 0: age secret + no-provider secret
        assert_eq!(levels[0], vec!["OP_SERVICE_ACCOUNT_TOKEN", "PLAIN_VAR"]);
        // Level 1: 1Password secrets that depend on the token
        assert_eq!(levels[1], vec!["DB_PASSWORD", "TUNNEL_TOKEN"]);
    }
}
