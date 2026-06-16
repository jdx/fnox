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
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

/// Extract a value from JSON using dot notation (e.g., "nested.path")
/// Supports escaped dots: "foo\.bar" accesses the literal key "foo.bar"
fn extract_json_path(json_str: &str, path: &str) -> Result<String> {
    let value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| FnoxError::Config(format!("Failed to parse JSON secret: {}", e)))?;

    let mut current = &value;
    for part in split_key_path(path) {
        current = current.get(&part).ok_or_else(|| {
            FnoxError::Config(format!("JSON path '{}' not found in secret", path))
        })?;
    }

    match current {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Null => Ok("null".to_string()),
        other => Ok(other.to_string()), // Numbers, bools, arrays, objects
    }
}

/// Split a key path on unescaped dots, unescaping `\.` to `.` in each part.
/// Examples:
///   "foo.bar" -> ["foo", "bar"]
///   "foo\.bar" -> ["foo.bar"]
///   "a.b\.c.d" -> ["a", "b.c", "d"]
///   "foo\\\.bar" -> ["foo\.bar"] (escaped backslash + escaped dot)
fn split_key_path(key: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = key.chars();

    while let Some(c) = chars.next() {
        if c == '\\' {
            // Escape the next character.
            if let Some(next_char) = chars.next() {
                current.push(next_char);
            } else {
                // A trailing backslash is treated as a literal backslash.
                current.push('\\');
            }
        } else if c == '.' {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }

    parts.push(current);
    parts
}

/// Extract the Nth (1-indexed) line from a multi-line value.
///
/// Uses `str::lines()` so both `\n` and `\r\n` line endings are handled and a
/// single trailing newline is not counted as an extra empty line.
fn extract_line(value: &str, line: usize) -> Result<String> {
    if line == 0 {
        return Err(FnoxError::Config(
            "`line` must be a 1-indexed line number (got 0)".to_string(),
        ));
    }

    if let Some(l) = value.lines().nth(line - 1) {
        return Ok(l.to_string());
    }

    let count = value.lines().count();
    Err(FnoxError::Config(format!(
        "`line = {line}` is out of range; secret has {count} line(s)"
    )))
}

/// Apply post-processing to a secret value based on SecretConfig settings.
/// `json_path` extracts a path from a JSON value; `line` returns the Nth
/// line (1-indexed) of the raw value. The two are mutually exclusive.
fn apply_post_processing(value: String, secret_config: &SecretConfig) -> Result<String> {
    if secret_config.json_path.is_some() && secret_config.line.is_some() {
        return Err(FnoxError::Config(
            "`json_path` and `line` are mutually exclusive on a secret".to_string(),
        ));
    }
    if let Some(ref json_path) = secret_config.json_path {
        if json_path.is_empty() {
            return Err(FnoxError::Config("json_path must not be empty".to_string()));
        }
        return extract_json_path(&value, json_path);
    }
    if let Some(line) = secret_config.line {
        return extract_line(&value, line);
    }
    Ok(value)
}

fn extract_default_references(default: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut rest = default;

    while let Some(start) = rest.find("${") {
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            break;
        };

        let name = &after_start[..end];
        if !name.is_empty() && !refs.iter().any(|existing| existing == name) {
            refs.push(name.to_string());
        }
        rest = &after_start[end + 1..];
    }

    refs
}

fn has_default_interpolation(default: &str) -> bool {
    default.contains("${")
}

fn render_default_template(
    key: &str,
    default: &str,
    resolved: &HashMap<String, Option<String>>,
) -> Result<String> {
    let mut rendered = String::with_capacity(default.len());
    let mut rest = default;

    while let Some(start) = rest.find("${") {
        rendered.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            rendered.push_str(&rest[start..]);
            return Ok(rendered);
        };

        let name = &after_start[..end];
        if name.is_empty() {
            return Err(FnoxError::Config(format!(
                "Secret '{}' has an empty interpolation reference in default value",
                key
            )));
        }

        let value = resolved.get(name).ok_or_else(|| {
            FnoxError::Config(format!(
                "Secret '{}' references '{}' in default value, but '{}' did not resolve",
                key, name, name
            ))
        })?;
        if let Some(value) = value {
            rendered.push_str(value);
        }
        rest = &after_start[end + 1..];
    }

    rendered.push_str(rest);
    Ok(rendered)
}

fn default_reference_error(key: &str, reference: &str) -> FnoxError {
    FnoxError::Config(format!(
        "Secret '{}' references undefined secret '{}' in default value",
        key, reference
    ))
}

fn default_can_be_used_in_batch(
    config: &Config,
    profile: &str,
    secret_config: &SecretConfig,
) -> bool {
    if secret_config.sync.is_some() {
        return false;
    }

    if secret_config.value().is_none() {
        return true;
    }

    secret_config.provider().is_none()
        && !matches!(config.get_default_provider(profile), Ok(Some(_)))
}

fn collect_interpolation_closure(
    config: &Config,
    profile: &str,
    key: &str,
    secrets: &IndexMap<String, SecretConfig>,
) -> Result<IndexMap<String, SecretConfig>> {
    struct ClosureCollector<'a> {
        config: &'a Config,
        profile: &'a str,
        root_key: &'a str,
        secrets: &'a IndexMap<String, SecretConfig>,
        visiting: HashSet<String>,
        visited: HashSet<String>,
        subset: IndexMap<String, SecretConfig>,
    }

    impl ClosureCollector<'_> {
        fn visit(&mut self, key: &str) -> Result<()> {
            if self.visited.contains(key) {
                return Ok(());
            }
            if !self.visiting.insert(key.to_string()) {
                return Err(FnoxError::Config(format!(
                    "Interpolation dependency cycle among secrets: {}",
                    key
                )));
            }

            let secret_config = self.secrets.get(key).ok_or_else(|| {
                FnoxError::Config(format!(
                    "Secret '{}' is not defined in the active profile",
                    key
                ))
            })?;

            if (key == self.root_key
                || default_can_be_used_in_batch(self.config, self.profile, secret_config))
                && let Some(default) = &secret_config.default
            {
                for reference in extract_default_references(default) {
                    if !self.secrets.contains_key(&reference) {
                        return Err(default_reference_error(key, &reference));
                    }
                    self.visit(&reference)?;
                }
            }

            self.visiting.remove(key);
            self.visited.insert(key.to_string());
            self.subset.insert(key.to_string(), secret_config.clone());
            Ok(())
        }
    }

    let mut collector = ClosureCollector {
        config,
        profile,
        root_key: key,
        secrets,
        visiting: HashSet::new(),
        visited: HashSet::new(),
        subset: IndexMap::new(),
    };
    collector.visit(key)?;
    Ok(collector.subset)
}

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
/// Post-processing (e.g., JSON path extraction) is applied to all sources consistently.
pub async fn resolve_secret(
    config: &Config,
    profile: &str,
    key: &str,
    secret_config: &SecretConfig,
) -> Result<Option<String>> {
    if let Some(default) = &secret_config.default
        && has_default_interpolation(default)
    {
        let secrets = config.get_secrets(profile)?;
        if secrets.contains_key(key) {
            let subset = collect_interpolation_closure(config, profile, key, &secrets)?;
            let mut resolved = resolve_secrets_batch(config, profile, &subset).await?;
            if let Some(Some(value)) = resolved.shift_remove(key) {
                return Ok(Some(value));
            }
            let resolved_context: HashMap<String, Option<String>> = resolved.into_iter().collect();
            let default = render_default_template(key, default, &resolved_context)?;
            return Ok(Some(apply_post_processing(default, secret_config)?));
        }
    }

    resolve_secret_raw(config, profile, key, secret_config).await
}

async fn resolve_secret_raw(
    config: &Config,
    profile: &str,
    key: &str,
    secret_config: &SecretConfig,
) -> Result<Option<String>> {
    // Try to get a value from any source (provider, default, or env var)
    let value_to_process =
        // Priority 1: Provider (if specified and has a value)
        if let Some(value) = try_resolve_from_provider(config, profile, secret_config).await? {
            Some(value)
        // Priority 2: Default value
        } else if let Some(default) = &secret_config.default {
            tracing::debug!("Using default value for secret '{}'", key);
            Some(default.clone())
        // Priority 3: Environment variable
        } else if let Ok(env_value) = env::var(key) {
            tracing::debug!("Found secret '{}' in current environment", key);
            Some(env_value)
        } else {
            None
        };

    // Apply post-processing to whatever value we found (e.g., JSON path extraction)
    if let Some(value) = value_to_process {
        let processed = apply_post_processing(value, secret_config)?;
        return Ok(Some(processed));
    }

    // No value found - handle based on if_missing with priority chain
    handle_missing_secret(key, secret_config, config)
}

async fn try_resolve_from_provider(
    config: &Config,
    profile: &str,
    secret_config: &SecretConfig,
) -> Result<Option<String>> {
    // If a sync cache exists, resolve from the sync provider/value instead
    let (provider_name, provider_value) = if let Some(ref sync) = secret_config.sync {
        (sync.provider.clone(), sync.value.clone())
    } else {
        // Only try provider if we have a value to pass to it
        let Some(pv) = secret_config.value() else {
            return Ok(None);
        };

        // Determine which provider to use
        let pn = if let Some(provider_name) = secret_config.provider() {
            // Explicit provider specified
            provider_name.to_string()
        } else if let Some(default_provider) = config.get_default_provider(profile)? {
            // Use default provider
            default_provider
        } else {
            // No provider configured, can't resolve
            return Ok(None);
        };
        (pn, pv.to_string())
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
        &provider_value,
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
    if crate::env::is_non_interactive() && provider_config.requires_interactive_auth() {
        return Err(FnoxError::Provider(format!(
            "Provider '{}' requires interactive authentication and cannot be used in non-interactive mode. Use 'fnox exec' instead.",
            provider_name
        )));
    }

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
    let all_keys: Vec<String> = secrets.keys().cloned().collect();
    let secret_keys: HashSet<&str> = all_keys.iter().map(|k| k.as_str()).collect();
    let mut default_deps: HashMap<String, Vec<String>> = HashMap::new();

    for (key, secret_config) in secrets {
        // If a sync cache exists, use the sync provider/value
        if let Some(ref sync) = secret_config.sync {
            secret_provider.insert(key.clone(), (sync.provider.clone(), sync.value.clone()));
            continue;
        }

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

    for key in &no_provider {
        let secret_config = &secrets[key];
        let Some(default) = &secret_config.default else {
            continue;
        };

        let refs = extract_default_references(default);
        if refs.iter().any(|reference| reference == key) {
            return Err(FnoxError::Config(format!(
                "Secret '{}' has an interpolation cycle in default value",
                key
            )));
        }

        for reference in &refs {
            if !secret_keys.contains(reference.as_str()) {
                return Err(default_reference_error(key, reference));
            }
        }

        if !refs.is_empty() {
            default_deps.insert(key.clone(), refs);
        }
    }

    // Build dependency graph and compute resolution levels using Kahn's algorithm.
    let mut deps_for_secret: HashMap<String, Vec<String>> = HashMap::new();
    for (key, (provider_name, _)) in &secret_provider {
        let deps = providers
            .get(provider_name)
            .map(|pc| pc.env_dependencies())
            .unwrap_or(&[]);
        deps_for_secret.insert(
            key.clone(),
            deps.iter().map(|dep| dep.to_string()).collect(),
        );
    }
    for (key, refs) in &default_deps {
        match deps_for_secret.entry(key.clone()) {
            Entry::Occupied(mut entry) => {
                let deps = entry.get_mut();
                for reference in refs {
                    if !deps.iter().any(|dep| dep == reference) {
                        deps.push(reference.clone());
                    }
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(refs.clone());
            }
        }
    }

    let no_provider_set: HashSet<&str> = no_provider.iter().map(|s| s.as_str()).collect();
    let (levels, cycle) = compute_resolution_levels(&all_keys, &deps_for_secret, &no_provider_set);

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
            &temp_results,
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
        let cycle_keys: HashSet<&str> = cycle.iter().map(|key| key.as_str()).collect();
        let has_default_cycle = cycle.iter().any(|key| {
            default_deps.get(key).is_some_and(|refs| {
                refs.iter()
                    .any(|reference| cycle_keys.contains(reference.as_str()))
            })
        });
        if has_default_cycle {
            let mut sorted_cycle = cycle.clone();
            sorted_cycle.sort();
            return Err(FnoxError::Config(format!(
                "Interpolation dependency cycle among secrets: {}",
                sorted_cycle.join(", ")
            )));
        }

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
            &temp_results,
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
    deps_for_secret: &HashMap<String, Vec<String>>,
    no_provider: &HashSet<&str>,
) -> (Vec<Vec<String>>, Vec<String>) {
    let secret_keys: HashSet<&str> = all_keys.iter().map(|k| k.as_str()).collect();
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

    for (key, deps) in deps_for_secret {
        let mut degree = 0usize;
        for dep_env in deps {
            if secret_keys.contains(dep_env.as_str()) && dep_env != key {
                degree += 1;
                dependents
                    .entry(dep_env.clone())
                    .or_default()
                    .push(key.clone());
            }
        }
        in_degree.insert(key.clone(), degree);
    }

    // No-provider secrets without dependency entries start at in_degree 0.
    for key in all_keys {
        if no_provider.contains(key.as_str()) {
            in_degree.entry(key.clone()).or_insert(0);
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
    resolved_so_far: &HashMap<String, Option<String>>,
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
    let no_provider_results: Vec<Result<_>> = stream::iter(level_no_provider)
        .map(|key| async move {
            let secret_config = &secrets[&key];
            let value =
                resolve_no_provider_secret(config, profile, &key, secret_config, resolved_so_far)
                    .await?;
            Ok((key, value))
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

async fn resolve_no_provider_secret(
    config: &Config,
    profile: &str,
    key: &str,
    secret_config: &SecretConfig,
    resolved_so_far: &HashMap<String, Option<String>>,
) -> Result<Option<String>> {
    if let Some(default) = &secret_config.default {
        tracing::debug!("Using default value for secret '{}'", key);
        let value = if has_default_interpolation(default) {
            render_default_template(key, default, resolved_so_far)?
        } else {
            default.clone()
        };
        return Ok(Some(apply_post_processing(value, secret_config)?));
    }

    resolve_secret_raw(config, profile, key, secret_config).await
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

    // Skip interactive providers in non-interactive mode (e.g. TUI).
    // Handle per-secret if_missing policy (like ProviderNotConfigured above)
    // so other providers at the same resolution level are not affected.
    if crate::env::is_non_interactive() && provider_config.requires_interactive_auth() {
        for (key, _) in &provider_secrets {
            let secret_config = &secrets[key];
            let if_missing = resolve_if_missing_behavior(secret_config, config);
            let error = FnoxError::Provider(format!(
                "Provider '{}' requires interactive authentication and cannot be used in non-interactive mode. Use 'fnox exec' instead.",
                provider_name
            ));
            if let Some(error) = handle_provider_error(key, error, if_missing, true) {
                return Err(error);
            }
            results.insert(key.clone(), None);
        }
        return Ok(results);
    }

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
            let auth_error = extract_auth_error_from_batch(&batch_results);
            if let Some(ref auth_err) = auth_error
                && prompt_and_run_auth(config, provider_config, provider_name, auth_err)?
            {
                // Auth prompt successful, retry the batch operation.
                let retry_results = try_get_secrets_batch(
                    config,
                    profile,
                    provider_name,
                    provider_config,
                    provider_secrets,
                )
                .await?;
                process_batch_results(secrets, config, retry_results, results)?;
                return Ok(std::mem::take(results));
            }
            // No auth error, or user declined auth prompt. Process original results.
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

/// Extract the first auth error from batch results, if any.
/// Returns an owned clone so we can use it without borrowing `batch_results`.
fn extract_auth_error_from_batch(
    batch_results: &HashMap<String, Result<String>>,
) -> Option<FnoxError> {
    batch_results.values().find_map(|result| match result {
        Err(FnoxError::ProviderAuthFailed {
            provider,
            details,
            hint,
            url,
        }) => Some(FnoxError::ProviderAuthFailed {
            provider: provider.clone(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        }),
        _ => None,
    })
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
                // Apply post-processing (e.g., JSON path extraction)
                match apply_post_processing(value, secret_config) {
                    Ok(processed) => {
                        results.insert(key, Some(processed));
                    }
                    Err(e) => {
                        // Post-processing errors (invalid JSON, missing key) are config/data errors,
                        // not "missing secret" — always fail hard regardless of if_missing.
                        return Err(e);
                    }
                }
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
    use crate::config::ProfileConfig;

    /// Helper to call compute_resolution_levels and sort each level for deterministic assertions.
    fn compute_sorted(
        all_keys: &[&str],
        env_deps: &[(&str, &[&str])],
        no_provider: &[&str],
    ) -> (Vec<Vec<String>>, Vec<String>) {
        let all: Vec<String> = all_keys.iter().map(|s| s.to_string()).collect();
        let deps: HashMap<String, Vec<String>> = env_deps
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|dep| dep.to_string()).collect()))
            .collect();
        let np: HashSet<&str> = no_provider.iter().copied().collect();
        let (mut levels, mut cycle) = compute_resolution_levels(&all, &deps, &np);
        for level in &mut levels {
            level.sort();
        }
        cycle.sort();
        (levels, cycle)
    }

    fn default_secret(value: &str) -> SecretConfig {
        let mut secret = SecretConfig::new();
        secret.default = Some(value.to_string());
        secret
    }

    fn plain_provider_secret(value: &str) -> SecretConfig {
        let mut secret = SecretConfig::new();
        secret.set_provider(Some("plain".to_string()));
        secret.set_value(Some(value.to_string()));
        secret
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

    #[tokio::test]
    async fn test_interpolated_default_resolves_independent_of_order() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"),
        );
        secrets.insert("POSTGRES_PASSWORD".to_string(), default_secret("secret"));
        secrets.insert("POSTGRES_USER".to_string(), default_secret("app"));
        secrets.insert("POSTGRES_DB".to_string(), default_secret("fnox"));
        secrets.insert("POSTGRES_HOST".to_string(), default_secret("localhost"));
        secrets.insert("POSTGRES_PORT".to_string(), default_secret("5432"));

        let resolved = resolve_secrets_batch(&config, "default", &secrets)
            .await
            .unwrap();

        assert_eq!(
            resolved
                .get("DATABASE_URL")
                .and_then(|value| value.as_ref()),
            Some(&"postgres://app:secret@localhost:5432/fnox".to_string())
        );
    }

    #[tokio::test]
    async fn test_interpolated_default_uses_profile_overrides() {
        let mut config = Config::new();
        config.secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db/fnox"),
        );
        config
            .secrets
            .insert("POSTGRES_USER".to_string(), default_secret("base"));
        config.secrets.insert(
            "POSTGRES_PASSWORD".to_string(),
            default_secret("base-password"),
        );

        let mut dev = ProfileConfig::new();
        dev.secrets
            .insert("POSTGRES_USER".to_string(), default_secret("dev"));
        dev.secrets.insert(
            "POSTGRES_PASSWORD".to_string(),
            default_secret("dev-password"),
        );
        let mut secrets = config.secrets.clone();
        secrets.extend(dev.secrets.clone());
        config.profiles.insert("dev".to_string(), dev);

        let resolved = resolve_secrets_batch(&config, "dev", &secrets)
            .await
            .unwrap();

        assert_eq!(
            resolved
                .get("DATABASE_URL")
                .and_then(|value| value.as_ref()),
            Some(&"postgres://dev:dev-password@db/fnox".to_string())
        );
    }

    #[tokio::test]
    async fn test_interpolated_default_errors_for_missing_reference() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${POSTGRES_USER}@localhost/fnox"),
        );

        let err = resolve_secrets_batch(&config, "default", &secrets)
            .await
            .unwrap_err();
        let msg = format!("{err}");

        assert!(
            msg.contains("undefined secret 'POSTGRES_USER'"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn test_interpolated_default_errors_for_cycle() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        secrets.insert("A".to_string(), default_secret("${B}"));
        secrets.insert("B".to_string(), default_secret("${A}"));

        let err = resolve_secrets_batch(&config, "default", &secrets)
            .await
            .unwrap_err();
        let msg = format!("{err}");

        assert!(
            msg.contains("Interpolation dependency cycle"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn test_interpolated_default_can_use_provider_backed_reference() {
        let mut config = Config::new();
        config.providers.insert(
            "plain".to_string(),
            ProviderConfig::Plain { auth_command: None },
        );

        let mut secrets = IndexMap::new();
        secrets.insert("POSTGRES_USER".to_string(), plain_provider_secret("app"));
        secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${POSTGRES_USER}@localhost/fnox"),
        );

        let resolved = resolve_secrets_batch(&config, "default", &secrets)
            .await
            .unwrap();

        assert_eq!(
            resolved
                .get("DATABASE_URL")
                .and_then(|value| value.as_ref()),
            Some(&"postgres://app@localhost/fnox".to_string())
        );
    }

    #[tokio::test]
    async fn test_provider_value_wins_over_interpolated_default() {
        let mut config = Config::new();
        config.providers.insert(
            "plain".to_string(),
            ProviderConfig::Plain { auth_command: None },
        );

        let mut secret = plain_provider_secret("provider-value");
        secret.default = Some("${MISSING_REF}".to_string());

        let mut secrets = IndexMap::new();
        secrets.insert("API_KEY".to_string(), secret);

        let resolved = resolve_secrets_batch(&config, "default", &secrets)
            .await
            .unwrap();

        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_ref()),
            Some(&"provider-value".to_string())
        );
    }

    #[tokio::test]
    async fn test_interpolated_default_errors_for_empty_reference() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        secrets.insert("DATABASE_URL".to_string(), default_secret("${}"));

        let err = resolve_secrets_batch(&config, "default", &secrets)
            .await
            .unwrap_err();
        let msg = format!("{err}");

        assert!(
            msg.contains("empty interpolation reference"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn test_interpolated_default_renders_missing_allowed_reference_as_empty() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        let mut user = SecretConfig::new();
        user.if_missing = Some(IfMissing::Ignore);
        secrets.insert("FNOX_TEST_MISSING_OPTIONAL_REF".to_string(), user);
        secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${FNOX_TEST_MISSING_OPTIONAL_REF}@localhost/fnox"),
        );

        let resolved = resolve_secrets_batch(&config, "default", &secrets)
            .await
            .unwrap();

        assert_eq!(
            resolved
                .get("DATABASE_URL")
                .and_then(|value| value.as_ref()),
            Some(&"postgres://@localhost/fnox".to_string())
        );
    }

    #[tokio::test]
    async fn test_resolve_secret_resolves_interpolated_default() {
        let mut config = Config::new();
        config.secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${POSTGRES_USER}@localhost/fnox"),
        );
        config
            .secrets
            .insert("POSTGRES_USER".to_string(), default_secret("app"));

        let secret_config = config.secrets.get("DATABASE_URL").unwrap();
        let resolved = resolve_secret(&config, "default", "DATABASE_URL", secret_config)
            .await
            .unwrap();

        assert_eq!(resolved, Some("postgres://app@localhost/fnox".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_secret_closure_includes_chained_defaults_without_default_provider() {
        let mut config = Config::new();
        config.root = true;
        let mut database_url = default_secret("${DB_HOST}");
        database_url.set_value(Some("provider-ref-without-provider".to_string()));
        config
            .secrets
            .insert("DATABASE_URL".to_string(), database_url);
        config
            .secrets
            .insert("DB_HOST".to_string(), default_secret("${HOSTNAME}"));
        config
            .secrets
            .insert("HOSTNAME".to_string(), default_secret("localhost"));

        let secret_config = config.secrets.get("DATABASE_URL").unwrap();
        let resolved = resolve_secret(&config, "default", "DATABASE_URL", secret_config)
            .await
            .unwrap();

        assert_eq!(resolved, Some("localhost".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_secret_uses_interpolated_default_when_provider_missing_is_allowed() {
        let mut config = Config::new();
        config
            .secrets
            .insert("HOSTNAME".to_string(), default_secret("localhost"));

        let mut database_url = default_secret("postgres://${HOSTNAME}/fnox");
        database_url.set_provider(Some("missing-provider".to_string()));
        database_url.set_value(Some("Database/url".to_string()));
        database_url.if_missing = Some(IfMissing::Ignore);
        config
            .secrets
            .insert("DATABASE_URL".to_string(), database_url);

        let secret_config = config.secrets.get("DATABASE_URL").unwrap();
        let resolved = resolve_secret(&config, "default", "DATABASE_URL", secret_config)
            .await
            .unwrap();

        assert_eq!(resolved, Some("postgres://localhost/fnox".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_secret_interpolation_ignores_unrelated_invalid_default() {
        let mut config = Config::new();
        config.secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${POSTGRES_USER}@localhost/fnox"),
        );
        config
            .secrets
            .insert("POSTGRES_USER".to_string(), default_secret("app"));
        config.secrets.insert(
            "UNRELATED".to_string(),
            default_secret("${MISSING_UNRELATED}"),
        );

        let secret_config = config.secrets.get("DATABASE_URL").unwrap();
        let resolved = resolve_secret(&config, "default", "DATABASE_URL", secret_config)
            .await
            .unwrap();

        assert_eq!(resolved, Some("postgres://app@localhost/fnox".to_string()));
    }

    #[test]
    fn test_split_key_path_simple() {
        assert_eq!(split_key_path("foo"), vec!["foo"]);
        assert_eq!(split_key_path("foo.bar"), vec!["foo", "bar"]);
        assert_eq!(split_key_path("a.b.c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_split_key_path_escaped_dot() {
        // Single escaped dot
        assert_eq!(split_key_path(r"foo\.bar"), vec!["foo.bar"]);
        // Escaped dot in the middle of a path
        assert_eq!(split_key_path(r"a.b\.c.d"), vec!["a", "b.c", "d"]);
        // Multiple escaped dots
        assert_eq!(split_key_path(r"foo\.bar\.baz"), vec!["foo.bar.baz"]);
    }

    #[test]
    fn test_split_key_path_escaped_backslash() {
        // Escaped backslash followed by dot (literal backslash + path separator)
        assert_eq!(split_key_path(r"foo\\.bar"), vec!["foo\\", "bar"]);
        // Escaped backslash followed by escaped dot
        assert_eq!(split_key_path(r"foo\\\.bar"), vec!["foo\\.bar"]);
    }

    #[test]
    fn test_split_key_path_edge_cases() {
        // Empty string
        assert_eq!(split_key_path(""), vec![""]);
        // Just a dot
        assert_eq!(split_key_path("."), vec!["", ""]);
        // Trailing dot
        assert_eq!(split_key_path("foo."), vec!["foo", ""]);
        // Leading dot
        assert_eq!(split_key_path(".foo"), vec!["", "foo"]);
        // Backslash at end (kept as-is)
        assert_eq!(split_key_path(r"foo\"), vec!["foo\\"]);
    }

    fn secret_with_line(line: Option<usize>) -> SecretConfig {
        let mut s = SecretConfig::new();
        s.line = line;
        s
    }

    #[test]
    fn test_extract_line_first_and_subsequent() {
        let value = "hunter2\nuser: alice\nhttps://example.com";
        assert_eq!(extract_line(value, 1).unwrap(), "hunter2");
        assert_eq!(extract_line(value, 2).unwrap(), "user: alice");
        assert_eq!(extract_line(value, 3).unwrap(), "https://example.com");
    }

    #[test]
    fn test_extract_line_single_line_value() {
        assert_eq!(extract_line("just-one-line", 1).unwrap(), "just-one-line");
    }

    #[test]
    fn test_extract_line_preserves_intra_line_whitespace() {
        // Leading and trailing whitespace within a line must not be trimmed.
        let value = "pw\n  spaced  ";
        assert_eq!(extract_line(value, 2).unwrap(), "  spaced  ");
    }

    #[test]
    fn test_extract_line_zero_is_rejected() {
        let err = extract_line("foo\nbar", 0).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("1-indexed"), "unexpected error: {msg}");
    }

    #[test]
    fn test_extract_line_out_of_range() {
        let err = extract_line("foo\nbar", 5).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("out of range"), "unexpected error: {msg}");
        assert!(
            msg.contains("2 line"),
            "expected line count in error: {msg}"
        );
    }

    #[test]
    fn test_extract_line_ignores_trailing_newline() {
        // A trailing newline must not count as a fourth empty line — otherwise
        // values from providers that emit "<value>\n" would silently shift.
        let value = "a\nb\nc\n";
        assert_eq!(extract_line(value, 3).unwrap(), "c");
        let err = extract_line(value, 4).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("out of range"), "unexpected error: {msg}");
        assert!(
            msg.contains("3 line"),
            "expected line count in error: {msg}"
        );
    }

    #[test]
    fn test_extract_line_handles_crlf() {
        // Windows-style line endings should not leak `\r` into the returned line.
        let value = "first\r\nsecond\r\nthird";
        assert_eq!(extract_line(value, 1).unwrap(), "first");
        assert_eq!(extract_line(value, 2).unwrap(), "second");
        assert_eq!(extract_line(value, 3).unwrap(), "third");
    }

    #[test]
    fn test_apply_post_processing_line() {
        let cfg = secret_with_line(Some(2));
        let out = apply_post_processing("a\nb\nc".to_string(), &cfg).unwrap();
        assert_eq!(out, "b");
    }

    #[test]
    fn test_apply_post_processing_unset_returns_value_unchanged() {
        let cfg = secret_with_line(None);
        let out = apply_post_processing("a\nb\nc".to_string(), &cfg).unwrap();
        assert_eq!(out, "a\nb\nc");
    }

    #[test]
    fn test_apply_post_processing_line_and_json_path_are_mutually_exclusive() {
        let mut cfg = secret_with_line(Some(1));
        cfg.json_path = Some("user".to_string());
        let err = apply_post_processing(r#"{"user":"x"}"#.to_string(), &cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("mutually exclusive"),
            "unexpected error: {msg}"
        );
    }
}
