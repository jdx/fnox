use crate::auth_prompt::{prompt_for_auth_command, run_confirmed_auth_command};
use crate::config::{Config, IfMissing, SecretConfig};
use crate::env::{self, PROVIDER_ENV_ACCESS, ProviderEnvOverlay};
use crate::error::{FnoxError, Result};
use crate::providers::{
    ProviderConfig, prepare_provider_read,
    resolver::{ResolutionContext, resolve_provider_config_with_context},
};
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
    profile: &[String],
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
    profile: &[String],
    key: &str,
    secrets: &IndexMap<String, SecretConfig>,
) -> Result<IndexMap<String, SecretConfig>> {
    struct ClosureCollector<'a> {
        config: &'a Config,
        profile: &'a [String],
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
    profile: &[String],
    secret_config: &SecretConfig,
    config: &Config,
) -> FnoxError {
    // Find similar provider names for suggestion
    let providers = config.get_providers(profile).unwrap_or_default();
    let available_providers: Vec<_> = providers.keys().map(|s| s.as_str()).collect();
    let similar = find_similar(provider_name, available_providers);
    let suggestion = format_suggestions(&similar);

    // Try to create a source-aware error if we have both source path and span
    if let (Some(path), Some(span)) = (&secret_config.source_path, secret_config.provider_span())
        && let Some(src) = source_registry::get_named_source(path)
    {
        return FnoxError::ProviderNotConfiguredWithSource {
            provider: provider_name.to_string(),
            profile: profile.join(","),
            suggestion,
            src,
            span: SourceSpan::new(span.start.into(), span.end - span.start),
        };
    }

    // Fall back to the basic error without source highlighting
    FnoxError::ProviderNotConfigured {
        provider: provider_name.to_string(),
        profile: profile.join(","),
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

fn log_provider_default_fallback(key: &str, error: &FnoxError, if_missing: IfMissing) {
    if if_missing == IfMissing::Ignore
        || matches!(
            error,
            FnoxError::ProviderNotConfigured { .. }
                | FnoxError::ProviderNotConfiguredWithSource { .. }
        )
    {
        tracing::debug!(
            "Falling back to default value for secret '{}' after provider resolution failed: {}",
            key,
            error
        );
    } else {
        tracing::warn!(
            "Falling back to default value for secret '{}' after provider resolution failed: {}",
            key,
            error
        );
    }
}

fn default_context(
    resolved_so_far: &HashMap<String, Option<String>>,
    results: &HashMap<String, Option<String>>,
) -> HashMap<String, Option<String>> {
    let mut context = resolved_so_far.clone();
    context.extend(
        results
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    context
}

fn resolve_default_fallbacks(
    keys: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    resolved_so_far: &HashMap<String, Option<String>>,
    results: &mut HashMap<String, Option<String>>,
) -> Result<HashSet<String>> {
    let mut context = default_context(resolved_so_far, results);
    let mut pending: Vec<String> = keys
        .iter()
        .filter(|key| secrets[*key].default.is_some())
        .cloned()
        .collect();
    let mut resolved = HashSet::new();

    while !pending.is_empty() {
        let pending_set: HashSet<String> = pending.iter().cloned().collect();
        let mut progressed = false;
        let mut next_pending = Vec::new();

        for key in pending {
            let secret_config = &secrets[&key];
            let refs = secret_config
                .default
                .as_deref()
                .map(extract_default_references)
                .unwrap_or_default();
            let unresolved_external_ref = refs.iter().any(|reference| {
                !context.contains_key(reference) && !pending_set.contains(reference)
            });
            if unresolved_external_ref {
                continue;
            }

            if refs.iter().any(|reference| {
                pending_set.contains(reference) && !context.contains_key(reference)
            }) {
                next_pending.push(key);
                continue;
            }

            if let Some(default) = resolve_default_value(&key, secret_config, &context)? {
                results.insert(key.clone(), Some(default.clone()));
                context.insert(key.clone(), Some(default));
                resolved.insert(key);
                progressed = true;
            }
        }

        if !progressed && !next_pending.is_empty() {
            return Err(FnoxError::Config(format!(
                "Interpolation dependency cycle among fallback defaults: {}",
                next_pending.join(", ")
            )));
        }

        pending = next_pending;
    }

    Ok(resolved)
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
    profile: &[String],
    key: &str,
    secret_config: &SecretConfig,
) -> Result<Option<String>> {
    resolve_secret_raw(config, profile, key, secret_config).await
}

async fn resolve_interpolated_default_value(
    config: &Config,
    profile: &[String],
    key: &str,
    secret_config: &SecretConfig,
) -> Result<Option<String>> {
    let Some(default) = &secret_config.default else {
        return Ok(None);
    };
    if !has_default_interpolation(default) {
        return Ok(None);
    }

    let secrets = config.get_secrets(profile)?;
    if !secrets.contains_key(key) {
        return Ok(None);
    }

    let mut subset = collect_interpolation_closure(config, profile, key, &secrets)?;
    // The caller has already attempted the root secret's provider. Keep the
    // root in the dependency graph for cycle detection, but remove the source
    // that would cause the provider to be retried.
    let root = subset
        .get_mut(key)
        .expect("interpolation closure contains its root");
    root.set_provider(None);
    root.set_value(None);
    root.sync = None;

    let mut resolved = resolve_secrets_batch(config, profile, &subset).await?;
    if let Some(Some(value)) = resolved.shift_remove(key) {
        return Ok(Some(value));
    }
    let resolved_context: HashMap<String, Option<String>> = resolved.into_iter().collect();
    let default = render_default_template(key, default, &resolved_context)?;
    Ok(Some(apply_post_processing(default, secret_config)?))
}

async fn resolve_secret_raw(
    config: &Config,
    profile: &[String],
    key: &str,
    secret_config: &SecretConfig,
) -> Result<Option<String>> {
    // Priority 1: Provider (if specified and has a value)
    let provider_value = match try_resolve_from_provider(config, profile, secret_config).await {
        Ok(value) => value,
        Err(error) if secret_config.default.is_some() => {
            log_provider_default_fallback(
                key,
                &error,
                resolve_if_missing_behavior(secret_config, config),
            );
            None
        }
        Err(error) => return Err(error),
    };

    if let Some(value) = provider_value {
        let processed = apply_post_processing(value, secret_config)?;
        return Ok(Some(processed));
    }

    // Priority 2: Default value
    if secret_config
        .default
        .as_deref()
        .is_some_and(has_default_interpolation)
        && let Some(value) =
            resolve_interpolated_default_value(config, profile, key, secret_config).await?
    {
        return Ok(Some(value));
    }

    if let Some(value) = resolve_default_value(key, secret_config, &HashMap::new())? {
        return Ok(Some(value));
    }

    // Priority 3: Environment variable
    let value_to_process = {
        let _access = PROVIDER_ENV_ACCESS.read().await;
        if let Ok(env_value) = env::var(key) {
            tracing::debug!("Found secret '{}' in current environment", key);
            Some(env_value)
        } else {
            None
        }
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
    profile: &[String],
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
    let providers = config.get_providers(profile)?;
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
    profile: &[String],
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
            if prompt_and_run_auth_guarded(config, provider_config, provider_name, &error).await? {
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

async fn prompt_and_run_auth_guarded(
    config: &Config,
    provider_config: &ProviderConfig,
    provider_name: &str,
    error: &FnoxError,
) -> Result<bool> {
    let Some(auth_command) =
        prompt_for_auth_command(config, provider_config, provider_name, error)?
    else {
        return Ok(false);
    };

    env::with_provider_env(&[], || async { run_confirmed_auth_command(auth_command) }).await
}

/// Helper to get a single secret from a provider without auth retry logic.
/// Creates the provider instance and calls `get_secret`.
async fn try_get_secret(
    config: &Config,
    profile: &[String],
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

    let mut ctx = ResolutionContext::new();
    let resolved_provider = resolve_provider_config_with_context(
        config,
        profile,
        provider_name,
        provider_config,
        &mut ctx,
    )
    .await?;
    let prepared_provider =
        prepare_provider_read(config, profile, provider_name, resolved_provider, &mut ctx).await?;
    let _access = PROVIDER_ENV_ACCESS.read().await;
    let provider = prepared_provider.instantiate(config, profile, provider_name)?;
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

fn resolve_default_value(
    key: &str,
    secret_config: &SecretConfig,
    resolved_so_far: &HashMap<String, Option<String>>,
) -> Result<Option<String>> {
    let Some(default) = &secret_config.default else {
        return Ok(None);
    };

    tracing::debug!("Using default value for secret '{}'", key);
    let value = if has_default_interpolation(default) {
        render_default_template(key, default, resolved_so_far)?
    } else {
        default.clone()
    };
    Ok(Some(apply_post_processing(value, secret_config)?))
}

/// Resolves multiple secrets efficiently using batch operations when possible.
///
/// Secrets are resolved in dependency order using Kahn's algorithm. Provider environment
/// dependencies, provider configuration secret references, nested provider dependencies,
/// and interpolated defaults are resolved before the secrets that consume them. Between
/// resolution levels, resolved values are set as environment variables so subsequent
/// providers can read them.
///
/// Returns an error immediately if any secret with `if_missing = "error"` fails to resolve.
pub async fn resolve_secrets_batch(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
) -> Result<IndexMap<String, Option<String>>> {
    Ok(resolve_secrets_batch_inner(
        config,
        profile,
        secrets,
        &IndexMap::new(),
        BatchFailureMode::FailFast,
    )
    .await?
    .values)
}

/// Adds provider and interpolated-default dependencies required to resolve a set of secrets.
pub fn include_resolution_dependencies(
    config: &Config,
    profile: &[String],
    all_secrets: &IndexMap<String, SecretConfig>,
    roots: &IndexMap<String, SecretConfig>,
) -> Result<IndexMap<String, SecretConfig>> {
    let providers = config.get_providers(profile)?;
    let default_provider = config.get_default_provider(profile)?;
    let mut requested = roots.clone();

    loop {
        let mut added = false;
        let keys: Vec<_> = requested.keys().cloned().collect();
        for key in keys {
            let secret = requested[&key].clone();
            let provider_name = secret
                .sync
                .as_ref()
                .map(|sync| sync.provider.as_str())
                .or_else(|| {
                    secret
                        .value()
                        .is_some()
                        .then(|| secret.provider().or(default_provider.as_deref()))
                        .flatten()
                });

            if let Some(provider) = provider_name.and_then(|name| providers.get(name)) {
                for dependency in provider.resolution_dependencies(&providers) {
                    if !requested.contains_key(&dependency)
                        && let Some(secret) = all_secrets.get(&dependency)
                    {
                        requested.insert(dependency, secret.clone());
                        added = true;
                    }
                }
            }

            if let Some(default) = &secret.default {
                for dependency in extract_default_references(default) {
                    if !requested.contains_key(&dependency)
                        && let Some(secret) = all_secrets.get(&dependency)
                    {
                        requested.insert(dependency, secret.clone());
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }

    Ok(requested)
}

/// Values and provider diagnostics collected by best-effort batch resolution.
#[derive(Debug, Default)]
pub struct BestEffortBatchResolution {
    pub values: IndexMap<String, Option<String>>,
    pub errors: IndexMap<String, String>,
}

/// Resolves multiple secrets while retaining successful values and per-secret diagnostics
/// when provider-backed siblings fail. Structural configuration and post-processing errors
/// still fail the batch.
pub async fn resolve_secrets_batch_best_effort(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
) -> Result<BestEffortBatchResolution> {
    resolve_secrets_batch_inner(
        config,
        profile,
        secrets,
        &IndexMap::new(),
        BatchFailureMode::BestEffort,
    )
    .await
}

/// Resolves multiple secrets while treating previously resolved values as
/// dependencies that are already available.
pub async fn resolve_secrets_batch_with_pre_resolved(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    pre_resolved: &IndexMap<String, Option<String>>,
) -> Result<IndexMap<String, Option<String>>> {
    Ok(resolve_secrets_batch_inner(
        config,
        profile,
        secrets,
        pre_resolved,
        BatchFailureMode::FailFast,
    )
    .await?
    .values)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BatchFailureMode {
    FailFast,
    BestEffort,
}

async fn resolve_secrets_batch_inner(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    pre_resolved: &IndexMap<String, Option<String>>,
    failure_mode: BatchFailureMode,
) -> Result<BestEffortBatchResolution> {
    // Classify each secret: provider-backed vs no-provider
    let mut secret_provider: HashMap<String, (String, String)> = HashMap::new(); // key -> (provider_name, provider_value)
    let mut no_provider = Vec::new();

    let providers = config.get_providers(profile)?;
    let all_keys: Vec<String> = secrets.keys().cloned().collect();
    let secret_keys: HashSet<&str> = all_keys
        .iter()
        .map(|key| key.as_str())
        .chain(pre_resolved.keys().map(|key| key.as_str()))
        .collect();
    let mut default_deps: HashMap<String, Vec<String>> = HashMap::new();
    let mut hard_default_deps: HashMap<String, Vec<String>> = HashMap::new();

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

    let no_provider_set: HashSet<&str> = no_provider.iter().map(|s| s.as_str()).collect();
    for (key, secret_config) in secrets {
        let provider_is_unconfigured = secret_provider
            .get(key)
            .is_some_and(|(provider_name, _)| !providers.contains_key(provider_name));
        let hard_default = no_provider_set.contains(key.as_str()) || provider_is_unconfigured;

        let Some(default) = &secret_config.default else {
            continue;
        };

        let refs = extract_default_references(default);
        if hard_default && refs.iter().any(|reference| reference == key) {
            return Err(FnoxError::Config(format!(
                "Secret '{}' has an interpolation cycle in default value",
                key
            )));
        }

        let mut deps = Vec::new();
        for reference in refs {
            if secret_keys.contains(reference.as_str()) {
                deps.push(reference);
            } else if hard_default {
                return Err(default_reference_error(key, &reference));
            }
        }

        if !deps.is_empty() {
            default_deps.insert(key.clone(), deps.clone());
            if hard_default {
                hard_default_deps.insert(key.clone(), deps);
            }
        }
    }

    // Build dependency graph and compute resolution levels using Kahn's algorithm.
    let mut deps_for_secret: HashMap<String, Vec<String>> = HashMap::new();
    for (key, (provider_name, _)) in &secret_provider {
        let deps = providers
            .get(provider_name)
            .map(|provider| provider.resolution_dependencies(&providers))
            .unwrap_or_default();
        deps_for_secret.insert(key.clone(), deps);
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

    let (levels, cycle) = compute_resolution_levels(&all_keys, &deps_for_secret, &no_provider_set);

    // Resolve each level in order
    let mut temp_results: HashMap<String, Option<String>> =
        pre_resolved.clone().into_iter().collect();
    let mut temp_errors = HashMap::new();
    if failure_mode == BatchFailureMode::FailFast {
        let _access = PROVIDER_ENV_ACCESS.write().await;
        for (key, value) in pre_resolved {
            if let Some(value) = value {
                env::set_var(key, value);
            }
        }
    }

    for ready in &levels {
        let level_results = resolve_level(
            config,
            profile,
            secrets,
            &secret_provider,
            ready,
            &temp_results,
            failure_mode,
        )
        .await?;

        // Normal resolution exports every value for subsequent levels and callers.
        // Check resolution scopes only declared dependencies around each provider.
        if failure_mode == BatchFailureMode::FailFast {
            let _access = PROVIDER_ENV_ACCESS.write().await;
            for (key, value) in &level_results.values {
                if let Some(val) = value {
                    env::set_var(key, val);
                }
            }
        }

        temp_results.extend(level_results.values);
        temp_errors.extend(level_results.errors);
    }

    // Handle any remaining secrets (cycles) - resolve best-effort
    if !cycle.is_empty() {
        let cycle_keys: HashSet<&str> = cycle.iter().map(|key| key.as_str()).collect();
        let has_default_cycle = cycle.iter().any(|key| {
            hard_default_deps.get(key).is_some_and(|refs| {
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
            &cycle,
            &temp_results,
            failure_mode,
        )
        .await?;
        temp_results.extend(level_results.values);
        temp_errors.extend(level_results.errors);
    }

    // Build final results in the original order from the input secrets IndexMap
    let mut results = IndexMap::new();
    let mut errors = IndexMap::new();
    for (key, _secret_config) in secrets {
        if let Some(value) = temp_results.remove(key) {
            results.insert(key.clone(), value);
        }
        if let Some(error) = temp_errors.remove(key) {
            errors.insert(key.clone(), error);
        }
    }

    Ok(BestEffortBatchResolution {
        values: results,
        errors,
    })
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
#[derive(Default)]
struct LevelResolution {
    values: HashMap<String, Option<String>>,
    errors: HashMap<String, String>,
}

async fn resolve_level(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    secret_provider: &HashMap<String, (String, String)>,
    ready: &[String],
    resolved_so_far: &HashMap<String, Option<String>>,
    failure_mode: BatchFailureMode,
) -> Result<LevelResolution> {
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
        } else {
            level_no_provider.push(key.clone());
        }
    }

    let mut level_resolution = LevelResolution::default();

    let provider_results: Vec<_> = stream::iter(by_provider)
        .map(|(provider_name, provider_secrets)| async move {
            resolve_provider_batch(
                config,
                profile,
                secrets,
                &provider_name,
                provider_secrets,
                resolved_so_far,
                failure_mode,
            )
            .await
        })
        .buffer_unordered(10)
        .collect()
        .await;

    for provider_result in provider_results {
        let provider_resolution = provider_result?;
        level_resolution.values.extend(provider_resolution.values);
        level_resolution.errors.extend(provider_resolution.errors);
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
        level_resolution.values.insert(key, value);
    }

    Ok(level_resolution)
}

async fn resolve_no_provider_secret(
    config: &Config,
    profile: &[String],
    key: &str,
    secret_config: &SecretConfig,
    resolved_so_far: &HashMap<String, Option<String>>,
) -> Result<Option<String>> {
    if let Some(value) = resolve_default_value(key, secret_config, resolved_so_far)? {
        return Ok(Some(value));
    }

    resolve_secret_raw(config, profile, key, secret_config).await
}

/// Resolve all secrets for a single provider using batch operations
async fn resolve_provider_batch(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    provider_name: &str,
    provider_secrets: Vec<(String, String)>,
    resolved_so_far: &HashMap<String, Option<String>>,
    failure_mode: BatchFailureMode,
) -> Result<LevelResolution> {
    let mut resolution = LevelResolution::default();

    tracing::debug!(
        "Resolving {} secrets from provider '{}' using batch",
        provider_secrets.len(),
        provider_name
    );

    // Get the provider config
    let providers = config.get_providers(profile)?;
    let provider_config = match providers.get(provider_name) {
        Some(config) => config,
        None => {
            // Find similar provider names for suggestion
            let available_providers: Vec<_> = providers.keys().map(|s| s.as_str()).collect();
            let similar = find_similar(provider_name, available_providers);
            let suggestion = format_suggestions(&similar);

            // Provider not configured, handle errors for all secrets
            let fallback_keys: Vec<String> = provider_secrets
                .iter()
                .map(|(key, _)| key.clone())
                .collect();
            let fallback_resolved = resolve_default_fallbacks(
                &fallback_keys,
                secrets,
                resolved_so_far,
                &mut resolution.values,
            )?;
            for (key, _) in &provider_secrets {
                if fallback_resolved.contains(key) {
                    let secret_config = &secrets[key];
                    log_provider_default_fallback(
                        key,
                        &FnoxError::ProviderNotConfigured {
                            provider: provider_name.to_string(),
                            profile: profile.join(","),
                            config_path: None,
                            suggestion: suggestion.clone(),
                        },
                        resolve_if_missing_behavior(secret_config, config),
                    );
                    continue;
                }

                let secret_config = &secrets[key];
                let if_missing = batch_if_missing_behavior(secret_config, config, failure_mode);
                let error = FnoxError::ProviderNotConfigured {
                    provider: provider_name.to_string(),
                    profile: profile.join(","),
                    config_path: config.provider_sources.get(provider_name).cloned(),
                    suggestion: suggestion.clone(),
                };
                if failure_mode == BatchFailureMode::BestEffort {
                    resolution.errors.insert(key.clone(), error.to_string());
                    resolution.values.insert(key.clone(), None);
                    continue;
                }
                if let Some(error) = handle_provider_error(key, error, if_missing, true) {
                    // Fail fast if if_missing is error
                    return Err(error);
                }
                resolution.values.insert(key.clone(), None);
            }
            return Ok(resolution);
        }
    };

    // Skip interactive providers in non-interactive mode (e.g. TUI).
    // Handle per-secret if_missing policy (like ProviderNotConfigured above)
    // so other providers at the same resolution level are not affected.
    if crate::env::is_non_interactive() && provider_config.requires_interactive_auth() {
        let fallback_keys: Vec<String> = provider_secrets
            .iter()
            .map(|(key, _)| key.clone())
            .collect();
        let fallback_resolved = resolve_default_fallbacks(
            &fallback_keys,
            secrets,
            resolved_so_far,
            &mut resolution.values,
        )?;
        for (key, _) in &provider_secrets {
            if fallback_resolved.contains(key) {
                let secret_config = &secrets[key];
                log_provider_default_fallback(
                    key,
                    &FnoxError::Provider(format!(
                        "Provider '{}' requires interactive authentication and cannot be used in non-interactive mode. Use 'fnox exec' instead.",
                        provider_name
                    )),
                    resolve_if_missing_behavior(secret_config, config),
                );
                continue;
            }

            let secret_config = &secrets[key];
            let if_missing = batch_if_missing_behavior(secret_config, config, failure_mode);
            let error = FnoxError::Provider(format!(
                "Provider '{}' requires interactive authentication and cannot be used in non-interactive mode. Use 'fnox exec' instead.",
                provider_name
            ));
            if failure_mode == BatchFailureMode::BestEffort {
                resolution.errors.insert(key.clone(), error.to_string());
                resolution.values.insert(key.clone(), None);
                continue;
            }
            if let Some(error) = handle_provider_error(key, error, if_missing, true) {
                return Err(error);
            }
            resolution.values.insert(key.clone(), None);
        }
        return Ok(resolution);
    }

    let ctx = ProviderBatchContext {
        config,
        profile,
        secrets,
        provider_name,
        provider_config,
        resolved_so_far,
        failure_mode,
    };

    // Try to get secrets with auth retry on failure
    try_batch_with_auth_retry(&ctx, &provider_secrets, &mut resolution).await
}

struct ProviderBatchContext<'a> {
    config: &'a Config,
    profile: &'a [String],
    secrets: &'a IndexMap<String, SecretConfig>,
    provider_name: &'a str,
    provider_config: &'a ProviderConfig,
    resolved_so_far: &'a HashMap<String, Option<String>>,
    failure_mode: BatchFailureMode,
}

/// Attempts to resolve secrets in batch with optional auth retry.
/// If the initial attempt fails and we're in a TTY with auth prompting enabled,
/// prompts the user to run the auth command and retries once.
async fn try_batch_with_auth_retry(
    ctx: &ProviderBatchContext<'_>,
    provider_secrets: &[(String, String)],
    resolution: &mut LevelResolution,
) -> Result<LevelResolution> {
    // Initial batch secret retrieval attempt before any authentication retry logic
    match try_get_secrets_batch(ctx, provider_secrets).await {
        Ok(batch_results) => {
            let auth_error = extract_auth_error_from_batch(&batch_results);
            if let Some(ref auth_err) = auth_error
                && prompt_and_run_batch_auth(ctx, auth_err).await?
            {
                // Auth prompt successful, retry the batch operation.
                return match try_get_secrets_batch(ctx, provider_secrets).await {
                    Ok(retry_results) => {
                        process_batch_results(
                            ctx.secrets,
                            ctx.config,
                            retry_results,
                            ctx.resolved_so_far,
                            &mut resolution.values,
                            &mut resolution.errors,
                            ctx.failure_mode,
                        )?;
                        Ok(std::mem::take(resolution))
                    }
                    Err(retry_error) => handle_batch_error(
                        ctx.secrets,
                        ctx.config,
                        provider_secrets,
                        &retry_error,
                        ctx.resolved_so_far,
                        resolution,
                        ctx.failure_mode,
                    ),
                };
            }
            // No auth error, or user declined auth prompt. Process original results.
            process_batch_results(
                ctx.secrets,
                ctx.config,
                batch_results,
                ctx.resolved_so_far,
                &mut resolution.values,
                &mut resolution.errors,
                ctx.failure_mode,
            )?;
            Ok(std::mem::take(resolution))
        }
        Err(error) => {
            // Try auth prompt and retry
            if prompt_and_run_batch_auth(ctx, &error).await? {
                // Auth command ran successfully, retry
                match try_get_secrets_batch(ctx, provider_secrets).await {
                    Ok(batch_results) => {
                        process_batch_results(
                            ctx.secrets,
                            ctx.config,
                            batch_results,
                            ctx.resolved_so_far,
                            &mut resolution.values,
                            &mut resolution.errors,
                            ctx.failure_mode,
                        )?;
                        Ok(std::mem::take(resolution))
                    }
                    Err(retry_error) => handle_batch_error(
                        ctx.secrets,
                        ctx.config,
                        provider_secrets,
                        &retry_error,
                        ctx.resolved_so_far,
                        resolution,
                        ctx.failure_mode,
                    ),
                }
            } else {
                // No auth prompt or user declined - apply if_missing handling per secret
                handle_batch_error(
                    ctx.secrets,
                    ctx.config,
                    provider_secrets,
                    &error,
                    ctx.resolved_so_far,
                    resolution,
                    ctx.failure_mode,
                )
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
    resolved_so_far: &HashMap<String, Option<String>>,
    resolution: &mut LevelResolution,
    failure_mode: BatchFailureMode,
) -> Result<LevelResolution> {
    let fallback_keys: Vec<String> = provider_secrets
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    let fallback_resolved = resolve_default_fallbacks(
        &fallback_keys,
        secrets,
        resolved_so_far,
        &mut resolution.values,
    )?;
    for (key, _) in provider_secrets {
        if fallback_resolved.contains(key) {
            let secret_config = &secrets[key];
            log_provider_default_fallback(
                key,
                error,
                resolve_if_missing_behavior(secret_config, config),
            );
            continue;
        }

        let secret_config = &secrets[key];
        let if_missing = batch_if_missing_behavior(secret_config, config, failure_mode);
        let provider_error = FnoxError::Provider(error.to_string());
        if failure_mode == BatchFailureMode::BestEffort {
            resolution
                .errors
                .insert(key.clone(), provider_error.to_string());
            resolution.values.insert(key.clone(), None);
            continue;
        }
        if let Some(err) = handle_provider_error(key, provider_error, if_missing, true) {
            // Fail fast if if_missing is error
            return Err(err);
        }
        resolution.values.insert(key.clone(), None);
    }
    Ok(std::mem::take(resolution))
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

async fn prompt_and_run_batch_auth(
    ctx: &ProviderBatchContext<'_>,
    error: &FnoxError,
) -> Result<bool> {
    let Some(auth_command) =
        prompt_for_auth_command(ctx.config, ctx.provider_config, ctx.provider_name, error)?
    else {
        return Ok(false);
    };

    let values = ProviderEnvOverlay::resolved_values(
        ctx.provider_config.env_dependencies(),
        ctx.resolved_so_far,
    );
    env::with_provider_env(&values, || async {
        run_confirmed_auth_command(auth_command)
    })
    .await
}

/// Helper to get multiple secrets in batch from a provider without auth retry logic.
/// Creates the provider instance and calls `get_secrets_batch` on it.
async fn try_get_secrets_batch(
    ctx: &ProviderBatchContext<'_>,
    provider_secrets: &[(String, String)],
) -> Result<HashMap<String, Result<String>>> {
    // Nested providers use the same pre-resolved dependency context while each
    // provider command receives only its own declared environment values.
    let mut resolution_ctx = ResolutionContext::with_pre_resolved(ctx.resolved_so_far);
    let resolved_provider = resolve_provider_config_with_context(
        ctx.config,
        ctx.profile,
        ctx.provider_name,
        ctx.provider_config,
        &mut resolution_ctx,
    )
    .await?;
    let prepared_provider = prepare_provider_read(
        ctx.config,
        ctx.profile,
        ctx.provider_name,
        resolved_provider,
        &mut resolution_ctx,
    )
    .await?;
    let values = ProviderEnvOverlay::resolved_values(
        ctx.provider_config.env_dependencies(),
        ctx.resolved_so_far,
    );

    env::with_provider_env(&values, || async {
        let provider = prepared_provider.instantiate(ctx.config, ctx.profile, ctx.provider_name)?;
        Ok(provider.get_secrets_batch(provider_secrets).await)
    })
    .await
}

/// Process batch results and populate the results map
fn process_batch_results(
    secrets: &IndexMap<String, SecretConfig>,
    config: &Config,
    batch_results: HashMap<String, Result<String>>,
    resolved_so_far: &HashMap<String, Option<String>>,
    results: &mut HashMap<String, Option<String>>,
    errors: &mut HashMap<String, String>,
    failure_mode: BatchFailureMode,
) -> Result<()> {
    let mut failed = Vec::new();

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
                failed.push((key, e));
            }
        }
    }

    let fallback_keys: Vec<String> = failed.iter().map(|(key, _)| key.clone()).collect();
    let fallback_resolved =
        resolve_default_fallbacks(&fallback_keys, secrets, resolved_so_far, results)?;

    for (key, e) in failed {
        if fallback_resolved.contains(&key) {
            let secret_config = &secrets[&key];
            log_provider_default_fallback(
                &key,
                &e,
                resolve_if_missing_behavior(secret_config, config),
            );
            continue;
        }

        let secret_config = &secrets[&key];
        let if_missing = batch_if_missing_behavior(secret_config, config, failure_mode);
        if failure_mode == BatchFailureMode::BestEffort {
            errors.insert(key.clone(), e.to_string());
            results.insert(key, None);
            continue;
        }
        if let Some(error) = handle_provider_error(&key, e, if_missing, true) {
            // Fail fast if if_missing is error
            return Err(error);
        }
        results.insert(key, None);
    }

    Ok(())
}

fn batch_if_missing_behavior(
    secret_config: &SecretConfig,
    config: &Config,
    failure_mode: BatchFailureMode,
) -> IfMissing {
    match failure_mode {
        BatchFailureMode::FailFast => resolve_if_missing_behavior(secret_config, config),
        BatchFailureMode::BestEffort => IfMissing::Ignore,
    }
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

    fn profile(name: &str) -> Vec<String> {
        vec![name.to_string()]
    }

    fn plain_provider_secret(value: &str) -> SecretConfig {
        let mut secret = SecretConfig::new();
        secret.set_provider(Some("plain".to_string()));
        secret.set_value(Some(value.to_string()));
        secret
    }

    fn provider_secret_not_found(secret: &str) -> FnoxError {
        FnoxError::ProviderSecretNotFound {
            provider: "plain".to_string(),
            secret: secret.to_string(),
            hint: String::new(),
            url: "https://fnox.jdx.dev/providers".to_string(),
        }
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

        let resolved = resolve_secrets_batch(&config, &profile("default"), &secrets)
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

        let resolved = resolve_secrets_batch(&config, &profile("dev"), &secrets)
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

        let err = resolve_secrets_batch(&config, &profile("default"), &secrets)
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

        let err = resolve_secrets_batch(&config, &profile("default"), &secrets)
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
            ProviderConfig::Plain {
                auth_command: None,
                daemon_cache: None,
            },
        );

        let mut secrets = IndexMap::new();
        secrets.insert("POSTGRES_USER".to_string(), plain_provider_secret("app"));
        secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${POSTGRES_USER}@localhost/fnox"),
        );

        let resolved = resolve_secrets_batch(&config, &profile("default"), &secrets)
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
    async fn test_interpolated_default_can_use_pre_resolved_reference() {
        let config = Config::new();
        let secrets = IndexMap::from([(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${POSTGRES_USER}@localhost/fnox"),
        )]);
        let pre_resolved =
            IndexMap::from([("POSTGRES_USER".to_string(), Some("cached-user".to_string()))]);

        let resolved = resolve_secrets_batch_with_pre_resolved(
            &config,
            &profile("default"),
            &secrets,
            &pre_resolved,
        )
        .await
        .unwrap();

        assert_eq!(
            resolved
                .get("DATABASE_URL")
                .and_then(|value| value.as_ref()),
            Some(&"postgres://cached-user@localhost/fnox".to_string())
        );
    }

    #[tokio::test]
    async fn test_provider_value_wins_over_interpolated_default() {
        let mut config = Config::new();
        config.providers.insert(
            "plain".to_string(),
            ProviderConfig::Plain {
                auth_command: None,
                daemon_cache: None,
            },
        );

        let mut secret = plain_provider_secret("provider-value");
        secret.default = Some("${MISSING_REF}".to_string());

        let mut secrets = IndexMap::new();
        secrets.insert("API_KEY".to_string(), secret);

        let resolved = resolve_secrets_batch(&config, &profile("default"), &secrets)
            .await
            .unwrap();

        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_ref()),
            Some(&"provider-value".to_string())
        );
    }

    #[tokio::test]
    async fn test_resolve_secret_provider_value_wins_over_interpolated_default() {
        let mut config = Config::new();
        config.providers.insert(
            "plain".to_string(),
            ProviderConfig::Plain {
                auth_command: None,
                daemon_cache: None,
            },
        );

        let mut secret = plain_provider_secret("provider-value");
        secret.default = Some("${MISSING_REF}".to_string());
        config.secrets.insert("API_KEY".to_string(), secret);

        let secret_config = config.secrets.get("API_KEY").unwrap();
        let resolved = resolve_secret(&config, &profile("default"), "API_KEY", secret_config)
            .await
            .unwrap();

        assert_eq!(resolved, Some("provider-value".to_string()));
    }

    #[test]
    fn test_batch_default_fallback_can_use_same_batch_success() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        secrets.insert("HOSTNAME".to_string(), SecretConfig::new());
        secrets.insert(
            "DATABASE_URL".to_string(),
            default_secret("postgres://${HOSTNAME}/fnox"),
        );

        let mut batch_results = HashMap::new();
        batch_results.insert("HOSTNAME".to_string(), Ok("localhost".to_string()));
        batch_results.insert(
            "DATABASE_URL".to_string(),
            Err(provider_secret_not_found("DATABASE_URL")),
        );

        let resolved_so_far = HashMap::new();
        let mut results = HashMap::new();
        let mut errors = HashMap::new();
        process_batch_results(
            &secrets,
            &config,
            batch_results,
            &resolved_so_far,
            &mut results,
            &mut errors,
            BatchFailureMode::FailFast,
        )
        .unwrap();

        assert_eq!(
            results.get("DATABASE_URL").and_then(|value| value.as_ref()),
            Some(&"postgres://localhost/fnox".to_string())
        );
    }

    #[test]
    fn test_batch_default_fallback_skips_unresolved_reference() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        let mut host = SecretConfig::new();
        host.if_missing = Some(IfMissing::Ignore);
        let mut database_url = default_secret("postgres://${DB_HOST}/fnox");
        database_url.if_missing = Some(IfMissing::Ignore);
        secrets.insert("DB_HOST".to_string(), host);
        secrets.insert("DATABASE_URL".to_string(), database_url);

        let mut batch_results = HashMap::new();
        batch_results.insert(
            "DB_HOST".to_string(),
            Err(provider_secret_not_found("DB_HOST")),
        );
        batch_results.insert(
            "DATABASE_URL".to_string(),
            Err(provider_secret_not_found("DATABASE_URL")),
        );

        let resolved_so_far = HashMap::new();
        let mut results = HashMap::new();
        let mut errors = HashMap::new();
        process_batch_results(
            &secrets,
            &config,
            batch_results,
            &resolved_so_far,
            &mut results,
            &mut errors,
            BatchFailureMode::FailFast,
        )
        .unwrap();

        assert_eq!(results.get("DB_HOST"), Some(&None));
        assert_eq!(results.get("DATABASE_URL"), Some(&None));
    }

    #[test]
    fn test_batch_default_fallback_reports_cycle() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        secrets.insert("A".to_string(), default_secret("${B}"));
        secrets.insert("B".to_string(), default_secret("${A}"));

        let mut batch_results = HashMap::new();
        batch_results.insert("A".to_string(), Err(provider_secret_not_found("A")));
        batch_results.insert("B".to_string(), Err(provider_secret_not_found("B")));

        let resolved_so_far = HashMap::new();
        let mut results = HashMap::new();
        let mut errors = HashMap::new();
        let err = process_batch_results(
            &secrets,
            &config,
            batch_results,
            &resolved_so_far,
            &mut results,
            &mut errors,
            BatchFailureMode::FailFast,
        )
        .unwrap_err();
        let msg = format!("{err}");

        assert!(
            msg.contains("Interpolation dependency cycle among fallback defaults"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_best_effort_batch_keeps_successful_siblings() {
        let config = Config::new();
        let mut required = SecretConfig::new();
        required.if_missing = Some(IfMissing::Error);
        let secrets = [
            ("GOOD".to_string(), required.clone()),
            ("BAD".to_string(), required),
        ]
        .into_iter()
        .collect();
        let batch_results = [
            ("GOOD".to_string(), Ok("value".to_string())),
            ("BAD".to_string(), Err(provider_secret_not_found("BAD"))),
        ]
        .into_iter()
        .collect();
        let mut results = HashMap::new();
        let mut errors = HashMap::new();

        process_batch_results(
            &secrets,
            &config,
            batch_results,
            &HashMap::new(),
            &mut results,
            &mut errors,
            BatchFailureMode::BestEffort,
        )
        .unwrap();

        assert_eq!(results.get("GOOD"), Some(&Some("value".to_string())));
        assert_eq!(results.get("BAD"), Some(&None));
        assert!(errors["BAD"].contains("secret 'BAD' not found"));
    }

    #[test]
    fn test_best_effort_batch_omits_recovered_errors() {
        let config = Config::new();
        let mut secret = default_secret("fallback");
        secret.if_missing = Some(IfMissing::Error);
        let secrets = [("RECOVERED".to_string(), secret)].into_iter().collect();
        let batch_results = [(
            "RECOVERED".to_string(),
            Err(provider_secret_not_found("RECOVERED")),
        )]
        .into_iter()
        .collect();
        let mut results = HashMap::new();
        let mut errors = HashMap::new();

        process_batch_results(
            &secrets,
            &config,
            batch_results,
            &HashMap::new(),
            &mut results,
            &mut errors,
            BatchFailureMode::BestEffort,
        )
        .unwrap();

        assert_eq!(
            results.get("RECOVERED"),
            Some(&Some("fallback".to_string()))
        );
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn test_scoped_provider_env_restores_declared_dependencies() {
        const EXISTING: &str = "FNOX_TEST_SCOPED_PROVIDER_EXISTING";
        const ABSENT: &str = "FNOX_TEST_SCOPED_PROVIDER_ABSENT";
        const UNRELATED: &str = "FNOX_TEST_SCOPED_PROVIDER_UNRELATED";

        env::set_var(EXISTING, "original");
        env::remove_var(ABSENT);
        env::remove_var(UNRELATED);
        let resolved = HashMap::from([
            (EXISTING.to_string(), Some("replacement".to_string())),
            (ABSENT.to_string(), Some("temporary".to_string())),
            (UNRELATED.to_string(), Some("secret".to_string())),
        ]);

        let values = ProviderEnvOverlay::resolved_values(&[EXISTING, ABSENT], &resolved);
        assert_eq!(values.len(), 2);
        assert!(values.iter().all(|(key, _)| key != UNRELATED));

        env::with_provider_env(&values, || async {
            assert_eq!(env::var(EXISTING).as_deref(), Ok("replacement"));
            assert_eq!(env::var(ABSENT).as_deref(), Ok("temporary"));
            assert!(env::var_os(UNRELATED).is_none());
        })
        .await;

        assert_eq!(env::var(EXISTING).as_deref(), Ok("original"));
        assert!(env::var_os(ABSENT).is_none());
        assert!(env::var_os(UNRELATED).is_none());
        env::remove_var(EXISTING);
    }

    #[tokio::test]
    async fn test_batch_auth_prompt_checks_before_acquiring_provider_env_access() {
        let config = Config::new();
        let provider_config = ProviderConfig::OnePassword {
            vault: crate::providers::OptionStringOrSecretRef::literal("default"),
            account: crate::providers::OptionStringOrSecretRef::none(),
            token: crate::providers::OptionStringOrSecretRef::none(),
            auth_command: None,
            daemon_cache: None,
        };
        let secrets = IndexMap::new();
        let profile = profile("default");
        let resolved = HashMap::from([(
            "OP_SERVICE_ACCOUNT_TOKEN".to_string(),
            Some("token".to_string()),
        )]);
        let ctx = ProviderBatchContext {
            config: &config,
            profile: &profile,
            secrets: &secrets,
            provider_name: "1password",
            provider_config: &provider_config,
            resolved_so_far: &resolved,
            failure_mode: BatchFailureMode::FailFast,
        };
        let error = provider_secret_not_found("TEST");
        assert!(
            !ProviderEnvOverlay::resolved_values(provider_config.env_dependencies(), &resolved)
                .is_empty()
        );

        let _access = PROVIDER_ENV_ACCESS.write().await;
        let prompted = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            prompt_and_run_batch_auth(&ctx, &error),
        )
        .await
        .expect("auth validation should not wait for provider environment access")
        .unwrap();

        assert!(!prompted);
    }

    #[tokio::test]
    async fn test_provider_env_access_serializes_overlays() {
        const KEY: &str = "FNOX_TEST_SERIALIZED_PROVIDER_ENV";

        env::remove_var(KEY);
        let first_started = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let release_first = std::sync::Arc::new(tokio::sync::Notify::new());
        let second_started = std::sync::Arc::new(tokio::sync::Notify::new());

        let first = {
            let first_started = first_started.clone();
            let release_first = release_first.clone();
            tokio::spawn(async move {
                let _access = PROVIDER_ENV_ACCESS.write().await;
                let _env = ProviderEnvOverlay::apply(&[(KEY.to_string(), "first".to_string())]);
                first_started.wait().await;
                release_first.notified().await;
                assert_eq!(env::var(KEY).as_deref(), Ok("first"));
            })
        };

        first_started.wait().await;
        let second = {
            let second_started = second_started.clone();
            tokio::spawn(async move {
                let _access = PROVIDER_ENV_ACCESS.write().await;
                let _env = ProviderEnvOverlay::apply(&[(KEY.to_string(), "second".to_string())]);
                second_started.notify_one();
                assert_eq!(env::var(KEY).as_deref(), Ok("second"));
            })
        };

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                second_started.notified()
            )
            .await
            .is_err()
        );
        release_first.notify_one();
        first.await.unwrap();
        second_started.notified().await;
        second.await.unwrap();
        assert!(env::var_os(KEY).is_none());
    }

    #[tokio::test]
    async fn test_environment_fallback_waits_for_provider_overlay_restoration() {
        const KEY: &str = "FNOX_TEST_PROVIDER_ENV_FALLBACK";

        env::remove_var(KEY);
        let overlay_started = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let release_overlay = std::sync::Arc::new(tokio::sync::Notify::new());
        let read_started = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let read_finished = std::sync::Arc::new(tokio::sync::Notify::new());

        let overlay = {
            let overlay_started = overlay_started.clone();
            let release_overlay = release_overlay.clone();
            tokio::spawn(async move {
                let _access = PROVIDER_ENV_ACCESS.write().await;
                let _env = ProviderEnvOverlay::apply(&[(KEY.to_string(), "temporary".to_string())]);
                overlay_started.wait().await;
                release_overlay.notified().await;
            })
        };

        overlay_started.wait().await;
        let reader = {
            let read_started = read_started.clone();
            let read_finished = read_finished.clone();
            tokio::spawn(async move {
                let config = Config::new();
                let mut secret = SecretConfig::new();
                secret.if_missing = Some(IfMissing::Ignore);
                read_started.wait().await;
                let result =
                    resolve_secret_raw(&config, &["default".to_string()], KEY, &secret).await;
                read_finished.notify_one();
                result
            })
        };

        read_started.wait().await;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                read_finished.notified()
            )
            .await
            .is_err()
        );
        release_overlay.notify_one();
        overlay.await.unwrap();
        assert_eq!(reader.await.unwrap().unwrap(), None);
        assert!(env::var_os(KEY).is_none());
    }

    #[tokio::test]
    async fn test_configured_provider_default_reference_orders_fallback_dependency() {
        let mut config = Config::new();
        config.providers.insert(
            "plain".to_string(),
            ProviderConfig::Plain {
                auth_command: None,
                daemon_cache: None,
            },
        );

        let mut database_url = plain_provider_secret("provider-value");
        database_url.default = Some("postgres://${DB_HOST}/fnox".to_string());

        let mut secrets = IndexMap::new();
        secrets.insert("DATABASE_URL".to_string(), database_url);
        secrets.insert("DB_HOST".to_string(), default_secret("localhost"));

        let resolved = resolve_secrets_batch(&config, &profile("default"), &secrets)
            .await
            .unwrap();

        assert_eq!(
            resolved
                .get("DATABASE_URL")
                .and_then(|value| value.as_ref()),
            Some(&"provider-value".to_string())
        );
        assert_eq!(
            resolved.get("DB_HOST").and_then(|value| value.as_ref()),
            Some(&"localhost".to_string())
        );
    }

    #[tokio::test]
    async fn test_interpolated_default_errors_for_empty_reference() {
        let config = Config::new();
        let mut secrets = IndexMap::new();
        secrets.insert("DATABASE_URL".to_string(), default_secret("${}"));

        let err = resolve_secrets_batch(&config, &profile("default"), &secrets)
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

        let resolved = resolve_secrets_batch(&config, &profile("default"), &secrets)
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
        let resolved = resolve_secret(&config, &profile("default"), "DATABASE_URL", secret_config)
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
        let resolved = resolve_secret(&config, &profile("default"), "DATABASE_URL", secret_config)
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
        let resolved = resolve_secret(&config, &profile("default"), "DATABASE_URL", secret_config)
            .await
            .unwrap();

        assert_eq!(resolved, Some("postgres://localhost/fnox".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_secret_preserves_cycle_through_root_fallback() {
        use crate::providers::OptionStringOrSecretRef;

        let mut config = Config::new();
        config.providers.insert(
            "onepassword".to_string(),
            ProviderConfig::OnePassword {
                vault: OptionStringOrSecretRef::none(),
                account: OptionStringOrSecretRef::none(),
                token: OptionStringOrSecretRef::none(),
                auth_command: None,
                daemon_cache: None,
            },
        );

        let mut root = default_secret("${DEPENDENT_SECRET}");
        root.set_provider(Some("missing-provider".to_string()));
        root.set_value(Some("encrypted-root".to_string()));
        root.if_missing = Some(IfMissing::Ignore);
        config
            .secrets
            .insert("OP_SERVICE_ACCOUNT_TOKEN".to_string(), root);

        let mut dependent = SecretConfig::new();
        dependent.set_provider(Some("onepassword".to_string()));
        dependent.set_value(Some("op://vault/item/field".to_string()));
        config
            .secrets
            .insert("DEPENDENT_SECRET".to_string(), dependent);

        let root_config = &config.secrets["OP_SERVICE_ACCOUNT_TOKEN"];
        let err = resolve_secret(
            &config,
            &profile("default"),
            "OP_SERVICE_ACCOUNT_TOKEN",
            root_config,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("Interpolation dependency cycle among secrets"),
            "unexpected error: {err}"
        );
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
        let resolved = resolve_secret(&config, &profile("default"), "DATABASE_URL", secret_config)
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
