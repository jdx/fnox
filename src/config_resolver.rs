//! Configuration value resolution for provider configs.
//!
//! This module handles resolving `ConfigValue` fields in provider configurations,
//! which may be either plain values or references to secrets.

use crate::config::{Config, ConfigValue, SecretConfig};
use crate::env;
use crate::error::{FnoxError, Result};

/// Context for resolving secrets with cycle detection.
///
/// Tracks the resolution stack to detect and prevent circular secret references.
pub struct ResolutionContext<'a> {
    pub config: &'a Config,
    pub profile: String,
    resolving: Vec<String>,
}

impl<'a> ResolutionContext<'a> {
    pub fn new(config: &'a Config, profile: &str) -> Self {
        Self {
            config,
            profile: profile.to_string(),
            resolving: Vec::new(),
        }
    }

    /// Check if resolving this secret would create a cycle.
    pub fn would_cycle(&self, secret_name: &str) -> bool {
        self.resolving.contains(&secret_name.to_string())
    }

    /// Push a secret onto the resolution stack.
    pub fn push(&mut self, secret_name: &str) {
        self.resolving.push(secret_name.to_string());
    }

    /// Pop a secret from the resolution stack.
    pub fn pop(&mut self) {
        self.resolving.pop();
    }

    /// Get the current resolution stack for error messages.
    pub fn stack_trace(&self) -> String {
        self.resolving.join(" → ")
    }
}

/// Resolve a ConfigValue to a plain string.
pub async fn resolve(value: &ConfigValue, ctx: &mut ResolutionContext<'_>) -> Result<String> {
    match value {
        ConfigValue::Plain(s) => Ok(s.clone()),
        ConfigValue::SecretRef(r) => resolve_secret_ref(&r.secret, ctx).await,
    }
}

/// Resolve an optional ConfigValue.
pub async fn resolve_opt(
    value: &Option<ConfigValue>,
    ctx: &mut ResolutionContext<'_>,
) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(v) => Ok(Some(resolve(v, ctx).await?)),
    }
}

/// Resolve a vec of ConfigValues.
pub async fn resolve_vec(
    values: &[ConfigValue],
    ctx: &mut ResolutionContext<'_>,
) -> Result<Vec<String>> {
    let mut resolved = Vec::with_capacity(values.len());
    for v in values {
        resolved.push(resolve(v, ctx).await?);
    }
    Ok(resolved)
}

/// Resolve a secret reference by name.
///
/// Priority:
/// 1. Environment variable with the secret name
/// 2. Secret defined in config (resolved via its provider)
async fn resolve_secret_ref(secret_name: &str, ctx: &mut ResolutionContext<'_>) -> Result<String> {
    // Check for cycle
    if ctx.would_cycle(secret_name) {
        return Err(FnoxError::Config(format!(
            "Circular secret reference detected: {} → {}",
            ctx.stack_trace(),
            secret_name
        )));
    }

    // Priority 1: Check environment variable (no cycle possible)
    if let Ok(env_value) = env::var(secret_name) {
        tracing::debug!(
            "Resolved secret '{}' from environment variable",
            secret_name
        );
        return Ok(env_value);
    }

    // Push onto stack before resolving
    ctx.push(secret_name);

    // Priority 2: Look up secret in config
    let result = resolve_secret_from_config(secret_name, ctx).await;

    // Pop from stack
    ctx.pop();

    result
}

/// Resolve a secret from config.
async fn resolve_secret_from_config(
    secret_name: &str,
    ctx: &mut ResolutionContext<'_>,
) -> Result<String> {
    let secrets = ctx.config.get_secrets(&ctx.profile)?;
    let secret_config = secrets.get(secret_name).ok_or_else(|| {
        FnoxError::Config(format!(
            "Secret '{}' not found in config or environment. \
            Provider config secrets must be defined in [secrets] or available as environment variables.",
            secret_name
        ))
    })?;

    resolve_secret_for_provider_config(secret_name, secret_config, ctx).await
}

/// Resolve a secret specifically for use in provider config.
///
/// Uses `Box::pin` for the recursive async call to `create_provider` to satisfy
/// the compiler's requirement for bounded async recursion.
fn resolve_secret_for_provider_config<'a>(
    secret_name: &'a str,
    secret_config: &'a SecretConfig,
    ctx: &'a mut ResolutionContext<'_>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
    Box::pin(async move {
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
        } else if let Some(default) = ctx.config.get_default_provider(&ctx.profile)? {
            default
        } else {
            return Err(FnoxError::Config(format!(
                "Secret '{}' has no provider specified and no default provider configured",
                secret_name
            )));
        };

        // Get the provider config
        let providers = ctx.config.get_providers(&ctx.profile);
        let provider_config =
            providers
                .get(&provider_name)
                .ok_or_else(|| FnoxError::ProviderNotConfigured {
                    provider: provider_name.clone(),
                    profile: ctx.profile.clone(),
                    config_path: ctx.config.provider_sources.get(&provider_name).cloned(),
                })?;

        // Create the provider (this will recursively resolve any secret refs in its config)
        let provider = provider_config.create_provider(ctx).await?;

        // Resolve the secret
        let value = provider.get_secret(provider_value).await?;
        tracing::debug!(
            "Resolved secret '{}' from provider '{}'",
            secret_name,
            provider_name
        );
        Ok(value)
    })
}
