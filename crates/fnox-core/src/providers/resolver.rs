//! Provider configuration resolution.
//!
//! This module handles resolving `ProviderConfig` to `ResolvedProviderConfig` by
//! looking up any secret references in the configuration or environment.
//!
//! The resolution process supports recursive secret references (a provider's config
//! can reference a secret from another provider) and detects circular dependencies.

use crate::config::Config;
use crate::env::{self, PROVIDER_ENV_ACCESS, ProviderEnvOverlay};
use crate::error::{FnoxError, Result};
use crate::suggest::{find_similar, format_suggestions};
use std::collections::{HashMap, HashSet};

use super::secret_ref::{OptionProviderSecretRef, OptionStringOrSecretRef, StringOrSecretRef};
use super::{ProviderConfig, ResolvedProviderConfig};

/// Context for resolving provider configurations, tracking the resolution stack
/// to detect circular dependencies.
pub struct ResolutionContext {
    /// Stack of provider names currently being resolved (for cycle detection)
    provider_stack: HashSet<String>,
    /// Stack path for error messages
    resolution_path: Vec<String>,
    pre_resolved: HashMap<String, Option<String>>,
    age_identity_cycle_guard: super::age::AgeIdentityCycleGuard,
}

impl ResolutionContext {
    /// Create a new resolution context
    pub fn new() -> Self {
        Self {
            provider_stack: HashSet::new(),
            resolution_path: Vec::new(),
            pre_resolved: HashMap::new(),
            age_identity_cycle_guard: super::age::AgeIdentityCycleGuard::default(),
        }
    }

    pub(crate) fn with_pre_resolved(pre_resolved: &HashMap<String, Option<String>>) -> Self {
        Self {
            provider_stack: HashSet::new(),
            resolution_path: Vec::new(),
            pre_resolved: pre_resolved.clone(),
            age_identity_cycle_guard: super::age::AgeIdentityCycleGuard::default(),
        }
    }

    pub(crate) fn with_identity_cycle_guard(
        age_identity_cycle_guard: super::age::AgeIdentityCycleGuard,
    ) -> Self {
        Self {
            provider_stack: HashSet::new(),
            resolution_path: Vec::new(),
            pre_resolved: HashMap::new(),
            age_identity_cycle_guard,
        }
    }

    pub(crate) fn age_identity_cycle_guard(&self) -> super::age::AgeIdentityCycleGuard {
        self.age_identity_cycle_guard.clone()
    }

    /// Check if we're already resolving this provider (cycle detection)
    fn is_resolving(&self, provider_name: &str) -> bool {
        self.provider_stack.contains(provider_name)
    }

    /// Push a provider onto the resolution stack
    pub fn push(&mut self, provider_name: &str) {
        self.provider_stack.insert(provider_name.to_string());
        self.resolution_path.push(provider_name.to_string());
    }

    /// Pop a provider from the resolution stack
    pub fn pop(&mut self) {
        if let Some(provider_name) = self.resolution_path.pop() {
            self.provider_stack.remove(&provider_name);
        }
    }

    /// Get the current resolution path as a string for error messages
    fn path_string(&self) -> String {
        self.resolution_path.join(" -> ")
    }
}

impl Default for ResolutionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a `ProviderConfig` to a `ResolvedProviderConfig` by resolving any secret references.
///
/// This function handles recursive resolution - if a provider's config references a secret
/// that itself uses another provider, that provider's config will also be resolved.
///
/// # Arguments
/// * `config` - The full configuration containing secrets and providers
/// * `profile` - The profile to use for secret lookups
/// * `provider_name` - The name of the provider being resolved (for cycle detection)
/// * `provider_config` - The provider configuration to resolve
///
/// # Returns
/// A `ResolvedProviderConfig` with all secret references replaced with actual values.
pub async fn resolve_provider_config(
    config: &Config,
    profile: &[String],
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> Result<ResolvedProviderConfig> {
    let mut ctx = ResolutionContext::new();
    resolve_provider_config_with_context(config, profile, provider_name, provider_config, &mut ctx)
        .await
}

/// Internal function that carries the resolution context for cycle detection.
pub fn resolve_provider_config_with_context<'a>(
    config: &'a Config,
    profile: &'a [String],
    provider_name: &'a str,
    provider_config: &'a ProviderConfig,
    ctx: &'a mut ResolutionContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedProviderConfig>> + Send + 'a>>
{
    Box::pin(async move {
        // Check for circular dependency
        if ctx.is_resolving(provider_name) {
            return Err(FnoxError::ProviderConfigCycle {
                provider: provider_name.to_string(),
                cycle: format!("{} -> {}", ctx.path_string(), provider_name),
            });
        }

        // Push onto resolution stack
        ctx.push(provider_name);

        // Resolve using generated match (capturing result to ensure cleanup on error)
        let result = super::generated::providers_resolver::resolve_provider_config_match(
            config,
            profile,
            provider_name,
            provider_config,
            ctx,
        )
        .await;

        // Pop from resolution stack (always runs, even on error)
        ctx.pop();

        result
    })
}

/// Resolve a required `StringOrSecretRef` field to its actual string value.
pub fn resolve_required<'a>(
    config: &'a Config,
    profile: &'a [String],
    provider_name: &'a str,
    _field_name: &'a str,
    value: &'a StringOrSecretRef,
    ctx: &'a mut ResolutionContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
    Box::pin(async move {
        match value {
            StringOrSecretRef::Literal(s) => Ok(s.clone()),
            StringOrSecretRef::SecretRef { secret } => {
                resolve_secret_ref(config, profile, provider_name, secret, ctx).await
            }
        }
    })
}

/// Resolve an optional `OptionStringOrSecretRef` field to its actual value.
pub fn resolve_option<'a>(
    config: &'a Config,
    profile: &'a [String],
    provider_name: &'a str,
    value: &'a OptionStringOrSecretRef,
    ctx: &'a mut ResolutionContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<String>>> + Send + 'a>> {
    Box::pin(async move {
        match value.as_ref() {
            None => Ok(None),
            Some(StringOrSecretRef::Literal(s)) => Ok(Some(s.clone())),
            Some(StringOrSecretRef::SecretRef { secret }) => {
                let resolved =
                    resolve_secret_ref(config, profile, provider_name, secret, ctx).await?;
                Ok(Some(resolved))
            }
        }
    })
}

/// Resolve an optional provider-backed secret reference to its actual value.
pub fn resolve_provider_ref<'a>(
    config: &'a Config,
    profile: &'a [String],
    value: &'a OptionProviderSecretRef,
    ctx: &'a mut ResolutionContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<String>>> + Send + 'a>> {
    Box::pin(async move {
        let Some(provider_ref) = value.as_ref() else {
            return Ok(None);
        };

        let providers = config.get_providers(profile)?;
        let Some(provider_config) = providers.get(&provider_ref.provider) else {
            let available_providers: Vec<_> = providers.keys().map(|s| s.as_str()).collect();
            let similar = find_similar(&provider_ref.provider, available_providers);
            let suggestion = format_suggestions(&similar);

            return Err(FnoxError::ProviderNotConfigured {
                provider: provider_ref.provider.clone(),
                profile: profile.join(","),
                config_path: config.provider_sources.get(&provider_ref.provider).cloned(),
                suggestion,
            });
        };

        if env::is_non_interactive() && provider_config.requires_interactive_auth() {
            return Err(FnoxError::Provider(format!(
                "Provider '{}' requires interactive authentication and cannot be used in non-interactive mode. Use 'fnox exec' instead.",
                provider_ref.provider
            )));
        }

        let resolved_provider = resolve_provider_config_with_context(
            config,
            profile,
            &provider_ref.provider,
            provider_config,
            ctx,
        )
        .await?;
        let prepared_provider = super::prepare_provider_read(
            config,
            profile,
            &provider_ref.provider,
            resolved_provider,
            ctx,
        )
        .await?;
        let values = ProviderEnvOverlay::resolved_values(
            provider_config.env_dependencies(),
            &ctx.pre_resolved,
        );
        let value = env::with_provider_env(&values, || async {
            let provider =
                prepared_provider.instantiate(config, profile, &provider_ref.provider)?;
            provider.get_secret(&provider_ref.value).await
        })
        .await?;

        Ok(Some(value))
    })
}

/// Resolve a secret reference by name.
///
/// This looks up the secret in config first, then falls back to environment variable.
/// If the secret is defined in config and uses another provider, that provider's
/// config will also be resolved recursively.
fn resolve_secret_ref<'a>(
    config: &'a Config,
    profile: &'a [String],
    provider_name: &'a str,
    secret_name: &'a str,
    ctx: &'a mut ResolutionContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
    Box::pin(async move {
        if let Some(value) = ctx.pre_resolved.get(secret_name) {
            return value
                .clone()
                .ok_or_else(|| FnoxError::ProviderConfigResolutionFailed {
                    provider: provider_name.to_string(),
                    secret: secret_name.to_string(),
                    details: format!("Secret '{secret_name}' did not resolve"),
                });
        }

        // First, try to find the secret in config
        let secrets = config.get_secrets(profile)?;

        if let Some(secret_config) = secrets.get(secret_name) {
            // Secret found in config - resolve it
            if let Some(secret_provider_name) = secret_config.provider()
                && let Some(provider_value) = secret_config.value()
            {
                // This secret uses a provider - need to resolve that provider first
                let providers = config.get_providers(profile)?;
                if let Some(secret_provider_config) = providers.get(secret_provider_name) {
                    if env::is_non_interactive()
                        && secret_provider_config.requires_interactive_auth()
                    {
                        return Err(FnoxError::Provider(format!(
                            "Provider '{}' requires interactive authentication and cannot be used in non-interactive mode. Use 'fnox exec' instead.",
                            secret_provider_name
                        )));
                    }

                    // Recursively resolve the provider's config
                    let resolved_provider = resolve_provider_config_with_context(
                        config,
                        profile,
                        secret_provider_name,
                        secret_provider_config,
                        ctx,
                    )
                    .await?;
                    let prepared_provider = super::prepare_provider_read(
                        config,
                        profile,
                        secret_provider_name,
                        resolved_provider,
                        ctx,
                    )
                    .await?;

                    let values = ProviderEnvOverlay::resolved_values(
                        secret_provider_config.env_dependencies(),
                        &ctx.pre_resolved,
                    );
                    return env::with_provider_env(&values, || async {
                        let provider =
                            prepared_provider.instantiate(config, profile, secret_provider_name)?;
                        provider.get_secret(provider_value).await
                    })
                    .await;
                } else {
                    // Find similar provider names for suggestion
                    let available_providers: Vec<_> =
                        providers.keys().map(|s| s.as_str()).collect();
                    let similar = find_similar(secret_provider_name, available_providers);
                    let suggestion = format_suggestions(&similar);

                    return Err(FnoxError::ProviderNotConfigured {
                        provider: secret_provider_name.to_string(),
                        profile: profile.join(","),
                        config_path: config.provider_sources.get(secret_provider_name).cloned(),
                        suggestion,
                    });
                }
            }

            // Secret has a default value
            if let Some(ref default) = secret_config.default {
                return Ok(default.clone());
            }
        }

        // Fall back to environment variable
        let _access = PROVIDER_ENV_ACCESS.read().await;
        env::var(secret_name).map_err(|_| FnoxError::ProviderConfigResolutionFailed {
            provider: provider_name.to_string(),
            secret: secret_name.to_string(),
            details: format!(
                "Secret '{}' not found in config or environment",
                secret_name
            ),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution_context_cycle_detection() {
        let mut ctx = ResolutionContext::new();

        assert!(!ctx.is_resolving("provider_a"));

        ctx.push("provider_a");
        assert!(ctx.is_resolving("provider_a"));
        assert!(!ctx.is_resolving("provider_b"));

        ctx.push("provider_b");
        assert!(ctx.is_resolving("provider_a"));
        assert!(ctx.is_resolving("provider_b"));

        ctx.pop();
        assert!(ctx.is_resolving("provider_a"));
        assert!(!ctx.is_resolving("provider_b"));

        ctx.pop();
        assert!(!ctx.is_resolving("provider_a"));
    }

    #[test]
    fn test_resolution_path() {
        let mut ctx = ResolutionContext::new();

        ctx.push("a");
        ctx.push("b");
        ctx.push("c");

        assert_eq!(ctx.path_string(), "a -> b -> c");
    }

    #[tokio::test]
    async fn secret_ref_propagates_profile_inheritance_errors() {
        let config: Config = toml_edit::de::from_str(
            r#"
[profiles.a]
inherits = ["b"]

[profiles.b]
inherits = ["a"]
"#,
        )
        .unwrap();
        let mut ctx = ResolutionContext::new();

        let error = resolve_secret_ref(
            &config,
            &["a".to_string()],
            "provider",
            "FNOX_CYCLE_TEST_SECRET",
            &mut ctx,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            FnoxError::ProfileInheritanceCycle { cycle } if cycle == "a -> b -> a"
        ));
    }

    #[tokio::test]
    async fn secret_ref_uses_pre_resolved_value() {
        let config = Config::new();
        let mut ctx = ResolutionContext::with_pre_resolved(&HashMap::from([(
            "TOKEN".to_string(),
            Some("resolved-token".to_string()),
        )]));

        let value = resolve_secret_ref(
            &config,
            &["default".to_string()],
            "provider",
            "TOKEN",
            &mut ctx,
        )
        .await
        .unwrap();

        assert_eq!(value, "resolved-token");
    }

    #[tokio::test]
    async fn secret_ref_does_not_retry_pre_resolved_missing_value() {
        let config = Config::new();
        let mut ctx =
            ResolutionContext::with_pre_resolved(&HashMap::from([("TOKEN".to_string(), None)]));

        let error = resolve_secret_ref(
            &config,
            &["default".to_string()],
            "provider",
            "TOKEN",
            &mut ctx,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            FnoxError::ProviderConfigResolutionFailed { secret, .. } if secret == "TOKEN"
        ));
    }
}
