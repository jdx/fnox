//! Provider configuration resolution.
//!
//! This module handles resolving `ProviderConfig` to `ResolvedProviderConfig` by
//! looking up any secret references in the configuration or environment.
//!
//! The resolution process supports recursive secret references (a provider's config
//! can reference a secret from another provider) and detects circular dependencies.

use crate::config::Config;
use crate::env;
use crate::error::{FnoxError, Result};
use std::collections::HashSet;

use super::ProviderConfig;
use super::resolved::ResolvedProviderConfig;
use super::secret_ref::{OptionStringOrSecretRef, StringOrSecretRef};

/// Context for resolving provider configurations, tracking the resolution stack
/// to detect circular dependencies.
pub struct ResolutionContext {
    /// Stack of provider names currently being resolved (for cycle detection)
    provider_stack: HashSet<String>,
    /// Stack path for error messages
    resolution_path: Vec<String>,
}

impl ResolutionContext {
    /// Create a new resolution context
    pub fn new() -> Self {
        Self {
            provider_stack: HashSet::new(),
            resolution_path: Vec::new(),
        }
    }

    /// Check if we're already resolving this provider (cycle detection)
    fn is_resolving(&self, provider_name: &str) -> bool {
        self.provider_stack.contains(provider_name)
    }

    /// Push a provider onto the resolution stack
    fn push(&mut self, provider_name: &str) {
        self.provider_stack.insert(provider_name.to_string());
        self.resolution_path.push(provider_name.to_string());
    }

    /// Pop a provider from the resolution stack
    fn pop(&mut self, provider_name: &str) {
        self.provider_stack.remove(provider_name);
        self.resolution_path.pop();
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
    profile: &str,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> Result<ResolvedProviderConfig> {
    let mut ctx = ResolutionContext::new();
    resolve_provider_config_with_context(config, profile, provider_name, provider_config, &mut ctx)
        .await
}

/// Internal function that carries the resolution context for cycle detection.
fn resolve_provider_config_with_context<'a>(
    config: &'a Config,
    profile: &'a str,
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

        // Resolve based on provider type
        let result = match provider_config {
            ProviderConfig::Plain => Ok(ResolvedProviderConfig::Plain),

            ProviderConfig::OnePassword { vault, account } => {
                Ok(ResolvedProviderConfig::OnePassword {
                    vault: resolve_option(config, profile, provider_name, vault, ctx).await?,
                    account: resolve_option(config, profile, provider_name, account, ctx).await?,
                })
            }

            ProviderConfig::AgeEncryption {
                recipients,
                key_file,
            } => {
                // Vec<String> fields are not resolved (v1 scope decision)
                Ok(ResolvedProviderConfig::AgeEncryption {
                    recipients: recipients.clone(),
                    key_file: resolve_option(config, profile, provider_name, key_file, ctx).await?,
                })
            }

            ProviderConfig::AwsKms { key_id, region } => Ok(ResolvedProviderConfig::AwsKms {
                key_id: resolve_required(config, profile, provider_name, "key_id", key_id, ctx)
                    .await?,
                region: resolve_required(config, profile, provider_name, "region", region, ctx)
                    .await?,
            }),

            ProviderConfig::AwsSecretsManager { region, prefix } => {
                Ok(ResolvedProviderConfig::AwsSecretsManager {
                    region: resolve_required(config, profile, provider_name, "region", region, ctx)
                        .await?,
                    prefix: resolve_option(config, profile, provider_name, prefix, ctx).await?,
                })
            }

            ProviderConfig::AwsParameterStore { region, prefix } => {
                Ok(ResolvedProviderConfig::AwsParameterStore {
                    region: resolve_required(config, profile, provider_name, "region", region, ctx)
                        .await?,
                    prefix: resolve_option(config, profile, provider_name, prefix, ctx).await?,
                })
            }

            ProviderConfig::AzureKms {
                vault_url,
                key_name,
            } => Ok(ResolvedProviderConfig::AzureKms {
                vault_url: resolve_required(
                    config,
                    profile,
                    provider_name,
                    "vault_url",
                    vault_url,
                    ctx,
                )
                .await?,
                key_name: resolve_required(
                    config,
                    profile,
                    provider_name,
                    "key_name",
                    key_name,
                    ctx,
                )
                .await?,
            }),

            ProviderConfig::AzureSecretsManager { vault_url, prefix } => {
                Ok(ResolvedProviderConfig::AzureSecretsManager {
                    vault_url: resolve_required(
                        config,
                        profile,
                        provider_name,
                        "vault_url",
                        vault_url,
                        ctx,
                    )
                    .await?,
                    prefix: resolve_option(config, profile, provider_name, prefix, ctx).await?,
                })
            }

            ProviderConfig::Bitwarden {
                collection,
                organization_id,
                profile: bw_profile,
                backend,
            } => Ok(ResolvedProviderConfig::Bitwarden {
                collection: resolve_option(config, profile, provider_name, collection, ctx).await?,
                organization_id: resolve_option(
                    config,
                    profile,
                    provider_name,
                    organization_id,
                    ctx,
                )
                .await?,
                profile: resolve_option(config, profile, provider_name, bw_profile, ctx).await?,
                backend: *backend,
            }),

            ProviderConfig::GcpKms {
                project,
                location,
                keyring,
                key,
            } => Ok(ResolvedProviderConfig::GcpKms {
                project: resolve_required(config, profile, provider_name, "project", project, ctx)
                    .await?,
                location: resolve_required(
                    config,
                    profile,
                    provider_name,
                    "location",
                    location,
                    ctx,
                )
                .await?,
                keyring: resolve_required(config, profile, provider_name, "keyring", keyring, ctx)
                    .await?,
                key: resolve_required(config, profile, provider_name, "key", key, ctx).await?,
            }),

            ProviderConfig::GoogleSecretManager { project, prefix } => {
                Ok(ResolvedProviderConfig::GoogleSecretManager {
                    project: resolve_required(
                        config,
                        profile,
                        provider_name,
                        "project",
                        project,
                        ctx,
                    )
                    .await?,
                    prefix: resolve_option(config, profile, provider_name, prefix, ctx).await?,
                })
            }

            ProviderConfig::Infisical {
                project_id,
                environment,
                path,
            } => Ok(ResolvedProviderConfig::Infisical {
                project_id: resolve_option(config, profile, provider_name, project_id, ctx).await?,
                environment: resolve_option(config, profile, provider_name, environment, ctx)
                    .await?,
                path: resolve_option(config, profile, provider_name, path, ctx).await?,
            }),

            ProviderConfig::KeePass {
                database,
                keyfile,
                password,
            } => Ok(ResolvedProviderConfig::KeePass {
                database: resolve_required(
                    config,
                    profile,
                    provider_name,
                    "database",
                    database,
                    ctx,
                )
                .await?,
                keyfile: resolve_option(config, profile, provider_name, keyfile, ctx).await?,
                password: resolve_option(config, profile, provider_name, password, ctx).await?,
            }),

            ProviderConfig::Keychain { service, prefix } => Ok(ResolvedProviderConfig::Keychain {
                service: resolve_required(config, profile, provider_name, "service", service, ctx)
                    .await?,
                prefix: resolve_option(config, profile, provider_name, prefix, ctx).await?,
            }),

            ProviderConfig::PasswordStore {
                prefix,
                store_dir,
                gpg_opts,
            } => Ok(ResolvedProviderConfig::PasswordStore {
                prefix: resolve_option(config, profile, provider_name, prefix, ctx).await?,
                store_dir: resolve_option(config, profile, provider_name, store_dir, ctx).await?,
                gpg_opts: resolve_option(config, profile, provider_name, gpg_opts, ctx).await?,
            }),

            ProviderConfig::HashiCorpVault {
                address,
                path,
                token,
            } => Ok(ResolvedProviderConfig::HashiCorpVault {
                address: resolve_required(config, profile, provider_name, "address", address, ctx)
                    .await?,
                path: resolve_option(config, profile, provider_name, path, ctx).await?,
                token: resolve_option(config, profile, provider_name, token, ctx).await?,
            }),
        };

        // Pop from resolution stack
        ctx.pop(provider_name);

        result
    }) // Close async move and Box::pin
}

/// Resolve a required `StringOrSecretRef` field to its actual string value.
fn resolve_required<'a>(
    config: &'a Config,
    profile: &'a str,
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
fn resolve_option<'a>(
    config: &'a Config,
    profile: &'a str,
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

/// Resolve a secret reference by name.
///
/// This looks up the secret in config first, then falls back to environment variable.
/// If the secret is defined in config and uses another provider, that provider's
/// config will also be resolved recursively.
fn resolve_secret_ref<'a>(
    config: &'a Config,
    profile: &'a str,
    provider_name: &'a str,
    secret_name: &'a str,
    ctx: &'a mut ResolutionContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
    Box::pin(async move {
        // First, try to find the secret in config
        let secrets = config.get_secrets(profile).unwrap_or_default();

        if let Some(secret_config) = secrets.get(secret_name) {
            // Secret found in config - resolve it
            if let Some(ref secret_provider_name) = secret_config.provider
                && let Some(ref provider_value) = secret_config.value
            {
                // This secret uses a provider - need to resolve that provider first
                let providers = config.get_providers(profile);
                if let Some(secret_provider_config) = providers.get(secret_provider_name) {
                    // Recursively resolve the provider's config
                    let resolved_provider = resolve_provider_config_with_context(
                        config,
                        profile,
                        secret_provider_name,
                        secret_provider_config,
                        ctx,
                    )
                    .await?;

                    // Create the provider and get the secret
                    let provider = super::get_provider_from_resolved(&resolved_provider)?;
                    return provider.get_secret(provider_value).await;
                } else {
                    return Err(FnoxError::ProviderNotConfigured {
                        provider: secret_provider_name.clone(),
                        profile: profile.to_string(),
                        config_path: config.provider_sources.get(secret_provider_name).cloned(),
                    });
                }
            }

            // Secret has a default value
            if let Some(ref default) = secret_config.default {
                return Ok(default.clone());
            }
        }

        // Fall back to environment variable
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

        ctx.pop("provider_b");
        assert!(ctx.is_resolving("provider_a"));
        assert!(!ctx.is_resolving("provider_b"));

        ctx.pop("provider_a");
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
}
