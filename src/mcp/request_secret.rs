use std::time::Duration;

use indexmap::IndexMap;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars;
use rmcp::service::{ElicitationError, ElicitationMode};
use rmcp::{ErrorData as McpError, Peer, RoleServer, tool, tool_router};

use super::page::{PageDetails, SecretPage, Submission};
use super::server::FnoxMcpServer;
use crate::commands::set::{SetCommand, local_target_path, storage_provider, stores_securely};
use crate::config::{self, Config, McpTool, SecretConfig};
use crate::daemon::Purpose;
use crate::generate::GenerateKind;

/// How long request_secret waits for the user to enter a value
const REQUEST_SECRET_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Longest agent-written reason the secret page shows
const MAX_REASON_CHARS: usize = 500;

/// MCP tool parameter: ask the user to enter a secret
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RequestSecretParams {
    /// The secret's name, which is also its environment variable name, such as TAILSCALE_AUTHKEY
    pub name: String,
    /// Why the secret is needed and where the user can create it. Shown to the user next to the input box.
    #[serde(default)]
    pub reason: Option<String>,
    /// Ask for a new value even if the secret already has one
    #[serde(default)]
    pub replace: bool,
}

#[tool_router(router = request_secret_tools, vis = "pub(super)")]
impl FnoxMcpServer {
    /// Ask the user to enter a secret on a one-time local page.
    ///
    /// The page's URL reaches the user through URL-mode elicitation, so the
    /// value never passes through the client. fnox stores it the way `fnox set`
    /// would, and the agent learns only that it was stored.
    #[tool(
        description = "Ask the user to enter a secret that isn't set yet, such as an API key or auth token. fnox shows the user a local page to type it into, stores it, and makes it available to the exec tool as an environment variable. The value is never returned to you. Use this instead of asking the user to paste a secret into the chat."
    )]
    async fn request_secret(
        &self,
        Parameters(params): Parameters<RequestSecretParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if !self.mcp_config.tools().contains(&McpTool::RequestSecret) {
            return Err(McpError::invalid_request(
                "Tool 'request_secret' is not enabled in this configuration",
                None,
            ));
        }
        let name = params.name;
        config::validate_secret_name(&name)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        if let Some(allowlist) = &self.mcp_config.secrets
            && !allowlist.contains(&name)
        {
            return Err(McpError::invalid_request(
                format!("Secret '{name}' is not in mcp.secrets, so it can't be requested"),
                None,
            ));
        }
        if let Some(proxy) = &self.proxy
            && !proxy.has_rule(&name)
        {
            return Err(McpError::invalid_request(
                format!(
                    "No [[proxy.rules]] entry names '{name}', so the proxy couldn't send it anywhere. Ask the user to add a rule for it and restart the proxy session."
                ),
                None,
            ));
        }

        let config = Config::load_smart(self.config_path.as_path())
            .map_err(|e| McpError::internal_error(format!("Failed to load config: {e}"), None))?;
        if !params.replace && self.has_value(&config, &name).await? {
            let text = if self.proxy.is_some() {
                format!(
                    "Secret '{name}' already has a value, which the proxy sends on requests its rules allow. Call request_secret with replace=true to ask the user for a new value."
                )
            } else {
                format!(
                    "Secret '{name}' already has a value. Use exec to run commands with it, or call request_secret with replace=true to ask the user for a new value."
                )
            };
            return Ok(CallToolResult::success(vec![ContentBlock::text(text)]));
        }

        // Refuse a provider that would leave the value in plain text before
        // the user types anything, on the page or in the terminal
        let provider = self.secure_provider(&config, &name).await?;

        if !peer
            .supported_elicitation_modes()
            .contains(&ElicitationMode::Url)
        {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                self.terminal_fallback(&name),
            )]));
        }

        let internal = |e: crate::error::FnoxError| McpError::internal_error(e.to_string(), None);
        let write_profile =
            Config::resolve_write_profile(&self.profile, self.write_profile.as_deref())
                .map_err(internal)?;
        let target = local_target_path(
            &self.config_path,
            &self.profile,
            self.write_profile.as_deref(),
        )
        .map_err(internal)?;

        let reason = params
            .reason
            .map(|reason| reason.chars().take(MAX_REASON_CHARS).collect());
        // One deadline covers opening the link and submitting the page; the
        // page stops serving when this call returns
        let deadline = tokio::time::Instant::now() + REQUEST_SECRET_TIMEOUT;
        let mut page = SecretPage::start(PageDetails {
            name: name.clone(),
            reason,
            provider: provider.clone(),
            target: target.clone(),
            profile: write_profile,
        })
        .await
        .map_err(internal)?;

        let elicitation_id = data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>());
        let message = format!(
            "fnox needs a value for {name}. Open this local page to enter it. fnox stores it with provider '{provider}' and does not show it to the agent."
        );
        match peer
            .elicit_url_with_timeout(
                message,
                page.url().clone(),
                elicitation_id,
                Some(deadline.saturating_duration_since(tokio::time::Instant::now())),
            )
            .await
        {
            Ok(ElicitationAction::Accept) => {}
            Ok(_) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "The user declined to open the page for '{name}'. Don't ask for the value in the chat."
                ))]));
            }
            Err(ElicitationError::CapabilityNotSupported) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    self.terminal_fallback(&name),
                )]));
            }
            Err(e) => {
                return Err(McpError::internal_error(
                    format!("Failed to show the secret page link: {e}"),
                    None,
                ));
            }
        }

        // Accepting the elicitation only means the user opened the link; the
        // value arrives when they submit the page.
        let submission = tokio::time::timeout_at(deadline, page.next())
            .await
            .ok()
            .flatten();
        match submission {
            None => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Timed out waiting for the user to enter '{name}'."
            ))])),
            Some(Submission::Declined) => {
                Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "The user declined to enter '{name}'. Don't ask for the value in the chat."
                ))]))
            }
            Some(Submission::Value { value, reply }) => {
                // One store at a time, so two pages for the same name can't
                // both pass the recheck
                let Ok(_store) = tokio::time::timeout_at(deadline, self.store_lock.lock()).await
                else {
                    let message = "another value was still being stored when this request expired, so fnox stored nothing";
                    let _ = reply.send(Err(message.to_string()));
                    return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "Failed to store '{name}': {message}."
                    ))]));
                };
                // The config may have changed while the page was open
                let saved = match self.recheck(&name, &value, params.replace, &provider).await {
                    Ok(config) => self.save(&name, value, config, &target).await,
                    Err(e) => Err(e),
                };
                if let Err(e) = saved {
                    let _ = reply.send(Err(e.to_string()));
                    return Err(McpError::internal_error(
                        format!("Failed to store '{name}': {e}"),
                        None,
                    ));
                }
                let stored = format!(
                    "fnox stored it with provider '{provider}' in {}",
                    target.display()
                );
                let reloaded = {
                    let _reload = self.reload_lock.lock().await;
                    let reloaded = self.reload_stored(&name, &target).await;
                    if reloaded.is_ok() {
                        // The user just entered this value; nothing to wait for
                        self.sent_to_terminal
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&name);
                    }
                    reloaded
                };
                if let Err(e) = reloaded {
                    let _ = reply.send(Ok(format!(
                        "fnox stored {name}, but couldn't read it back: {e}"
                    )));
                    return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "The user entered '{name}' and {stored}, but reading it back failed: {e}. The value is saved; don't ask for it again."
                    ))]));
                }
                let _ = reply.send(Ok(format!(
                    "fnox stored {name}. You can close this tab and go back to the agent."
                )));
                let usage = if self.proxy.is_some() {
                    "The proxy now sends it in place of its placeholder on requests that match its rules."
                        .to_string()
                } else if self
                    .secrets()
                    .get(&name)
                    .is_some_and(|secret| secret.env_mode().in_exec())
                {
                    format!("The exec tool now sets it as ${name}.")
                } else {
                    "Its env setting keeps it out of commands that the exec tool runs.".into()
                };
                Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                    "The user entered '{name}'. {stored}. {usage}"
                ))]))
            }
        }
    }

    /// The provider a new value for `name` would be stored with, refusing one
    /// that would leave it in plain text in the config
    async fn secure_provider(&self, config: &Config, name: &str) -> Result<String, McpError> {
        let internal = |e: crate::error::FnoxError| McpError::internal_error(e.to_string(), None);
        let write_profile =
            Config::resolve_write_profile(&self.profile, self.write_profile.as_deref())
                .map_err(internal)?;
        let write_stack = std::slice::from_ref(&write_profile);
        let effective = config
            .get_secret(write_stack, name)
            .map_err(internal)?
            .cloned();
        let Some(provider) =
            storage_provider(config, &write_profile, None, effective.as_ref()).map_err(internal)?
        else {
            return Err(McpError::invalid_request(
                format!(
                    "Secret '{name}' has no provider and the config sets no default_provider, so fnox would store it in plain text. Ask the user to set default_provider."
                ),
                None,
            ));
        };
        let providers = config.get_providers(write_stack).map_err(internal)?;
        let Some(provider_config) = providers.get(&provider) else {
            return Err(McpError::invalid_request(
                format!("Provider '{provider}' not found in configuration"),
                None,
            ));
        };
        let capabilities = crate::providers::get_provider_resolved(
            config,
            write_stack,
            &provider,
            provider_config,
        )
        .await
        .map_err(internal)?
        .capabilities();
        if !stores_securely(provider_config, &capabilities) {
            return Err(McpError::invalid_request(
                format!(
                    "Provider '{provider}' would leave '{name}' in plain text in the config. Ask the user to set default_provider to a provider that encrypts values or stores them remotely."
                ),
                None,
            ));
        }
        Ok(provider)
    }

    /// Reload the config after the user submits and check that storing still
    /// matches what the page showed: no value set meanwhile (unless
    /// replacing), and the same secure provider
    async fn recheck(
        &self,
        name: &str,
        value: &str,
        replace: bool,
        provider: &str,
    ) -> crate::error::Result<Config> {
        let config = Config::load_smart(self.config_path.as_path())?;
        let changed = |message: String| crate::error::FnoxError::Config(message);
        if !replace
            && self
                .has_value(&config, name)
                .await
                .map_err(|e| changed(e.message.to_string()))?
        {
            return Err(changed(format!(
                "'{name}' was set while this page was open, so fnox stored nothing"
            )));
        }
        let current = self
            .secure_provider(&config, name)
            .await
            .map_err(|e| changed(e.message.to_string()))?;
        if current != provider {
            return Err(changed(format!(
                "the provider for '{name}' changed from '{provider}' to '{current}' while this page was open, so fnox stored nothing"
            )));
        }
        // A value that doesn't fit the secret's json_path or line setting
        // would replace a working one with one that can't be read. Check the
        // secret as the active profiles read it and as the write profile,
        // which `--write-profile` may set to another profile, stores it.
        let write_profile =
            Config::resolve_write_profile(&self.profile, self.write_profile.as_deref())?;
        let read = config.get_secrets(&self.profile)?.shift_remove(name);
        let written = config
            .get_secret(std::slice::from_ref(&write_profile), name)?
            .cloned();
        for secret in read.iter().chain(written.iter()) {
            if secret.json_path.is_none() && secret.line.is_none() {
                continue;
            }
            crate::secret_resolver::apply_post_processing(value.to_string(), secret).map_err(
                |e| {
                    changed(format!(
                        "the value doesn't fit the json_path or line setting of '{name}' ({e}), so fnox stored nothing"
                    ))
                },
            )?;
        }
        Ok(config)
    }

    /// Whether `name` resolves to a value, checking `config` (freshly loaded)
    /// for a secret set outside this session, such as with `fnox set`
    async fn has_value(&self, config: &Config, name: &str) -> Result<bool, McpError> {
        let load_error = |e: crate::error::FnoxError| {
            McpError::internal_error(
                format!(
                    "Secret '{name}' is configured but failed to resolve: {e}. Call request_secret with replace=true to ask the user for a new value."
                ),
                None,
            )
        };
        let marked = || {
            self.sent_to_terminal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(name)
        };
        let cached = async || self.cache.read().await.get(name).cloned().flatten();

        // After the terminal fallback, the user may replace a value this
        // session (and the daemon) still caches, so a name sent there is
        // reloaded on every check until its value changes
        let reload_guard = if marked() {
            Some(self.reload_lock.lock().await)
        } else {
            None
        };
        if reload_guard.is_none() || !marked() {
            if cached().await.is_some() {
                return Ok(true);
            }
            return self.load(config, name).await.map_err(load_error);
        }

        crate::daemon::refresh_with_context(
            &self.daemon_context,
            config,
            std::slice::from_ref(&name.to_string()),
        )
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let before = cached().await;
        let loaded = self.load(config, name).await.map_err(load_error)?;
        if !loaded {
            // Don't keep serving a value the config no longer has
            self.cache.write().await.remove(name);
        } else if cached().await != before {
            // The user's new value arrived; until then, keep reloading
            self.sent_to_terminal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(name);
        }
        Ok(loaded)
    }

    /// Resolve `name` from `config` the way a new session would, and make it
    /// available to the tools if it has a value. Going through `get_secrets`
    /// and the resolver applies the top-level `env` default and settings such
    /// as `json_path`.
    async fn load(&self, config: &Config, name: &str) -> crate::error::Result<bool> {
        let Some(secret) = config.get_secrets(&self.profile)?.shift_remove(name) else {
            return Ok(false);
        };
        let single: IndexMap<String, SecretConfig> =
            [(name.to_string(), secret.clone())].into_iter().collect();
        let resolved = crate::daemon::resolve_batch_with_context(
            &self.daemon_context,
            config,
            &self.profile,
            &single,
            Purpose::Mcp,
            true,
        )
        .await?;
        match resolved.into_iter().next().and_then(|(_, value)| value) {
            Some(value) => {
                self.add_secret(name, secret, value).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Store a value the user entered, as `fnox set` would
    async fn save(
        &self,
        name: &str,
        value: String,
        config: Config,
        target: &std::path::Path,
    ) -> crate::error::Result<()> {
        let set = SetCommand {
            key: Some(name.to_string()),
            value: Some(value),
            description: None,
            global: false,
            key_name: None,
            dry_run: false,
            provider: None,
            base64_encode: false,
            default: None,
            file: None,
            force: false,
            from_file: None,
            generate: false,
            generate_type: GenerateKind::Password,
            if_missing: None,
            length: None,
            show: false,
            source: None,
        };
        set.store_at(
            config,
            &self.profile,
            self.write_profile.as_deref(),
            target,
            true,
        )
        .await?;
        Ok(())
    }

    /// Load a value `save` just stored, so the tools use it
    async fn reload_stored(
        &self,
        name: &str,
        target: &std::path::Path,
    ) -> crate::error::Result<()> {
        let config = Config::load_smart(self.config_path.as_path())?;
        // A remote provider keeps the same reference when a value is replaced,
        // so the daemon would otherwise keep serving the old value
        crate::daemon::refresh_with_context(
            &self.daemon_context,
            &config,
            std::slice::from_ref(&name.to_string()),
        )
        .await?;
        if !self.load(&config, name).await? {
            return Err(crate::error::FnoxError::Config(
                "it resolves to no value".into(),
            ));
        }
        // Another file that takes precedence may define the secret too, such
        // as one created while the page was open; the stored value is then
        // not the one in use
        let source = self
            .secrets()
            .get(name)
            .and_then(|secret| secret.source_path.clone());
        if let Some(source) = source {
            let same = |a: &std::path::Path, b: &std::path::Path| {
                a == b
                    || std::fs::canonicalize(a)
                        .ok()
                        .zip(std::fs::canonicalize(b).ok())
                        .is_some_and(|(a, b)| a == b)
            };
            if !same(&source, target) {
                return Err(crate::error::FnoxError::Config(format!(
                    "'{name}' is read from {}, which takes precedence over {}, so the new value isn't in use",
                    source.display(),
                    target.display()
                )));
            }
        }
        Ok(())
    }

    /// What to tell the agent when the client can't show a URL
    fn terminal_fallback(&self, name: &str) -> String {
        self.sent_to_terminal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_string());
        let mut command = vec!["fnox".to_string()];
        if self.config_path.as_path() != std::path::Path::new(config::DEFAULT_CONFIG_FILENAME) {
            command.push("-c".into());
            command
                .push(crate::shell::posix_quote(&self.config_path.to_string_lossy()).into_owned());
        }
        if self.profile.as_slice() != ["default"] {
            command.push("-P".into());
            command.push(crate::shell::posix_quote(&self.profile.join(",")).into_owned());
        }
        if let Some(write_profile) = self.write_profile.as_deref() {
            command.push("--write-profile".into());
            command.push(crate::shell::posix_quote(write_profile).into_owned());
        }
        command.push("set".into());
        command.push(name.to_string());
        let command = command.join(" ");
        let command = match std::env::current_dir() {
            Ok(dir) => format!(
                "cd {} && {command}",
                crate::shell::posix_quote(&dir.to_string_lossy())
            ),
            Err(_) => command,
        };
        format!(
            "This MCP client can't open fnox's secure input page (it doesn't support URL-mode elicitation). Don't ask the user to paste '{name}' into the chat. Ask them to run this in their own terminal, where fnox prompts for the value with hidden input:\n\n    {command}\n\nThen call request_secret again with the same name and without replace. fnox will load the stored value without showing it to you."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpConfig;
    use crate::daemon::ResolveContext;

    #[test]
    fn terminal_fallback_quotes_profile_names() {
        let profile = vec!["my profile".to_string()];
        let server = FnoxMcpServer::new(
            Config::default(),
            profile.clone(),
            McpConfig::default(),
            ResolveContext {
                config: "fnox.toml".into(),
                profile,
                age_key_file: None,
                if_missing: None,
                no_defaults: false,
                non_interactive: true,
                no_daemon: true,
            },
            IndexMap::new(),
        )
        .with_write_target("fnox.toml".into(), Some("my profile".into()));

        let text = server.terminal_fallback("API_TOKEN");
        assert!(
            text.contains("fnox -P 'my profile' --write-profile 'my profile' set API_TOKEN"),
            "{text}"
        );
    }
}
