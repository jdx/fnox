use std::time::Duration;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars;
use rmcp::service::{ElicitationError, ElicitationMode};
use rmcp::{ErrorData as McpError, Peer, RoleServer, ServiceError, tool, tool_router};

use super::page::{PageDetails, SecretPage, Submission};
use super::server::FnoxMcpServer;
use crate::config::{self, Config, McpTool};
use crate::secret_session::StorageProvider;

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
        if !self.enabled_tools().contains(&McpTool::RequestSecret) {
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

        let config = self
            .session
            .load_config()
            .map_err(|e| McpError::internal_error(format!("Failed to load config: {e}"), None))?;
        if !params.replace && self.has_value(&config, &name).await? {
            let usage = match &self.proxy {
                // The value may have just been loaded, such as after the
                // terminal fallback, so the proxy may not have it yet
                Some(proxy) => self.hand_to_proxy(proxy, &name).await,
                None => "Use exec to run commands with it.".to_string(),
            };
            return Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                "Secret '{name}' already has a value. {usage} Call request_secret with replace=true to ask the user for a new value."
            ))]));
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
        let write_profile = self.session.write_profile().map_err(internal)?;
        let target = self.session.target_path().map_err(internal)?;

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

        if let Some(result) = self
            .open_secret_page(&peer, &name, &provider, &page, deadline)
            .await?
        {
            return Ok(result);
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
                let Ok(_store) =
                    tokio::time::timeout_at(deadline, self.session.store_lock().lock()).await
                else {
                    let message = "another value was still being stored when this request expired, so fnox stored nothing";
                    let _ = reply.send(Err(message.to_string()));
                    return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "Failed to store '{name}': {message}."
                    ))]));
                };
                // The config may have changed while the page was open
                let saved = match self.recheck(&name, &value, params.replace, &provider).await {
                    Ok(config) => self.session.save(config, &name, value, &target).await,
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
                    let _reload = self.session.reload_lock().lock().await;
                    let reloaded = self.session.reload_stored(&name, &target).await;
                    if reloaded.is_ok() {
                        // The user just entered this value; nothing to wait for
                        self.session.unmark_for_reload(&name);
                    }
                    reloaded
                };
                if let Err(e) = reloaded {
                    // The session may still hold the old value; reload until a
                    // later check reads the new one
                    self.session.mark_for_reload(&name);
                    // Nor may the proxy keep injecting the value this one
                    // replaced; it reads the new one from the config instead
                    let proxy_note = match &self.proxy {
                        Some(proxy) if !proxy.rules_for(&name).is_empty() => {
                            proxy.forget_value(&name);
                            " The proxy reads it from the config on the next request that needs it."
                        }
                        _ => "",
                    };
                    let _ = reply.send(Ok(format!(
                        "fnox stored {name}, but couldn't read it back: {e}"
                    )));
                    return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "The user entered '{name}' and {stored}, but reading it back failed: {e}. The value is saved; don't ask for it again.{proxy_note}"
                    ))]));
                }
                let _ = reply.send(Ok(format!(
                    "fnox stored {name}. You can close this tab and go back to the agent."
                )));
                let usage = if let Some(proxy) = &self.proxy {
                    self.hand_to_proxy(proxy, &name).await
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

    /// Open the input page through the client, reporting transport outcomes
    /// separately from a decision made on the form itself.
    async fn open_secret_page(
        &self,
        peer: &Peer<RoleServer>,
        name: &str,
        provider: &str,
        page: &SecretPage,
        deadline: tokio::time::Instant,
    ) -> Result<Option<CallToolResult>, McpError> {
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
            Ok(ElicitationAction::Accept) => Ok(None),
            Ok(action) => Ok(Some(CallToolResult::error(vec![ContentBlock::text(
                page_open_outcome(name, &action),
            )]))),
            Err(ElicitationError::CapabilityNotSupported) => {
                Ok(Some(CallToolResult::error(vec![ContentBlock::text(
                    self.terminal_fallback(name),
                )])))
            }
            Err(ElicitationError::Service(ServiceError::Timeout { .. })) => Ok(Some(
                CallToolResult::error(vec![ContentBlock::text(format!(
                    "Timed out waiting for the MCP client to answer the page-opening request for '{name}'. fnox stored no value through this request. This is not a user decline. Don't reopen the page automatically or ask for the value in the chat."
                ))]),
            )),
            Err(e) => Err(McpError::internal_error(
                format!("Failed to show the secret page link: {e}"),
                None,
            )),
        }
    }

    /// The provider a new value for `name` would be stored with, refusing one
    /// that would leave it in plain text in the config
    async fn secure_provider(&self, config: &Config, name: &str) -> Result<String, McpError> {
        match self.session.storage_provider(config, name).await {
            Ok(StorageProvider::Secure(provider)) => Ok(provider),
            Ok(StorageProvider::Refused(message)) => Err(McpError::invalid_request(message, None)),
            Err(e) => Err(McpError::internal_error(e.to_string(), None)),
        }
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
        let config = self.session.load_config()?;
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
        // would replace a working one with one that can't be read
        let effective = self
            .session
            .check_value_fits(&config, name, value)
            .map_err(|e| {
                changed(format!(
                    "the value doesn't fit the json_path or line setting of '{name}' ({e}), so fnox stored nothing"
                ))
            })?;
        // Under the proxy, a value it would refuse (such as one containing a
        // placeholder, or an empty json_path result) would be saved but never
        // injected. It gets the value after json_path or line, so check that.
        if let Some(proxy) = &self.proxy
            && !proxy.rules_for(name).is_empty()
        {
            proxy.check_value(name, &effective).map_err(|e| {
                changed(format!(
                    "the proxy can't use this value ({e}), so fnox stored nothing"
                ))
            })?;
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
        let marked = || self.session.is_marked_for_reload(name);
        let cached = async || self.session.cached(name).await.flatten();

        // After the terminal fallback, the user may replace a value this
        // session (and the daemon) still caches, so a name sent there is
        // reloaded on every check until its value changes
        let reload_guard = if marked() {
            Some(self.session.reload_lock().lock().await)
        } else {
            None
        };
        if reload_guard.is_none() || !marked() {
            if cached().await.is_some() {
                return Ok(true);
            }
            return self.session.load(config, name).await.map_err(load_error);
        }

        self.session
            .evict_from_daemon(config, name)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let before = cached().await;
        let loaded = self.session.load(config, name).await.map_err(load_error)?;
        if !loaded {
            // Don't keep serving a value the config no longer has
            self.session.forget(name).await;
        } else if cached().await != before {
            // The user's new value arrived; until then, keep reloading
            self.session.unmark_for_reload(name);
        }
        Ok(loaded)
    }

    /// What to tell the agent when the client can't show a URL
    fn terminal_fallback(&self, name: &str) -> String {
        self.session.mark_for_reload(name);
        let mut command = vec!["fnox".to_string()];
        let config_path = self.session.config_path();
        if config_path != std::path::Path::new(config::DEFAULT_CONFIG_FILENAME) {
            command.push("-c".into());
            command.push(crate::shell::posix_quote(&config_path.to_string_lossy()).into_owned());
        }
        let profile = self.session.profile();
        if profile != ["default"] {
            command.push("-P".into());
            command.push(crate::shell::posix_quote(&profile.join(",")).into_owned());
        }
        if let Some(write_profile) = self.session.write_profile_flag() {
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

/// A client can return `decline` without showing the prompt at all. The wire
/// response identifies the client action, not who made the decision.
fn page_open_outcome(name: &str, action: &ElicitationAction) -> String {
    let outcome = match action {
        ElicitationAction::Decline => format!(
            "The MCP client returned 'decline' for the page-opening request for '{name}'. fnox cannot tell whether the user declined or the client rejected the URL or blocked the prompt. If no prompt was shown, check the client's approval policy and support for the page's URL."
        ),
        ElicitationAction::Cancel => format!(
            "The MCP client canceled the page-opening request for '{name}'. fnox stored no value through this request. This is not a user decline."
        ),
        _ => format!(
            "The MCP client did not accept the page-opening request for '{name}'. fnox stored no value through this request."
        ),
    };
    format!("{outcome} Don't reopen the page automatically or ask for the value in the chat.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::server::test_server;
    use rmcp::ServiceExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn terminal_fallback_quotes_profile_names() {
        let server = test_server(vec!["my profile".into()], Some("my profile".into()));

        let text = server.terminal_fallback("API_TOKEN");
        assert!(
            text.contains("fnox -P 'my profile' --write-profile 'my profile' set API_TOKEN"),
            "{text}"
        );
    }

    #[test]
    fn a_client_decline_is_not_attributed_to_the_user() {
        let text = page_open_outcome("API_TOKEN", &ElicitationAction::Decline);
        assert!(text.contains("MCP client returned 'decline'"));
        assert!(text.contains("fnox cannot tell whether the user declined"));
        assert!(text.contains("approval policy"));
        assert!(text.contains("Don't reopen the page automatically"));
        assert!(!text.contains("The user declined"));
    }

    #[test]
    fn a_canceled_opening_request_is_reported_separately() {
        let text = page_open_outcome("API_TOKEN", &ElicitationAction::Cancel);
        assert!(text.contains("MCP client canceled"));
        assert!(text.contains("fnox stored no value"));
        assert!(!text.contains("The user declined"));
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_opening_request_times_out_without_a_retry() {
        let server = test_server(vec!["default".into()], None);
        let (server_io, client_io) = tokio::io::duplex(8192);
        let serving = tokio::spawn({
            let server = server.clone();
            async move { server.serve(server_io).await.unwrap() }
        });
        let mut client = BufReader::new(client_io);
        let initialize = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": { "elicitation": { "url": {} } },
                "clientInfo": { "name": "unresponsive-test-client", "version": "1" }
            }
        });
        client
            .get_mut()
            .write_all(format!("{initialize}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        client.read_line(&mut line).await.unwrap();
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], 1);
        assert!(response.get("error").is_none());
        client
            .get_mut()
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();
        let service = serving.await.unwrap();
        let peer = service.peer().clone();
        let page = SecretPage::start(PageDetails {
            name: "API_TOKEN".into(),
            reason: None,
            provider: "age".into(),
            target: "fnox.toml".into(),
            profile: "default".into(),
        })
        .await
        .unwrap();
        let opening = tokio::spawn(async move {
            server
                .open_secret_page(
                    &peer,
                    "API_TOKEN",
                    "age",
                    &page,
                    tokio::time::Instant::now() + Duration::from_secs(2),
                )
                .await
        });
        line.clear();
        client.read_line(&mut line).await.unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["method"], "elicitation/create");
        assert_eq!(request["params"]["mode"], "url");
        // The client deliberately never answers this request.
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!opening.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        let result = opening.await.unwrap().unwrap().unwrap();
        assert_eq!(result.is_error, Some(true));
        let response = serde_json::to_value(result).unwrap();
        let text = response["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Timed out waiting for the MCP client"));
        assert!(text.contains("fnox stored no value"));
        assert!(text.contains("This is not a user decline"));
        assert!(text.contains("Don't reopen the page automatically"));
        assert!(text.contains("or ask for the value in the chat"));
        line.clear();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        while let Ok(read) = tokio::time::timeout_at(deadline, client.read_line(&mut line)).await {
            if read.unwrap() == 0 {
                break;
            }
            let message: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_ne!(
                message["method"], "elicitation/create",
                "unexpected retry: {line}"
            );
            line.clear();
        }
        service.cancel().await.unwrap();
    }
}
