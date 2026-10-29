//! How the tools behave inside `fnox proxy run`, where the agent works with
//! placeholders and the proxy holds the real values.

use rmcp::ErrorData as McpError;
use rmcp::model::*;

use super::server::FnoxMcpServer;
use crate::proxy::ProxyHandle;

impl FnoxMcpServer {
    /// `get_secret` inside the proxy: the placeholder and where it works,
    /// never the value
    pub(super) fn placeholder_result(
        &self,
        proxy: &ProxyHandle,
        name: &str,
    ) -> Result<CallToolResult, McpError> {
        if let Some(allowlist) = &self.mcp_config.secrets
            && !allowlist.iter().any(|allowed| allowed == name)
        {
            return Err(McpError::invalid_params(
                format!("Secret '{name}' not found in configuration"),
                None,
            ));
        }
        if proxy.rules_for(name).is_empty() {
            return Err(McpError::invalid_request(
                format!(
                    "No proxy rule uses '{name}', so it isn't available inside fnox proxy run. Ask the user to add a [[proxy.rules]] entry for it."
                ),
                None,
            ));
        }
        let mut text = proxy_usage(proxy, name);
        if proxy.is_pending(name) {
            text.push_str(
                " It isn't set yet, so those requests are refused until it is; call request_secret to ask the user for it.",
            );
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Give the proxy the value the session now holds for `name`, and say
    /// how the agent can use it
    pub(super) async fn hand_to_proxy(&self, proxy: &ProxyHandle, name: &str) -> String {
        if proxy.rules_for(name).is_empty() {
            return format!(
                "No proxy rule uses '{name}', so nothing in this session can use it until a [[proxy.rules]] entry names it."
            );
        }
        let Some(Some(value)) = self.session.cached(name).await else {
            return format!("fnox couldn't read '{name}' back, so the proxy doesn't have it yet.");
        };
        match proxy.set_value(name, value) {
            Ok(()) => proxy_usage(proxy, name),
            Err(error) => format!("The proxy refused the value: {error}"),
        }
    }
}

/// "Send its placeholder …; the proxy injects the real value into requests to …"
pub(super) fn proxy_usage(proxy: &ProxyHandle, name: &str) -> String {
    let rules = proxy.rules_for(name);
    let Some(first) = rules.first() else {
        return String::new();
    };
    let mut domains: Vec<&str> = Vec::new();
    for rule in &rules {
        if !domains.contains(&rule.domain.as_str()) {
            domains.push(&rule.domain);
        }
    }
    format!(
        "Its placeholder is {} (in ${}): send that where the secret goes, and the proxy replaces it with the real value in requests to {}.",
        first.placeholder,
        first.env,
        domains.join(", ")
    )
}
