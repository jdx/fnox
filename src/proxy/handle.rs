//! What `fnox mcp` running inside `fnox proxy run` may learn about the proxy:
//! each rule's placeholder and destination, never a real value, plus a way to
//! hand the proxy a value the user just entered.

use super::*;

/// The CONNECT host a `fnox mcp` relay asks for to reach the proxy's MCP
/// service. The `.invalid` top-level domain never resolves (RFC 2606).
pub const MCP_HOST: &str = "fnox-mcp.invalid";

/// A client connection handed to the MCP service
pub trait ClientStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ClientStream for T {}

/// Serves one relay connection
pub type McpService = Arc<
    dyn Fn(Box<dyn ClientStream>) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Holds the [`McpService`] in the policy, which derives `Debug`
pub(super) struct McpSlot(pub(super) McpService);

impl std::fmt::Debug for McpSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("McpService")
    }
}

/// A rule as the MCP tools describe it
#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub secret: String,
    /// The child's environment variable that holds the placeholder
    pub env: String,
    pub domain: String,
    pub placeholder: String,
}

#[derive(Clone)]
pub struct ProxyHandle {
    pub(super) policy: Arc<ProxyPolicy>,
    pub(super) rules: Arc<Vec<RuleInfo>>,
}

impl ProxyHandle {
    /// The rules that inject `secret`
    pub fn rules_for(&self, secret: &str) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .filter(|rule| rule.secret == secret)
            .cloned()
            .collect()
    }

    pub fn rules(&self) -> &[RuleInfo] {
        &self.rules
    }

    /// Whether `secret` has no value yet
    pub fn is_pending(&self, secret: &str) -> bool {
        self.policy.values.value(secret).is_none()
    }

    /// Inject `value` for `secret` from now on. A value it replaces stays
    /// redacted from responses for the rest of the run.
    pub fn set_value(&self, secret: &str, value: String) -> Result<()> {
        self.policy.values.replace(secret, value)
    }
}
