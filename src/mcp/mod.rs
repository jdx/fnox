//! The `fnox mcp` server: a session-scoped secret broker for AI agents.
//!
//! [`server`] holds the session state and the MCP handler, [`tools`] the
//! `get_secret` and `exec` tools, [`request_secret`] the tool that asks the
//! user for a missing secret, and [`page`] the one-time local page it serves.

pub mod page;
mod request_secret;
mod server;
mod tools;

pub use request_secret::RequestSecretParams;
pub use server::FnoxMcpServer;
pub use tools::{ExecParams, GetSecretParams};
