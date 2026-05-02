// Library interface for fnox
//
// The provider library, config types, and secret resolver live in the `fnox-core`
// crate (`crates/fnox-core/`). This binary crate re-exports them so existing
// `fnox::providers`, `fnox::config`, etc. paths continue to work for downstream
// consumers and for our own modules.

pub use fnox_core::{
    auth_prompt, config, env, error, http, lease, lease_backends, library, providers,
    secret_resolver, settings, source_registry, spanned, suggest, temp_file_secrets,
};

// CLI-only modules — depend on fnox-core for everything else.
pub mod commands;
pub mod hook_env;
pub mod mcp_server;
pub mod shell;
pub mod tui;

// Re-export commonly used items
pub use error::{FnoxError, Result};
pub use library::Fnox;
