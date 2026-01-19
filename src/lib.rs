// Library interface for fnox
pub mod auth_prompt;
pub mod commands;
pub mod config;
pub mod env;
pub mod error;
pub mod hook_env;
pub mod providers;
pub mod secret_resolver;
pub mod settings;
pub mod shell;
pub mod tui;

#[cfg(test)]
mod clap_sort;

// Re-export commonly used items
pub use error::{FnoxError, Result};
