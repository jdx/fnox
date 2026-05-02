//! Core library for fnox: provider implementations, config types, secret resolution.
//!
//! This crate is the reusable engine underneath the `fnox` binary. It contains the
//! [`Provider`](providers::Provider) trait, every provider implementation, the config
//! data types, the secret resolver, the lease backends, and the [`Fnox`](library::Fnox)
//! convenience API for downstream consumers.
//!
//! The `fnox` binary depends on this crate and adds CLI-shaped bits (commands, MCP
//! server, TUI, shell integration, hook-env machinery) on top.

pub mod auth_prompt;
pub mod config;
pub mod env;
pub mod error;
pub mod http;
pub mod lease;
pub mod lease_backends;
pub mod library;
pub mod providers;
pub mod secret_resolver;
pub mod settings;
pub mod source_registry;
pub mod spanned;
pub mod suggest;
pub mod temp_file_secrets;

// Re-export commonly used items
pub use error::{FnoxError, Result};
pub use library::Fnox;
