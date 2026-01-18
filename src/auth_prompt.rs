//! Authentication prompt handling for providers.
//!
//! When a provider fails due to authentication issues, this module handles
//! prompting the user to run the appropriate auth command and retrying.

use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::providers::ProviderConfig;
use demand::Confirm;
use std::process::Command;

/// Prompts the user to run an auth command and executes it if they agree.
///
/// Returns `Ok(true)` if the auth command was run successfully,
/// `Ok(false)` if the user declined or no auth command is available,
/// `Err` if the auth command failed.
pub fn prompt_and_run_auth(
    config: &Config,
    provider_config: &ProviderConfig,
    provider_name: &str,
    error: &FnoxError,
) -> Result<bool> {
    // Check if we should prompt
    if !config.should_prompt_auth() {
        return Ok(false);
    }

    // Get the auth command for this provider
    let Some(auth_command) = provider_config.default_auth_command() else {
        return Ok(false);
    };

    // Show the error and prompt
    eprintln!(
        "Authentication failed for provider '{}': {}",
        provider_name, error
    );

    let user_confirmed = Confirm::new(format!("Run `{}` to authenticate?", auth_command))
        .affirmative("Yes")
        .negative("No")
        .run()
        .map_err(|e| FnoxError::Provider(format!("Failed to show prompt: {}", e)))?;

    if !user_confirmed {
        return Ok(false);
    }

    // Run the auth command
    eprintln!("Running: {}", auth_command);

    let status = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", auth_command]).status()
    } else {
        Command::new("sh").args(["-c", auth_command]).status()
    };

    match status {
        Ok(exit_status) if exit_status.success() => {
            eprintln!("Authentication successful, retrying...");
            Ok(true)
        }
        Ok(exit_status) => Err(FnoxError::Provider(format!(
            "Auth command failed with exit code: {}",
            exit_status.code().unwrap_or(-1)
        ))),
        Err(e) => Err(FnoxError::Provider(format!(
            "Failed to run auth command: {}",
            e
        ))),
    }
}
