//! Authentication prompt handling for providers.
//!
//! When a provider fails due to authentication issues, this module handles
//! prompting the user to run the appropriate auth command and retrying.

use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::providers::ProviderConfig;
use demand::Confirm;
use std::process::Command;

/// Returns true if all preconditions are met for attempting an auth prompt.
/// Pure function — no side effects, fully testable.
fn should_attempt_auth_prompt(
    is_auth_error: bool,
    prompt_auth_enabled: bool,
    has_auth_command: bool,
) -> bool {
    is_auth_error && prompt_auth_enabled && has_auth_command
}

/// Prompts the user to run an auth command and executes it if they agree.
///
/// Returns `Ok(true)` if the auth command was run successfully,
/// `Ok(false)` if the user declined or no auth command is available,
/// `Err` if the auth command failed.
#[cfg(test)]
mod tests {
    use super::*;

    // Exhaustive table test for the pure decision function.
    // Each row: (is_auth_error, prompt_enabled, has_auth_command) -> expected
    #[test]
    fn should_attempt_auth_prompt_truth_table() {
        let cases = [
            // Only true when all three conditions are met
            (true, true, true, true),
            // Any single false -> no prompt
            (false, true, true, false),
            (true, false, true, false),
            (true, true, false, false),
            // Two false
            (false, false, true, false),
            (false, true, false, false),
            (true, false, false, false),
            // All false
            (false, false, false, false),
        ];

        for (is_auth, prompt_enabled, has_cmd, expected) in cases {
            assert_eq!(
                should_attempt_auth_prompt(is_auth, prompt_enabled, has_cmd),
                expected,
                "is_auth={}, prompt_enabled={}, has_cmd={} -> expected {}",
                is_auth,
                prompt_enabled,
                has_cmd,
                expected
            );
        }
    }

    // Integration-level: non-auth errors return Ok(false) from prompt_and_run_auth
    #[test]
    fn non_auth_error_skips_prompt() {
        let config = Config::new();
        let provider_config = ProviderConfig::Plain;
        let error = FnoxError::ProviderSecretNotFound {
            provider: "test".to_string(),
            secret: "MY_SECRET".to_string(),
            hint: "check".to_string(),
            url: "https://example.com".to_string(),
        };
        let result = prompt_and_run_auth(&config, &provider_config, "test", &error);
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn cli_failed_error_skips_prompt() {
        let config = Config::new();
        let provider_config = ProviderConfig::Plain;
        let error = FnoxError::ProviderCliFailed {
            provider: "test".to_string(),
            details: "field does not exist".to_string(),
            hint: "check".to_string(),
            url: "https://example.com".to_string(),
        };
        let result = prompt_and_run_auth(&config, &provider_config, "test", &error);
        assert_eq!(result.unwrap(), false);
    }
}

pub fn prompt_and_run_auth(
    config: &Config,
    provider_config: &ProviderConfig,
    provider_name: &str,
    error: &FnoxError,
) -> Result<bool> {
    let auth_command = match provider_config.default_auth_command() {
        Some(cmd) => cmd,
        None => return Ok(false),
    };

    if !should_attempt_auth_prompt(
        error.is_auth_error(),
        config.should_prompt_auth(),
        true, // has_auth_command: pre-checked above for early return; helper retains the param for full truth-table testability
    ) {
        return Ok(false);
    }

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
