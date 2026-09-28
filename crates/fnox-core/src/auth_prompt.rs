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
    if !error.is_auth_error() {
        return Ok(false);
    }

    if !config.should_prompt_auth() {
        return Ok(false);
    }

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

    let status = run_auth_command(auth_command);

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

fn run_auth_command(auth_command: &str) -> std::io::Result<std::process::ExitStatus> {
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", auth_command])
            .stdout(std::io::stderr())
            .status()
    } else {
        Command::new("sh")
            .args(["-c", auth_command])
            .stdout(std::io::stderr())
            .status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::OptionStringOrSecretRef;

    fn provider_with_auth_command() -> ProviderConfig {
        ProviderConfig::OnePassword {
            vault: OptionStringOrSecretRef::literal("default"),
            account: OptionStringOrSecretRef::none(),
            token: OptionStringOrSecretRef::none(),
            auth_command: None,
            daemon_cache: None,
        }
    }

    // Integration-level: non-auth errors return Ok(false) from prompt_and_run_auth
    #[test]
    fn non_auth_error_skips_prompt() {
        let config = Config::new();
        let provider_config = provider_with_auth_command();
        let error = FnoxError::ProviderSecretNotFound {
            provider: "test".to_string(),
            secret: "MY_SECRET".to_string(),
            hint: "check".to_string(),
            url: "https://example.com".to_string(),
        };
        let result = prompt_and_run_auth(&config, &provider_config, "1password", &error);
        assert!(!result.unwrap());
    }

    #[test]
    fn cli_failed_error_skips_prompt() {
        let config = Config::new();
        let provider_config = provider_with_auth_command();
        let error = FnoxError::ProviderCliFailed {
            provider: "test".to_string(),
            details: "field does not exist".to_string(),
            hint: "check".to_string(),
            url: "https://example.com".to_string(),
        };
        let result = prompt_and_run_auth(&config, &provider_config, "1password", &error);
        assert!(!result.unwrap());
    }

    #[test]
    fn auth_command_stdout_is_redirected_to_stderr() {
        const CHILD_ENV: &str = "FNOX_TEST_AUTH_COMMAND_STDOUT";
        const MARKER: &str = "auth-command-output-marker";

        if std::env::var(CHILD_ENV).ok().as_deref() == Some("1") {
            run_auth_command(&format!("echo {MARKER}")).unwrap();
            return;
        }

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "auth_prompt::tests::auth_command_stdout_is_redirected_to_stderr",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();

        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(MARKER));
        assert!(String::from_utf8_lossy(&output.stderr).contains(MARKER));
    }
}
