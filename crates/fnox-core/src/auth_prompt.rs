//! Authentication prompt handling for providers.
//!
//! When a provider fails due to authentication issues, this module handles
//! prompting the user to run the appropriate auth command and retrying.

use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::providers::ProviderConfig;
use demand::Confirm;
use std::borrow::Cow;
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
    resolved_auth_command: Option<&str>,
    error: &FnoxError,
) -> Result<bool> {
    if !error.is_auth_error() {
        return Ok(false);
    }

    if !config.should_prompt_auth() {
        return Ok(false);
    }

    let Some(auth_command) = provider_config.default_auth_command(resolved_auth_command) else {
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

/// Quote an argument for the shell `run_auth_command` uses.
pub(crate) fn quote_arg(arg: &str) -> Option<Cow<'_, str>> {
    if cfg!(target_os = "windows") {
        arg.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .then_some(Cow::Borrowed(arg))
    } else {
        shlex::try_quote(arg).ok()
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
        let result = prompt_and_run_auth(&config, &provider_config, "1password", None, &error);
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
        let result = prompt_and_run_auth(&config, &provider_config, "1password", None, &error);
        assert!(!result.unwrap());
    }

    fn aws_provider(extra: serde_json::Value) -> ProviderConfig {
        let mut value = serde_json::json!({"type": "aws-ps", "region": "eu-central-1"});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    /// The auth command offered for an AWS provider resolved for `fnox_profiles`.
    async fn aws_auth_command(
        config: &Config,
        extra: serde_json::Value,
        fnox_profiles: &[&str],
    ) -> Option<String> {
        let provider_config = aws_provider(extra);
        let fnox_profiles: Vec<String> = fnox_profiles.iter().map(|p| p.to_string()).collect();
        let provider = crate::providers::get_provider_resolved(
            config,
            &fnox_profiles,
            "aws",
            &provider_config,
        )
        .await
        .unwrap();
        provider_config
            .default_auth_command(provider.auth_command().as_deref())
            .map(str::to_string)
    }

    #[tokio::test]
    async fn aws_auth_command_uses_resolved_profile() {
        let mut config = Config::new();
        let mut secret = crate::config::SecretConfig::new();
        secret.default = Some("from-secret".to_string());
        config
            .secrets
            .insert("AWS_PROFILE_NAME".to_string(), secret);

        let cases = [
            (serde_json::json!({}), Some("aws sso login")),
            (
                serde_json::json!({"profile": "production"}),
                Some("aws sso login --profile production"),
            ),
            (
                serde_json::json!({"profile": "{{ fnox.profile }}"}),
                Some("aws sso login --profile staging"),
            ),
            (
                serde_json::json!({"profile": {"secret": "AWS_PROFILE_NAME"}}),
                Some("aws sso login --profile from-secret"),
            ),
            (
                serde_json::json!({"profile": "production", "auth_command": "custom login"}),
                Some("custom login"),
            ),
            (
                serde_json::json!({"profile": "production", "auth_command": ""}),
                None,
            ),
        ];
        for (extra, expected) in cases {
            assert_eq!(
                aws_auth_command(&config, extra.clone(), &["staging"])
                    .await
                    .as_deref(),
                expected,
                "{extra}"
            );
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn aws_auth_command_quotes_profile() {
        assert_eq!(
            aws_auth_command(
                &Config::new(),
                serde_json::json!({"profile": "a b; rm -rf ~"}),
                &[]
            )
            .await
            .as_deref(),
            Some("aws sso login --profile 'a b; rm -rf ~'")
        );
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
