use crate::error::{FnoxError, Result};
use crate::secret_resolver::{handle_provider_error, resolve_if_missing_behavior, resolve_secret};
use crate::{commands::Cli, config::Config};
use clap::{Args, ValueHint};
use std::process::Command;

#[derive(Debug, Args)]
#[command(visible_alias = "x", alias = "run")]
pub struct ExecCommand {
    /// Command to run
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_hint = ValueHint::CommandWithArguments)]
    pub command: Vec<String>,
}

impl ExecCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if self.command.is_empty() {
            return Err(FnoxError::CommandNotSpecified);
        }

        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Running command with secrets from profile '{}'", profile);

        // Get the profile secrets
        let profile_secrets = config.get_secrets(&profile)?;

        let mut cmd = Command::new(&self.command[0]);
        if self.command.len() > 1 {
            cmd.args(&self.command[1..]);
        }

        // Resolve and add each secret as an environment variable
        for (key, secret_config) in &profile_secrets {
            match resolve_secret(
                &config,
                &profile,
                key,
                secret_config,
                cli.age_key_file.as_deref(),
            )
            .await
            {
                Ok(Some(value)) => {
                    cmd.env(key, value);
                }
                Ok(None) => {
                    // Secret not found but if_missing allows it (already handled by resolve_secret)
                }
                Err(e) => {
                    // Provider error - respect if_missing to decide whether to fail or continue
                    let if_missing = resolve_if_missing_behavior(secret_config, &config);

                    if let Some(error) = handle_provider_error(key, e, if_missing, true) {
                        return Err(error);
                    }
                }
            }
        }

        let status = cmd
            .status()
            .map_err(|e| FnoxError::CommandExecutionFailed {
                command: self.command.join(" "),
                source: e,
            })?;

        if !status.success()
            && let Some(code) = status.code()
        {
            return Err(FnoxError::CommandExitFailed {
                command: self.command.join(" "),
                status: code,
            });
        }

        Ok(())
    }
}
