use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secret;
use crate::{
    commands::Cli,
    config::{Config, IfMissing},
};
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
                    // Provider error (auth, network, missing secret, etc.)
                    // Respect if_missing to decide whether to fail or continue
                    match secret_config.if_missing {
                        Some(IfMissing::Error) => {
                            tracing::error!("Error resolving secret '{}': {}", key, e);
                            return Err(e);
                        }
                        Some(IfMissing::Warn) | None => {
                            // Default (None) is Warn
                            tracing::warn!("Error resolving secret '{}': {}", key, e);
                        }
                        Some(IfMissing::Ignore) => {
                            // Silently skip
                        }
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
