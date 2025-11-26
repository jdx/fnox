use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secrets_batch;
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

        // Resolve secrets using batch resolution for better performance
        let resolved_secrets = resolve_secrets_batch(&config, &profile, &profile_secrets).await?;

        // Add resolved secrets as environment variables
        for (key, value) in resolved_secrets {
            if let Some(value) = value {
                cmd.env(key, value);
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
