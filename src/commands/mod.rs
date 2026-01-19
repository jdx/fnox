use std::path::PathBuf;

use crate::error::{FnoxError, Result};
use clap::{Parser, Subcommand};

use crate::config::Config;

pub mod activate;
pub mod check;
pub mod ci_redact;
pub mod completion;
pub mod deactivate;
pub mod doctor;
pub mod edit;
pub mod exec;
pub mod export;
pub mod get;
pub mod hook_env;
pub mod import;
pub mod init;
pub mod list;
pub mod profiles;
pub mod provider;
pub mod remove;
pub mod scan;
pub mod set;
pub mod tui;
pub mod usage;
pub mod version;

#[derive(Parser)]
#[command(name = "fnox")]
#[command(about = "A flexible secret management tool by @jdx", long_about = None)]
#[command(version)]
#[command(help_expected = true)]
pub struct Cli {
    /// Path to the configuration file (default: fnox.toml, searches parent directories)
    #[arg(short, long, default_value = "fnox.toml", global = true)]
    pub config: PathBuf,

    /// Profile to use (default: default, or FNOX_PROFILE env var)
    #[arg(short = 'P', long, global = true)]
    pub profile: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Path to age key file for decryption (deprecated: use provider config instead)
    #[arg(long, global = true, hide = true)]
    pub age_key_file: Option<PathBuf>,

    /// What to do if a secret is missing (error, warn, ignore)
    #[arg(long, global = true)]
    pub if_missing: Option<String>,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Output shell activation code to enable automatic secret loading
    Activate(activate::ActivateCommand),

    /// Check if all required secrets are defined and configured
    Check(check::CheckCommand),

    /// Redact secrets in CI/CD output (GitHub Actions mask)
    #[command(hide = true)]
    CiRedact(ci_redact::CiRedactCommand),

    /// Generate shell completions
    Completion(completion::CompletionCommand),

    /// Disable fnox shell integration in the current shell session
    Deactivate(deactivate::DeactivateCommand),

    /// Show diagnostic information about the current fnox state
    Doctor(doctor::DoctorCommand),

    /// Edit the configuration file
    Edit(edit::EditCommand),

    /// Execute a command with secrets as environment variables
    Exec(exec::ExecCommand),

    /// Export secrets in various formats
    Export(export::ExportCommand),

    /// Get a secret value
    Get(get::GetCommand),

    /// Internal command used by shell hooks to load secrets
    #[command(hide = true)]
    HookEnv(hook_env::HookEnvCommand),

    /// Import secrets from various sources
    Import(import::ImportCommand),

    /// Initialize a new fnox configuration file
    Init(init::InitCommand),

    /// List all secrets
    List(list::ListCommand),

    /// List available profiles
    Profiles(profiles::ProfilesCommand),

    /// Manage providers (defaults to list)
    Provider(provider::ProviderCommand),

    /// Remove a secret
    Remove(remove::RemoveCommand),

    /// Scan repository for potential secrets
    Scan(scan::ScanCommand),

    /// Set a secret value
    Set(set::SetCommand),

    /// Interactive TUI dashboard for managing secrets
    Tui(tui::TuiCommand),

    /// Generate usage specification
    Usage(usage::UsageCommand),

    /// Show version information
    Version(version::VersionCommand),
}

impl Commands {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        match self {
            // Commands that don't need config
            Commands::Version(cmd) => cmd.run(cli).await,
            Commands::Init(cmd) => cmd.run(cli).await,
            Commands::Completion(cmd) => cmd.run(cli).await,
            Commands::Usage(cmd) => cmd.run(cli).await,
            Commands::Activate(cmd) => cmd
                .run()
                .await
                .map_err(|e| FnoxError::Config(e.to_string())),
            Commands::Deactivate(cmd) => cmd
                .run(cli, Config::new())
                .await
                .map_err(|e| FnoxError::Config(e.to_string())),
            Commands::HookEnv(cmd) => cmd
                .run()
                .await
                .map_err(|e| FnoxError::Config(e.to_string())),

            // Commands that need config
            Commands::Check(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::CiRedact(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Doctor(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Edit(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Export(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Get(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Import(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::List(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Profiles(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Provider(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Remove(cmd) => cmd.run(cli).await,
            Commands::Exec(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Set(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Scan(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Tui(cmd) => cmd.run(cli, self.load_config(cli)?).await,
        }
    }

    fn load_config(&self, cli: &Cli) -> Result<Config> {
        Config::load_smart(&cli.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_ordering() {
        // Validate that CLI commands and arguments are properly sorted
        // according to clap_sort conventions
        crate::clap_sort::assert_command_order(&Cli::command());
    }
}
