use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use clap::{Args, Subcommand, ValueEnum};
use strum::{Display, EnumString, VariantNames};

mod add;
mod list;
mod remove;
mod test;

pub use add::AddCommand;
pub use list::ListCommand;
pub use remove::RemoveCommand;
pub use test::TestCommand;

/// Supported provider types
#[derive(Debug, Clone, Copy, ValueEnum, Display, EnumString, VariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum ProviderType {
    /// 1Password
    #[value(name = "1password")]
    #[strum(serialize = "1password")]
    OnePassword,
    /// Age encryption
    #[value(name = "age")]
    Age,
    /// AWS Secrets Manager
    #[value(name = "aws")]
    Aws,
    /// AWS KMS
    #[value(name = "aws-kms")]
    #[strum(serialize = "aws-kms")]
    AwsKms,
    /// AWS Parameter Store
    #[value(name = "aws-ps")]
    #[strum(serialize = "aws-ps")]
    AwsParameterStore,
    /// Azure Key Vault KMS
    #[value(name = "azure-kms")]
    #[strum(serialize = "azure-kms")]
    AzureKms,
    /// Azure Key Vault Secrets Manager
    #[value(name = "azure-sm")]
    #[strum(serialize = "azure-sm")]
    AzureSecretsManager,
    /// Google Cloud Secret Manager
    #[value(name = "gcp")]
    Gcp,
    /// Google Cloud KMS
    #[value(name = "gcp-kms")]
    #[strum(serialize = "gcp-kms")]
    GcpKms,
    /// Infisical
    #[value(name = "infisical")]
    Infisical,
    /// Click Studios Passwordstate
    #[value(name = "passwordstate")]
    Passwordstate,
    /// HashiCorp Vault
    #[value(name = "vault")]
    Vault,
}

#[derive(Debug, Args)]
pub struct ProviderCommand {
    #[command(subcommand)]
    pub action: Option<ProviderAction>,
}

#[derive(Debug, Subcommand)]
pub enum ProviderAction {
    /// Add a new provider
    Add(AddCommand),

    /// List available providers
    List(ListCommand),

    /// Remove a provider
    Remove(RemoveCommand),

    /// Test a provider connection
    Test(TestCommand),
}

impl ProviderCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        match &self.action {
            None => ListCommand { complete: false }.run(cli, config).await,
            Some(ProviderAction::List(cmd)) => cmd.run(cli, config).await,
            Some(ProviderAction::Add(cmd)) => cmd.run(cli).await,
            Some(ProviderAction::Remove(cmd)) => cmd.run(cli).await,
            Some(ProviderAction::Test(cmd)) => cmd.run(cli, config).await,
        }
    }
}
