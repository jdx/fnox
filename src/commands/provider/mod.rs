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
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Display, EnumString, VariantNames)]
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
    /// Bitwarden Password Manager
    #[value(name = "bitwarden")]
    Bitwarden,
    /// Bitwarden Secrets Manager
    #[value(name = "bitwarden-sm")]
    #[strum(serialize = "bitwarden-sm")]
    BitwardenSecretsManager,
    /// Infisical
    #[value(name = "infisical")]
    Infisical,
    /// KeePass
    #[value(name = "keepass")]
    #[strum(serialize = "keepass")]
    KeePass,
    /// OS Keychain
    #[value(name = "keychain")]
    Keychain,
    /// password-store (pass)
    #[value(name = "password-store")]
    #[strum(serialize = "password-store")]
    PasswordStore,
    /// Click Studios Passwordstate
    #[value(name = "passwordstate")]
    Passwordstate,
    /// Plain text provider
    #[value(name = "plain")]
    Plain,
    /// Proton Pass
    #[value(name = "proton-pass")]
    #[strum(serialize = "proton-pass")]
    ProtonPass,
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

#[cfg(test)]
mod tests {
    use super::ProviderType;
    use clap::ValueEnum;
    use std::collections::BTreeSet;

    fn normalize_provider_type_for_add(provider_type: &str) -> String {
        match provider_type {
            "aws-sm" => "aws".to_string(),
            "gcp-sm" => "gcp".to_string(),
            _ => provider_type.to_string(),
        }
    }

    #[test]
    fn provider_add_types_match_provider_definitions() {
        let providers_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("providers");

        let defined_types: BTreeSet<String> = std::fs::read_dir(&providers_dir)
            .expect("providers directory should exist")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .filter_map(|path| {
                path.file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
            })
            .map(|provider_type| normalize_provider_type_for_add(&provider_type))
            .collect();

        let cli_types: BTreeSet<String> = ProviderType::value_variants()
            .iter()
            .filter_map(|variant| {
                variant
                    .to_possible_value()
                    .map(|value| value.get_name().to_string())
            })
            .collect();

        assert_eq!(
            cli_types, defined_types,
            "provider add choices drifted from providers/*.toml definitions"
        );
    }
}
