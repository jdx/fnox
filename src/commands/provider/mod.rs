use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, usage_rs::ValueEnum, Display, EnumString, VariantNames,
)]
#[strum(serialize_all = "kebab-case")]
pub enum ProviderType {
    /// 1Password
    #[usage(name = "1password")]
    #[strum(serialize = "1password")]
    OnePassword,
    /// Age encryption
    #[usage(name = "age")]
    Age,
    /// AWS Secrets Manager
    #[usage(name = "aws")]
    Aws,
    /// AWS KMS
    #[usage(name = "aws-kms")]
    #[strum(serialize = "aws-kms")]
    AwsKms,
    /// AWS Parameter Store
    #[usage(name = "aws-ps")]
    #[strum(serialize = "aws-ps")]
    AwsParameterStore,
    /// Azure App Configuration
    #[usage(name = "azure-ac")]
    #[strum(serialize = "azure-ac")]
    AzureAppConfiguration,
    /// Azure Key Vault KMS
    #[usage(name = "azure-kms")]
    #[strum(serialize = "azure-kms")]
    AzureKms,
    /// Azure Key Vault Secrets Manager
    #[usage(name = "azure-sm")]
    #[strum(serialize = "azure-sm")]
    AzureSecretsManager,
    /// Google Cloud Secret Manager
    #[usage(name = "gcp")]
    Gcp,
    /// Google Cloud KMS
    #[usage(name = "gcp-kms")]
    #[strum(serialize = "gcp-kms")]
    GcpKms,
    /// FIDO2 hmac-secret hardware-backed encryption
    #[cfg(not(target_env = "musl"))]
    #[usage(name = "fido2")]
    Fido2,
    /// Bitwarden Password Manager
    #[usage(name = "bitwarden")]
    Bitwarden,
    /// Doppler secrets manager
    #[usage(name = "doppler")]
    Doppler,
    /// FOKS (Federated Open Key Service)
    #[usage(name = "foks")]
    Foks,
    /// Bitwarden Secrets Manager
    #[usage(name = "bitwarden-sm")]
    #[strum(serialize = "bitwarden-sm")]
    BitwardenSecretsManager,
    /// Infisical
    #[usage(name = "infisical")]
    Infisical,
    /// KeePass
    #[usage(name = "keepass")]
    #[strum(serialize = "keepass")]
    KeePass,
    /// Keeper Secrets Manager
    #[usage(name = "keeper-sm")]
    #[strum(serialize = "keeper-sm")]
    KeeperSecretsManager,
    /// OS Keychain
    #[usage(name = "keychain")]
    Keychain,
    /// password-store (pass)
    #[usage(name = "password-store")]
    #[strum(serialize = "password-store")]
    PasswordStore,
    /// Click Studios Passwordstate
    #[usage(name = "passwordstate")]
    Passwordstate,
    /// Plain text provider
    #[usage(name = "plain")]
    Plain,
    /// Proton Pass
    #[usage(name = "proton-pass")]
    #[strum(serialize = "proton-pass")]
    ProtonPass,
    /// HashiCorp Vault
    #[usage(name = "vault")]
    Vault,
    /// YubiKey HMAC-SHA1 hardware-backed encryption
    #[usage(name = "yubikey")]
    Yubikey,
}

#[derive(Debug, usage_rs::Args)]
pub struct ProviderCommand {
    #[usage(subcommand)]
    pub action: Option<ProviderAction>,
}

#[derive(Debug, usage_rs::Subcommands)]
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
    use std::collections::BTreeSet;
    use usage_rs::spec::ValueEnum;

    fn normalize_provider_type_for_add(provider_type: &str) -> String {
        match provider_type {
            "aws-sm" => "aws".to_string(),
            "gcp-sm" => "gcp".to_string(),
            _ => provider_type.to_string(),
        }
    }

    #[test]
    fn provider_add_types_match_provider_definitions() {
        let providers_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("crates")
            .join("fnox-core")
            .join("providers");

        let defined_types: BTreeSet<String> = std::fs::read_dir(&providers_dir)
            .expect("providers directory should exist")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .filter_map(|path| {
                path.file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
            })
            // fido2 is excluded from musl builds — mirror build/generate_providers.rs.
            .filter(|name| !(cfg!(target_env = "musl") && name == "fido2"))
            .map(|provider_type| normalize_provider_type_for_add(&provider_type))
            .collect();

        let cli_types: BTreeSet<String> = ProviderType::CHOICES
            .iter()
            .map(|value| (*value).to_string())
            .collect();

        assert_eq!(
            cli_types, defined_types,
            "provider add choices drifted from providers/*.toml definitions"
        );
    }
}
