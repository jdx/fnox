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
    /// FIDO2 hmac-secret hardware-backed encryption
    #[cfg(not(target_env = "musl"))]
    #[value(name = "fido2")]
    Fido2,
    /// Bitwarden Password Manager
    #[value(name = "bitwarden")]
    Bitwarden,
    /// Doppler secrets manager
    #[value(name = "doppler")]
    Doppler,
    /// FOKS (Federated Open Key Service)
    #[value(name = "foks")]
    Foks,
    /// Bitwarden Secrets Manager
    #[value(name = "bitwarden-sm")]
    #[strum(serialize = "bitwarden-sm")]
    BitwardenSecretsManager,
    /// Infisical
    #[value(name = "infisical")]
    Infisical,
    /// KeePass
    #[cfg(feature = "keepass")]
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
    /// YubiKey HMAC-SHA1 hardware-backed encryption
    #[value(name = "yubikey")]
    Yubikey,
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

    /// Returns true when the provider whose TOML descriptor sits at
    /// `path` is currently compiled into this build — either because
    /// it has no `cargo_feature` (always compiled) or because the
    /// feature named there is enabled in the current Cargo invocation.
    ///
    /// Mirrored against the build-script behavior in
    /// `crates/fnox-core/build/generate_providers.rs`. Update both
    /// together when adding a new gated provider.
    fn provider_feature_enabled(path: &std::path::Path) -> bool {
        let Ok(content) = std::fs::read_to_string(path) else {
            return false;
        };
        let cargo_feature = content
            .lines()
            .find_map(|line| {
                let line = line.trim();
                let rest = line.strip_prefix("cargo_feature")?;
                let rest = rest.trim_start().strip_prefix('=')?.trim();
                rest.strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .map(str::to_owned)
            });

        match cargo_feature.as_deref() {
            None => true,
            Some("keepass") => cfg!(feature = "keepass"),
            // When extending this match for a new gated provider,
            // also wire the matching `#[cfg(feature = "...")]` on
            // its `ProviderType` variant and on its arm in
            // `src/commands/provider/add.rs`.
            Some(other) => panic!(
                "provider TOML at {} declares cargo_feature = {:?} but \
                 the drift test doesn't know about it — add a `cfg!` \
                 branch for it in src/commands/provider/mod.rs::tests",
                path.display(),
                other
            ),
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
            // fido2 is excluded from musl builds — mirror build/generate_providers.rs.
            .filter(|path| {
                let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                !(cfg!(target_env = "musl") && name == "fido2")
            })
            // Providers gated behind a Cargo feature are only in the CLI
            // when that feature is enabled; mirror the gating here so
            // the drift test stays meaningful across feature combos.
            .filter(|path| provider_feature_enabled(path))
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
