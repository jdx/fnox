use crate::commands::Cli;
use crate::config::Config;
use crate::env;
use crate::error::Result;
use crate::providers::get_provider_resolved;
use clap::Args;

#[derive(Debug, Args)]
#[command(visible_aliases = ["dr"])]
pub struct DoctorCommand {}

impl DoctorCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());

        println!("🏥 Fnox Doctor Report");
        println!("====================");
        println!();

        // Config file info
        println!("📄 Configuration:");
        println!("  File: fnox.toml");
        println!("  Profile: {}", profile);

        config.validate()?;
        println!("  Status: ✓ Loaded successfully");
        println!();

        // Secrets info
        println!("🔐 Secrets:");
        match config.get_secrets(&profile) {
            Ok(secrets) => {
                println!("  Count: {}", secrets.len());
                if !secrets.is_empty() {
                    let mut with_values = 0;
                    let mut required = 0;
                    let mut with_providers = 0;

                    for secret in secrets.values() {
                        if secret.has_value() {
                            with_values += 1;
                        }
                        if secret.provider().is_some() {
                            with_providers += 1;
                        }
                        if secret.if_missing == Some(crate::config::IfMissing::Error) {
                            required += 1;
                        }
                    }

                    println!("  With value source: {}", with_values);
                    println!("  Required: {}", required);
                    println!("  Using providers: {}", with_providers);

                    if secrets.len() <= 10 {
                        println!("  Secrets:");
                        for (name, secret) in secrets {
                            let status = if secret.has_value() { "✓" } else { "?" };
                            let provider = secret.provider().unwrap_or("plain");
                            println!("    {} {} (provider: {})", status, name, provider);
                        }
                    }
                }
            }
            Err(_) => {
                println!("  Status: Profile not found");
            }
        }
        println!();

        // Providers info
        println!("🔧 Providers:");
        let providers = config.get_providers(&profile);
        println!("  Count: {}", providers.len());

        if !providers.is_empty() {
            println!("  Providers:");
            for (name, provider_config) in &providers {
                println!("    {} ({})", name, provider_config.provider_type());
            }
        }
        println!();

        // Environment info
        println!("🌍 Environment:");
        if let Some(env_profile) = (*env::FNOX_PROFILE).clone() {
            println!("  FNOX_PROFILE: {}", env_profile);
        } else {
            println!("  FNOX_PROFILE: (not set)");
        }

        // A top-level env = "exec" / env = false posture is meant to keep
        // secrets out of the interactive shell — but an exported FNOX_AGE_KEY
        // is itself a shell-visible master credential that undermines it.
        if let Some(env_default) = config.env
            && !env_default.in_shell()
            && env::FNOX_AGE_KEY.is_some()
        {
            println!(
                "  ⚠ FNOX_AGE_KEY is exported in this shell while the top-level `env` \
                 default keeps secrets out of it."
            );
            println!("    Anything running in this shell can decrypt your secrets with that key.");
            println!("    Consider `age_key_file` or an OS keychain instead.");
        }

        // Test providers
        if !providers.is_empty() {
            println!();
            println!("🔍 Provider Health:");
            for (name, provider_config) in &providers {
                match get_provider_resolved(&config, &profile, name, provider_config).await {
                    Ok(provider) => {
                        print!("  {}: Testing...", name);
                        match provider.test_connection().await {
                            Ok(_) => println!(" ✓"),
                            Err(e) => println!(" ✗ {}", e),
                        }
                    }
                    Err(e) => {
                        println!("  {}: ✗ Failed to initialize: {}", name, e);
                    }
                }
            }
        }

        // Summary
        println!();
        println!("📊 Summary:");
        let total_secrets = config.get_secrets(&profile).map(|s| s.len()).unwrap_or(0);
        println!("  Total secrets: {}", total_secrets);
        println!("  Total providers: {}", providers.len());

        println!();
        println!("💡 Tips:");
        if total_secrets == 0 {
            println!("  - Add secrets with: fnox set <name> <value>");
        }
        if providers.is_empty() && total_secrets > 3 {
            println!("  - Consider using a provider for better secret management");
        }
        println!("  - Run 'fnox check' to validate your configuration");

        Ok(())
    }
}
