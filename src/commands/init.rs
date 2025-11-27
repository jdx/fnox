use crate::commands::Cli;
use crate::config::{Config, ProviderConfig, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::providers::{WizardCategory, WizardInfo, get_provider};
use clap::Args;
use demand::{Confirm, DemandOption, Input, Select};
use std::collections::HashMap;

#[derive(Debug, Args)]
#[command(visible_alias = "i")]
pub struct InitCommand {
    /// Initialize the global config file (~/.config/fnox/config.toml)
    #[arg(short = 'g', long)]
    global: bool,

    /// Overwrite existing configuration file
    #[arg(long)]
    force: bool,

    /// Skip the interactive wizard and create a minimal config
    #[arg(long)]
    skip_wizard: bool,
}

impl InitCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        // Determine the target config path
        let config_path = if self.global {
            Config::global_config_path()
        } else {
            cli.config.clone()
        };

        tracing::debug!(
            "Initializing new fnox configuration at '{}'",
            config_path.display()
        );

        if config_path.exists() && !self.force {
            return Err(FnoxError::Config(format!(
                "Configuration file '{}' already exists. Use --force to overwrite.",
                config_path.display()
            )));
        }

        // Create parent directory if it doesn't exist (for global config)
        if self.global
            && let Some(parent) = config_path.parent()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                FnoxError::Config(format!(
                    "Failed to create config directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let config = if self.skip_wizard || !atty::is(atty::Stream::Stdin) {
            // Non-interactive mode
            Config::new()
        } else {
            // Interactive wizard mode
            self.run_wizard().await?
        };

        config.save(&config_path)?;

        println!(
            "\n✓ Created new fnox configuration at '{}'",
            config_path.display()
        );
        if self.global {
            println!("\nThis global config will be used as the base for all projects.");
        }
        println!("\nNext steps:");
        println!(
            "  • Add secrets: fnox set MY_SECRET <value>{}",
            if self.global { " --global" } else { "" }
        );
        println!("  • List secrets: fnox list");
        println!("  • Use in commands: fnox exec -- <command>");

        Ok(())
    }

    async fn run_wizard(&self) -> Result<Config> {
        println!("\n🔐 Welcome to fnox setup wizard!\n");
        println!("This will help you configure your first secret provider.\n");

        // Ask if they want to set up a provider
        let setup_provider = Confirm::new("Would you like to set up a provider now?")
            .affirmative("Yes")
            .negative("No, I'll configure it later")
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        if !setup_provider {
            println!("\n✓ Creating minimal configuration file.");
            return Ok(Config::new());
        }

        // Select provider category
        let category = self.select_category()?;

        // Get providers for that category
        let providers = ProviderConfig::wizard_info_by_category(category);

        // Select specific provider
        let provider_info = self.select_provider(&providers)?;

        // Print setup instructions
        println!("\n{}\n", provider_info.setup_instructions);

        // Collect fields from user
        let fields = self.collect_fields(provider_info)?;

        // Build the config using the builder
        let provider_config =
            ProviderConfig::from_wizard_fields(provider_info.provider_type, &fields)?;

        // Test the connection using the Provider trait
        self.test_provider_connection(&provider_config).await;

        // Get provider name
        let provider_name = self.get_provider_name(provider_info.default_name)?;

        // Create config with provider
        let mut config = Config::new();
        config
            .providers
            .insert(provider_name.clone(), provider_config);
        config.default_provider = Some(provider_name);

        // Ask if they want to add an example secret
        let add_example = Confirm::new("Would you like to add an example secret?")
            .affirmative("Yes")
            .negative("No")
            .run()
            .unwrap_or(false);

        if add_example {
            let secret_name = Input::new("Secret name:")
                .placeholder("MY_SECRET")
                .run()
                .unwrap_or_else(|_| "EXAMPLE_SECRET".to_string());

            let description = Input::new("Description (optional):")
                .placeholder("Example secret for testing")
                .run()
                .ok();

            config.secrets.insert(
                secret_name,
                SecretConfig {
                    description: description.filter(|s| !s.is_empty()),
                    provider: config.default_provider.clone(),
                    value: None, // Will be set with `fnox set` later
                    default: None,
                    if_missing: None,
                    source_path: None,
                },
            );
        }

        Ok(config)
    }

    /// Select a provider category
    fn select_category(&self) -> Result<WizardCategory> {
        let mut select = Select::new("What type of provider do you want to use?")
            .description("Choose a category based on your security and convenience needs")
            .filterable(false);

        for category in WizardCategory::all() {
            select = select.option(
                DemandOption::new(category.display_name())
                    .label(category.display_name())
                    .description(category.description()),
            );
        }

        let selected = select
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        // Map the display name back to the category
        for category in WizardCategory::all() {
            if category.display_name() == selected {
                return Ok(*category);
            }
        }

        Err(FnoxError::Config("Unknown provider category".to_string()))
    }

    /// Select a specific provider from the given list
    fn select_provider(&self, providers: &[&'static WizardInfo]) -> Result<&'static WizardInfo> {
        let mut select = Select::new("Select provider:").filterable(false);

        for info in providers {
            select = select.option(
                DemandOption::new(info.provider_type)
                    .label(info.display_name)
                    .description(info.description),
            );
        }

        let selected = select
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        // Find the selected provider info
        for info in providers {
            if info.provider_type == selected {
                return Ok(info);
            }
        }

        Err(FnoxError::Config("Unknown provider".to_string()))
    }

    /// Collect field values from the user
    fn collect_fields(&self, info: &WizardInfo) -> Result<HashMap<String, String>> {
        let mut fields = HashMap::new();

        for field in info.fields {
            let result = Input::new(field.label).placeholder(field.placeholder).run();

            match result {
                Ok(value) => {
                    if value.is_empty() && field.required {
                        return Err(FnoxError::Config(format!("{} is required", field.name)));
                    }
                    fields.insert(field.name.to_string(), value);
                }
                Err(e) => {
                    return Err(FnoxError::Config(format!("Wizard cancelled: {}", e)));
                }
            }
        }

        Ok(fields)
    }

    /// Get the provider name from the user
    fn get_provider_name(&self, default: &str) -> Result<String> {
        Input::new("Provider name:")
            .placeholder(default)
            .run()
            .map(|name| {
                if name.is_empty() {
                    default.to_string()
                } else {
                    name
                }
            })
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))
    }

    /// Test the provider connection and print the result
    async fn test_provider_connection(&self, provider_config: &ProviderConfig) {
        println!("\n🔍 Testing provider connection...");

        match get_provider(provider_config) {
            Ok(provider) => match provider.test_connection().await {
                Ok(()) => {
                    println!("✓ Provider connection successful!\n");
                }
                Err(e) => {
                    println!("⚠️  Provider connection test failed: {}", e);
                    println!("   You can still save the configuration and fix the issue later.\n");
                }
            },
            Err(e) => {
                println!("⚠️  Could not create provider: {}", e);
                println!("   You can still save the configuration and fix the issue later.\n");
            }
        }
    }
}
