use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::plugins::{self, PluginSource, UpdateOutcome};
use std::path::PathBuf;

#[derive(Debug, usage_rs::Args)]
#[usage(about = "Manage Lua provider plugins")]
pub struct PluginCommand {
    #[usage(subcommand)]
    pub subcommand: Option<PluginSubcommand>,
}

#[derive(Debug, usage_rs::Subcommands)]
pub enum PluginSubcommand {
    /// Install plugins from git
    Install(PluginInstallCommand),
    /// Link a local plugin directory, for plugin development
    Link(PluginLinkCommand),
    /// List installed and declared plugins
    #[usage(alias("list"))]
    Ls(PluginLsCommand),
    /// Remove an installed or linked plugin
    #[usage(alias("rm", "remove"))]
    Uninstall(PluginUninstallCommand),
    /// Update installed plugins to their declared source
    #[usage(alias("upgrade"))]
    Update(PluginUpdateCommand),
}

/// Install plugins from git
///
/// With no arguments, installs every plugin declared under `[plugins]` that is
/// not installed yet. A source is a git URL, optionally followed by `#<ref>`
/// to pin a tag, branch, or commit; `owner/repo` is shorthand for GitHub.
#[derive(Debug, usage_rs::Args)]
#[usage(
    after_long_help = "Examples:\n  fnox plugin install\n  fnox plugin install corp\n  fnox plugin install corp acme/fnox-plugin-corp#v1.0.0\n  fnox plugin install corp https://git.example.com/fnox-plugin-corp.git"
)]
pub struct PluginInstallCommand {
    /// Plugin name; installs all declared plugins when omitted
    pub name: Option<String>,

    /// Git source; defaults to the name's entry under `[plugins]`
    pub source: Option<String>,

    /// Reinstall even if the plugin is already installed
    #[usage(short, long)]
    pub force: bool,
}

#[derive(Debug, usage_rs::Args)]
pub struct PluginLinkCommand {
    /// Plugin name
    pub name: String,

    /// Plugin directory containing provider.lua
    pub path: PathBuf,

    /// Replace an existing plugin with the link
    #[usage(short, long)]
    pub force: bool,
}

#[derive(Debug, usage_rs::Args)]
pub struct PluginLsCommand {}

#[derive(Debug, usage_rs::Args)]
pub struct PluginUninstallCommand {
    /// Plugin name
    pub name: String,
}

#[derive(Debug, usage_rs::Args)]
pub struct PluginUpdateCommand {
    /// Plugins to update; updates all installed plugins when omitted
    pub names: Vec<String>,
}

impl PluginCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        match &self.subcommand {
            None => PluginLsCommand {}.run(cli),
            Some(PluginSubcommand::Install(cmd)) => cmd.run(cli).await,
            Some(PluginSubcommand::Link(cmd)) => cmd.run(),
            Some(PluginSubcommand::Ls(cmd)) => cmd.run(cli),
            Some(PluginSubcommand::Uninstall(cmd)) => cmd.run(),
            Some(PluginSubcommand::Update(cmd)) => cmd.run(cli).await,
        }
    }
}

/// Load the config for `[plugins]` declarations. Plugin commands also work
/// outside a project, so a missing config file is not an error.
fn load_config(cli: &Cli) -> Result<Config> {
    match Config::load_smart(&cli.config) {
        Ok(config) => Ok(config),
        Err(FnoxError::ConfigNotFound { .. } | FnoxError::ConfigFileNotFound { .. }) => {
            Ok(Config::new())
        }
        Err(e) => Err(e),
    }
}

fn declared_source(config: &Config, name: &str) -> Result<Option<PluginSource>> {
    config
        .plugins
        .get(name)
        .map(|source| PluginSource::parse(source))
        .transpose()
}

impl PluginInstallCommand {
    async fn run(&self, cli: &Cli) -> Result<()> {
        let config = load_config(cli)?;
        let Some(name) = &self.name else {
            if self.source.is_some() {
                return Err(FnoxError::Config(
                    "a plugin source requires a plugin name".to_string(),
                ));
            }
            if config.plugins.is_empty() {
                println!("No plugins declared under [plugins]");
                return Ok(());
            }
            for name in config.plugins.keys() {
                if plugins::is_installed(name) && !self.force {
                    tracing::debug!("plugin '{name}' is already installed");
                    continue;
                }
                self.install(name, declared_source(&config, name)?.unwrap())
                    .await?;
            }
            return Ok(());
        };

        let source = match &self.source {
            Some(source) => PluginSource::parse(source)?,
            None => declared_source(&config, name)?.ok_or_else(|| FnoxError::Plugin {
                plugin: name.clone(),
                details: "no source given".to_string(),
                help: format!(
                    "Run `fnox plugin install {name} <git-url>`, or declare `{name} = \"<git-url>\"` under [plugins]"
                ),
            })?,
        };
        self.install(name, source).await
    }

    async fn install(&self, name: &str, source: PluginSource) -> Result<()> {
        eprintln!("Installing plugin '{name}' from {source}");
        let dir = plugins::install(name, &source, self.force).await?;
        println!("✓ Installed plugin '{name}' to {}", dir.display());
        Ok(())
    }
}

impl PluginLinkCommand {
    fn run(&self) -> Result<()> {
        let dest = plugins::link(&self.name, &self.path, self.force)?;
        println!(
            "✓ Linked plugin '{}' to {}",
            self.name,
            std::fs::read_link(&dest).unwrap_or(dest).display()
        );
        Ok(())
    }
}

impl PluginLsCommand {
    fn run(&self, cli: &Cli) -> Result<()> {
        let config = load_config(cli)?;
        let installed = plugins::list_installed()?;
        let mut rows: Vec<[String; 3]> = installed
            .iter()
            .map(|plugin| {
                let source = match &plugin.link_target {
                    Some(target) => format!("-> {}", target.display()),
                    None => plugin.url.clone().unwrap_or_default(),
                };
                let revision = match &plugin.link_target {
                    Some(_) => "(linked)".to_string(),
                    None => plugin.revision.clone().unwrap_or_default(),
                };
                [plugin.name.clone(), source, revision]
            })
            .collect();
        for (name, source) in &config.plugins {
            if !installed.iter().any(|p| &p.name == name) {
                rows.push([name.clone(), source.clone(), "(not installed)".to_string()]);
            }
        }
        if rows.is_empty() {
            println!("No plugins installed");
            return Ok(());
        }
        rows.sort_by(|a, b| a[0].cmp(&b[0]));
        let name_width = rows.iter().map(|r| r[0].len()).max().unwrap_or(0);
        let source_width = rows.iter().map(|r| r[1].len()).max().unwrap_or(0);
        for [name, source, revision] in rows {
            println!("{name:name_width$}  {source:source_width$}  {revision}");
        }
        Ok(())
    }
}

impl PluginUninstallCommand {
    fn run(&self) -> Result<()> {
        plugins::uninstall(&self.name)?;
        println!("✓ Uninstalled plugin '{}'", self.name);
        Ok(())
    }
}

impl PluginUpdateCommand {
    async fn run(&self, cli: &Cli) -> Result<()> {
        let config = load_config(cli)?;
        let names: Vec<String> = if self.names.is_empty() {
            plugins::list_installed()?
                .into_iter()
                .map(|p| p.name)
                .collect()
        } else {
            self.names.clone()
        };
        if names.is_empty() {
            println!("No plugins installed");
            return Ok(());
        }
        for name in &names {
            let source = declared_source(&config, name)?;
            match plugins::update(name, source.as_ref()).await? {
                UpdateOutcome::Updated => println!("✓ Updated plugin '{name}'"),
                UpdateOutcome::Linked => println!("Skipped linked plugin '{name}'"),
            }
        }
        Ok(())
    }
}
