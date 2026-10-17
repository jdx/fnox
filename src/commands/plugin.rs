use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::plugins::{self, PluginSource, UpdateOutcome};
use std::path::PathBuf;

/// Manage Lua provider plugins
///
/// Plugins add provider types written in Lua. They are installed per user in
/// `$FNOX_PLUGINS_DIR` (default: `~/.local/share/fnox/plugins`) and declared per
/// project under `[plugins]`. Without a subcommand, `fnox plugin` lists them.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox plugin", header = "List installed and declared plugins"),
    example("fnox plugin install", header = "Install every plugin the project declares"),
    after_long_help = "See also:\n- Lua plugins: https://fnox.jdx.dev/providers/lua"
)]
pub struct PluginCommand {
    #[usage(subcommand)]
    pub subcommand: Option<PluginSubcommand>,
}

#[derive(Debug, usage_rs::Subcommands)]
pub enum PluginSubcommand {
    Install(PluginInstallCommand),
    Link(PluginLinkCommand),
    #[usage(alias("list"))]
    Ls(PluginLsCommand),
    #[usage(alias("rm", "remove"))]
    Uninstall(PluginUninstallCommand),
    #[usage(alias("upgrade"))]
    Update(PluginUpdateCommand),
}

/// Install Lua plugins from git
///
/// With no arguments, installs every plugin declared under `[plugins]` that is
/// not installed yet. With NAME, installs that plugin from SOURCE, or from its
/// `[plugins]` entry when SOURCE is omitted. A source is a git URL, optionally
/// followed by `#<ref>` to pin a tag, branch, or commit; `owner/repo` is
/// shorthand for GitHub. Installing does not add a `[plugins]` entry.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox plugin install", header = "Install every declared plugin"),
    example("fnox plugin install corp", header = "Install one declared plugin"),
    example(
        "fnox plugin install corp acme/fnox-plugin-corp#v1.0.0",
        header = "Install a pinned version from GitHub"
    ),
    example(
        "fnox plugin install corp https://git.example.com/fnox-plugin-corp.git",
        header = "Install from any git URL"
    ),
    after_long_help = "See also:\n- Lua plugins: https://fnox.jdx.dev/providers/lua"
)]
pub struct PluginInstallCommand {
    /// Plugin to install (default: every declared plugin)
    pub name: Option<String>,

    /// Git source (default: the plugin's entry under `[plugins]`)
    pub source: Option<String>,

    /// Reinstall even if the plugin is already installed
    #[usage(short, long)]
    pub force: bool,
}

/// Link a local plugin directory for development
///
/// Installs NAME as a symlink to PATH, so edits take effect without
/// reinstalling. `fnox plugin update` skips linked plugins.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox plugin link corp ~/src/fnox-plugin-corp", header = "Link a checkout"),
    example("fnox plugin link corp ./plugin --force", header = "Replace an installed plugin"),
    after_long_help = "See also:\n- Lua plugins: https://fnox.jdx.dev/providers/lua"
)]
pub struct PluginLinkCommand {
    /// Plugin name
    pub name: String,

    /// Directory that contains `provider.lua`
    pub path: PathBuf,

    /// Replace an existing plugin of the same name
    #[usage(short, long)]
    pub force: bool,
}

/// List installed and declared plugins
///
/// Prints each installed plugin with its git source and checked-out revision,
/// each linked plugin with its target, and each plugin declared under
/// `[plugins]` that is not installed yet.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox plugin ls", header = "List plugins"),
    after_long_help = "See also:\n- Lua plugins: https://fnox.jdx.dev/providers/lua"
)]
pub struct PluginLsCommand {}

/// Remove an installed or linked plugin
///
/// Deletes the plugin's directory, or only the link for a linked plugin. Its
/// declaration under `[plugins]` stays, so `fnox plugin install` can reinstall
/// it.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox plugin uninstall corp", header = "Remove a plugin"),
    after_long_help = "See also:\n- Lua plugins: https://fnox.jdx.dev/providers/lua"
)]
pub struct PluginUninstallCommand {
    /// Plugin name
    pub name: String,
}

/// Update installed plugins to their declared source
///
/// Checks out each plugin's declared ref, or its remote's default branch when
/// no ref is declared. With no arguments, updates every installed plugin.
/// Linked plugins are skipped.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox plugin update", header = "Update every installed plugin"),
    example("fnox plugin update corp", header = "Update one plugin"),
    after_long_help = "See also:\n- Lua plugins: https://fnox.jdx.dev/providers/lua"
)]
pub struct PluginUpdateCommand {
    /// Plugins to update (default: every installed plugin)
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
