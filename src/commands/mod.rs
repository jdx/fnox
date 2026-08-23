use std::path::PathBuf;

use crate::error::{FnoxError, Result};

use crate::config::Config;

pub mod activate;
pub mod check;
pub mod ci_redact;
pub mod completion;
pub mod config_files;
pub mod daemon;
pub mod deactivate;
pub mod doctor;
pub mod edit;
pub mod exec;
pub mod export;
pub mod get;
pub mod hook_env;
pub mod import;
pub mod init;
pub mod lease;
pub mod list;
pub mod mcp;
pub mod profiles;
pub mod provider;
pub mod proxy;
pub mod reencrypt;
pub mod remove;
pub mod scan;
pub mod schema;
pub mod set;
pub mod sponsors;
pub mod sync;
pub mod tui;
pub mod usage;
pub mod version;

#[derive(usage_rs::Cli)]
#[usage(name = "fnox", unknown_flags = "error")]
#[usage(config = crate::settings::SettingsData)]
#[usage(about = "A flexible secret management tool by @jdx")]
#[usage(version)]
pub struct Cli {
    /// Path to the configuration file (default: fnox.toml, searches parent directories)
    #[usage(short, long, default = "fnox.toml", global)]
    pub config: PathBuf,

    /// Profile to use (default: default, or FNOX_PROFILE env var). Supports multiple
    /// profiles separated by commas or repeated flags; later profiles overlay earlier ones.
    #[usage(short = 'P', long, global, setting = "profile")]
    pub profile: Vec<String>,

    /// Enable verbose logging
    #[usage(short, long, global)]
    pub verbose: bool,

    /// Path to age key file for decryption (deprecated: use provider config instead)
    #[usage(long, global, hide, setting = "age_key_file")]
    pub age_key_file: Option<PathBuf>,

    /// What to do if a secret is missing (error, warn, ignore)
    #[usage(long, global, setting = "if_missing")]
    pub if_missing: Option<String>,

    /// Disable colored output
    #[usage(long, global)]
    pub no_color: bool,

    /// Disable daemon-backed resolution for this invocation
    #[usage(long, global)]
    pub no_daemon: bool,

    /// Do not merge top-level secrets into the selected profile
    #[usage(long, global, setting = "no_defaults")]
    pub no_defaults: bool,

    /// Disable prompts and browser-based auth flows; use cached/non-interactive auth only (env: FNOX_NON_INTERACTIVE)
    #[usage(long, global, env = "FNOX_NON_INTERACTIVE")]
    pub non_interactive: bool,

    /// Target profile for write commands (set, remove, import, sync, provider add/remove).
    /// Required when multiple profiles are active; defaults to the single active profile otherwise.
    #[usage(long, global)]
    pub write_profile: Option<String>,

    #[usage(subcommand)]
    pub command: Commands,
}

#[derive(usage_rs::Subcommands)]
pub enum Commands {
    /// Output shell activation code to enable automatic secret loading
    Activate(activate::ActivateCommand),

    /// Check if all required secrets are defined and configured
    Check(check::CheckCommand),

    /// Redact secrets in CI/CD output (GitHub Actions mask)
    #[usage(hide)]
    CiRedact(ci_redact::CiRedactCommand),

    /// Generate shell completions
    Completion(completion::CompletionCommand),

    /// List all config files that would be loaded
    ConfigFiles(config_files::ConfigFilesCommand),

    /// Manage the per-user daemon
    Daemon(daemon::DaemonCommand),

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
    #[usage(hide)]
    HookEnv(hook_env::HookEnvCommand),

    /// Import secrets from various sources
    Import(import::ImportCommand),

    /// Initialize a new fnox configuration file
    Init(init::InitCommand),

    /// Manage ephemeral credential leases
    Lease(lease::LeaseCommand),

    /// List all secrets
    List(list::ListCommand),

    /// Start an MCP server for secret-gated AI agent access
    Mcp(mcp::McpCommand),

    /// List available profiles
    Profiles(profiles::ProfilesCommand),

    /// Manage providers (defaults to list)
    Provider(provider::ProviderCommand),

    /// Broker credentials into destination-scoped HTTPS requests
    Proxy(proxy::ProxyCommand),

    /// Re-encrypt secrets with current provider configuration
    Reencrypt(reencrypt::ReencryptCommand),

    /// Remove a secret
    Remove(remove::RemoveCommand),

    /// Scan repository for potential secrets
    Scan(scan::ScanCommand),

    /// Generate JSON Schema for fnox configuration
    #[usage(hide)]
    Schema(schema::SchemaCommand),

    /// Set a secret value
    Set(set::SetCommand),

    /// Show the companies sponsoring fnox and the jdx.dev open source tools
    Sponsors(sponsors::SponsorsCommand),

    /// Sync secrets from remote providers to a local encryption provider
    Sync(sync::SyncCommand),

    /// Interactive TUI dashboard for managing secrets
    Tui(tui::TuiCommand),

    /// Generate usage specification
    #[usage(hide)]
    Usage(usage::UsageCommand),

    /// Show version information
    Version(version::VersionCommand),
}

fn completion_config_path(ctx: &usage_rs::spec::CompleteCtx<'_>) -> PathBuf {
    let mut path = PathBuf::from("fnox.toml");
    let mut words = ctx.words.iter();
    while let Some(word) = words.next() {
        if let Some(value) = word.strip_prefix("--config=") {
            path = value.into();
        } else if matches!(word.as_str(), "-c" | "--config")
            && let Some(value) = words.next()
        {
            path = value.into();
        } else if let Some(value) = word.strip_prefix("-c").filter(|value| !value.is_empty()) {
            path = value.into();
        }
    }
    path
}

fn completion_config(ctx: &usage_rs::spec::CompleteCtx<'_>) -> Config {
    let path = completion_config_path(ctx);
    Config::load_smart(path).unwrap_or_else(|_| Config::new())
}

fn completion_profiles(ctx: &usage_rs::spec::CompleteCtx<'_>) -> Vec<String> {
    let mut profiles = Vec::new();
    let mut words = ctx.words.iter();
    while let Some(word) = words.next() {
        if let Some(value) = word.strip_prefix("--profile=") {
            profiles.push(value.to_string());
        } else if matches!(word.as_str(), "-P" | "--profile") {
            if let Some(value) = words.next() {
                profiles.push(value.to_string());
            }
        } else if let Some(value) = word.strip_prefix("-P").filter(|value| !value.is_empty()) {
            profiles.push(value.to_string());
        }
    }
    profiles
}

fn candidates(values: impl IntoIterator<Item = String>) -> Vec<usage_rs::spec::Candidate<'static>> {
    values
        .into_iter()
        .map(usage_rs::spec::Candidate::new)
        .collect()
}

fn complete_key(ctx: usage_rs::spec::CompleteCtx<'_>) -> usage_rs::complete::CompletionFuture<'_> {
    Box::pin(async move {
        let config = completion_config(&ctx);
        let profiles = Config::get_profiles(&completion_profiles(&ctx));
        candidates(
            config
                .get_secrets(&profiles)
                .unwrap_or_default()
                .into_keys(),
        )
    })
}

fn complete_profile(
    ctx: usage_rs::spec::CompleteCtx<'_>,
) -> usage_rs::complete::CompletionFuture<'_> {
    Box::pin(async move {
        let config = completion_config(&ctx);
        let mut names = vec!["default".to_string()];
        names.extend(config.profiles.keys().cloned());
        names.sort();
        names.dedup();
        candidates(names)
    })
}

fn complete_provider(
    ctx: usage_rs::spec::CompleteCtx<'_>,
) -> usage_rs::complete::CompletionFuture<'_> {
    Box::pin(async move {
        let config = completion_config(&ctx);
        let profiles = Config::get_profiles(&completion_profiles(&ctx));
        candidates(config.get_providers(&profiles).into_keys())
    })
}

static COMPLETIONS: [usage_rs::complete::CompletionOverlay<'static>; 3] = [
    usage_rs::complete::CompletionOverlay::async_any("key", complete_key),
    usage_rs::complete::CompletionOverlay::async_any("provider", complete_provider),
    usage_rs::complete::CompletionOverlay::async_any("profile", complete_profile),
];

pub fn completion_app() -> usage_rs::complete::App<'static> {
    Cli::app().completion_app().completions(&COMPLETIONS)
}

impl Commands {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        match self {
            // Commands that don't need config
            Commands::Version(cmd) => cmd.run(cli).await,
            Commands::Init(cmd) => cmd.run(cli).await,
            Commands::Completion(cmd) => cmd.run(cli).await,
            Commands::ConfigFiles(cmd) => cmd.run(cli).await,
            Commands::Daemon(cmd) => cmd.run(cli).await,
            Commands::Schema(cmd) => cmd.run(cli).await,
            Commands::Sponsors(cmd) => cmd.run(cli).await,
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
                .run(cli)
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
            Commands::Lease(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::List(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Mcp(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Profiles(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Provider(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Proxy(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Reencrypt(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Remove(cmd) => cmd.run(cli).await,
            Commands::Exec(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Set(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Sync(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Scan(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Tui(cmd) => cmd.run(cli, self.load_config(cli)?).await,
        }
    }

    /// Load configuration and validate the active profiles for this command.
    fn load_config(&self, cli: &Cli) -> Result<Config> {
        let config = Config::load_smart(&cli.config)?;
        let profiles = Config::get_profiles(&cli.profile);
        let allow_missing = match self {
            Commands::Set(_) | Commands::Import(_) => Some(Config::resolve_write_profile(
                &profiles,
                cli.write_profile.as_deref(),
            )?),
            // Provider add intentionally ignores FNOX_PROFILE and uses only
            // explicit CLI profiles. It also loads and updates its target
            // config independently, so there is nothing to validate here.
            Commands::Provider(cmd)
                if matches!(&cmd.action, Some(provider::ProviderAction::Add(_))) =>
            {
                return Ok(config);
            }
            Commands::Profiles(_) => return Ok(config),
            _ => {
                config.validate_profiles(&profiles, None)?;
                return Ok(config);
            }
        };
        config.validate_profiles(&profiles, allow_missing.as_deref())?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_this_cli_reads_are_the_flags_its_settings_declare() {
        // A flag documented as setting something and read by nothing — or bound and
        // documented nowhere — fails here rather than in a user's hands.
        assert_eq!(
            crate::settings::SettingsData::SETTINGS_REGISTRY.drift(Cli::SETTINGS_BINDINGS),
            Vec::<String>::new()
        );
    }

    #[test]
    fn test_cli_ordering() {
        fn short_key(short: u8) -> (u8, bool) {
            (short.to_ascii_lowercase(), short.is_ascii_uppercase())
        }

        fn assert_sorted<'a>(command: &usage_rs::spec::CommandMeta<'a>, path: &mut Vec<&'a str>) {
            path.push(command.cmd.name);

            let subcommands = command
                .subcommands
                .iter()
                .map(|subcommand| subcommand.cmd.name)
                .collect::<Vec<_>>();
            let mut sorted_subcommands = subcommands.clone();
            sorted_subcommands.sort_unstable();
            assert_eq!(
                subcommands,
                sorted_subcommands,
                "subcommands in '{}' should remain sorted",
                path.join(" ")
            );

            let short_flags = command
                .flags
                .iter()
                .filter_map(|flag| flag.flag.shorts.first().copied())
                .collect::<Vec<_>>();
            let mut sorted_short_flags = short_flags.clone();
            sorted_short_flags.sort_by_key(|short| short_key(*short));
            assert_eq!(
                short_flags,
                sorted_short_flags,
                "short flags in '{}' should remain sorted",
                path.join(" ")
            );

            let long_only_flags = command
                .flags
                .iter()
                .filter(|flag| flag.flag.shorts.is_empty())
                .filter_map(|flag| flag.flag.longs.first().copied())
                .collect::<Vec<_>>();
            let mut sorted_long_only_flags = long_only_flags.clone();
            sorted_long_only_flags.sort_unstable();
            assert_eq!(
                long_only_flags,
                sorted_long_only_flags,
                "long-only flags in '{}' should remain sorted",
                path.join(" ")
            );

            for subcommand in command.subcommands {
                assert_sorted(subcommand, path);
            }
            path.pop();
        }

        assert_sorted(Cli::spec().root, &mut Vec::new());
    }

    #[test]
    fn exec_replace_flag_matches_platform() {
        let exec = Cli::spec()
            .root
            .subcommands
            .iter()
            .find(|command| command.cmd.name == "exec")
            .unwrap();
        let has_replace = exec
            .flags
            .iter()
            .any(|flag| flag.flag.longs.contains(&"replace"));

        assert_eq!(has_replace, cfg!(unix));
    }

    #[test]
    fn glued_short_config_value_is_used_for_completion() {
        let words = vec!["fnox".to_string(), "-cother.toml".to_string()];
        let ctx = usage_rs::spec::CompleteCtx {
            words: &words,
            cword: words.len(),
            prefix: "",
            command_path: &[],
            command_words: &words[1..],
        };

        assert_eq!(completion_config_path(&ctx), PathBuf::from("other.toml"));
        let separated_words = vec![
            "fnox".to_string(),
            "-c".to_string(),
            "other.toml".to_string(),
        ];
        let separated_ctx = usage_rs::spec::CompleteCtx {
            words: &separated_words,
            cword: separated_words.len(),
            prefix: "",
            command_path: &[],
            command_words: &separated_words[1..],
        };
        assert_eq!(
            completion_config_path(&separated_ctx),
            PathBuf::from("other.toml")
        );
    }
}
