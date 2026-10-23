use std::path::PathBuf;

use crate::error::{FnoxError, Result};

use crate::config::Config;

pub mod activate;
pub mod audit;
pub mod check;
pub mod ci_redact;
pub mod completion;
pub mod config_files;
pub mod daemon;
pub mod deactivate;
pub mod doctor;
pub mod edit;
pub mod env;
pub mod exec;
pub mod export;
pub mod get;
pub mod hook_env;
pub mod import;
pub mod init;
pub mod lease;
pub mod list;
pub mod mcp;
pub mod plugin;
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

/// Load secrets from encrypted files, password managers, and cloud secret stores
///
/// fnox reads `fnox.toml` from the current directory and its parents, resolves
/// each secret through the provider it names, and hands the values to your
/// shell or to the command you run.
///
/// Commands by task:
///
///  - Read and run: get, list, exec, env, export, check
///  - Store and migrate: set, remove, import, sync, reencrypt, edit
///  - Configure: init, provider, plugin, profiles, config-files
///  - Shell and tools: activate, deactivate, completion, tui, mcp
///  - Diagnose: doctor, scan
///  - Cache and broker: daemon, lease, proxy
///
/// Put fnox options before the `--` that starts a child command, as in
/// `fnox -P prod exec -- npm start`. Everything after `--` belongs to the
/// child command.
#[derive(usage_rs::Cli)]
#[usage(name = "fnox", unknown_flags = "error", max_term_width = 100)]
#[usage(config = crate::settings::SettingsData)]
#[usage(version)]
#[usage(
    example("fnox init", header = "Create a config in the current directory"),
    example(
        "fnox set DATABASE_URL",
        header = "Store a secret (prompts for the value)"
    ),
    example(
        "fnox exec -- npm start",
        header = "Run a command with secrets in its environment"
    ),
    example("fnox -P staging list", header = "List the secrets in another profile"),
    after_long_help = "See also:\n- Quick start: https://fnox.jdx.dev/guide/quick-start\n- Configuration reference: https://fnox.jdx.dev/reference/configuration"
)]
pub struct Cli {
    /// Config file to load
    ///
    /// The bare names `fnox.toml`, `.fnox.toml`, `fnox.local.toml`, and
    /// `.fnox.local.toml` search the current directory and its parents. Any other
    /// path, such as `./fnox.toml`, loads only that file, its imports, and the
    /// global config.
    #[usage(short, long, default = "fnox.toml", global)]
    pub config: PathBuf,

    /// Profile to use; repeat or comma-separate to layer several
    ///
    /// Later profiles override earlier ones. Defaults to `FNOX_PROFILE`, then
    /// `default`.
    #[usage(short = 'P', long, global, setting = "profile")]
    pub profile: Vec<String>,

    /// Print debug logs to stderr
    #[usage(short, long, global)]
    pub verbose: bool,

    /// Path to age key file for decryption (deprecated: use provider config instead)
    #[usage(long, global, hide, setting = "age_key_file")]
    pub age_key_file: Option<PathBuf>,

    /// Override `if_missing` for every secret: `error`, `warn`, or `ignore`
    ///
    /// Takes precedence over `FNOX_IF_MISSING` and every `if_missing` value in
    /// the config.
    #[usage(long, global, setting = "if_missing")]
    pub if_missing: Option<String>,

    /// Disable colored output
    #[usage(long, global)]
    pub no_color: bool,

    /// Resolve secrets directly instead of through the daemon
    #[usage(long, global)]
    pub no_daemon: bool,

    /// Use only the selected profile's secrets, without top-level `[secrets]`
    #[usage(long, global, setting = "no_defaults")]
    pub no_defaults: bool,

    /// Never prompt or open a browser; use only cached or non-interactive auth
    #[usage(long, global, env = "FNOX_NON_INTERACTIVE")]
    pub non_interactive: bool,

    /// Profile that write commands modify when several profiles are active
    ///
    /// Applies to `set`, `remove`, `import`, `sync`, and `provider add|remove`.
    /// Required when more than one profile is active; otherwise defaults to the
    /// active profile.
    #[usage(long, global)]
    pub write_profile: Option<String>,

    #[usage(subcommand)]
    pub command: Commands,
}

#[derive(usage_rs::Subcommands)]
pub enum Commands {
    Activate(activate::ActivateCommand),

    Audit(audit::AuditCommand),

    Check(check::CheckCommand),

    /// Redact secrets in CI/CD output (GitHub Actions mask)
    #[usage(hide)]
    CiRedact(ci_redact::CiRedactCommand),

    Completion(completion::CompletionCommand),

    ConfigFiles(config_files::ConfigFilesCommand),

    Daemon(daemon::DaemonCommand),

    Deactivate(deactivate::DeactivateCommand),

    Doctor(doctor::DoctorCommand),

    Edit(edit::EditCommand),

    Env(env::EnvCommand),

    Exec(exec::ExecCommand),

    Export(export::ExportCommand),

    Get(get::GetCommand),

    /// Internal command used by shell hooks to load secrets
    #[usage(hide)]
    HookEnv(hook_env::HookEnvCommand),

    Import(import::ImportCommand),

    Init(init::InitCommand),

    Lease(lease::LeaseCommand),

    List(list::ListCommand),

    Mcp(mcp::McpCommand),

    Plugin(plugin::PluginCommand),

    Profiles(profiles::ProfilesCommand),

    Provider(provider::ProviderCommand),

    Proxy(proxy::ProxyCommand),

    Reencrypt(reencrypt::ReencryptCommand),

    Remove(remove::RemoveCommand),

    Scan(scan::ScanCommand),

    /// Generate JSON Schema for fnox configuration
    #[usage(hide)]
    Schema(schema::SchemaCommand),

    Set(set::SetCommand),

    Sponsors(sponsors::SponsorsCommand),

    Sync(sync::SyncCommand),

    Tui(tui::TuiCommand),

    /// Generate usage specification
    #[usage(hide)]
    Usage(usage::UsageCommand),

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
        candidates(
            config
                .get_providers(&profiles)
                .unwrap_or_default()
                .into_keys(),
        )
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
            Commands::Plugin(cmd) => cmd.run(cli).await,
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
            Commands::Audit(cmd) => cmd.run(cli, self.load_config(cli)?).await,
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
            Commands::Provider(cmd)
                if matches!(&cmd.action, Some(provider::ProviderAction::Add(_))) =>
            {
                cmd.run(cli, Config::new()).await
            }
            Commands::Provider(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Proxy(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Reencrypt(cmd) => cmd.run(cli, self.load_config(cli)?).await,
            Commands::Env(cmd) => cmd.run(cli).await,
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
        match self {
            Commands::Set(_) | Commands::Import(_) => {
                let config = Config::load_smart(&cli.config)?;
                let profiles = Config::get_profiles(&cli.profile);
                let write_profile =
                    Config::resolve_write_profile(&profiles, cli.write_profile.as_deref())?;
                config.validate_profiles(&profiles, Some(&write_profile))?;
                Ok(config)
            }
            Commands::Profiles(_) => Config::load_smart(&cli.config),
            _ => load_read_config(cli),
        }
    }
}

/// Load configuration for a command that only reads it, and validate the active profiles.
pub(crate) fn load_read_config(cli: &Cli) -> Result<Config> {
    let config = Config::load_smart(&cli.config)?;
    let profiles = Config::get_profiles(&cli.profile);
    config.validate_profiles(&profiles, None)?;
    Ok(config)
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
