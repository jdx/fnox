use crate::commands::Cli;
use crate::error::Result;

/// Print a shell completion script
///
/// Prints a completion script for SHELL to stdout. Once installed, it completes
/// commands and flags, and reads secret keys, profiles, and providers from your
/// config when you press Tab.
#[derive(usage_rs::Args)]
#[usage(alias_hidden("complete", "completions"))]
#[usage(
    example(
        "fnox completion bash > ~/.local/share/bash-completion/completions/fnox",
        header = "Install Bash completions"
    ),
    example("fnox completion zsh > \"${fpath[1]}/_fnox\"", header = "Install Zsh completions"),
    example(
        "fnox completion fish > ~/.config/fish/completions/fnox.fish",
        header = "Install Fish completions"
    ),
    after_long_help = "See also:\n- Shell integration: https://fnox.jdx.dev/guide/shell-integration"
)]
pub struct CompletionCommand {
    /// Shell to generate for: `bash`, `zsh`, `fish`, `elvish`, `nu`, or `pwsh`
    #[usage(arg, name = "SHELL")]
    pub shell: String,
}

impl CompletionCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        let shell = usage_rs::complete::Shell::from_name(&self.shell).ok_or_else(|| {
            crate::error::FnoxError::Config(format!("Unsupported shell: {}", self.shell))
        })?;
        print!("{}", super::completion_app().completion_script(shell));

        Ok(())
    }
}
