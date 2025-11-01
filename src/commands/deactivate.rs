use crate::commands::Cli;
use crate::config::Config;
use crate::hook_env::PREV_SESSION;
use crate::shell;
use anyhow::Result;
use clap::Parser;

/// Disable fnox shell integration in the current shell session
///
/// This removes the hook that automatically loads secrets when entering
/// directories with fnox.toml files. It also restores environment variables
/// to their state before fnox was activated.
///
/// Note: This only affects the current shell session. To re-enable fnox,
/// run the activation command again for your shell.
#[derive(Debug, Clone, Parser)]
#[clap(verbatim_doc_comment)]
pub struct DeactivateCommand {}

impl DeactivateCommand {
    pub async fn run(&self, _cli: &Cli, _config: Config) -> Result<()> {
        // Check if fnox is activated in the current shell
        if std::env::var("FNOX_SHELL").is_err() {
            anyhow::bail!(
                "fnox is not activated in this shell session.\n\
                 Run the activation command for your shell to enable fnox."
            );
        }

        let shell = shell::get_shell(None)?;

        // First, restore the original environment (unset all loaded secrets)
        let output = clear_old_env(&*shell);
        print!("{}", output);

        // Then output shell-specific deactivation commands
        let deactivate_output = shell.deactivate();
        print!("{}", deactivate_output);

        Ok(())
    }
}

/// Generate shell commands to restore the environment to its original state
fn clear_old_env(shell: &dyn shell::Shell) -> String {
    // Get the previous session state (if any)
    let prev_session = &*PREV_SESSION;

    // Unset all loaded secrets from the previous session
    let mut output = String::new();
    for key in prev_session.secret_hashes.keys() {
        output.push_str(&shell.unset_env(key));
    }

    output
}
