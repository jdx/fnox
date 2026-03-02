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

        // Generate deactivation output via the shell's trait method.
        // Eval-based shells produce shell code; structured shells (nushell)
        // produce JSON that the wrapper function interprets.
        let secret_keys: Vec<String> = PREV_SESSION.secret_hashes.keys().cloned().collect();
        let output = shell.deactivate_output(&secret_keys);
        print!("{}", output);

        Ok(())
    }
}
