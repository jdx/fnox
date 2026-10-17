use crate::commands::Cli;
use crate::config::Config;
use crate::hook_env::PREV_SESSION;
use crate::shell;
use anyhow::Result;

/// Turn off shell integration in the current shell
///
/// Removes the fnox hook from the current shell session and unsets the secrets
/// it loaded. Other shells and new sessions are unaffected: to turn integration
/// off for good, remove the `fnox activate` line from your shell startup file.
/// To turn it back on in this shell, run the activation command again.
///
/// Fails when fnox is not active in the current shell.
#[derive(Debug, Clone, usage_rs::Args)]
#[usage(
    example("fnox deactivate", header = "Turn off the hook in this shell"),
    after_long_help = "See also:\n- Shell integration: https://fnox.jdx.dev/guide/shell-integration"
)]
pub struct DeactivateCommand;

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

        // Persistent as_file secrets outlive the hook-env process. Remove the
        // files before the shell discards __FNOX_SESSION, which owns their paths.
        super::hook_env::cleanup_session_temp_files()?;

        // Generate deactivation output via the shell's trait method.
        // Eval-based shells produce shell code; structured shells (nushell)
        // produce JSON that the wrapper function interprets.
        let secret_keys: Vec<String> = PREV_SESSION.secret_hashes.keys().cloned().collect();
        let output = shell.deactivate_output(&secret_keys);
        print!("{}", output);

        Ok(())
    }
}
