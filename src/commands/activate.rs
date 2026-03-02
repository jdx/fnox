use crate::shell::{self, ActivateOptions};
use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(about = "Output shell activation code to enable automatic secret loading")]
pub struct ActivateCommand {
    /// Shell to generate activation code for (bash, zsh, fish, nu)
    #[arg(value_name = "SHELL")]
    pub shell: Option<String>,

    /// Don't automatically invoke hook-env (for testing)
    #[arg(long)]
    pub no_hook_env: bool,
}

impl ActivateCommand {
    pub async fn run(&self) -> Result<()> {
        let shell_name = match &self.shell {
            Some(s) => s.clone(),
            None => shell::detect_shell().ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not detect shell. Please specify shell explicitly: fnox activate <shell>"
                )
            })?,
        };

        let shell = shell::get_shell(Some(&shell_name))?;

        // Get the current executable path
        let exe = std::env::current_exe()
            .or_else(|_| which::which("fnox"))
            .unwrap_or_else(|_| std::path::PathBuf::from("fnox"));

        let opts = ActivateOptions {
            exe,
            no_hook_env: self.no_hook_env,
        };

        let activation_code = shell.activate(opts);
        print!("{}", activation_code);

        Ok(())
    }
}
