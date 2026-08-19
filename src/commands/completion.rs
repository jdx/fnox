use crate::commands::Cli;
use crate::error::Result;
use std::process::Command;

#[derive(usage_derive::Args)]
#[usage(about = "Generate shell completions")]
#[usage(alias("complete", "completions"))]
pub struct CompletionCommand {
    /// Shell type to generate completions for
    #[usage(arg, name = "SHELL")]
    pub shell: String,
}

impl CompletionCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        let output = Command::new("usage")
            .args([
                "g",
                "completion",
                &self.shell,
                "fnox",
                "--usage-cmd",
                "fnox usage",
                "--cache-key",
                env!("CARGO_PKG_VERSION"),
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::error::FnoxError::Config(format!(
                "Failed to generate completions: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        print!("{}", stdout);

        Ok(())
    }
}
