use crate::commands::Cli;
use crate::error::Result;

#[derive(usage_rs::Args)]
#[usage(about = "Generate shell completions")]
#[usage(alias_hidden("complete", "completions"))]
pub struct CompletionCommand {
    /// Shell type to generate completions for
    #[usage(arg, name = "SHELL")]
    pub shell: String,
}

impl CompletionCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        let shell = usage_rs::complete::Shell::from_name(&self.shell).ok_or_else(|| {
            crate::error::FnoxError::Config(format!("Unsupported shell: {}", self.shell))
        })?;
        print!("{}", Cli::completion_script(shell));

        Ok(())
    }
}
