use crate::shell::{self, ActivateOptions};
use anyhow::Result;

/// Print shell code that loads secrets when you enter a project
///
/// Prints a hook for your shell to evaluate. Once active, the hook runs before
/// each prompt: it loads the secrets with `env = true` (the default) when you
/// enter a directory with a fnox config and removes them when you leave.
///
/// SHELL defaults to `$FNOX_SHELL`, then the name of `$SHELL`. Set
/// `FNOX_SHELL_OUTPUT` to `none`, `normal`, or `debug` to control what the hook
/// prints.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("eval \"$(fnox activate bash)\"", header = "Bash (add to ~/.bashrc)"),
    example("eval \"$(fnox activate zsh)\"", header = "Zsh (add to ~/.zshrc)"),
    example(
        "fnox activate fish | source",
        header = "Fish (add to ~/.config/fish/config.fish)"
    ),
    after_long_help = "See also:\n- Shell integration: https://fnox.jdx.dev/guide/shell-integration"
)]
pub struct ActivateCommand {
    /// Shell to generate code for: `bash`, `zsh`, `fish`, `nu`, or `pwsh`
    #[usage(arg, name = "SHELL")]
    pub shell: Option<String>,

    /// Print the hook without its initial `hook-env` call (for testing)
    #[usage(long)]
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

        let exe = invoked_exe()
            .or_else(|| std::env::current_exe().ok())
            .or_else(|| which::which("fnox").ok())
            .unwrap_or_else(|| std::path::PathBuf::from("fnox"));

        let opts = ActivateOptions {
            exe,
            no_hook_env: self.no_hook_env,
        };

        let activation_code = shell.activate(opts);
        print!("{}", activation_code);

        Ok(())
    }
}

/// The path fnox was invoked through, made absolute but with symlinks kept.
///
/// `current_exe` resolves symlinks, which bakes a version-specific path such as
/// `.../installs/fnox/1.5.2/fnox` into the hook. Version managers like mise
/// remove that directory on upgrade, while the path used to invoke fnox (for
/// example `.../installs/fnox/latest/fnox`) keeps working. Returns `None` unless
/// that path really points at the running binary.
fn invoked_exe() -> Option<std::path::PathBuf> {
    let arg0 = std::path::PathBuf::from(std::env::args_os().next()?);
    let invoked = if arg0.components().count() > 1 {
        std::path::absolute(&arg0).ok()?
    } else {
        which::which(&arg0).ok()?
    };
    let current = std::env::current_exe().ok()?.canonicalize().ok()?;
    (invoked.canonicalize().ok()? == current).then_some(invoked)
}
