use std::fmt;

mod bash;
mod fish;
mod nushell;
mod zsh;

pub use bash::Bash;
pub use fish::Fish;
pub use nushell::Nushell;
pub use zsh::Zsh;

/// Options for shell activation
#[derive(Debug, Clone)]
pub struct ActivateOptions {
    /// Path to the fnox executable
    pub exe: std::path::PathBuf,
    /// Additional shell-specific options
    pub no_hook_env: bool,
}

/// Trait for shell-specific implementations
pub trait Shell: fmt::Display + Send + Sync {
    /// Generate activation script for this shell
    fn activate(&self, opts: ActivateOptions) -> String;

    /// Generate deactivation script for this shell
    fn deactivate(&self) -> String;

    /// Generate code to set an environment variable
    fn set_env(&self, key: &str, value: &str) -> String;

    /// Generate code to unset an environment variable
    fn unset_env(&self, key: &str) -> String;

    /// Generate the complete hook-env output for a set of environment changes.
    ///
    /// The default implementation produces shell code using `set_env`/`unset_env`
    /// suitable for shells with `eval` (bash, zsh, fish). Shells without `eval`
    /// (e.g. Nushell) should override this to produce structured output (JSON)
    /// that their activation hook can parse natively.
    fn hook_env_output(
        &self,
        added: &[(String, String)],
        removed: &[String],
        session_encoded: &str,
    ) -> String {
        let mut output = String::new();
        for (key, value) in added {
            output.push_str(&self.set_env(key, value));
        }
        for key in removed {
            output.push_str(&self.unset_env(key));
        }
        output.push_str(&self.set_env("__FNOX_SESSION", session_encoded));
        output
    }

    /// Generate the complete deactivation output (unset secrets + shell cleanup).
    ///
    /// The default implementation produces shell code via `unset_env` + `deactivate()`,
    /// suitable for eval-based shells. Shells without eval should override this to
    /// produce structured output that their wrapper function can interpret.
    fn deactivate_output(&self, secret_keys: &[String]) -> String {
        let mut output = String::new();
        for key in secret_keys {
            output.push_str(&self.unset_env(key));
        }
        output.push_str(&self.deactivate());
        output
    }
}

/// Parse shell name into Shell implementation
/// If name is None, detect shell from environment
pub fn get_shell(name: Option<&str>) -> anyhow::Result<Box<dyn Shell>> {
    let shell_name = match name {
        Some(n) => n.to_string(),
        None => detect_shell().ok_or_else(|| anyhow::anyhow!("Could not detect shell"))?,
    };

    match shell_name.as_str() {
        "bash" => Ok(Box::new(Bash)),
        "zsh" => Ok(Box::new(Zsh)),
        "fish" => Ok(Box::new(Fish)),
        "nu" => Ok(Box::new(Nushell)),
        _ => anyhow::bail!("unsupported shell: {}", shell_name),
    }
}

/// Detect current shell from environment
pub fn detect_shell() -> Option<String> {
    if let Ok(shell) = std::env::var("FNOX_SHELL") {
        return Some(shell);
    }

    std::env::var("SHELL")
        .ok()
        .and_then(|s| s.rsplit('/').next().map(String::from))
}
