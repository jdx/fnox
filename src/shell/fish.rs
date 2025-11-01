use super::{ActivateOptions, Shell};
use std::fmt;

pub struct Fish;

impl Shell for Fish {
    fn activate(&self, opts: ActivateOptions) -> String {
        let mut out = String::new();
        let exe = opts.exe.display().to_string();

        // Export shell type
        out.push_str("set -gx FNOX_SHELL fish\n");

        // Define the fnox wrapper function
        out.push_str(&format!(
            r#"
function fnox
    set command $argv[1]

    switch "$command"
        case deactivate shell
            eval (command {exe} "$command" $argv[2..-1])
        case '*'
            command {exe} "$command" $argv[2..-1]
    end
end
"#,
        ));

        if !opts.no_hook_env {
            // Define the hook function that runs on every prompt
            out.push_str(&format!(
                r#"
function __fnox_env_eval --on-event fish_prompt
    if test "$FNOX_SHELL" = "fish"
        eval ({exe} hook-env -s fish | string collect)
    end
end
"#,
            ));

            // Register the hook on PWD change as well
            out.push_str(
                r#"
function __fnox_cd_hook --on-variable PWD
    if test "$FNOX_SHELL" = "fish"
        __fnox_env_eval
    end
end
"#,
            );

            // Initial hook execution
            out.push_str("__fnox_env_eval\n");
        }

        out
    }

    fn deactivate(&self) -> String {
        let mut out = String::new();

        // Remove hook functions
        out.push_str("functions -e __fnox_env_eval __fnox_cd_hook 2>/dev/null\n");

        // Unset fnox-related variables (one at a time for compatibility)
        out.push_str("set -e FNOX_SHELL 2>/dev/null\n");
        out.push_str("set -e __FNOX_SESSION 2>/dev/null\n");

        // Erase the fnox function last (we're currently inside it)
        out.push_str("functions -e fnox 2>/dev/null\n");

        out
    }

    fn set_env(&self, key: &str, value: &str) -> String {
        // Fish uses different quoting
        let value = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$");
        format!("set -gx {} \"{}\"\n", key, value)
    }

    fn unset_env(&self, key: &str) -> String {
        format!("set -e {}\n", key)
    }
}

impl fmt::Display for Fish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fish")
    }
}
