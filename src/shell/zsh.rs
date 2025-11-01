use super::{ActivateOptions, Shell};
use std::fmt;

pub struct Zsh;

impl Shell for Zsh {
    fn activate(&self, opts: ActivateOptions) -> String {
        let mut out = String::new();
        let exe = opts.exe.display().to_string();

        // Export shell type
        out.push_str("export FNOX_SHELL=zsh\n");

        // Define the fnox wrapper function
        out.push_str(&format!(
            r#"
fnox() {{
  local command
  command="${{1:-}}"
  if [ "$#" = 0 ]; then
    {exe}
    return
  fi
  shift

  case "$command" in
  deactivate|shell)
    eval "$({exe} "$command" "$@")"
    ;;
  *)
    {exe} "$command" "$@"
    ;;
  esac
}}
"#,
        ));

        if !opts.no_hook_env {
            // Define the hook function
            out.push_str(&format!(
                r#"
_fnox_hook() {{
  trap -- '' SIGINT
  eval "$({exe} hook-env -s zsh)"
  trap - SIGINT
}}
"#,
            ));

            // Add hook to precmd_functions
            out.push_str(
                r#"
typeset -ag precmd_functions
if [[ -z "${precmd_functions[(r)_fnox_hook]+1}" ]]; then
  precmd_functions=( _fnox_hook ${precmd_functions[@]} )
fi
"#,
            );

            // Add hook to chpwd_functions for directory changes
            out.push_str(
                r#"
typeset -ag chpwd_functions
if [[ -z "${chpwd_functions[(r)_fnox_hook]+1}" ]]; then
  chpwd_functions=( _fnox_hook ${chpwd_functions[@]} )
fi
"#,
            );
        }

        out
    }

    fn deactivate(&self) -> String {
        let mut out = String::new();

        // Remove hook from precmd_functions and chpwd_functions
        out.push_str(
            r#"
precmd_functions=( ${precmd_functions[@]:#_fnox_hook} )
chpwd_functions=( ${chpwd_functions[@]:#_fnox_hook} )
"#,
        );

        // Unset fnox-related variables
        out.push_str("unset -f fnox _fnox_hook\n");
        out.push_str("unset FNOX_SHELL __FNOX_SESSION\n");

        out
    }

    fn set_env(&self, key: &str, value: &str) -> String {
        let value = value.replace('\\', "\\\\").replace('"', "\\\"");
        format!("export {}=\"{}\"\n", key, value)
    }

    fn unset_env(&self, key: &str) -> String {
        format!("unset {}\n", key)
    }
}

impl fmt::Display for Zsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zsh")
    }
}
