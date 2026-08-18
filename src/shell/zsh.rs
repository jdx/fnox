use super::{ActivateOptions, Shell};
use std::fmt;

pub struct Zsh;

impl Shell for Zsh {
    fn activate(&self, opts: ActivateOptions) -> String {
        let mut out = String::new();
        let exe = opts.exe.display().to_string();

        // Export shell type
        out.push_str("export FNOX_SHELL=zsh\n");

        // A nested zsh inherits its parent's environment. Discard the encoded
        // parent session so the child's first hook creates independently owned
        // as_file paths instead of deleting the parent's paths on exit.
        out.push_str(
            r#"if [[ -n "${__FNOX_SESSION:-}" && "${__FNOX_ZSH_PID:-}" != "$$" ]]; then
  unset __FNOX_SESSION
fi
export __FNOX_ZSH_PID=$$
"#,
        );

        // Define the fnox wrapper function
        out.push_str(&format!(
            r#"
fnox() {{
  local command output status
  command="${{1:-}}"
  if [ "$#" = 0 ]; then
    {exe}
    return
  fi
  shift

  case "$command" in
  deactivate|shell)
    output="$({exe} "$command" "$@")"
    status=$?
    if (( status != 0 )); then
      return $status
    fi
    eval "$output"
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

_fnox_cleanup() {{
  {exe} deactivate >/dev/null
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

            // Clean up persistent as_file secrets when the shell exits.
            out.push_str(
                r#"
autoload -Uz add-zsh-hook
add-zsh-hook zshexit _fnox_cleanup
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

        // Remove prompt, directory-change, and exit hooks
        out.push_str(
            r#"
precmd_functions=( ${precmd_functions[@]:#_fnox_hook} )
chpwd_functions=( ${chpwd_functions[@]:#_fnox_hook} )
autoload -Uz add-zsh-hook
add-zsh-hook -d zshexit _fnox_cleanup 2>/dev/null
"#,
        );

        // Unset fnox-related variables
        out.push_str("unset -f fnox _fnox_hook _fnox_cleanup\n");
        out.push_str("unset FNOX_SHELL __FNOX_SESSION __FNOX_ZSH_PID\n");

        out
    }

    fn set_env(&self, key: &str, value: &str) -> String {
        format!("export {}={}\n", key, super::posix_quote(value))
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
