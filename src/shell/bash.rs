use super::{ActivateOptions, Shell};
use std::fmt;

pub struct Bash;

impl Shell for Bash {
    fn activate(&self, opts: ActivateOptions) -> String {
        let mut out = String::new();
        let exe = opts.exe.display().to_string();

        // Export shell type
        out.push_str("export FNOX_SHELL=bash\n");

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
  local previous_exit_status=$?
  trap -- '' SIGINT
  eval "$({exe} hook-env -s bash)"
  trap - SIGINT
  return $previous_exit_status
}}
"#,
            ));

            // Add hook to PROMPT_COMMAND
            out.push_str(
                r#"
if ! [[ "${PROMPT_COMMAND:-}" =~ _fnox_hook ]]; then
  PROMPT_COMMAND="_fnox_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
"#,
            );
        }

        out
    }

    fn deactivate(&self) -> String {
        let mut out = String::new();

        // Remove hook from PROMPT_COMMAND
        out.push_str(
            r#"
PROMPT_COMMAND="${PROMPT_COMMAND//_fnox_hook;/}"
PROMPT_COMMAND="${PROMPT_COMMAND//_fnox_hook/}"
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

impl fmt::Display for Bash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bash")
    }
}
