use super::{ActivateOptions, Shell};
use std::fmt;

pub struct Nushell;

impl Shell for Nushell {
    fn activate(&self, opts: ActivateOptions) -> String {
        let mut out = String::new();
        let exe = opts.exe.display().to_string();

        out.push_str("$env.FNOX_SHELL = \"nu\"\n");

        // Helper: apply JSON from fnox hook-env / deactivate in the current shell.
        // Handles {"set": {...}, "unset": [...]} structured output.
        out.push_str(
            r#"
def --env _fnox_apply [json: string] {
    let changes = ($json | from json)
    if "set" in $changes and ($changes.set | is-not-empty) {
        $changes.set | load-env
    }
    if "unset" in $changes and ($changes.unset | is-not-empty) {
        for $var in $changes.unset {
            hide-env -i $var
        }
    }
}
"#,
        );

        // Wrapper function: most subcommands just call the binary directly.
        // `deactivate` and `shell` need to modify the current shell's environment,
        // so the binary outputs JSON that _fnox_apply interprets.
        out.push_str(&format!(
            r#"
def --env --wrapped fnox [...rest] {{
    let command = ($rest | first | default "")
    match $command {{
        "deactivate" | "shell" => {{
            let result = (do -i {{ ^"{exe}" $command ...($rest | skip 1) }} | complete)
            if ($result.stderr | str trim | is-not-empty) {{
                print -e $result.stderr
            }}
            if $result.exit_code == 0 and ($result.stdout | str trim | is-not-empty) {{
                _fnox_apply $result.stdout
            }}
            if $command == "deactivate" {{
                $env.config = ($env.config | upsert hooks.pre_prompt ($env.config.hooks.pre_prompt? | default [] | where {{ ($in | describe) != "closure" or (view source $in) !~ "_fnox_hook" }}))
                hide-env -i FNOX_SHELL
                hide-env -i __FNOX_SESSION
            }}
        }}
        _ => {{ ^"{exe}" ...$rest }}
    }}
}}
"#,
        ));

        // --no-hook-env: skip registering the prompt hook (used by tests to
        // verify the activation output in isolation).
        if !opts.no_hook_env {
            out.push_str(&format!(
                r#"
def --env _fnox_hook [] {{
    let result = (do -i {{ ^"{exe}" hook-env -s nu }} | complete)
    if ($result.stderr | str trim | is-not-empty) {{
        print -e $result.stderr
    }}
    if $result.exit_code == 0 and ($result.stdout | str trim | is-not-empty) {{
        _fnox_apply $result.stdout
    }}
}}
"#,
            ));

            // Only hook pre_prompt — it fires after every cd anyway (prompt is
            // redrawn), so a separate env_change.PWD hook would just cause a
            // redundant process spawn that early-exit optimises away.
            out.push_str(
                r#"
$env.config = ($env.config | upsert hooks.pre_prompt ($env.config.hooks.pre_prompt? | default [] | append {|| _fnox_hook }))
"#,
            );

            out.push_str("_fnox_hook\n");
        }

        out
    }

    fn deactivate(&self) -> String {
        // Nushell has no eval — deactivation is handled by deactivate_output()
        // producing JSON, and the wrapper function cleaning up hooks/env inline.
        unimplemented!("Nushell uses deactivate_output() instead")
    }

    fn set_env(&self, _key: &str, _value: &str) -> String {
        // Nushell has no eval — hook_env_output() produces JSON directly.
        unimplemented!("Nushell uses hook_env_output() instead")
    }

    fn unset_env(&self, _key: &str) -> String {
        // Nushell has no eval — hook_env_output() produces JSON directly.
        unimplemented!("Nushell uses hook_env_output() instead")
    }

    fn hook_env_output(
        &self,
        added: &[(String, String)],
        removed: &[String],
        session_encoded: &str,
    ) -> String {
        let mut set_map = serde_json::Map::new();
        for (key, value) in added {
            set_map.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        set_map.insert(
            "__FNOX_SESSION".to_string(),
            serde_json::Value::String(session_encoded.to_string()),
        );
        let unset_list: Vec<serde_json::Value> = removed
            .iter()
            .map(|k| serde_json::Value::String(k.clone()))
            .collect();
        serde_json::json!({"set": set_map, "unset": unset_list}).to_string()
    }

    fn deactivate_output(&self, secret_keys: &[String]) -> String {
        // Output JSON that the wrapper's _fnox_apply can parse.
        // Hook removal and FNOX_SHELL/SESSION cleanup are handled
        // inline by the wrapper function after applying this output.
        let mut unset_keys: Vec<serde_json::Value> = secret_keys
            .iter()
            .map(|k| serde_json::Value::String(k.clone()))
            .collect();
        unset_keys.push(serde_json::Value::String("__FNOX_SESSION".to_string()));
        serde_json::json!({"set": {}, "unset": unset_keys}).to_string()
    }
}

impl fmt::Display for Nushell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nu")
    }
}
