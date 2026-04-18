use super::{ActivateOptions, Shell};
use std::borrow::Cow;
use std::fmt;

pub struct Pwsh;

impl Shell for Pwsh {
    fn activate(&self, opts: ActivateOptions) -> String {
        let exe = opts.exe.to_string_lossy();
        let mut out = String::new();

        out.push_str("$env:FNOX_SHELL='pwsh'\n");

        out.push_str(&format!(r#"
function fnox {{
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]] $arguments
    )

    if ($arguments.Count -eq 0) {{
        & "{exe}"
        return
    }}

    $command = $arguments[0]
    if ($arguments.Count -gt 1) {{
        $remainingArgs = $arguments[1..($arguments.Count - 1)]
    }} else {{
        $remainingArgs = @()
    }}

    switch ($command) {{
        {{ $_ -in 'deactivate', 'shell' }} {{
            & "{exe}" $command @remainingArgs | Out-String | Invoke-Expression -ErrorAction SilentlyContinue
        }}
        default {{
            & "{exe}" $command @remainingArgs
        }}
    }}
}}
"#,
        ));

        if !opts.no_hook_env {
            out.push_str(&format!(
                r#"
function Global:_fnox_hook {{
    if ($env:FNOX_SHELL -eq 'pwsh') {{
        $output = & "{exe}" hook-env -s pwsh | Out-String
        if ($output -and $output.Trim()) {{
            $output | Invoke-Expression
            if (Test-Path -Path Function:\__fnox_print_changes) {{
                __fnox_print_changes
                Remove-Item -Path Function:\__fnox_print_changes
            }}
        }}
    }}
}}

function __enable_fnox_prompt {{
    if (-not $__fnox_pwsh_previous_prompt_function) {{
        $Global:__fnox_pwsh_previous_prompt_function = $function:prompt
        function global:prompt {{
            if (Test-Path -Path Function:\_fnox_hook) {{
                _fnox_hook
            }}
            & $__fnox_pwsh_previous_prompt_function
        }}
    }}
}}
__enable_fnox_prompt
Remove-Item -ErrorAction SilentlyContinue -Path Function:\__enable_fnox_prompt

_fnox_hook"#,
            ));
        }

        out
    }

    fn deactivate(&self) -> String {
        r#"
if ($Global:__fnox_pwsh_previous_prompt_function) {
    $function:prompt = $Global:__fnox_pwsh_previous_prompt_function
    Remove-Variable -Name __fnox_pwsh_previous_prompt_function -Scope Global -ErrorAction SilentlyContinue
}
Remove-Item -ErrorAction SilentlyContinue -Path Function:\fnox
Remove-Item -ErrorAction SilentlyContinue -Path Function:\_fnox_hook
Remove-Item -ErrorAction SilentlyContinue -LiteralPath 'Env:FNOX_SHELL'
Remove-Item -ErrorAction SilentlyContinue -LiteralPath 'Env:__FNOX_SESSION'
        "#
        .to_string()
    }

    fn hook_env_output(
        &self,
        added: &[(String, String)],
        removed: &[String],
        session_encoded: &str,
    ) -> String {
        let mut output = String::new();

        if !added.is_empty() || !removed.is_empty() {
            let mut count_parts = Vec::new();
            if !added.is_empty() {
                count_parts.push(format!("+{}", added.len()));
            }
            if !removed.is_empty() {
                count_parts.push(format!("-{}", removed.len()));
            }
            let counts = count_parts.join(" ");

            let all_keys: Vec<&str> = added
                .iter()
                .map(|(k, _)| k.as_str())
                .chain(removed.iter().map(|k| k.as_str()))
                .collect();
            let keys = powershell_escape(all_keys.join(", ").into());
            let prefix = powershell_escape(format!("fnox: {} ", counts).into());

            /*
                Because of the way activate/deactivate call hook-env, any calls to Write-Host get eaten.
                To get around this, we package the Write-Host calls into a function to be executed in the context
                of the rest of the activate/deactivate code.
            */
            output.push_str("function __fnox_print_changes {\n");
            output.push_str(&format!(
                "    Write-Host '{prefix}' -NoNewline -ForegroundColor DarkGray\n"
            ));
            output.push_str(&format!("    Write-Host '{keys}' -ForegroundColor Cyan\n"));
            output.push_str("}\n");
        }

        for (key, value) in added {
            output.push_str(&self.set_env(key, value));
        }
        for key in removed {
            output.push_str(&self.unset_env(key));
        }
        output.push_str(&self.set_env("__FNOX_SESSION", session_encoded));
        output
    }

    fn set_env(&self, key: &str, value: &str) -> String {
        let v = powershell_escape(value.into());
        format!("${{Env:{key}}}='{v}'\n")
    }

    fn unset_env(&self, key: &str) -> String {
        let k = powershell_escape(key.into());
        format!("Remove-Item -ErrorAction SilentlyContinue -LiteralPath 'Env:{k}'\n")
    }
}

impl fmt::Display for Pwsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pwsh")
    }
}

fn powershell_escape(s: Cow<str>) -> Cow<str> {
    if !s.contains('\'') {
        return s;
    }
    s.replace('\'', "''").into()
}
