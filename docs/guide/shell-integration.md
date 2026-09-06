---
description: "Load and unload project secrets automatically in Bash, Zsh, Fish, Nushell, and PowerShell."
---

# Shell integration

Shell integration loads secrets when you enter a project and restores the previous environment when you leave. Enable it for interactive work, or use `fnox exec -- <command>` when a single subprocess needs secrets.

## Enable shell integration

Add this to your shell profile:

::: code-group

```bash [Bash]
# Add to ~/.bashrc or ~/.bash_profile
eval "$(fnox activate bash)"
```

```zsh [Zsh]
# Add to ~/.zshrc
eval "$(fnox activate zsh)"
```

```fish [Fish]
# Add to ~/.config/fish/config.fish
fnox activate fish | source
```

```nu [Nushell]
# Requires Nushell 0.96+
# Add to the end of your Nushell configuration
# (find it by running `$nu.config-path` in Nushell):
mkdir ($nu.data-dir | path join "vendor/autoload")
fnox activate nu | save -f ($nu.data-dir | path join "vendor/autoload/fnox.nu")
```

```powershell [PowerShell]
# Add this to your PowerShell profile.
# To find your profile, see https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles
(&fnox activate pwsh) | Out-String | Invoke-Expression
```

:::

## How it works

Once enabled, fnox installs a hook that runs before each prompt. When you enter a directory with `fnox.toml`:

```bash
~/projects $ cd my-app
fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET
~/projects/my-app $
```

When you leave:

```bash
~/projects/my-app $ cd ..
fnox: -3 DATABASE_URL, API_KEY, JWT_SECRET
~/projects $
```

## Limit shell injection

Set top-level `env = "exec"` in `fnox.toml` to keep secrets out of the interactive shell while retaining subprocess injection. Individual secrets can override this with their own `env` setting. See [injection settings](/reference/configuration#env).

## Output control

Control what gets printed with `FNOX_SHELL_OUTPUT`:

```bash
# Silent mode (no output)
export FNOX_SHELL_OUTPUT=none

# Normal mode (show count and keys) - default
export FNOX_SHELL_OUTPUT=normal

# Debug mode (verbose logging)
export FNOX_SHELL_OUTPUT=debug
```

## Using profiles

Switch environments with `FNOX_PROFILE`:

```bash
# Use production secrets
export FNOX_PROFILE=production
cd my-app
# fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET (from production profile)

# Switch to staging
export FNOX_PROFILE=staging
# fnox detects the change on the next prompt automatically
# fnox: +3 -3 DATABASE_URL, API_KEY, JWT_SECRET (from staging profile)
```

## Hierarchical loading

fnox searches parent directories for `fnox.toml` files and merges them:

```text
project/
├── fnox.toml              # Common secrets (age provider, shared keys)
└── services/
    ├── api/
    │   └── fnox.toml      # API-specific secrets
    └── worker/
        └── fnox.toml      # Worker-specific secrets
```

When you `cd services/api/`, fnox loads:

1. Secrets from `project/fnox.toml`
2. Secrets from `project/services/api/fnox.toml` (overrides parent)

## Manual reload

fnox's shell hook runs on every prompt and automatically detects changes to config files and environment variables like `FNOX_PROFILE`. In most cases, no manual reload is needed.

With fnox activated, its shell function handles the deactivation output. To reset the integration in Bash:

```bash
# Disable
fnox deactivate

# Re-enable
eval "$(fnox activate bash)"
```

If a value changed in the remote vault, refresh the [sync cache](/guide/sync) or clear the [daemon cache](/guide/daemon) as appropriate. Re-enabling the hook does not refresh those caches.

## Next steps

- [Per-User Daemon](/guide/daemon) - Cache resolved secrets in memory for faster refreshes
- [Profiles](/guide/profiles) - Manage multiple environments
- [Hierarchical Config](/guide/hierarchical-config) - Organize secrets across directories
- [Real-World Example](/guide/real-world-example) - See a complete setup
