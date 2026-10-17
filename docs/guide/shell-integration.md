---
description: "Load a project's secrets into your shell when you cd into it and unload them when you leave. Works in Bash, Zsh, Fish, Nushell, and PowerShell."
---

# Shell integration

With shell integration, entering a directory that has a `fnox.toml` loads its secrets into your shell, and leaving restores the previous environment:

```text
~/projects $ cd my-app
fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET
~/projects/my-app $ cd ..
fnox: -3 DATABASE_URL, API_KEY, JWT_SECRET
```

It's convenient for interactive work. For scripts, tasks, and CI, prefer [`fnox exec`](/guide/running-commands), which doesn't depend on how the shell was set up.

## Enable it

Add one line to your shell's startup file, then open a new terminal.

::: code-group

```sh [Bash]
# ~/.bashrc
eval "$(fnox activate bash)"
```

```sh [Zsh]
# ~/.zshrc
eval "$(fnox activate zsh)"
```

```sh [Fish]
# ~/.config/fish/config.fish
fnox activate fish | source
```

```sh [Nushell]
# Run once (Nushell 0.96+). Re-run after upgrading fnox.
mkdir ($nu.data-dir | path join "vendor/autoload")
fnox activate nu | save -f ($nu.data-dir | path join "vendor/autoload/fnox.nu")
```

```powershell [PowerShell]
# Add to your $PROFILE
(&fnox activate pwsh) | Out-String | Invoke-Expression
```

:::

## How it works

The activation code installs a hook that runs before each prompt. The hook checks whether any config file in the current directory tree or any `FNOX_*` variable (such as `FNOX_PROFILE`) changed, and if so, updates the shell's environment. When nothing changed, it exits immediately.

The hook loads the same merged config as other fnox commands, so parent-directory configs, profile files, and `fnox.local.toml` all apply. See [config files](/guide/config-files).

## Keep secrets out of the shell

Anything in your shell's environment is visible to every program you start from it, including editors, language servers, and AI agents. To load only non-sensitive values into the shell and keep secrets for `fnox exec`, set the top-level `env` default:

```toml
env = "exec"

[secrets]
LOG_LEVEL = { default = "debug", env = true } # still loaded into the shell
DATABASE_URL = { provider = "age", value = "YWdl..." } # fnox exec only
```

See [choose which secrets reach a command](/guide/running-commands#choose-which-secrets-reach-a-command).

## Switch profiles

```sh
export FNOX_PROFILE=staging
```

The hook notices the change at the next prompt and swaps in the staging values.

## Control the output

```sh
export FNOX_SHELL_OUTPUT=none     # silent
export FNOX_SHELL_OUTPUT=normal   # the +N/-N summary (default)
export FNOX_SHELL_OUTPUT=debug    # verbose, for troubleshooting
```

## Turn it off

`fnox deactivate` removes the hook and unloads the project's secrets from the current shell. Remove the activation line from your startup file to disable it for new shells.

## Stale values

The hook reloads when a config file or an `FNOX_*` variable changes, not when a value changes in a remote vault.

- With a [sync cache](/guide/sync), run `fnox sync` again. It rewrites `fnox.local.toml`, so the hook picks up the new values at the next prompt.
- With the [daemon](/guide/daemon), run `fnox daemon clear`, then open a new terminal.

## See also

- [Running commands](/guide/running-commands): `fnox exec` and the `env` setting.
- [Memory cache (daemon)](/guide/daemon): make prompt-time loading fast with remote providers.
- [Troubleshooting](/guide/troubleshooting#shell-integration-is-not-loading): when secrets don't load.
