---
description: "Run mise tasks with fnox-managed secrets and understand the limitations of the fnox environment plugin."
---

# mise integration

Use [mise](https://mise.jdx.dev) to install fnox and run project tasks. Put `fnox exec` in tasks that need secrets so those tasks work from a shell, an editor, or CI.

## Install fnox for the project

```sh
mise use fnox
```

This adds fnox to the project's mise configuration. To install it for all projects, use `mise use -g fnox` instead.

## Run tasks with secrets

Add tasks to `mise.toml`:

```toml
[tasks.dev]
run = "fnox exec -- npm run dev"

[tasks.test]
run = "fnox exec -- npm test"

[tasks.deploy]
run = "fnox exec --profile production --if-missing error -- ./deploy.sh"
```

Run them normally:

```sh
mise run dev
mise run test
mise run deploy
```

fnox owns secret resolution, including profiles, file secrets, lease creation, and cache settings. CI must still authenticate to the configured provider before running these tasks.

## Load secrets in the interactive shell

[fnox shell integration](/guide/shell-integration) can run alongside mise activation. Add the appropriate fnox activation command to your shell's startup file:

```bash
# Bash: ~/.bashrc
eval "$(fnox activate bash)"
```

For tasks, keep the explicit `fnox exec` wrapper even when shell integration is enabled. It makes the task's secret requirements independent of the calling shell.

Use top-level `env = "exec"` in `fnox.toml` if you want secrets available only to commands launched through fnox, rather than every process in the interactive shell.

## Choose a cache

If remote reads are slow, configure caching in fnox:

- [Sync](/guide/sync) creates a persistent encrypted local snapshot. Use age or another local provider for offline access.
- The [daemon](/guide/daemon) keeps resolved values in memory during a session.

Both work when a mise task invokes `fnox exec`.

## Experimental environment plugin

The [`jdx/mise-env-fnox`](https://github.com/jdx/mise-env-fnox) environment plugin is an incomplete experiment and does not track all fnox features. Existing users can consult its repository for its current configuration and limitations.

For a maintained setup, remove the `_.fnox-env` entry from mise's `[env]` configuration and use the task wrappers or shell activation shown above. Remove the plugin registration only if nothing else in your mise configuration uses it.

## Troubleshooting

```sh
mise exec -- fnox --version
mise exec -- fnox config-files
mise exec -- fnox check --all
```

These checks distinguish tool installation, config discovery, and secret resolution problems. Continue with [fnox troubleshooting](/guide/troubleshooting) if the CLI is available but secrets do not resolve.
