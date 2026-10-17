---
description: "Install fnox with mise, pin its version per project, and run mise tasks with secrets by wrapping them in fnox exec."
---

# mise integration

[mise](https://mise.jdx.dev) and fnox are designed to work together: mise installs fnox and runs your tasks, and fnox supplies the secrets those tasks need.

## Pin fnox in the project

```sh
mise use fnox
```

This adds fnox to `mise.toml`, so every teammate and CI runner (via [`jdx/mise-action`](/guide/ci#_1-install-fnox)) uses the same version.

## Run tasks with secrets

Wrap the commands that need secrets in `fnox exec`:

```toml
# mise.toml
[tasks.dev]
run = "fnox exec -- npm run dev"

[tasks.test]
run = "fnox exec -- npm test"

[tasks.deploy]
run = "fnox exec --profile production --if-missing error -- ./deploy.sh"
```

```sh
mise run dev
```

The wrapper makes each task's secrets explicit and independent of how the calling shell was set up, so the task behaves the same from a terminal, an editor, or CI.

## Shell integration alongside mise

`mise activate` and `fnox activate` can both be in your shell startup file; they don't interfere. Keep the `fnox exec` wrapper in tasks anyway. To keep secrets out of the interactive shell entirely, set `env = "exec"` in `fnox.toml` (see [running commands](/guide/running-commands#choose-which-secrets-reach-a-command)).

## Speed up remote providers

If tasks read from a remote vault and feel slow, turn on a fnox cache. Both work with tasks that call `fnox exec`:

- [Sync](/guide/sync): an encrypted local copy that survives restarts and works offline.
- [Daemon](/guide/daemon): resolved values kept in memory for your session. mise can also read the daemon's cache directly through the [`fnox env --json`](/reference/env-json) protocol.

## The `mise-env-fnox` plugin

The [`jdx/mise-env-fnox`](https://github.com/jdx/mise-env-fnox) environment plugin was an experiment and doesn't support all fnox features. If you use it, replace the `_.fnox-env` entry in mise's `[env]` with the task wrappers above.

## Troubleshooting

```sh
mise exec -- fnox --version        # is fnox installed?
mise exec -- fnox config-files     # is the config found?
mise exec -- fnox check --all      # do the secrets resolve?
```

Each command narrows the problem to installation, config discovery, or secret resolution. Then see [troubleshooting](/guide/troubleshooting).

## See also

- [Running commands](/guide/running-commands): what `fnox exec` does.
- [CI/CD](/guide/ci): run the same tasks in CI.
