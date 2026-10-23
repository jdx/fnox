---
description: "Run commands with secrets using fnox exec, read single values with fnox get, export to other formats, and hand tools a file path instead of a value."
---

# Running commands

Most of the time you use fnox through one command, `fnox exec`. This page covers it and the other ways to get secrets out of fnox: `get`, `export`, file secrets, and `env --json` for tools.

## `fnox exec`

```sh
fnox exec -- npm start
fnox exec --profile production -- ./deploy.sh
```

fnox resolves the secrets for the current directory and profile, starts the command with them added to its environment, and exits with the command's exit code. Your shell's environment is not changed.

Put fnox options before `--`. Everything after it is passed to the command untouched.

Your shell expands `$VARIABLES` _before_ fnox runs, so this prints an empty line:

```sh
fnox exec -- echo $DATABASE_URL   # wrong: expanded by your shell first
```

To use a secret in a shell expression, run a child shell and single-quote the script:

```sh
fnox exec -- sh -c 'psql "$DATABASE_URL" -c "select 1"'
```

Useful options:

| Option                 | What it does                                                                                                                                                                                   |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-P, --profile <name>` | Use a [profile](/guide/profiles). Repeat or comma-separate to stack profiles.                                                                                                                  |
| `--if-missing error`   | Fail if any secret can't be resolved. See [missing secrets](/guide/missing-secrets).                                                                                                           |
| `--only <NAME>`        | Resolve only these secrets (names or globs) and what they depend on. See [resolve only some secrets](#filter-secrets).                                                                         |
| `--except <NAME>`      | Do not resolve these secrets (names or globs). See [resolve only some secrets](#filter-secrets).                                                                                               |
| `--refresh <KEY>`      | Re-read one secret from its provider instead of the [daemon](/guide/daemon) cache.                                                                                                             |
| `--replace`            | Replace the fnox process with the command (Unix only). Rejected when the command would receive an `as_file` secret or the profile configures leases, since fnox must clean those up afterward. |
| `--non-interactive`    | Never prompt or open a browser to authenticate. Use in CI.                                                                                                                                     |

`fnox x` is a short alias for `fnox exec`.

## Choose which secrets reach a command

Each secret has an `env` setting:

| `env`            | `fnox exec`  | Interactive shell ([shell integration](/guide/shell-integration)) |
| ---------------- | ------------ | ----------------------------------------------------------------- |
| `true` (default) | Injected     | Injected                                                          |
| `"exec"`         | Injected     | Not injected                                                      |
| `false`          | Not injected | Not injected                                                      |

```toml
env = "exec"   # project-wide default: keep secrets out of the interactive shell

[secrets]
DATABASE_URL = { provider = "age", value = "YWdl..." }
SIGNING_KEY = { provider = "age", value = "YWdl...", env = false }
```

An `env = false` secret is still available to `fnox get`, to other secrets and providers that [reference it](/reference/configuration#default), and to [lease backends](/guide/leases) that use it as a bootstrap credential. `fnox exec` resolves it only when something it injects depends on it.

## Resolve only some secrets {#filter-secrets}

By default `fnox exec` resolves every secret in the profile, so one unreachable provider or an expired login can stop a command that never needed that secret. `--only` and `--except` limit the run to the secrets it does need. Secrets outside the filter are not resolved at all: their providers are never called, so there are no auth prompts, network requests, or failures from them.

```sh
# Only DATABASE_URL and every secret whose name starts with AWS_
fnox exec --only DATABASE_URL,'AWS_*' -- ./migrate.sh

# Everything except one secret whose provider is down
fnox exec --except LEGACY_API_KEY -- npm start
```

- **Patterns** are exact names or globs (`*`, `?`, `[abc]`), matched case-sensitively. Repeat the flag or comma-separate values. When both flags are given, a secret must match `--only` and not match `--except`.
- **Dependencies are pulled in.** If a selected secret needs another secret to resolve, such as a provider token stored as a secret, fnox resolves that secret too but only passes it to the command if the filter selects it.
- **`if_missing` still applies** to selected secrets: with `if_missing = "error"`, a selected secret that cannot be resolved fails the run.
- **Typos are errors.** An unknown name (with close matches suggested) or an `--only` glob that matches nothing fails before anything is resolved, instead of silently running without the secret.
- **`as_file` secrets** follow the same filter: only selected ones are written to temporary files.
- **Leases** run only when `--only` names a variable they produce, and are skipped when `--except` names one. Only the variables the filter allows are passed to the command, even if a lease produces more. With only `--except`, other leases still run. A `command` lease can read any secret, so it is skipped whenever `--only` or `--except` is used.
- **The [daemon](/guide/daemon) cache** is per secret, so a filtered run neither reads nor hides the others: a later unfiltered run still resolves everything.
- A variable already in your environment under an excluded secret's name is left alone.

For machine-readable output, `fnox env --json --keys NAME,...` offers the same selection of exact names.

## Secrets as files {#secrets-as-files}

Some tools want a path to a file, such as a service-account key or a TLS certificate. Set `as_file = true`, and the variable holds the path to a private temporary file instead of the value:

```toml
[secrets]
GOOGLE_APPLICATION_CREDENTIALS = { provider = "op", value = "GCP/key.json", as_file = true }
```

`fnox exec` deletes the file when the command exits. To store a file's exact contents, including trailing newlines, use `fnox set KEY --from-file path`.

## `fnox get`

Print one value to stdout:

```sh
fnox get DATABASE_URL
fnox get DATABASE_URL --profile staging
```

Use it in scripts that need a single value. For an `as_file` secret, `get` prints a file path. `--base64-decode` decodes a base64-encoded value before printing.

To check that secrets resolve without printing them, use `fnox check --all`.

## `fnox export`

Write the resolved environment in another format, for tools that can't be wrapped in `fnox exec`:

```sh
fnox export                         # KEY=value (.env format)
fnox export --format shell          # export KEY=value
fnox export --format json -o secrets.json
```

Formats are `env`, `shell`, `json`, `yaml`, and `toml`. Output contains **plaintext secrets**, so prefer `fnox exec` when you can, and keep exported files out of git. Like the interactive shell, export skips `env = "exec"` and `env = false` secrets unless you pass `--all`.

See [import and export](/guide/import-export) for migrations between formats and providers.

## `fnox env --json`

Tools that start processes themselves (mise, editors, test runners) can ask fnox for the environment as JSON rather than wrapping each command:

```sh
fnox env --json
fnox env --json --describe   # keys and where they would be injected, no values
```

The output format is documented in the [fnox env JSON reference](/reference/env-json).

## See also

- [Shell integration](/guide/shell-integration): load secrets when you `cd` into a project.
- [mise integration](/guide/mise-integration): wrap tasks with `fnox exec`.
- [`fnox exec` reference](/cli/exec): every flag.
