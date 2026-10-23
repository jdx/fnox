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
| `--refresh <KEY>`      | Re-read one secret from its provider instead of the [daemon](/guide/daemon) cache.                                                                                                             |
| `--replace`            | Replace the fnox process with the command (Unix only). Rejected when the command would receive an `as_file` secret or the profile configures leases, since fnox must clean those up afterward. |
| `--redact`             | Replace secret values with `[REDACTED]` in the command's piped or redirected output. See [redact output](#redact-output).                                                                      |
| `--no-redact`          | Turn redaction off when the config or `FNOX_EXEC_REDACT` enables it.                                                                                                                           |
| `--non-interactive`    | Never prompt or open a browser to authenticate. Use in CI.                                                                                                                                     |

`fnox x` is a short alias for `fnox exec`.

### Redact output

Secrets that a command prints end up in CI logs and files. With `--redact`, fnox replaces each secret value in the command's stdout and stderr with `[REDACTED]`:

```sh
fnox exec --redact -- sh -c 'echo "token=$API_TOKEN"' | tee build.log
# token=[REDACTED]
```

To make it the default, set `redact_exec = true` in `fnox.toml` or `FNOX_EXEC_REDACT=1`. `--redact` and `--no-redact` override both. It is off by default.

- **Only piped output is filtered.** Each of stdout and stderr is redacted only when it is not a terminal, so interactive programs (editors, REPLs, anything checking `isatty`) run untouched. Output to your terminal is never redacted.
- **Streaming.** Output is filtered as it is produced. A value split across reads is still caught; fnox holds back at most the longest secret's length of trailing bytes, and only when they could be the start of a secret. Memory use does not grow with output size.
- **What counts as a secret.** Every value fnox sets in the command's environment, including `as_file` contents. When values overlap, the longest wins. Values are trimmed, and values shorter than 3 characters are skipped so ordinary output is not mangled.
- **Exit status is unchanged**, including death by signal. `--replace` is rejected when redaction is on (by flag, config or `FNOX_EXEC_REDACT`) and output is piped, since fnox must stay running to filter; pass `--no-redact` to use it anyway. If a background process keeps the output pipe open after the command exits, fnox stops waiting once the output has been idle for two seconds. If writing the filtered output fails, fnox reports an error even when the command succeeded.

::: warning Redaction is not a sandbox
fnox matches the exact value (after trimming). A command that transforms a secret before printing it, such as base64, URL encoding, splitting it across lines, or hashing, is not caught. Treat redaction as protection against accidental leaks in logs, not against a command that is trying to exfiltrate a value.
:::

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
