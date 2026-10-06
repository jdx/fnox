---
description: "Reference for fnox env --json: the versioned JSON contract that tools such as mise use to get the environment fnox exec would give a command."
---

# `fnox env --json`

`fnox env --json` prints the environment that `fnox exec` would give a command, as JSON, so that tools which start processes themselves can apply it. It is the machine-readable counterpart of `fnox exec`, with key selection, no leftover files, and a versioned schema.

```console
$ fnox env --json --keys DATABASE_URL,GCP_SA_JSON
{"schema":1,"fnox_version":"1.39.0","scope":"exec","profile":["default"],"set":{"DATABASE_URL":"postgres://…"},"files":{"GCP_SA_JSON":"{…contents…}"},"remove":["FNOX_AGE_KEY","FNOX_AGE_KEY_FILE","ENPASS_PASSWORD","FNOX_ENPASS_PASSWORD","SIGNING_KEY"],"missing":[],"leases":[]}
```

::: warning
stdout contains secret values in plain text. Do not log it. Use `--describe` to inspect keys without resolving any value.
:::

Use this instead of `fnox export --format json`, which selects keys by shell-injection rules, writes persistent files for `as_file` secrets, drops missing keys silently and has no schema version.

## Usage

```
fnox [global flags] env --json [--for exec|shell] [--keys K1,K2 ...] [--describe]
```

Global flags such as `-P/--profile`, `-c/--config`, `--if-missing`, `--no-defaults`, `--non-interactive` and `--no-daemon` go **before** `env`.

| Flag            | Meaning                                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `--json`        | Required in v1. Without it, fnox exits 1 with `fnox env requires --json` and prints no JSON.                                          |
| `--for <SCOPE>` | `exec` (default): `env = true` and `env = "exec"` secrets, plus credential leases. `shell`: `env = true` secrets only, and no leases. |
| `--keys <KEY>`  | Only these keys. Repeatable and comma-separated; duplicates are dropped, keeping the first. Without it, every key in scope.           |
| `--describe`    | List keys and where each may be injected. Resolves nothing, contacts no daemon, creates no leases and shows no prompts.               |

Argument errors that fnox's argument parser reports itself, such as an unknown `--for` value, exit with status 2 and print no JSON. Every other failure exits 1 with an error document on stdout.

## Which keys are selected

| Situation                  | Roots                                                       |
| -------------------------- | ----------------------------------------------------------- |
| No `--keys`, `--for exec`  | Every secret whose `env` mode is in scope, plus every lease |
| No `--keys`, `--for shell` | Every secret whose `env` mode is in scope; no leases        |
| `--keys`                   | Exactly the listed keys                                     |

Each listed key is checked against the active profile:

1. A secret whose `env` mode is in scope is a root.
2. Under `--for exec`, a lease that produces the key is selected, and its credential wins over a same-name secret, as in `fnox exec`.
3. Any other secret is `not_injectable`, reported with its `env` mode (`false`, or `"exec"` under `--for shell`).
4. Anything else is `unknown`, with suggestions for similar names. An empty key is unknown.

All problems are reported together in one `invalid_keys` error. A `command` lease produces no statically known keys, so its keys cannot be listed in `--keys`; they appear only when `--keys` is absent.

A `command` lease also declares no inputs, so when one is selected fnox resolves the whole profile for the lease to read, as `fnox exec` does. Only the selected keys are ever printed: `env = false` values the lease reads are not in the output.

## What gets resolved

fnox resolves the roots plus the secrets they depend on: secrets referenced with `${NAME}` in a `default`, and the secrets a provider reads from the environment (for example `OP_SERVICE_ACCOUNT_TOKEN` for a `1password` secret). For each selected lease, the secrets that lease consumes are included as well.

`env = false` secrets are never printed. They are resolved only when a requested key depends on them, or when a selected `command` lease may read them. (`fnox exec` currently resolves every secret in the profile, including `env = false` ones, and removes them from the child's environment.)

`as_file` secrets come back as raw contents in `files`, so fnox leaves no files behind. The caller writes them. Lease credentials that point at lease-time files (files fnox writes so a lease backend can read an `as_file` secret) are not usable through `fnox env`, because those files are removed when it exits; `as_file` secrets themselves come back in `files`.

## Documents (schema 1)

Every document is one line of compact JSON followed by a newline. stdout carries the document only; warnings and prompts go to stderr.

### Success

```json
{
  "schema": 1,
  "fnox_version": "1.39.0",
  "scope": "exec",
  "profile": ["default"],
  "set": { "DATABASE_URL": "postgres://…" },
  "files": { "GCP_SA_JSON": "{…}" },
  "remove": [
    "FNOX_AGE_KEY",
    "FNOX_AGE_KEY_FILE",
    "ENPASS_PASSWORD",
    "FNOX_ENPASS_PASSWORD",
    "SIGNING_KEY"
  ],
  "missing": ["OPTIONAL_TOKEN"],
  "leases": ["aws"]
}
```

| Field     | Meaning                                                                                                                                                                                                              |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `set`     | Variables to set: secrets in config order, then lease credentials. A lease credential replaces a same-name secret. With `--keys`, only requested keys.                                                               |
| `files`   | `as_file` secrets that resolved: contents for the caller to write to a file, then set `KEY=<path>`.                                                                                                                  |
| `remove`  | Variables to remove from the inherited environment: the ambient scrub (`FNOX_AGE_KEY`, `FNOX_AGE_KEY_FILE`, the Enpass master password), then every secret that is out of scope, minus anything in `set` or `files`. |
| `missing` | Requested or in-scope keys that resolved to nothing under `if_missing = "warn"` or `"ignore"`. With `if_missing = "error"` the command fails instead.                                                                |
| `leases`  | Leases that actually ran. A lease whose prerequisites are missing and that has no cached credential is skipped with a warning, as in `fnox exec`.                                                                    |
| `profile` | The active profiles.                                                                                                                                                                                                 |

**Apply order:** `remove`, then `set`, then `files` (write each value to a file and set `KEY=<path>`).

### Describe

`fnox env --json --describe` lists every key regardless of `--for`. With `--keys`, it validates them against `--for` exactly as resolution would, so a grant can be checked without resolving anything, and lists only those keys.

```json
{
  "schema": 1,
  "fnox_version": "1.39.0",
  "profile": ["default"],
  "keys": [
    {
      "key": "DATABASE_URL",
      "kind": "secret",
      "env": true,
      "as_file": false,
      "description": "Main DB",
      "injectable": { "exec": true, "shell": true }
    },
    {
      "key": "STRIPE_KEY",
      "kind": "secret",
      "env": "exec",
      "as_file": false,
      "injectable": { "exec": true, "shell": false }
    },
    {
      "key": "SIGNING_KEY",
      "kind": "secret",
      "env": false,
      "as_file": false,
      "injectable": { "exec": false, "shell": false }
    },
    {
      "key": "AWS_ACCESS_KEY_ID",
      "kind": "lease",
      "lease": "aws",
      "injectable": { "exec": true, "shell": false }
    }
  ],
  "dynamic_leases": ["build_token"]
}
```

(The real output is a single line.) `env` and `as_file` are present only when a secret of that name exists, `description` only when set, and `kind` is `"lease"` when a lease produces the key. `dynamic_leases` names `command` leases, whose keys are only known after they run.

### Error

```json
{
  "schema": 1,
  "error": {
    "kind": "invalid_keys",
    "message": "…",
    "unknown": ["DEPLOY_KYE"],
    "suggestions": { "DEPLOY_KYE": ["DEPLOY_KEY"] },
    "not_injectable": [{ "key": "SIGNING_KEY", "env": false }]
  }
}
```

`kind` names the phase that failed:

- `config`: loading the configuration and the active profiles.
- `invalid_keys`: validating `--keys`. Only this kind carries `unknown`, `suggestions` and `not_injectable`; empty ones are omitted.
- `resolution`: everything after validation, including provider, interpolation, lease and daemon errors.

## Exit codes and streams

| Case                                     | Exit | stdout         | stderr        |
| ---------------------------------------- | ---- | -------------- | ------------- |
| Success, including a non-empty `missing` | 0    | the document   | warnings only |
| Missing `--json`                         | 1    | nothing        | error message |
| Any other failure                        | 1    | error document | error report  |
| Argument parsing error                   | 2    | nothing        | usage message |

Authentication prompts need stdin on a terminal: fnox prompts only when stdin is a TTY and `--non-interactive` is not set. Callers that may prompt should keep stdin and stderr attached to the terminal and pipe only stdout. Prompts and auth commands write to stderr or the terminal, never to stdout.

## Compatibility

Consumers must ignore unknown fields. New optional fields may appear within schema 1. Any breaking change increments `schema`.

## Daemon

`fnox env --json` resolves through the same path as `fnox exec`, using the daemon cache purpose `exec` for `--for exec` and `hook-env` for `--for shell`:

| Condition                                                                              | Behavior                                                           |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Unsupported platform, `--no-daemon`, `FNOX_DAEMON` off, or `[daemon] enabled` not true | Resolves directly                                                  |
| Daemon enabled but not running                                                         | Starts it automatically                                            |
| Interactive, cache misses                                                              | Resolves on its own terminal, then stores the values in the daemon |

With `--non-interactive` and the daemon enabled, the daemon resolves cache misses itself. Callers that want resolution to stay in the client also pass `--no-daemon`. `--describe` never touches the daemon. See [the daemon guide](/guide/daemon).
