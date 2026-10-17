---
description: "Keep non-sensitive settings as plaintext in fnox.toml, or read values from an unencrypted .env, JSON, YAML, or TOML file."
---

# Plain text

The `plain` provider returns values without encryption: either the `value` written in `fnox.toml`, or a key looked up in an unencrypted file. Use it for non-sensitive settings such as log levels, ports, and public URLs. Anyone who can read the file can read the values.

|                     |                                                   |
| ------------------- | ------------------------------------------------- |
| Config type         | `plain`                                           |
| Storage             | Plaintext in config, or a local file              |
| Writes (`fnox set`) | Yes, into `fnox.toml`; No (read-only) with `file` |
| Requires            | Nothing                                           |

## Quick start

For a public setting, a `default` with no provider is usually simplest:

```toml
[secrets]
LOG_LEVEL = { default = "info" }
PORT = { default = "3000" }
API_URL = { default = "http://localhost:3000" }
```

`fnox set` also writes a plaintext default when neither the secret nor the configuration selects a provider. To encrypt a value, configure an [encryption provider](/providers/overview#encryption-in-your-config) first.

When a test or configuration needs a provider-backed value without encryption, use the `plain` provider. It returns `value` unchanged:

```toml
[providers.plain]
type = "plain"

[secrets]
LOG_LEVEL = { provider = "plain", value = "debug" }
```

## Configuration

| Field    | Required    | Default | Description                                                              |
| -------- | ----------- | ------- | ------------------------------------------------------------------------ |
| `file`   | No          | None    | Plaintext file to read values from. Requires `format`.                   |
| `format` | With `file` | None    | File format: `env`, `shell`, `json`, `yaml`, or `toml`. Requires `file`. |

Relative `file` paths resolve against the config file that declares the provider, and `~` expands to your home directory. Both fields accept `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

## Read from a plaintext file

With `file` and `format` set, each secret's `value` names the key to read from that file:

```toml
[providers.dotenv]
type = "plain"
file = "secrets.env"
format = "env"

[secrets]
DATABASE_URL = { provider = "dotenv", value = "DATABASE_URL" }
API_TOKEN = { provider = "dotenv", value = "SERVICE_TOKEN" }
```

With a `secrets.env` containing:

```sh
DATABASE_URL=postgres://localhost/app
SERVICE_TOKEN='abc$123'
```

`fnox get API_TOKEN` prints `abc$123`.

fnox does not guess the format from the file name. `format` accepts every format that [`fnox export`](/cli/export) writes:

| `format` | Contents                                                                            |
| -------- | ----------------------------------------------------------------------------------- |
| `env`    | `KEY=value` lines, as in a `.env` file. An `export ` prefix is allowed.             |
| `shell`  | `export KEY=value` statements using POSIX shell quoting. Values are not expanded.   |
| `json`   | An object of keys to values, or the `{"secrets": {...}}` document from fnox export. |
| `yaml`   | A mapping of keys to values, or the `secrets:` document from fnox export.           |
| `toml`   | A table of keys to values, or the `[secrets]` document from fnox export.            |

fnox reads the file when it resolves secrets from the provider, and secrets resolved together share a single read. The file may be read more than once in a single command, for example when one secret's `default` refers to another secret from the same file.

A provider with `file` is read-only: fnox never writes to the file. `fnox set DB_URL DATABASE_URL --provider dotenv` records `DATABASE_URL` as the key to look up, as it would for other read-only providers.

A key missing from the file is reported as a missing secret, so `if_missing` and `default` apply as usual.

## Fallbacks

A remote or encrypted secret can have a non-sensitive fallback:

```toml
[providers.aws]
type = "aws-sm"
region = "us-east-1"

[secrets]
REDIS_URL = { provider = "aws", value = "redis-url", default = "redis://localhost:6379" }
```

If the provider lookup fails, fnox can use the default. The default is plaintext even when the main value uses encryption. Avoid production fallbacks that would silently connect to the wrong service; use a separate [profile](/guide/profiles) when appropriate.

## Review before committing

Check both `value` and `default` fields. Setting `provider = "age"` does not encrypt a string you type into `value` by hand; let `fnox set` generate the ciphertext.

[`fnox scan`](/cli/scan) can flag potential secrets in files. It is a heuristic scan, not a guarantee that a repository or its history is free of secrets. If a real credential was exposed, rotate it at its source.

## Troubleshooting

### `file` requires `format` to be set

Add `format` with one of `env`, `shell`, `json`, `yaml`, or `toml`. Setting `format` without `file` is also an error.

### Key not found in the file

Check that the key is defined in the file and spelled as in `value`, then run `fnox provider test dotenv`, which reads and parses the file.

## See also

- [Quick start](/guide/quick-start): store sensitive values with encryption.
- [Missing secrets](/guide/missing-secrets): choose when to fall back, warn, or fail.
- [Configuration reference](/reference/configuration#default): interpolate defaults and set provider references.
