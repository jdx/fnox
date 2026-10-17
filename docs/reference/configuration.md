---
description: "Look up every fnox.toml field, its default, and how fnox merges global, project, profile, and local config files."
---

# Configuration reference

`fnox.toml` declares providers, secrets, profiles, and the settings that control how fnox resolves and injects them. This page lists every field and how config files combine. For a walkthrough, see [config files](/guide/config-files). For provider-specific fields, see the [provider catalog](/providers/overview).

## JSON schema

The schema at `https://fnox.jdx.dev/schema.json` provides completion and validation in editors that support TOML schemas, such as VS Code with Even Better TOML. Reference it from the first line of the file:

```toml
#:schema https://fnox.jdx.dev/schema.json
```

## Files and load order

fnox merges config files in this order. A later file overrides an earlier one.

1. The global config, `config.toml` in [`FNOX_CONFIG_DIR`](/reference/environment#fnox-config-dir) (default: `~/.config/fnox/config.toml`).
2. For each directory, from the filesystem root down to the current directory:
   1. `fnox.toml`, `.fnox.toml`, `.config/fnox.toml`
   2. `fnox.<profile>.toml`, `.fnox.<profile>.toml`, `.config/fnox.<profile>.toml` for each active profile, in order
   3. `fnox.local.toml`, `.fnox.local.toml`, `.config/fnox.local.toml`

The upward search stops at the first directory whose config sets [`root = true`](#root); the global config still loads. Each file is merged over the files it [imports](#import). Run `fnox config-files` to list the files fnox finds for the current directory.

| File                  | Purpose                                                                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fnox.toml`           | Project config, usually committed.                                                                                                                                           |
| `fnox.<profile>.toml` | Loaded only while `<profile>` is active. Its top-level `providers`, `secrets`, `leases`, and `default_provider` belong to that profile. `fnox.default.toml` is never loaded. |
| `fnox.local.toml`     | Personal overrides and `fnox sync --local-file` caches. Keep it out of git.                                                                                                  |
| global `config.toml`  | Providers and secrets for every project on the machine. Create it with `fnox init --global`.                                                                                 |

### Explicit config paths

`-c, --config` with a path other than the bare names `fnox.toml`, `.fnox.toml`, `fnox.local.toml`, or `.fnox.local.toml` turns off directory discovery. Write `./fnox.local.toml` to load a local file on its own. fnox loads that file, the files it imports, and the global config, without parent directories, profile files, or local overrides. To load a file with no global layer, point `FNOX_CONFIG_DIR` at a directory without a `config.toml`:

```sh
FNOX_CONFIG_DIR=/nonexistent fnox -c ./ci.toml get MY_SECRET
```

### Merge rules

| Field                                                                   | When a later file sets it                                                                       |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `providers.<name>`, `secrets.<name>`, `leases.<name>`, `plugins.<name>` | Replaces the earlier entry of that name as a whole. Fields are not merged.                      |
| `profiles.<name>`                                                       | Merged: its providers, secrets, and leases by name; `inherits` and `default_provider` replaced. |
| `default_provider`, `if_missing`, `env`, `prompt_auth`                  | Replaced.                                                                                       |
| `daemon`, `mcp`                                                         | Merged field by field. `mcp.secrets` is replaced as a whole.                                    |
| `proxy`                                                                 | Replaced as a whole, including every rule.                                                      |

### Path values

Relative paths in a config file resolve against the directory of the file that declares them. This applies to `import` and to these provider fields: `age.key_file`, `enpass.vault`, `enpass.keyfile`, `foks.home`, `keepass.database`, `keepass.keyfile`, `keeper-sm.config_file`, `kubernetes.kubeconfig`, `lua.plugin` (when it is a path), `password-store.store_dir`, and `plain.file`. A leading `~` expands to your home directory. Paths given on the command line resolve against the current directory.

## File structure

```toml
default_provider = "age"
if_missing = "warn"

[providers.age]
type = "age"
recipients = ["age1..."]

[providers.aws]
type = "aws-sm"
region = "us-east-1"

[secrets]
DATABASE_URL = { provider = "age", value = "YWdl..." } # ciphertext, abbreviated

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }
```

## Top-level settings

| Field              | Type                            | Default  | Description                                                                          |
| ------------------ | ------------------------------- | -------- | ------------------------------------------------------------------------------------ |
| `default_provider` | string                          | none     | Provider for secrets that do not name one, and the default target of write commands. |
| `if_missing`       | `"error"`, `"warn"`, `"ignore"` | `"warn"` | Missing-secret behavior for secrets that do not set their own.                       |
| `env`              | `true`, `"exec"`, `false`       | `true`   | Injection mode for secrets that do not set their own.                                |
| `import`           | array of paths                  | `[]`     | Config files to merge underneath this one.                                           |
| `root`             | boolean                         | `false`  | Stop the upward directory search at this file.                                       |
| `prompt_auth`      | boolean                         | `true`   | Offer to run a provider's auth command when authentication fails.                    |
| `age_key_file`     | path                            | none     | Accepted for compatibility; has no effect.                                           |
| `providers`        | table                           | `{}`     | [Provider instances](#provider-configuration), by name.                              |
| `secrets`          | table                           | `{}`     | [Secrets](#secrets) for the default profile, by name.                                |
| `profiles`         | table                           | `{}`     | [Named profiles](#profile-configuration).                                            |
| `leases`           | table                           | `{}`     | [Lease backends](#lease-backend-settings), by name.                                  |
| `plugins`          | table                           | `{}`     | [Lua plugin sources](#plugins), by name.                                             |
| `daemon`           | table                           | none     | [Daemon settings](#daemon).                                                          |
| `mcp`              | table                           | none     | [MCP server settings](#mcp-server-settings).                                         |
| `proxy`            | table                           | none     | [Credential proxy rules](#proxy).                                                    |

### `default_provider`

Names the provider for secrets that set a `value` but no `provider`. It is also the default target of `fnox set` and `fnox sync`, and of new secrets added in `fnox edit`. A profile's `default_provider` overrides the top-level one. When neither is set and exactly one provider is available, fnox uses that provider. When no provider applies, `fnox set` stores the value in plain text.

### `if_missing`

What fnox does when a secret resolves to nothing: `"error"` fails the command, `"warn"` prints a warning and continues, and `"ignore"` continues silently. The effective value is the first of these that is set:

1. `--if-missing`
2. `FNOX_IF_MISSING`
3. The secret's `if_missing`
4. The top-level `if_missing`
5. `FNOX_IF_MISSING_DEFAULT`
6. `"warn"`

See [missing secrets](/guide/missing-secrets).

### `env`

Default injection mode for every secret that does not set [`env`](#env-1) itself. With `env = "exec"`, no secret enters the interactive shell unless it opts back in with `env = true`; `fnox exec` still injects them.

```toml
env = "exec"

[secrets]
DATABASE_URL = { provider = "age", value = "YWdl..." } # exec only, inherited
GITHUB_TOKEN = { provider = "age", value = "YWdl...", env = true } # also in the shell
```

This limits what other programs in your shell can read from the environment. It is not an access boundary: anything that can run commands in your shell can still run `fnox get`.

### `import`

Paths of config files to merge underneath this one, relative to this file. The importing file overrides its imports, and an earlier import overrides a later one. Imports are not recursive: an imported file's own `import` and `root` are ignored.

```toml
import = ["./shared/base.toml"]
```

### `root`

`root = true` stops the upward search for config files at this file's directory. The global config still loads.

### `prompt_auth`

When a provider fails to authenticate in a terminal, fnox offers to run its [`auth_command`](#auth-command). Set `prompt_auth = false` to turn this off. `FNOX_PROMPT_AUTH` overrides this setting, and `--non-interactive` turns off all prompts.

### `age_key_file`

Parsed for compatibility with older configs, but nothing reads it. Set [`key_file`](/providers/age#set-decryption-key) on the age provider, or set `FNOX_AGE_KEY_FILE`.

## Providers {#provider-configuration}

```toml
[providers.op]
type = "1password"
vault = "Engineering"
```

Every provider entry needs a `type`. These fields apply to every type; the rest depend on the type and are listed on each [provider page](/providers/overview).

| Field          | Type    | Default             | Description                                                            |
| -------------- | ------- | ------------------- | ---------------------------------------------------------------------- |
| `type`         | string  | required            | Provider type, such as `age`, `1password`, or `aws-sm`.                |
| `auth_command` | string  | the type's built-in | Command to offer when authentication fails. `""` turns off the prompt. |
| `daemon_cache` | boolean | `true`              | Set `false` to stop the daemon caching values from this provider.      |

Provider types: `1password`, `age`, `aws-kms`, `aws-ps`, `aws-sm`, `azure-ac`, `azure-kms`, `azure-sm`, `bitwarden`, `bitwarden-sm`, `doppler`, `enpass`, `fido2`, `foks`, `gcp-kms`, `gcp-sm`, `gopass`, `infisical`, `keepass`, `keeper-sm`, `keychain`, `kubernetes`, `lua`, `password-store`, `passwordstate`, `plain`, `proton-pass`, `vault`, `yubikey`.

### `auth_command`

```toml
[providers.rbw]
type = "bitwarden"
backend = "rbw"
auth_command = "rbw unlock"
```

### Secret references in provider fields {#provider-specific-fields}

Many provider fields accept `{ secret = "NAME" }` instead of a literal, so a provider's credentials can be secrets themselves. fnox looks the name up among the configured secrets first, then in the environment, and reports a dependency cycle as an error.

```toml
[providers.vault]
type = "vault"
address = "https://vault.example.com:8200"
token = { secret = "VAULT_TOKEN" }

[secrets]
VAULT_TOKEN = { provider = "age", value = "YWdl..." } # ciphertext, abbreviated
```

See [secret references in provider config](/guide/config-files#secret-references-in-provider-config).

## Secrets

```toml
[secrets]
DATABASE_URL = { provider = "op", value = "Database/url", description = "Main database" }
```

Secret names are environment variable names: they must match `^[A-Za-z_][A-Za-z0-9_]*$`. Every field is optional; `API_KEY = {}` declares a secret that comes from the environment.

| Field          | Type                            | Default            | Description                                                                      |
| -------------- | ------------------------------- | ------------------ | -------------------------------------------------------------------------------- |
| `provider`     | string                          | `default_provider` | Provider that holds or decrypts the value.                                       |
| `value`        | string                          | none               | Ciphertext for encryption providers, or the item reference for remote providers. |
| `default`      | string                          | none               | Fallback when the provider returns nothing or fails.                             |
| `if_missing`   | `"error"`, `"warn"`, `"ignore"` | inherited          | Missing-secret behavior for this secret.                                         |
| `env`          | `true`, `"exec"`, `false`       | top-level `env`    | Where the secret is injected as an environment variable.                         |
| `as_file`      | boolean                         | `false`            | Inject the path of a temporary file holding the value.                           |
| `json_path`    | string                          | none               | Extract a field from a JSON value, with dot notation for nesting.                |
| `line`         | integer, 1 or more              | none               | Extract one line from a multi-line value.                                        |
| `description`  | string                          | none               | Shown by `fnox list`.                                                            |
| `daemon_cache` | boolean                         | `true`             | Set `false` to resolve this secret directly instead of from the daemon cache.    |
| `sync`         | table                           | none               | Encrypted cache written by `fnox sync`.                                          |

### Resolution order

fnox resolves a secret from the first source that produces a value:

1. The `sync` cache, decrypted with its provider. Without one, the `provider` and `value`.
2. `default`, with any `${NAME}` references expanded.
3. An environment variable with the secret's name.

If none produces a value, [`if_missing`](#if-missing) decides the outcome. `json_path` and `line` apply to whichever value was found.

### `value`

For an encryption provider such as `age` or `aws-kms`, `value` is ciphertext that `fnox set` writes. For a remote provider such as `1password` or `aws-sm`, it names the item; each provider's page gives the format.

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "YWdl..." } # ciphertext, abbreviated
STRIPE_KEY = { provider = "aws", value = "stripe-key" } # AWS Secrets Manager secret name
```

### `default`

Used when the provider returns nothing, including after a provider error. `${NAME}` inside a default expands to another secret's resolved value, in any declaration order:

```toml
[secrets]
API_BASE_URL = { default = "https://api.${BASE_URL}" }
BASE_URL = { default = "example.com" }
```

An undefined reference or a cycle is an error. A reference to a secret that resolves to nothing under `warn` or `ignore` expands to an empty string. Expansion applies only to `default`.

### `env` {#env-1}

| Value            | Shell integration and `fnox export` | `fnox exec` | `fnox get` |
| ---------------- | ----------------------------------- | ----------- | ---------- |
| `true` (default) | yes                                 | yes         | yes        |
| `"exec"`         | no                                  | yes         | yes        |
| `false`          | no                                  | no          | yes        |

`fnox export --all` includes all three. A provider or lease backend that depends on an `env = false` secret can still read it.

### `as_file`

fnox writes the value to a temporary file that only you can read, and sets the variable to the file's path. `fnox exec` deletes the file when the command exits. Store file contents with `fnox set KEY --from-file PATH`, which keeps them byte for byte, including trailing newlines.

```toml
[secrets]
GOOGLE_APPLICATION_CREDENTIALS = { provider = "op", value = "GCP/key file", as_file = true }
```

### `json_path` and `line` {#json-path}

`json_path` parses the value as JSON and extracts a field, using dot notation for nested keys. `line` returns the Nth line, counting from 1. They cannot be combined.

```toml
[secrets]
DB_PASSWORD = { provider = "aws", value = "db-credentials", json_path = "credentials.password" }
USERNAME = { provider = "pass", value = "master", line = 2 }
```

### `sync`

`fnox sync` writes `sync = { provider = "...", value = "..." }`, where `value` is the secret encrypted with `provider`. Resolution uses it instead of the original provider until `fnox sync` replaces it or `fnox reencrypt` clears it. Let `fnox sync` maintain this field. See [sync](/guide/sync).

## Profiles {#profile-configuration}

```toml
[profiles.production]
default_provider = "aws"

[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }
```

| Field              | Type             | Description                                                  |
| ------------------ | ---------------- | ------------------------------------------------------------ |
| `inherits`         | array of strings | Profiles applied before this one, in order.                  |
| `providers`        | table            | Providers added to the top-level providers for this profile. |
| `secrets`          | table            | Secrets that override top-level secrets of the same name.    |
| `leases`           | table            | Lease backends for this profile.                             |
| `default_provider` | string           | Overrides the top-level `default_provider`.                  |

Other fields are rejected. Settings such as `if_missing`, `env`, `daemon`, `mcp`, and `proxy` are top-level only.

A named profile starts from the top-level secrets and providers, applies each profile in `inherits` in order, then its own tables; later entries win. `--no-defaults` or `FNOX_NO_DEFAULTS` drops the top-level secrets but keeps the top-level providers. The name `default` refers to the top level, and a `[profiles.default]` table is ignored. Select profiles with `-P` or `FNOX_PROFILE`; several comma-separated profiles apply left to right. See [profiles](/guide/profiles).

## Lease backend settings

```toml
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

Define lease backends under `[leases.<name>]` or `[profiles.<profile>.leases.<name>]`. Every backend has a `type` and an optional `duration` (default: `15m`); the service may cap the actual lifetime. Types: [`aws-sts`](/leases/aws-sts), [`azure-token`](/leases/azure-token), [`cloudflare`](/leases/cloudflare), [`command`](/leases/command), [`gcp-iam`](/leases/gcp-iam), [`github-app`](/leases/github-app), [`github-oauth`](/leases/github-oauth), and [`vault`](/leases/vault). See [credential leases](/guide/leases).

## `plugins`

```toml
[plugins]
corp = "acme/fnox-plugin-corp#v1.2.0"

[providers.corp]
type = "lua"
plugin = "corp"
```

Maps a plugin name to its git source. A source is a git URL, optionally followed by `#<ref>` to pin a tag, branch, or commit; `owner/repo` is shorthand for GitHub. `fnox plugin install` installs declared plugins. See [Lua plugins](/providers/lua).

## `daemon`

```toml
[daemon]
enabled = true
idle_timeout = "8h"
```

| Field          | Type     | Default | Description                                                              |
| -------------- | -------- | ------- | ------------------------------------------------------------------------ |
| `enabled`      | boolean  | `false` | Resolve secrets through the per-user daemon. `FNOX_DAEMON` overrides it. |
| `idle_timeout` | duration | `"8h"`  | How long the daemon runs without requests before it exits.               |

See [daemon](/guide/daemon).

## `mcp` {#mcp-server-settings}

```toml
[mcp]
tools = ["exec"]
secrets = ["DATABASE_URL"]
```

| Field               | Type               | Default                  | Description                                                        |
| ------------------- | ------------------ | ------------------------ | ------------------------------------------------------------------ |
| `tools`             | array of strings   | `["get_secret", "exec"]` | Tools that `fnox mcp` offers.                                      |
| `secrets`           | array of strings   | every secret             | Allowlist of secrets the tools can reach.                          |
| `exec_timeout_secs` | integer, 1 or more | `300`                    | Time limit, in seconds, for a command run by the `exec` tool.      |
| `redact_output`     | boolean            | `true`                   | Replace resolved secret values in `exec` output with `[REDACTED]`. |

Redaction is not a sandbox: a command can transform a value before printing it. See [MCP server](/guide/mcp).

## `proxy`

```toml
[proxy]
egress = "strict"
audit = true

[[proxy.rules]]
secret = "GITHUB_TOKEN"
domain = "api.github.com"
methods = ["GET", "POST"]
paths = ["/repos/example/**"]
```

| Field                 | Type                       | Default           | Description                                                             |
| --------------------- | -------------------------- | ----------------- | ----------------------------------------------------------------------- |
| `egress`              | `"strict"`, `"permissive"` | `"strict"`        | Reject destinations without a rule, or tunnel them without credentials. |
| `audit`               | boolean                    | `true`            | Log request metadata. Headers, bodies, and values are never logged.     |
| `rules[].secret`      | string                     | required          | Secret to inject, from the active profile.                              |
| `rules[].domain`      | string                     | required          | Exact TLS server name the secret may be sent to.                        |
| `rules[].env`         | string                     | `rules[].secret`  | Variable that holds the placeholder in the command's environment.       |
| `rules[].header`      | string                     | `"authorization"` | Header, case-insensitive, in which the placeholder is replaced.         |
| `rules[].methods`     | array of strings           | every method      | Allowed HTTP methods.                                                   |
| `rules[].paths`       | array of globs             | every path        | Allowed URL paths.                                                      |
| `rules[].placeholder` | string                     | generated         | Placeholder value given to the command.                                 |

A later config file that sets `[proxy]` replaces the whole table, so it must restate every rule it allows. See [credential proxy](/guide/proxy).

## See also

- [Config files](/guide/config-files): how global, project, profile, and local files work together.
- [Environment variables](/reference/environment): variables that override these settings.
- [Provider catalog](/providers/overview): fields and reference formats for each provider type.
