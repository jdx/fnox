---
description: "Reference for fnox.toml settings, providers, secrets, profiles, imports, local overrides, caches, proxies, and leases."
---

# Configuration reference

Use this reference for configuration loading, top-level settings, providers, secrets, and profiles. Start with the [quick start](/guide/quick-start) for a working file, or use the [provider catalog](/providers/overview) for provider-specific fields.

## JSON schema

A JSON Schema is available for IDE autocompletion and validation:

```text
https://fnox.jdx.dev/schema.json
```

### Editor setup

**VS Code** with [Even Better TOML](https://marketplace.visualstudio.com/items?itemName=tamasfe.even-better-toml):

```toml
#:schema https://fnox.jdx.dev/schema.json

[providers]
age = { type = "age", recipients = ["age1..."] }
```

**JetBrains IDEs**: Add the schema URL in Settings > Languages & Frameworks > Schemas and DTDs > JSON Schema Mappings.

## File location

The global config is the base layer. fnox then loads discovered project directories from outermost to innermost. At **each directory**, it applies:

1. `fnox.toml` (or `.fnox.toml`).
2. `fnox.<profile>.toml` for each active non-default profile, in selection order.
3. `fnox.local.toml` (or `.fnox.local.toml`).

A closer directory overrides an outer directory, including its local overrides. Provider and secret definitions with the same name are replaced as a unit; they are not merged field by field. The global directory follows [`FNOX_CONFIG_DIR`](/reference/environment#fnox-config-dir).

An explicit path uses the separate behavior below. To see the actual stack for a command, run `fnox config-files`.

### Explicit config paths

Passing `-c, --config` with anything other than the bare default filename turns
off the hierarchical search: fnox loads that one file plus any files it
`import`s, and skips parent directories and their local overrides. The global
config is still loaded as the base layer, just as `root = true` stops
parent-directory recursion without skipping the global config.

To load a config in complete isolation, point `FNOX_CONFIG_DIR` at a directory
with no `config.toml`:

```bash
FNOX_CONFIG_DIR=/nonexistent fnox -c ./ci.toml get MY_SECRET
```

Use `fnox config-files` to see exactly which files a given directory and set of
flags will load.

### Global configuration

The global config file stores machine-wide secrets and providers that apply to all projects:

```bash
# Initialize global config
fnox init --global

# After configuring an age provider, add a secret with hidden input
fnox set MY_TOKEN --global --provider age

# Add providers to global config (the `aws` type is AWS Secrets Manager)
fnox provider add aws aws --global
```

**Location**: `~/.config/fnox/config.toml` (customizable via `FNOX_CONFIG_DIR`)

**Use cases**:

- Personal API tokens used across multiple projects
- Machine-specific credentials
- Default providers available everywhere

## Basic structure

```toml
# Top-level settings
if_missing = "warn"  # Global default for missing secrets
import = ["./shared/secrets.toml"]  # Import other configs

# Provider definitions
[providers]
PROVIDER_NAME = { type = "PROVIDER_TYPE" }  # ... provider-specific config ...

# Secret definitions
[secrets]
SECRET_NAME = { provider = "PROVIDER_NAME", value = "...", default = "...", if_missing = "error", description = "..." }

# Profile definitions
[profiles.PROFILE_NAME]
# Profiles support providers, secrets, leases, default_provider, and inherits
```

Secret names are environment variable names and must match
`^[A-Za-z_][A-Za-z0-9_]*$`.

## Top-level settings

### `default_provider`

Provider instance to use when a secret does not select one explicitly. It also supplies the default target for commands such as `fnox set` and `fnox sync`.

```toml
default_provider = "age"

[providers.age]
type = "age"
recipients = ["age1..."] # Replace with your public recipient
```

If no provider is selected, `fnox set` writes a plaintext default. Configure a provider before storing sensitive values.

### `root`

Stop the parent-directory search at this file. The global config still loads.

```toml
root = true
```

### `prompt_auth`

Allow fnox to offer a provider authentication command in a terminal. Defaults to `true`. `FNOX_PROMPT_AUTH` overrides this setting; `--non-interactive` also disables interactive authentication flows.

```toml
prompt_auth = false
```

### `age_key_file`

Legacy top-level path to an age identity file. Prefer `key_file` on the individual age provider so identity selection stays with its provider configuration. See [age identity selection](/providers/age#set-decryption-key).

### `if_missing`

Global default behavior when secrets cannot be resolved.

```toml
if_missing = "error"  # or "warn", "ignore"
```

**Values:**

- `"error"` - Fail if secret is missing
- `"warn"` - Print warning and continue (default)
- `"ignore"` - Silently skip missing secrets

**Priority:** Overridden by secret-level `if_missing`, `FNOX_IF_MISSING`, and CLI flags. Only `FNOX_IF_MISSING_DEFAULT` and the built-in default rank lower.

### `env`

Default injection mode for all secrets in the config. Secrets that don't set their own `env` inherit this value.

```toml
env = "exec"  # or true, false
```

**Values:**

- `true` - Inject into the shell (via shell integration / `fnox export`) and `fnox exec` subprocesses (default)
- `"exec"` - Only inject into `fnox exec` subprocesses; never the interactive shell
- `false` - Exclude from normal environment injection; explicit reads and internal provider or lease dependencies can still resolve the secret

Setting `env = "exec"` at the top level keeps every secret out of the interactive shell by default — useful when AI coding agents or other tools run in your shell and would otherwise inherit all injected secrets. Applications still receive secrets when launched through `fnox exec -- <command>`, and individual secrets can opt back in with `env = true`:

```toml
env = "exec"  # nothing enters the interactive shell...

[secrets]
DATABASE_URL = { provider = "age", value = "..." }              # exec-only (inherited)
HOMEBREW_GITHUB_API_TOKEN = { provider = "age", value = "...", env = true }  # ...except this
```

Note that this limits _ambient_ exposure: processes in your shell no longer see secret values in their environment. Anyone who can run commands in your shell can still invoke `fnox get` or `fnox exec` themselves — for a hard boundary, combine this with the [MCP server allowlist](/guide/mcp) and OS-level sandboxing.

### `import`

List of config files to import.

```toml
import = ["./shared/base.toml", "./envs/dev.toml"]
```

**Usage:**

- Paths relative to current config file
- Imported files merged into current config
- Later imports override earlier ones

### Path values

Paths declared in config files are resolved relative to the config file that declares them. This applies to imports and provider filesystem paths such as `age.key_file`, `keepass.database`, `keepass.keyfile`, `password-store.store_dir`, and `foks.home`.

```toml
# project/fnox.toml
import = ["./shared/secrets.toml"] # project/shared/secrets.toml

[providers.keepass]
type = "keepass"
database = "./secrets.kdbx" # project/secrets.kdbx
```

Paths beginning with `~` expand to your home directory. Absolute paths are used unchanged. CLI path arguments remain relative to the current working directory, and environment variable paths keep their existing environment-specific behavior.

### `daemon`

Enable memory-only daemon caching for supported read commands.

```toml
[daemon]
enabled = true
idle_timeout = "8h"
```

**Fields:**

- `enabled` - Enable daemon-backed resolution. Defaults to `false`.
- `idle_timeout` - How long the daemon stays alive while idle. Defaults to `"8h"`. Supports values such as `"30m"`, `"8h"`, or `"1d"`.

See [Per-User Daemon](/guide/daemon).

### `proxy`

Broker credentials into destination-scoped HTTPS requests without exposing real
secret values to the child process.

```toml
[proxy]
egress = "strict"
audit = true

[[proxy.rules]]
secret = "GITHUB_TOKEN"
domain = "api.github.com"
header = "authorization"
methods = ["GET", "POST"]
paths = ["/repos/example/**"]
placeholder = "ghp_000000000000000000000000000000000000"
```

**Fields:**

- `egress` - Behavior for destinations without rules: `"strict"` (default) or
  `"permissive"`.
- `audit` - Log safe request metadata. Defaults to `true`.
- `rules` - Credential substitution rules.
- `rules[].secret` - Secret name in the active profile.
- `rules[].domain` - Exact TLS server name.
- `rules[].env` - Child environment variable name. Defaults to the secret name.
- `rules[].header` - Header in which substitution is allowed. Defaults to
  `"authorization"`.
- `rules[].methods` - Allowed HTTP methods. Empty allows all methods.
- `rules[].paths` - Allowed path globs. Empty allows all paths.
- `rules[].placeholder` - Optional placeholder passed to the child.

Proxy policy is replaced as a unit during configuration layering. If a nearer,
profile-specific, or local config defines `[proxy]`, it must restate every rule
it intends to allow; fields and rules are not inherited from an earlier
`[proxy]` table. This keeps partial overlays from silently combining authority.

See [Credential Proxy](/guide/proxy).

## MCP server settings

```toml
[mcp]
tools = ["exec"]
secrets = ["DATABASE_URL"]
redact_output = true
```

- `tools`: exposed tools; defaults to `["get_secret", "exec"]`.
- `secrets`: optional allowlist of secret names; omitted means all active-profile secrets are available.
- `redact_output`: redact literal resolved values in subprocess output; defaults to `true`.

Output redaction is not a sandbox. An agent-controlled command can transform or transmit credentials. See [MCP access and limits](/guide/mcp).

## Lease backend settings

Define backends under `[leases.<name>]` or `[profiles.<name>.leases.<backend>]`. Each backend has a `type` and its own fields. `duration` requests a lifetime; the service controls the actual expiry.

```toml
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

See [credential leases](/guide/leases) for authentication, caching, revocation, and all backend types.

## Provider configuration

```toml
[providers.PROVIDER_NAME]
type = "PROVIDER_TYPE"
# ... provider-specific fields ...
```

### `auth_command`

Override the authentication command for a specific provider instance. When provider authentication fails in a TTY, fnox prompts to run this command. By default, each provider type has a built-in auth command (e.g., `bw login` for Bitwarden, `op signin` for 1Password).

```toml
[providers]
# Use rbw instead of the default bw CLI
rbw = { type = "bitwarden", backend = "rbw", auth_command = "rbw unlock" }

# Use a custom AWS SSO profile
aws = { type = "aws-sm", region = "us-east-1", auth_command = "aws sso login --profile myprofile" }

# Disable auth prompting for this provider
vault = { type = "vault", address = "https://vault.example.com", auth_command = "" }
```

Setting `auth_command = ""` disables the auth prompt for that provider instance.

### `daemon_cache`

Disable daemon cache reuse for all secrets that use this provider.

```toml
[providers.op]
type = "1password"
vault = "Engineering"
daemon_cache = false
```

### Provider-specific fields

The [provider catalog](/providers/overview) links to authentication, configuration, and reference formats for every supported provider. Fields such as `region`, `vault`, `prefix`, and `key_file` apply only to the types that document them.

Many provider fields accept `{ secret = "NAME" }` in place of a literal value. See [secret references in provider config](/guide/profiles#secret-references-in-provider-config). Avoid a dependency cycle in which a provider needs a secret stored in itself.

## Secret configuration

```toml
[secrets]
SECRET_NAME = { provider = "PROVIDER_NAME", value = "...", default = "...", if_missing = "error", description = "..." }
```

### Fields

#### `provider`

Provider instance to use for this secret. An explicit value overrides `default_provider`.

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted..." }
```

**Optional:** A secret can use `default_provider`, a plaintext `default`, or an existing environment variable. An empty definition such as `API_KEY = {}` can require a value supplied by the environment when no default provider applies.

#### `value`

Provider-specific value:

- **Encryption providers** (age, aws-kms, etc.): Encrypted ciphertext
- **Remote providers** (aws-sm, 1password, etc.): Secret name/reference

```toml
[secrets]
# Encrypted ciphertext (age)
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }

# Remote reference (AWS)
REMOTE_DATABASE_URL = { provider = "aws", value = "database-url" }  # Secret name in AWS Secrets Manager
```

#### `daemon_cache`

Disable daemon cache reuse for this secret.

```toml
[secrets]
PAYMENT_API_KEY = { provider = "op", value = "Payments/api-key", daemon_cache = false }
```

#### `default`

Fallback value if secret cannot be resolved.

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted...", default = "postgresql://localhost/dev" }  # Fallback for local dev
```

Use `${SECRET_NAME}` to include another secret in a default value:

```toml
[secrets]
API_BASE_URL = { default = "https://api.${BASE_URL}" }
BASE_URL = { default = "example.com" }
```

`API_BASE_URL` resolves to `https://api.example.com`. Declaration order does not
matter. Referenced secrets must be defined in the config and can resolve from a
provider, a default, or an environment variable. Profile overrides also apply.

Interpolation only works in `default` values. Resolution order is provider
values, interpolated defaults, literal defaults, then environment variables.
Undefined references and dependency cycles in an evaluated default are errors.
If a referenced secret is defined but resolves to no value under a non-error
`if_missing` policy, the reference expands to an empty string.

**Use for:**

- Non-sensitive defaults
- Local development fallbacks
- Optional configuration

#### `if_missing`

Behavior when secret cannot be resolved.

```toml
[secrets]
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }  # Fail if missing (critical secret)
ANALYTICS_KEY = { provider = "aws", value = "analytics-key", if_missing = "ignore" }  # Silently skip if missing (optional)
```

**Values:** `"error"`, `"warn"`, `"ignore"`

**Priority:** Overrides top-level `if_missing`, but overridden by env vars and CLI flags.

#### `env`

Where the secret is injected as an environment variable.

```toml
[secrets]
GITHUB_TOKEN = { provider = "age", value = "..." }                    # true (default): shell + fnox exec
DATABASE_URL = { provider = "age", value = "...", env = "exec" }      # only fnox exec subprocesses
SIGNING_KEY  = { provider = "age", value = "...", env = false }       # not normally injected; explicit reads still work
```

**Values:**

- `true` - Injected by shell integration and `fnox exec` (default)
- `"exec"` - Only injected into `fnox exec` subprocesses, never the interactive shell
- `false` - Never injected as an env var; retrieve explicitly with `fnox get`

**Priority:** Overrides the top-level `env` default.

`fnox export` follows shell semantics: `env = "exec"` and `env = false` secrets are excluded unless `--all` is passed.

#### `as_file`

Write the secret to an ephemeral temp file and set the env var to the file path instead of the value.

```toml
[secrets]
GOOGLE_APPLICATION_CREDENTIALS = { provider = "op", value = "GCP Service Account/key file", as_file = true }
```

When setting a secret whose contents come from a file, use `--from-file` to
preserve the file exactly, including trailing newlines:

```bash
fnox set SSH_PRIVATE_KEY --from-file ~/.ssh/id_ed25519
```

With `as_file = true`, fnox writes those exact contents to a restricted temporary
file and injects its path instead of the secret value.

#### `json_path`

Extract a field from a JSON secret value (dot notation for nesting).

```toml
[secrets]
DB_PASSWORD = { provider = "aws", value = "db-credentials", json_path = "credentials.password" }
```

#### `line`

Extract the Nth line (1-indexed) from a multi-line secret value. Useful for providers that pack several related values into one entry. Mutually exclusive with `json_path`.

```toml
[secrets]
USERNAME = { provider = "pass", value = "master", line = 2 }
```

#### `sync`

An encrypted cache generated by `fnox sync`. Resolution uses this cache before contacting the original provider. Keep personal caches in an ignored local file and let sync maintain the fields:

```toml
[secrets.DATABASE_URL]
provider = "op"
value = "Database/url"
sync = { provider = "sync-age", value = "encrypted-cache..." }
```

The ciphertext above is abbreviated. See [sync a local cache](/guide/sync) for setup and refresh behavior.

#### `description`

Human-readable description.

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted...", description = "Production database connection string" }
```

## Profile configuration

Profiles allow environment-specific configuration:

```toml
# Default profile (no prefix)
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted-dev..." }

# Production profile
[profiles.production]

[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }
```

### Profile structure

Profiles support `inherits`, `providers`, `secrets`, `leases`, and `default_provider`. Settings such as `if_missing`, `env`, `daemon`, `mcp`, and `proxy` belong at the top level or, where supported, on individual secrets. Unknown profile fields are rejected.

```toml
[profiles.PROFILE_NAME]
default_provider = "PROVIDER_NAME"

[profiles.PROFILE_NAME.providers]
PROVIDER_NAME = { type = "PROVIDER_TYPE" }  # ... provider config ...

[profiles.PROFILE_NAME.secrets]
SECRET_NAME = { provider = "PROVIDER_NAME", value = "..." }  # ... secret config ...
```

### Profile inheritance

Profiles inherit top-level secrets and providers:

```toml
# Top-level (inherited by all profiles)
[secrets]
LOG_LEVEL = { default = "info" }
DATABASE_URL = { provider = "age", value = "encrypted-dev..." }

# Production profile
[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "prod-db" }  # Overrides top-level DATABASE_URL
# Inherits LOG_LEVEL="info" from top-level
```

You can disable this merge behavior at runtime:

```bash
fnox exec --profile production --no-defaults -- ./deploy.sh
```

With `--no-defaults`, top-level secrets are excluded for a named profile. Secrets from selected profiles and their inherited profiles still apply, and top-level providers remain available.

Profiles can selectively inherit other named profiles as an ordered overlay:

```toml
[profiles.api-local]
inherits = ["openai", "database-local", "no-log-upload"]

[profiles.api-local-john]
inherits = ["api-local", "openai-john"]
```

Inherited profiles are applied before the profile that declares `inherits`.
Later inherited profiles override earlier ones, and declarations directly on
the selected profile override all of them. Inheritance includes secrets,
providers, lease backends, and `default_provider`.

## Complete example

```toml
# Global settings
if_missing = "warn"
import = ["./shared/common.toml"]

# Providers
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }

# Default profile secrets
[secrets]
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC...", default = "postgresql://localhost/dev", description = "Database connection string" }
JWT_SECRET = { provider = "age", value = "encrypted...", if_missing = "error" }
LOG_LEVEL = { default = "info" }

# Production profile
[profiles.production]

[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp-prod/" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url", description = "Production database", if_missing = "error" }
JWT_SECRET = { provider = "aws", value = "jwt-secret", if_missing = "error" }
# Inherits LOG_LEVEL from top-level
```

## Local overrides

Create `fnox.local.toml` alongside `fnox.toml` for local overrides:

```toml
# fnox.local.toml (gitignored)

[secrets]
DATABASE_URL = { default = "postgresql://localhost/mylocal" }  # Override for local development
DEBUG_MODE = { default = "true" }
```

**Important:** Add to `.gitignore`:

```text
fnox.local.toml
```

## Profile-specific config files

You can create environment-specific config files that load based on the active
profile(s). When multiple profiles are active, each profile's config file is
loaded in order:

```bash
# Directory structure
project/
├── fnox.toml              # Base config
├── fnox.production.toml   # Production overrides
├── fnox.staging.toml      # Staging overrides
├── fnox.development.toml  # Development overrides
└── fnox.local.toml        # Local overrides (gitignored)
```

Example usage:

```bash
# Use default config (fnox.toml only)
fnox exec -- npm start

# Use production config (fnox.toml + fnox.production.toml)
FNOX_PROFILE=production fnox exec -- ./deploy.sh

# Use staging config (fnox.toml + fnox.staging.toml)
FNOX_PROFILE=staging fnox exec -- ./deploy.sh

# Compose multiple profiles (fnox.toml + fnox.aws.toml + fnox.prod.toml)
FNOX_PROFILE=aws,prod fnox exec -- ./app
```

**Key differences:**

- `fnox.<profile>.toml` files are **committed to git** (environment-specific, but shared with team)
- `fnox.local.toml` is **gitignored** (machine-specific, personal overrides)
- Profile-specific files work with the default profile's secrets, not `[profiles.xxx]` sections
- `fnox.default.toml` is **not loaded** (use `fnox.toml` instead)
- With multiple active profiles, config files are loaded in profile order (later profiles override earlier)

## Hierarchical configuration

fnox searches parent directories for `fnox.toml` files:

```text
project/
├── fnox.toml              # Root config
└── services/
    └── api/
        └── fnox.toml      # API config (inherits from root)
```

Merge order (lowest to highest priority):

1. **Global config** (`~/.config/fnox/config.toml`)
2. Root `fnox.toml`
3. Root `fnox.<profile>.toml` for each active profile (in profile order)
4. Root `fnox.local.toml`
5. Child `fnox.toml`
6. Child `fnox.<profile>.toml` for each active profile (in profile order)
7. Child `fnox.local.toml`

**Note**: Setting `root = true` in a `fnox.toml` stops the parent-directory search at that file. The global config is always loaded, even when `root = true` stops parent directory recursion.

## Next steps

- [CLI Reference](/cli/) - All available commands
- [Environment Variables](/reference/environment) - Environment variable reference
- [Providers Overview](/providers/overview) - Available providers
