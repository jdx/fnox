# Mise Integration

fnox works well with [mise](https://mise.jdx.dev) as a tool installer and task
runner. The recommended setup is to install the fnox CLI with mise, then use
fnox directly through shell integration, `fnox exec`, or mise tasks.

::: warning Experimental plugin
We do not recommend using fnox through the
[`jdx/mise-env-fnox`](https://github.com/jdx/mise-env-fnox) env plugin. It is an
incomplete experiment and does not track every fnox feature.
:::

## Installation

Install fnox globally with mise:

```bash
mise use -g fnox
```

Then enable fnox shell integration if you want secrets to load automatically when
you enter a project directory:

```bash
eval "$(fnox activate bash)"
```

See [Shell Integration](/guide/shell-integration) for zsh, fish, Nushell, and
PowerShell setup.

## Using fnox in mise Tasks

For commands launched through mise, run them through `fnox exec`:

```toml
[tasks.dev]
run = "fnox exec -- npm run dev"

[tasks.deploy]
run = "fnox exec --profile production -- ./deploy.sh"
```

This keeps secret resolution inside fnox, so options such as `env = false`,
`as_file`, leases, profiles, and provider-specific behavior all work the same as
they do outside mise.

## Experimental Env Plugin

The `jdx/mise-env-fnox` env plugin is documented here only for existing users.
For new setups, prefer shell integration or `fnox exec`.

Add the plugin to your project's `mise.toml`:

```toml
[plugins]
fnox-env = "https://github.com/jdx/mise-env-fnox"

[tools]
fnox = "latest"

[env]
_.fnox-env = { tools = true }
```

> [!IMPORTANT]
> `tools = true` is required so the plugin can access the mise-managed fnox
> binary. Without it, the plugin runs before mise tools are added to PATH and
> won't be able to find fnox.

## How It Works

When mise activates your environment, the experimental fnox plugin:

1. Searches for `fnox.toml` in the current directory and parent directories
2. Resolves secrets using your configured providers
3. Exports the secrets as environment variables
4. Watches `fnox.toml` for changes to invalidate the cache

## Configuration Options

| Option     | Description                                                     | Default   |
| ---------- | --------------------------------------------------------------- | --------- |
| `tools`    | Use mise-managed tools (required if fnox is installed via mise) | `false`   |
| `profile`  | fnox profile to use                                             | `default` |
| `fnox_bin` | Path to fnox binary                                             | `fnox`    |

### Examples

```toml
[plugins]
fnox-env = "https://github.com/jdx/mise-env-fnox"

[env]
# Use default profile
_.fnox-env = { tools = true }
```

```toml
[plugins]
fnox-env = "https://github.com/jdx/mise-env-fnox"

[env]
# Use production profile
_.fnox-env = { tools = true, profile = "production" }
```

```toml
[plugins]
fnox-env = "https://github.com/jdx/mise-env-fnox"

[env]
# Custom fnox binary path (tools = true not needed when specifying fnox_bin)
_.fnox-env = { fnox_bin = "/usr/local/bin/fnox" }
```

## Environment-Specific Configuration

Combine with [mise's environment system](https://mise.jdx.dev/configuration/environments.html) for different profiles per environment. Mise uses separate config files for each environment:

**`mise.toml`** (default/dev):

```toml
[plugins]
fnox-env = "https://github.com/jdx/mise-env-fnox"

[tools]
fnox = "latest"

[env]
_.fnox-env = { tools = true, profile = "dev" }
```

**`mise.production.toml`**:

```toml
[env]
_.fnox-env = { tools = true, profile = "production" }
```

**`mise.staging.toml`**:

```toml
[env]
_.fnox-env = { tools = true, profile = "staging" }
```

Then activate different environments:

```bash
# Development (default)
mise env

# Production
MISE_ENV=production mise env

# Staging
MISE_ENV=staging mise env
```

## Caching

The fnox plugin supports mise's environment caching (when `MISE_ENV_CACHE=1`). Secrets are:

- Cached encrypted on disk for fast subsequent loads
- Automatically refreshed when `fnox.toml` changes
- Scoped to your shell session for security

To enable caching:

```bash
export MISE_ENV_CACHE=1
```

## Comparison with Shell Integration

| Feature                   | Shell Integration | Experimental mise env plugin |
| ------------------------- | ----------------- | ---------------------------- |
| Automatic loading on `cd` | Yes               | Yes (via mise)               |
| Works without mise        | Yes               | No                           |
| Caching                   | No                | Yes (with env cache)         |
| Task integration          | No                | Yes                          |
| Tool version management   | No                | Yes                          |
| Full fnox feature support | Yes               | No                           |

Use shell integration or `fnox exec` for the maintained fnox behavior. Use the
mise env plugin only when its current feature set is enough for your project.

## Troubleshooting

### Secrets not loading

1. Ensure `fnox.toml` exists in your project:

   ```bash
   ls fnox.toml
   ```

2. Test fnox directly:

   ```bash
   fnox export --format json
   ```

3. Check mise is loading the plugin:
   ```bash
   mise env
   ```

### Cache not invalidating

If secrets aren't updating after changes to `fnox.toml`:

```bash
# Clear mise's env cache
mise cache clear

# Or use fresh flag
mise exec --fresh-env -- your-command
```

## Next Steps

- [Shell Integration](/guide/shell-integration) - Alternative direct shell integration
- [Profiles](/guide/profiles) - Managing multiple environments
- [Hierarchical Config](/guide/hierarchical-config) - Organizing secrets across directories
