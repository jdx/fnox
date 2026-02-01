# Mise Integration

fnox integrates with [mise](https://mise.jdx.dev) through the `jdx/mise-env-fnox` env plugin, allowing you to automatically load secrets into your development environment.

## Installation

Add the plugin to your project's `mise.toml`:

```toml
[plugins]
fnox-env = "https://github.com/jdx/mise-env-fnox"

[tools]
fnox = "latest"

[env]
_.fnox-env = { tools = true }
```

> [!IMPORTANT] > `tools = true` is required so the plugin can access the mise-managed fnox binary. Without it, the plugin runs before mise tools are added to PATH and won't be able to find fnox.

## How It Works

When mise activates your environment, the fnox plugin:

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

Combine with mise's environment system for different profiles per environment:

```toml
[plugins]
fnox-env = "https://github.com/jdx/mise-env-fnox"

[env]
_.fnox-env = { tools = true, profile = "dev" }

[env.production]
_.fnox-env = { tools = true, profile = "production" }

[env.staging]
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

| Feature                   | Shell Integration | Mise Integration     |
| ------------------------- | ----------------- | -------------------- |
| Automatic loading on `cd` | Yes               | Yes (via mise)       |
| Works without mise        | Yes               | No                   |
| Caching                   | No                | Yes (with env cache) |
| Task integration          | No                | Yes                  |
| Tool version management   | No                | Yes                  |

Use shell integration if you want fnox-only secret loading. Use mise integration if you're already using mise for tool/environment management.

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
