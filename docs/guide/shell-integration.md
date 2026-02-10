# Shell Integration

fnox can automatically load secrets when you `cd` into directories with a `fnox.toml` file.

## Enable Shell Integration

Add this to your shell profile:

::: code-group

```bash [Bash]
# Add to ~/.bashrc or ~/.bash_profile
eval "$(fnox activate bash)"
```

```zsh [Zsh]
# Add to ~/.zshrc
eval "$(fnox activate zsh)"
```

```fish [Fish]
# Add to ~/.config/fish/config.fish
fnox activate fish | source
```

:::

## How It Works

Once enabled, fnox hooks into your shell's `cd` command. When you enter a directory with `fnox.toml`:

```bash
~/projects $ cd my-app
fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET
~/projects/my-app $
```

When you leave:

```bash
~/projects/my-app $ cd ..
fnox: -3 DATABASE_URL, API_KEY, JWT_SECRET
~/projects $
```

## Output Control

Control what gets printed with `FNOX_SHELL_OUTPUT`:

```bash
# Silent mode (no output)
export FNOX_SHELL_OUTPUT=none

# Normal mode (show count and keys) - default
export FNOX_SHELL_OUTPUT=normal

# Debug mode (verbose logging)
export FNOX_SHELL_OUTPUT=debug
```

## Using Profiles

Switch environments with `FNOX_PROFILE`:

```bash
# Use production secrets
export FNOX_PROFILE=production
cd my-app
# fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET (from production profile)

# Switch to staging
export FNOX_PROFILE=staging
# fnox detects the change on the next prompt automatically
# fnox: -3 +3 DATABASE_URL, API_KEY, JWT_SECRET (from staging profile)
```

## Hierarchical Loading

fnox searches parent directories for `fnox.toml` files and merges them:

```
project/
├── fnox.toml              # Common secrets (age provider, shared keys)
└── services/
    ├── api/
    │   └── fnox.toml      # API-specific secrets
    └── worker/
        └── fnox.toml      # Worker-specific secrets
```

When you `cd services/api/`, fnox loads:

1. Secrets from `project/fnox.toml`
2. Secrets from `project/services/api/fnox.toml` (overrides parent)

## Manual Reload

fnox's shell hook runs on every prompt and automatically detects changes to config files and environment variables like `FNOX_PROFILE`. In most cases, no manual reload is needed.

To force a full reload, temporarily disable and re-enable:

```bash
# Disable
fnox deactivate

# Re-enable
eval "$(fnox activate bash)"
```

## Next Steps

- [Profiles](/guide/profiles) - Manage multiple environments
- [Hierarchical Config](/guide/hierarchical-config) - Organize secrets across directories
- [Real-World Example](/guide/real-world-example) - See a complete setup
