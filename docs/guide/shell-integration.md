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
cd .  # Reload secrets
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

Force a reload without changing directories:

```bash
cd .
```

Or temporarily disable and re-enable:

```bash
# Disable
fnox deactivate

# Re-enable
eval "$(fnox activate bash)"
```

## Tips

- **One-time use:** Use `fnox exec` instead of shell integration for scripts
- **CI/CD:** Don't use shell integration in CI—use `fnox exec` explicitly
- **Multiple projects:** Shell integration works across all your projects automatically
- **Performance:** fnox caches config parsing but always fetches fresh secrets (no secret caching)

## Troubleshooting

### Secrets not loading

1. Check that `fnox.toml` exists in current or parent directories
2. Verify your provider credentials are set (e.g., `FNOX_AGE_KEY`)
3. Enable debug output: `export FNOX_SHELL_OUTPUT=debug`

### Conflicts with other tools

If you use other tools that modify `cd` (like direnv, mise, etc.), they may conflict. Order matters:

```bash
# Load fnox AFTER other tools
eval "$(mise activate bash)"
eval "$(direnv hook bash)"
eval "$(fnox activate bash)"  # fnox last
```

### Slow directory changes

If `cd` is slow, it's likely due to:

- Remote provider calls (AWS/1Password/etc. network latency)
- Many secrets to resolve

Solutions:

- Use encrypted secrets (age) for development (no network calls)
- Use profiles to reduce secret count
- Use `fnox exec` instead of shell integration for large setups

## Next Steps

- [Profiles](/guide/profiles) - Manage multiple environments
- [Hierarchical Config](/guide/hierarchical-config) - Organize secrets across directories
- [Real-World Example](/guide/real-world-example) - See a complete setup
