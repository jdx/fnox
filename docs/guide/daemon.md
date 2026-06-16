# Per-User Daemon

The fnox daemon keeps resolved secrets in memory for your user session. It is useful when your config points at remote providers such as 1Password, Bitwarden, AWS Secrets Manager, or Vault and repeated `fnox get`, `fnox exec`, or shell hook refreshes feel slow.

The daemon is opt-in. fnox does not use it unless you enable it in config or set `FNOX_DAEMON=on`.

## Enable It

Add a top-level `[daemon]` section:

```toml
[daemon]
enabled = true
idle_timeout = "8h"
```

When enabled, supported read commands auto-start the daemon. You can also manage it directly:

```bash
fnox daemon start
fnox daemon status
fnox daemon clear
fnox daemon stop
```

Use `--no-daemon` for a single direct resolution:

```bash
fnox --no-daemon get DATABASE_URL
```

Or disable it for a shell/session:

```bash
export FNOX_DAEMON=off
```

## What Uses It

Daemon-backed resolution applies to read-oriented commands:

- `fnox exec`
- `fnox get`
- `fnox hook-env`
- `fnox export`
- `fnox list --values`
- `fnox check`
- `fnox tui`
- `fnox mcp`
- `fnox ci-redact`

Mutation and admin commands still resolve directly, including `sync`, `reencrypt`, `edit`, `set`, `remove`, `provider`, and `lease create`.

## Cache Behavior

The daemon cache is memory-only. Secret values are not written to disk by the daemon.

Cached values are discarded when:

- You run `fnox daemon clear`
- You run `fnox daemon stop`
- The daemon exits after its idle timeout
- Config files, profile settings, provider references, post-processing options, or relevant `FNOX_*` and provider environment variables change

`fnox check` uses the daemon connection when daemon mode is enabled, but it does not reuse cached secret values. It still contacts providers so it can validate the current state.

Secrets with `env = false` are not resolved during normal batch environment injection. They can still be resolved explicitly, such as with `fnox get SECRET_NAME`.

## Opt Out Per Secret Or Provider

Set `daemon_cache = false` on a secret that should always resolve directly:

```toml
[secrets]
PAYMENT_API_KEY = { provider = "op", value = "Payments/api-key", daemon_cache = false }
```

Set it on a provider to bypass daemon caching for every secret that uses that provider:

```toml
[providers.op]
type = "1password"
vault = "Engineering"
daemon_cache = false
```

This disables cache reuse for those values. If daemon mode is enabled, fnox still talks to the daemon for supported read commands; the daemon resolves those entries directly instead of returning a cached value.

## Security Model

The daemon is Unix-first and uses a Unix domain socket. It does not listen on TCP.

The socket is created in a user-owned runtime directory with strict permissions. The daemon verifies that each client is owned by the same user before accepting requests, and clients verify the daemon peer before sending request data.

On unsupported platforms, daemon mode returns a clear unsupported error. Use `--no-daemon` or `FNOX_DAEMON=off` to force direct resolution.

## Daemon Vs Sync

Use the daemon when you want faster repeated reads during a session and are comfortable keeping resolved values in memory.

Use [syncing secrets locally](/guide/sync) when you want an encrypted local cache that survives restarts and can work offline.

## Next Steps

- [Shell Integration](/guide/shell-integration) - Auto-load secrets on `cd`
- [Syncing Secrets Locally](/guide/sync) - Store an encrypted local cache
- [CLI Reference](/cli/daemon) - Daemon command details
