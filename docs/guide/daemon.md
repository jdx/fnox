---
description: "Enable the optional fnox daemon to cache resolved secrets in memory, inspect its status, and clear stale values."
---

# Cache secrets in memory

The fnox daemon keeps resolved secrets in memory for your user session. It is useful when your config points at remote providers such as 1Password, Bitwarden, AWS Secrets Manager, or Vault and repeated `fnox get`, `fnox exec`, or shell hook refreshes feel slow.

The daemon is opt-in. fnox does not use it unless you enable it in config or set `FNOX_DAEMON=on`.

## Enable it

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

On a cache miss, an interactive fnox client resolves the requested secrets in
the foreground and sends the results to the daemon for memory-only caching.
This keeps terminal-dependent authentication, such as a FIDO2 PIN and hardware
key touch, attached to the terminal that invoked fnox. Explicitly
non-interactive clients resolve misses in the daemon and never prompt.

Use `--no-daemon` for a single direct resolution:

```bash
fnox --no-daemon get DATABASE_URL
```

Or disable it for a shell/session:

```bash
export FNOX_DAEMON=off
```

## What uses it

Daemon-backed resolution applies to read-oriented commands:

- `fnox exec`
- `fnox env --json`
- `fnox get`
- `fnox hook-env`
- `fnox export`
- `fnox list --values`
- `fnox check --all`
- `fnox tui`
- `fnox mcp`
- `fnox proxy run`
- `fnox ci-redact`

Mutation and admin commands still resolve directly, including `sync`, `reencrypt`, `edit`, `set`, `remove`, `provider`, and `lease create`.

## Other programs (mise)

Programs that start processes themselves can read the daemon's cache directly, without running `fnox`. The [`fnox-client`](https://crates.io/crates/fnox-client) crate is a small Rust client for this: one round trip over the daemon's Unix socket answers with the same JSON document as [`fnox env --json`](/reference/env-json), and mise uses it to start tasks with the secrets they were granted.

- **Ask describe first.** `fnox env --json --describe` reports `daemon_enabled`, whether fnox would use the daemon for this project. Send a request to the daemon only when it is `true`, so a project that disables the daemon never has its environment sent to it.
- **It only reads.** Such a client never starts the daemon, never stores values in it, and never makes it call a provider. If no daemon is running, it says so.
- **A miss is resolved by fnox.** When a requested secret is not cached (or needs a lease), the program runs `fnox env --json` itself. That command resolves on your terminal, so prompts and hardware-key touches work, and it fills the cache for next time.
- **`disabled` is decided per project.** One daemon can run while some projects do not enable it. For those, and for any request made with `FNOX_DAEMON=off`, the daemon answers `disabled` and the program resolves directly, as `fnox` does.
- **The environment matters.** The daemon's cache is keyed on `FNOX_*` variables and provider credentials such as `AWS_*`, so a program must send exactly the environment it gives `fnox env --json`. Otherwise every request misses.

The wire protocol is version 6, which adds a `hello` handshake and the `resolve_env` request these clients use. Version 6 also changes the socket path. After upgrading fnox, a daemon from the previous version keeps running until its idle timeout, and `fnox daemon clear` still reaches it. The first daemon-enabled command after the upgrade starts a new daemon, so its cache starts empty.

## Cache behavior

The daemon cache is memory-only. Secret values are not written to disk by the daemon.

Remote changes do not automatically invalidate cached values. After rotating a secret in its source provider, refresh just that secret so the rest of the cache stays warm:

```bash
fnox daemon clear API_TOKEN                # evict one key from every running daemon
fnox get --refresh API_TOKEN               # re-resolve it now and cache the new value
fnox exec --refresh API_TOKEN -- ./deploy  # same, while other secrets come from the cache
```

`--refresh` can be repeated on `fnox exec` to refresh several keys. Cached values are also discarded when:

- You run `fnox daemon clear` without keys, which clears all running profile-scoped daemon caches
- You run `fnox daemon stop`
- The daemon exits after its idle timeout
- Config files, profile settings, provider references, post-processing options, or relevant `FNOX_*` and provider environment variables change

`fnox check --all` uses the daemon connection when daemon mode is enabled, but it does not reuse cached secret values. It still contacts providers so it can validate the current state.

`fnox env --json` resolves an `env = false` secret only when a requested secret depends on it or when a selected `command` lease may read it, and never prints it. `fnox exec` currently resolves every secret in the profile, including `env = false` ones, and removes the `env = false` ones from the child's environment. Read one explicitly with `fnox get SECRET_NAME`.

## Opt out per secret or provider

Set `daemon_cache = false` on a secret that should be resolved again on each request:

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

This disables cache reuse for those values. If daemon mode is enabled, fnox still talks to the daemon for supported read commands, but those entries are resolved again for every request.

## Security model

The daemon is Unix-first and uses a Unix domain socket. It does not listen on TCP.

The socket is created in a user-owned runtime directory with strict permissions. The daemon verifies that each client is owned by the same user before accepting requests, and clients verify the daemon peer before sending request data.

On unsupported platforms, daemon mode returns a clear unsupported error. Use `--no-daemon` or `FNOX_DAEMON=off` to force direct resolution.

## Daemon vs sync

Use the daemon when you want faster repeated reads during a session and are comfortable keeping resolved values in memory.

Use [syncing secrets locally](/guide/sync) when you want an encrypted local cache that survives restarts and can work offline.

## Next steps

- [Shell Integration](/guide/shell-integration) - Auto-load secrets on `cd`
- [Syncing Secrets Locally](/guide/sync) - Store an encrypted local cache
- [CLI Reference](/cli/daemon) - Daemon command details
