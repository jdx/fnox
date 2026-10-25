---
description: "Turn on the optional fnox daemon to keep resolved secrets in memory for your session, so repeated reads from remote providers are instant."
---

# Memory cache (daemon)

The fnox daemon is an optional per-user background process that keeps resolved secrets in memory. The first `fnox exec` in a session reads from your providers; later ones are served from memory. It helps most when your config points at remote vaults and you run many short commands, or use [shell integration](/guide/shell-integration), which resolves at every directory change.

## Turn it on

```toml
# fnox.toml, or ~/.config/fnox/config.toml for every project
[daemon]
enabled = true
idle_timeout = "8h" # default
```

Or for your session: `export FNOX_DAEMON=on`. Read commands start the daemon automatically when they need it. To skip it for one command, use `--no-daemon`; to turn it off for a session, `export FNOX_DAEMON=off`.

```sh
fnox daemon status
fnox daemon stop
```

## Refresh a changed secret

The daemon doesn't know when a value changes in your vault. After rotating a secret, refresh just that one:

```sh
fnox get --refresh API_TOKEN               # re-read now and cache the new value
fnox exec --refresh API_TOKEN -- ./deploy  # same, while the rest come from the cache
fnox daemon clear API_TOKEN                # just evict it
fnox daemon clear                          # evict everything
```

The cache is also dropped automatically when:

- the daemon stops, or exits after `idle_timeout` with no requests;
- a config file, the selected profile, a provider setting, or a relevant `FNOX_*` or provider credential variable (such as `AWS_*`) changes.

## Where the socket lives

The daemon's socket goes in `$XDG_RUNTIME_DIR/fnox` when that is set. Otherwise it goes in `/tmp/fnox-<uid>/fnox`, or on macOS in the per-user directory from `confstr(_CS_DARWIN_USER_TEMP_DIR)`. `TMPDIR` is ignored, so tools that set their own `TMPDIR` (nix-shell, CI runners, sandboxed agents) share one daemon instead of each starting their own.

To pin the directory, set `FNOX_DAEMON_SOCKET_DIR`:

```bash
export FNOX_DAEMON_SOCKET_DIR="$HOME/.cache/fnox-daemon"
```

Use a dedicated directory: fnox creates it if missing and sets its mode to `0700`, even if it already exists, which revokes access for other users. fnox refuses a directory owned by another user. It must be an absolute path; a relative value is ignored, because it would name a different socket from every working directory.

Unix socket paths are limited to about 100 characters. If the socket path under the chosen directory would be longer, fnox uses a short hashed directory, `/tmp/fnox-<uid>/<hash>/fnox`, instead.

## What uses it

Read commands: `exec`, `get`, `export`, `list --values`, `env --json`, shell integration, `tui`, `mcp`, and `proxy run`. `check --all` connects to the daemon but always re-reads from providers, so it reports the current state.

Commands that write or administer (`set`, `remove`, `sync`, `reencrypt`, `edit`, `provider`, `lease create`) always resolve directly.

## Prompts and hardware keys

On a cache miss, fnox resolves the secret in your terminal and hands the result to the daemon. That way 1Password or SSO prompts, FIDO2 PINs, and YubiKey touches happen where you can see them. With `--non-interactive`, misses are resolved inside the daemon and never prompt.

## Exclude a secret or provider

```toml
[secrets]
PAYMENT_API_KEY = { provider = "op", value = "Payments/api-key", daemon_cache = false }

[providers.op]
type = "1password"
vault = "Engineering"
daemon_cache = false # applies to every secret from this provider
```

Those values are re-read on every request.

When one value unlocks another, such as a provider `token = { secret = "..." }` decrypted with age, set `daemon_cache = false` on both providers to keep both out of the cache. [Keep production out of the daemon](/guide/sync#keep-production-out-of-the-daemon) shows a production profile set up this way.

## Security

- Values are held in memory only; the daemon never writes them to disk.
- It listens on a Unix domain socket (Linux, macOS, FreeBSD, OpenBSD) in a private runtime directory, or a named pipe on Windows that only your user can open. There is no network listener.
- Both sides check that the other belongs to the same user before exchanging data.

Anything running as your user can ask the daemon for cached values, just as it could run `fnox get`. If that's a concern for a secret, set `daemon_cache = false` on it.

## Other programs {#other-programs-mise}

Tools that start processes themselves, such as mise, can read the daemon's cache directly with the [`fnox-client`](https://crates.io/crates/fnox-client) Rust crate. A request returns the same document as [`fnox env --json`](/reference/env-json).

Rules for client authors:

- Run `fnox env --json --describe` first, and talk to the daemon only if it reports `daemon_enabled: true`.
- The client only reads: it never starts the daemon, stores values, or triggers provider calls. On a miss, run `fnox env --json` yourself; that resolves in the user's terminal and fills the cache.
- Send exactly the environment you would give `fnox env --json`. The cache is keyed on `FNOX_*` and provider credential variables, so a different environment always misses.
- A `disabled` answer means this project, or `FNOX_DAEMON=off` in the request, doesn't use the daemon. Resolve directly.

The wire protocol is version 6. After upgrading fnox, the old daemon keeps running until its idle timeout, and the first command after the upgrade starts a new one with an empty cache.

## Daemon or sync?

Use the daemon for speed within a session. Use [sync](/guide/sync) when you also want reads to work offline and survive restarts. They work together.

## See also

- [Local sync cache](/guide/sync): encrypted, persistent, offline.
- [`fnox daemon` reference](/cli/daemon): `start`, `status`, `clear`, `stop`.
- [Configuration reference](/reference/configuration#daemon): `[daemon]` and `daemon_cache`.
