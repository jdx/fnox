# fnox-client

A read-only client for the [fnox](https://fnox.jdx.dev) daemon, and the types
of `fnox env --json`. Programs that start processes themselves (mise first) use
it to ask a running daemon for the environment a command would get, in one
Unix-socket round trip and with no fnox process.

It depends only on `serde`, `serde_json`, `indexmap`, `blake3` and `libc`. It
does not depend on `fnox-core`, `tokio` or any provider SDK.

## Guarantees

- **It never starts the daemon.** No daemon running means `EnvOutcome::Absent`.
- **It never stores values.** It sends no `StoreResolved`.
- **It never causes a provider call.** The daemon answers from its cache only.
  A miss is reported as a miss.
- **The peer is checked before anything is written.** The client refuses a
  socket owned by another user, and the daemon does the same in the other
  direction.
- **Only the environment you pass is sent.** The client reads nothing from its
  own process environment.
- **`Debug` never prints a secret value.** Values are `SecretValue`s, which
  print as `SecretValue(<redacted>)`, and the wire types print environments as
  `<N vars>`.

The crate compiles everywhere. On a platform without a daemon (anything but
Linux, macOS, FreeBSD and OpenBSD), `Client` answers `Absent`, so callers need
no `cfg`.

## Example

```rust
use fnox_client::document::EnvScope;
use fnox_client::{CliFlags, Client, EnvOutcome, EnvRequest, RuntimeEnv, SocketKey};
use std::path::Path;

let env: Vec<(String, String)> = std::env::vars().collect();
let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());

let flags = CliFlags::default();
let client = Client::new(
    SocketKey::from_cli_env(&flags, &get),
    &RuntimeEnv::from_env(&get),
);

let keys = vec!["DATABASE_URL".to_string()];
match client.resolve_env(&EnvRequest {
    cwd: Path::new("/path/to/project"), // where the CLI fallback would run
    config: Path::new("fnox.toml"),     // discovery, as the CLI default
    scope: EnvScope::Exec,
    keys: Some(&keys),                  // None = every key in scope
    env: &env,                          // exactly what the fallback gets
}) {
    EnvOutcome::Hit(doc) => { /* apply doc.remove, then doc.set, then doc.files */ }
    EnvOutcome::Rejected(why) => { /* the CLI would fail the same way */ }
    _ => { /* run `fnox env --json` instead */ }
}
```

`Client` uses blocking std I/O with a 5 second read and write timeout (change it
with `with_timeout`). Async callers use `spawn_blocking`.

## The intended caller algorithm

```text
flags = CliFlags { profile, ..Default::default() }
if interactive && platform_supported():
    client = Client::new(SocketKey::from_cli_env(&flags, &get(env)), &RuntimeEnv::from_env(&get(env)))
    match client.resolve_env(&EnvRequest{cwd: root, config: "fnox.toml", scope: Exec, keys, env}):
        Hit(doc) => use doc; Rejected(r) => error; otherwise fall through
argv = ["fnox", *flags.to_args(), *(interactive ? [] : ["--non-interactive","--no-daemon"]),
        "env", "--json", "--for", "exec", "--keys", keys.join(",")]
spawn: cwd=root, env=env, stdin=inherit (null if !interactive), stdout=piped, stderr=inherit
apply: remove -> set -> files (0600 temp files, deleted after the child exits)
```

### Outcomes

| Outcome           | Meaning                                                                                       | What to do                                                          |
| ----------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `Hit(doc)`        | Every requested key was cached.                                                               | Use `doc`.                                                          |
| `Miss { keys }`   | Some keys are not cached, or a lease is needed.                                               | Run `fnox env --json`.                                              |
| `Rejected(r)`     | A key is unknown, or is not injectable in this scope.                                         | Report it.                                                          |
| `Disabled`        | This project's fnox config, or `FNOX_DAEMON` in the env you sent, does not enable the daemon. | Run `fnox env --json`.                                              |
| `Absent`          | No daemon is running for this key, or the platform has none.                                  | Run `fnox env --json`, which starts one when the config enables it. |
| `VersionMismatch` | The daemon speaks another protocol.                                                           | Run `fnox env --json`.                                              |
| `Unavailable(e)`  | A timeout, a bad reply or another failure.                                                    | Run `fnox env --json`.                                              |

A key whose secret resolved to nothing is never cached, so a request that
includes an optional key that is currently missing always misses.

An empty `keys: Some(&[])` asks for no keys at all, while `fnox env --json
--keys ""` is an error. Skip the call when you have nothing to ask for.

## The env invariant

Send **exactly the environment you give the CLI fallback**. The daemon keys its
cache on `FNOX_*` variables and on the credentials providers read from the
environment (`AWS_*`, `VAULT_TOKEN`, and so on). A different environment makes
every request miss, and does so silently.

The same environment decides which daemon you talk to: `SocketKey::from_cli_env`
and `RuntimeEnv::from_env` read `FNOX_PROFILE`, `FNOX_NO_DEFAULTS`,
`FNOX_IF_MISSING`, `FNOX_AGE_KEY_FILE`, `XDG_RUNTIME_DIR` and `TMPDIR` from it.

The daemon reads fnox's global config file (`~/.config/fnox/config.toml`) on
every request, but locates it once, from its own environment. A request whose
`HOME`, `XDG_CONFIG_HOME` or `FNOX_CONFIG_DIR` differ from the daemon's gets the
daemon's global config, not yours. `fnox` behaves the same way.

## Following fnox's daemon setting

| Situation                                    | `fnox-client`           | `fnox env`        |
| -------------------------------------------- | ----------------------- | ----------------- |
| Config enables the daemon, and it is running | `Hit` or `Miss`         | uses it           |
| Enabled, not running                         | `Absent`                | starts it         |
| Running, but this project is not enabled     | `Disabled`              | resolves directly |
| `FNOX_DAEMON=off` in the env you send        | `Disabled`, without I/O | direct            |
| `FNOX_DAEMON=on`, config silent              | the daemon serves       | uses or starts it |

## Compatibility

- **Documents.** The JSON documents carry `schema: 1`. Consumers must ignore
  unknown fields: new optional fields may appear within schema 1. A breaking
  change increments `schema`. The document structs are `#[non_exhaustive]`;
  build them with their constructors.
- **Protocol.** The wire protocol version is part of the socket name, so a
  client never connects to a daemon with another version. After an fnox upgrade
  that bumps it, the old daemon keeps running until its idle timeout and the
  first daemon-enabled fnox command starts a new one.
- **Versioning.** `fnox-client` is released in lockstep with fnox: it always has
  the same version. A major fnox release therefore bumps this crate's major
  version too, even when the protocol is unchanged. Depend on it with a
  requirement such as `fnox-client = "1"`.
- **Semver surface.** `Client`, `EnvRequest`, `EnvOutcome`, `HelloInfo`,
  `CallError`, `CliFlags`, `SocketKey`, `RuntimeEnv`, `document::*`,
  `profile::*`, `platform_supported` and `daemon_env_override`. The `wire`,
  `path` and `peer` modules are shared with the fnox daemon and are not.
- **MSRV.** Rust 1.91.1, the same as fnox.
