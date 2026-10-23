---
description: "Turn on fnox's local audit log to record which secrets were read, by which command, and through which provider, without ever writing a value."
---

# Audit log

fnox can keep a local record of every secret it reads. Each read appends one JSON line naming the secret, the command, the profile, and the provider. Values, command lines, and environment contents are never written.

It answers "what read `DATABASE_URL` yesterday, and was it me?", which is useful when [AI agents](/guide/mcp), [the proxy](/guide/proxy), and [shell integration](/guide/shell-integration) all read secrets on your behalf.

## Turn it on

It's off by default.

```toml
# ~/.config/fnox/config.toml
[audit]
enabled = true
# path = "~/.local/state/fnox/audit.log" # default: audit.log in the state directory
```

Or for your session: `export FNOX_AUDIT=on`. `FNOX_AUDIT_PATH` overrides the file.

Put `[audit]` in your global config rather than a project's `fnox.toml`: a project file can set `path`, and you don't want a repository you cloned choosing where fnox appends.

## What is recorded

The audit covers `fnox exec`, `get`, `export`, `env --json`, `list --values`, `check`, shell integration (`hook-env`), `mcp`, `proxy run`, and the TUI, including reads served by the [daemon](/guide/daemon).

```json
{"ts":"2026-10-23T18:20:21.060Z","command":"get","profile":["default"],"config":"/home/me/app/fnox.toml","secret":"DATABASE_URL","provider":"age","cached":false}
```

| Field      | Meaning                                                                              |
| ---------- | ------------------------------------------------------------------------------------ |
| `ts`       | UTC time, RFC 3339.                                                                  |
| `command`  | The reading command: `exec`, `get`, `export`, `hook-env`, `mcp`, `proxy`, and so on. |
| `profile`  | Active profiles.                                                                     |
| `config`   | The config file that defines the secret.                                             |
| `secret`   | The secret's name.                                                                   |
| `provider` | The provider it is read through, or `null` for a default or environment value.       |
| `cached`   | `true` when the daemon answered from memory without calling the provider.            |

A failure to write the log is reported as a warning and never fails the read.

## Read it

```sh
fnox audit                                    # last 20 entries
fnox audit --secret DATABASE_URL -n 5         # recent reads of one secret
fnox audit --command mcp --json               # reads made through the MCP server
fnox audit --path                             # where the log lives
```

The log is JSON lines, so `jq` works too:

```sh
jq -r 'select(.secret == "DATABASE_URL") | .ts + " " + .command' "$(fnox audit --path)"
```

## Tamper model

The log is created with mode `0600` and opened append-only, and fnox never rewrites or truncates it. That keeps other users out and stops fnox itself from clobbering history.

It is **not tamper-proof**. It is a file owned by you, so anything running as you, including a compromised agent or a program fnox launched, can edit or delete it. A process that reads secrets without going through fnox, such as one that reads your age key directly, leaves no entry. Treat the log as a record of what fnox did, useful for review and for noticing surprises, not as evidence that would hold against an attacker with your account.

To get a record that survives that, ship it somewhere the account can't rewrite:

- Forward new lines to a remote log service as they appear (`tail -F "$(fnox audit --path)" | …`, or the agent your platform already runs).
- Point `path` at a location a separate, privileged collector reads and rotates.
- On Linux, mark the file append-only for the filesystem with `sudo chattr +a <path>`.

## See also

- [Configuration: `audit`](/reference/configuration#audit)
- [Memory cache (daemon)](/guide/daemon)
