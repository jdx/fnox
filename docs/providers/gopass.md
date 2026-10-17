---
description: "Read and write gopass secrets with fnox. Use an optional mount and resolve entries through your existing gopass stores and recipients."
---

# gopass

The `gopass` provider reads and writes secrets through [gopass](https://www.gopass.pw/), a password manager that encrypts entries with GPG or age and syncs them with git. `fnox.toml` holds entry paths; values stay in your stores. fnox runs the `gopass` CLI, so your existing stores, mounts, and recipients keep working.

|                     |                                             |
| ------------------- | ------------------------------------------- |
| Config type         | `gopass`                                    |
| Storage             | Local store                                 |
| Writes (`fnox set`) | Yes                                         |
| Requires            | `gopass` on `PATH` and an initialized store |

## Quick start

Install gopass and run `gopass setup` if you have not already. Add the provider:

```toml
[providers.gopass]
type = "gopass"
mount = "company" # optional

[secrets]
GITHUB_TOKEN = { provider = "gopass", value = "shared/github/token" }
```

```sh
fnox provider test gopass
fnox exec -- ./release.sh
```

To create an entry from fnox, run `fnox set DATABASE_URL --provider gopass`.

## Authentication

gopass decrypts with your GPG key or age identity. If fnox reports a locked key, unlock it with any gopass command, such as `gopass show <entry>`, and retry. If `fnox.toml` defines a secret named `GNUPGHOME`, `GOPASS_HOMEDIR`, or `GOPASS_CONFIG_NOWRAP`, fnox resolves it first and sets it in the environment that gopass runs in.

## Configuration

| Field   | Required | Default | Description                                                                                       |
| ------- | -------- | ------- | ------------------------------------------------------------------------------------------------- |
| `mount` | No       | None    | Mount (store) name prepended to every entry path as `<mount>/<value>`. Unset uses the root store. |

`mount` accepts `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

## Reference formats

| `value`                   | Command fnox runs (with `mount = "company"`) |
| ------------------------- | -------------------------------------------- |
| `apps/myapp/database_url` | `gopass cat company/apps/myapp/database_url` |
| `shared/github/token`     | `gopass cat company/shared/github/token`     |

Without `mount`, fnox uses `value` as the gopass path unchanged. fnox returns the entry's full contents, minus one trailing newline. Use the secret's `line` option to pick one line of a multi-line entry.

`fnox set` writes with `gopass insert -f`, replacing the entry at `<mount>/<key>`. Use `--key-name` to choose a path other than the secret's name.

## Troubleshooting

### Entry is not in the password store

Check the full path, including `mount`, with `gopass ls --flat`.

### GPG or age key locked or unavailable

Run `gopass show <entry>` to unlock the key, then retry. Check that your key is one of the store's recipients.

### `gopass` not found

Install gopass so it is on `PATH`, then run `fnox provider test gopass`, which lists the store with `gopass ls --flat`.

## See also

- [password-store](/providers/password-store): the original `pass` CLI.
- [age](/providers/age): encrypted secrets in `fnox.toml` without a separate store.
- [Teams](/guide/teams): share access to secrets across a team.
