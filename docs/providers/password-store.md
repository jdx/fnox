---
description: "Read and write password-store (pass) entries with fnox. Configure a prefix, store directory, GPG options, and multi-line entries."
---

# password-store

The `password-store` provider reads and writes entries through [pass](https://www.passwordstore.org/), the standard Unix password manager that keeps each secret in a GPG-encrypted file. `fnox.toml` holds entry paths; values stay in your store.

|                     |                                                          |
| ------------------- | -------------------------------------------------------- |
| Config type         | `password-store`                                         |
| Storage             | Local store                                              |
| Writes (`fnox set`) | Yes                                                      |
| Requires            | `pass` on `PATH`, an initialized store, and your GPG key |

## Quick start

Install `pass` and GnuPG, and initialize a store with your GPG key if you have not already:

```sh
pass init <gpg-key-id>
```

Add the provider:

```toml
[providers.pass]
type = "password-store"
prefix = "fnox/"
```

```sh
fnox set DATABASE_URL --provider pass
fnox provider test pass
fnox exec -- npm start
```

With `prefix = "fnox/"`, `fnox set DATABASE_URL` writes the entry `fnox/DATABASE_URL` and records `DATABASE_URL` in `fnox.toml`.

## Authentication

fnox runs `pass`, which runs GPG. Decryption uses your GPG key through `gpg-agent`, which may ask for the key's passphrase. Run `pass show <entry>` once to unlock the agent if fnox reports a GPG error. Anyone whose key is in the store's `.gpg-id` can decrypt.

## Configuration

| Field       | Required | Default                                | Description                                                                |
| ----------- | -------- | -------------------------------------- | -------------------------------------------------------------------------- |
| `prefix`    | No       | None                                   | String prepended to every entry path. Include a trailing `/` for a folder. |
| `store_dir` | No       | `pass`'s default (`~/.password-store`) | Store directory, passed to `pass` as `PASSWORD_STORE_DIR`.                 |
| `gpg_opts`  | No       | None                                   | Extra GPG options, passed to `pass` as `PASSWORD_STORE_GPG_OPTS`.          |

Relative `store_dir` paths are resolved from the config file that declares the provider. Paths beginning with `~` expand to your home directory, and absolute paths are used unchanged. All fields accept `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

### Environment variables

When `store_dir` or `gpg_opts` is unset, fnox reads these, in priority order:

| Setting     | Variables                                                      |
| ----------- | -------------------------------------------------------------- |
| Store       | `FNOX_PASSWORD_STORE_DIR`, then `PASSWORD_STORE_DIR`           |
| GPG options | `FNOX_PASSWORD_STORE_GPG_OPTS`, then `PASSWORD_STORE_GPG_OPTS` |

The provider fields take priority over both.

## Reference formats

| `value`               | Entry read (with `prefix = "fnox/"`) |
| --------------------- | ------------------------------------ |
| `api-key`             | `fnox/api-key`                       |
| `database/production` | `fnox/database/production`           |

fnox reads an entry with `pass show` and trims leading and trailing whitespace. It returns the whole entry, including any extra lines.

### Select a line

A common `pass` convention puts the password on line 1 and other fields on later lines. Select one with the secret's `line` option, which is 1-indexed:

```toml
[secrets]
DB_PASSWORD = { provider = "pass", value = "database", line = 1 }
DB_USERNAME = { provider = "pass", value = "database", line = 2 }
```

`line` cannot be combined with `json_path`.

## Write entries

`fnox set` writes the entry with `pass insert -m -f`, replacing the whole entry. Use `--key-name` for a path other than the secret's name, and `--from-file` for multi-line values:

```sh
fnox set DB_PASSWORD --provider pass --key-name database/production
fnox set SSH_PRIVATE_KEY --provider pass --from-file ~/.ssh/id_ed25519
```

::: warning Editing multi-line entries
`fnox set` cannot edit a single line in place. To change one field of a multi-line entry without losing the others, use `pass edit <entry>`. This applies whether or not the secret uses `line`.
:::

If the store is a git repository, `pass` commits each change; push with `pass git push`. To share a store, list every teammate's key with `pass init <key-id-1> <key-id-2>`.

## Troubleshooting

### Entry is not in the password store

Check the full path, including `prefix`, with `pass ls fnox/`.

### `decryption failed: No secret key`

Your GPG private key for one of the store's recipients is not available. Check with `gpg --list-secret-keys`.

### `Inappropriate ioctl for device`

GPG cannot find a terminal for the passphrase prompt. Set `export GPG_TTY=$(tty)` in your shell profile, or unlock the agent first with `pass show <entry>`.

### `pass` not found

Install password-store so `pass` is on `PATH` (`brew install pass`, `sudo apt install pass`).

## See also

- [gopass](/providers/gopass): a pass-compatible manager with mounts and age support.
- [age](/providers/age): encrypted secrets in `fnox.toml` without GPG.
- [KeePass](/providers/keepass): a single-file local database.
