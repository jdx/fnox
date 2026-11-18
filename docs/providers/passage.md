---
description: "Read and write passage entries with fnox. passage is pass with age encryption, so each secret can need an identity passphrase or hardware key on every use."
---

# passage

The `passage` provider reads and writes entries through [passage](https://github.com/FiloSottile/passage), a fork of [pass](/providers/password-store) that encrypts each entry with [age](https://age-encryption.org) instead of GPG. `fnox.toml` holds entry paths; values stay in your store.

Use it when you want a pass-style store without GPG. With a passphrase-protected or hardware-backed age identity, each read can require a passphrase or key tap, unlike a GPG key cached in `gpg-agent`.

|                     |                                                                  |
| ------------------- | ---------------------------------------------------------------- |
| Config type         | `passage`                                                        |
| Storage             | Local store                                                      |
| Writes (`fnox set`) | Yes                                                              |
| Requires            | `passage` on `PATH`, an initialized store, and your age identity |

## Quick start

Install `passage` and `age`, then create an identity and a store if you have not already:

```sh
mkdir -p ~/.passage/store
age-keygen -o ~/.passage/identities
age-keygen -y ~/.passage/identities > ~/.passage/store/.age-recipients
```

Add the provider:

```toml
[providers.passage]
type = "passage"
prefix = "fnox/"
```

```sh
fnox set DATABASE_URL --provider passage
fnox provider test passage
fnox exec -- npm start
```

With `prefix = "fnox/"`, `fnox set DATABASE_URL` writes the entry `fnox/DATABASE_URL` and records `DATABASE_URL` in `fnox.toml`.

## Authentication

fnox runs `passage`, which decrypts with the identity in `PASSAGE_IDENTITIES_FILE` (default `~/.passage/identities`). If the identity is passphrase-protected or backed by a plugin such as a YubiKey, `passage` prompts on each read. fnox reads passage entries one at a time so those prompts do not overlap, and shows the plugin's messages (such as a touch request) as they appear. Anyone whose public key is in the store's `.age-recipients` can add entries; only holders of a matching identity can decrypt.

## Configuration

| Field             | Required | Default                                  | Description                                                                |
| ----------------- | -------- | ---------------------------------------- | -------------------------------------------------------------------------- |
| `prefix`          | No       | None                                     | String prepended to every entry path. Include a trailing `/` for a folder. |
| `store_dir`       | No       | `passage`'s default (`~/.passage/store`) | Store directory, passed to `passage` as `PASSAGE_DIR`.                     |
| `identities_file` | No       | `passage`'s default                      | Age identities file, passed to `passage` as `PASSAGE_IDENTITIES_FILE`.     |

Relative `store_dir` and `identities_file` paths are resolved from the config file that declares the provider. Paths beginning with `~` expand to your home directory, and absolute paths are used unchanged. All fields accept `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

### Environment variables

When `store_dir` or `identities_file` is unset, fnox reads these, in priority order:

| Setting    | Variables                                                      |
| ---------- | -------------------------------------------------------------- |
| Store      | `FNOX_PASSAGE_DIR`, then `PASSAGE_DIR`                         |
| Identities | `FNOX_PASSAGE_IDENTITIES_FILE`, then `PASSAGE_IDENTITIES_FILE` |

The provider fields take priority over both. Other `passage` settings, such as `PASSAGE_AGE` and `PASSAGE_RECIPIENTS`, are inherited from your environment.

## Reference formats

| `value`               | Entry read (with `prefix = "fnox/"`) |
| --------------------- | ------------------------------------ |
| `api-key`             | `fnox/api-key`                       |
| `database/production` | `fnox/database/production`           |

fnox reads an entry with `passage show` and returns the stored value exactly as written, including any extra lines and any leading or trailing whitespace. An entry saved with a trailing newline (for example by `passage edit`) keeps it.

### Select a line

Put the secret on line 1 and other fields on later lines, then select one with the secret's `line` option, which is 1-indexed:

```toml
[secrets]
DB_PASSWORD = { provider = "passage", value = "database", line = 1 }
DB_USERNAME = { provider = "passage", value = "database", line = 2 }
```

`line` cannot be combined with `json_path`.

## Write entries

`fnox set` writes the entry with `passage insert -m -f`, replacing the whole entry. Use `--key-name` for a path other than the secret's name, and `--from-file` for multi-line values:

```sh
fnox set DB_PASSWORD --provider passage --key-name database/production
fnox set SSH_PRIVATE_KEY --provider passage --from-file ~/.ssh/id_ed25519
```

::: warning Editing multi-line entries
`fnox set` cannot edit a single line in place. To change one field of a multi-line entry without losing the others, use `passage edit <entry>`.
:::

## Use passage and password-store together

Both providers can live in one config, for example `passage` for long-lived keys that should always prompt and `pass` for short-lived credentials cached in `gpg-agent`:

```toml
[providers.passage]
type = "passage"
prefix = "fnox/"

[providers.pass]
type = "password-store"
prefix = "fnox/"

[secrets]
AWS_SECRET_ACCESS_KEY = { provider = "passage", value = "aws/secret-access-key" }
AWS_SESSION_TOKEN = { provider = "pass", value = "aws/session-token" }
```

The two stores are separate directories (`~/.passage/store` and `~/.password-store`), so entries do not collide.

## Troubleshooting

### Entry is not in the password store

Check the full path, including `prefix`, with `passage ls fnox/`.

### `no identity matched any of the recipients`

Your identity file is not one of the store's recipients. Check that `PASSAGE_IDENTITIES_FILE` (or `identities_file`) points at the right file, and that its public key is listed in `.age-recipients`.

### `passage` not found

Install passage so `passage` is on `PATH`. See the [passage project page](https://github.com/FiloSottile/passage) for install steps.

## See also

- [password-store](/providers/password-store): the GPG-based original.
- [gopass](/providers/gopass): a pass-compatible manager with mounts and age support.
- [age](/providers/age): encrypted secrets in `fnox.toml` without a store directory.
