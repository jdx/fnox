---
description: "Read and write entries in a local KeePass (.kdbx) database with fnox. Configure the database, key file, password, and entry paths."
---

# KeePass

The `keepass` provider reads and writes entries in a local KeePass database file (`.kdbx`). `fnox.toml` holds entry paths; values stay in the database. fnox opens the file directly, so no KeePass application is needed.

|                     |                                     |
| ------------------- | ----------------------------------- |
| Config type         | `keepass`                           |
| Storage             | Local store                         |
| Writes (`fnox set`) | Yes                                 |
| Requires            | A `.kdbx` database and its password |

## Quick start

```toml
[providers.keepass]
type = "keepass"
database = "~/secrets.kdbx"
```

```sh
fnox set DATABASE_URL --provider keepass
fnox provider test keepass
fnox exec -- npm start
```

fnox prompts for the database password. If the database file does not exist, `fnox set` creates a new KDBX4 database protected by the password you enter, along with any groups in the entry path.

## Authentication

fnox uses the first password it finds:

1. `FNOX_KEEPASS_PASSWORD`, then `KEEPASS_PASSWORD`.
2. The provider's `password` field.
3. A hidden terminal prompt.

The prompt reads from the terminal even when standard input is piped, so `fnox exec -- mycmd` can prompt before starting `mycmd`. One prompt covers every entry fnox reads from the same database and key file during a command. Shell integration does not prompt; set an environment variable for secrets loaded by `fnox hook-env`.

In [non-interactive mode](/reference/environment#fnox-non-interactive), a missing password is an authentication error. For unattended runs, supply the password through your CI secret store as `FNOX_KEEPASS_PASSWORD`.

::: warning
The provider also accepts a `password` field, but avoid storing the password directly in the provider config. Use an environment variable, or a `{ secret = "NAME" }` reference to another provider.
:::

## Configuration

| Field      | Required | Default | Description                                                  |
| ---------- | -------- | ------- | ------------------------------------------------------------ |
| `database` | Yes      | None    | Path to the `.kdbx` file. Created on first write if missing. |
| `keyfile`  | No       | None    | Path to a key file used together with the password.          |
| `password` | No       | None    | Database password. Environment variables take precedence.    |

Relative `database` and `keyfile` paths are resolved from the config file that declares the provider, and `~` expands to your home directory. All fields accept `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

## Reference formats

A reference is a `/`-separated path. If the last segment is a field name, fnox reads that field; otherwise it reads the password.

| `value`                      | What fnox reads                                          |
| ---------------------------- | -------------------------------------------------------- |
| `github`                     | Password of the first entry titled `github` in any group |
| `github/username`            | Username field of that entry                             |
| `work/github`                | Password of the entry `github` under group `work`        |
| `work/project/api-key/notes` | Notes field of entry `api-key` under `work/project`      |

The field names are `password`, `username`, `url`, `notes`, and `title`, matched case-insensitively. To read a custom (string) field, add its exact name as the last segment, for example `work/github/ApiToken`. fnox first looks for an entry titled with the full path and falls back to treating the last segment as a custom field, so an entry title takes precedence. Protected custom fields work too. Group names and entry titles match exactly.

`fnox set` writes to the same path, creating groups and the entry as needed. It stores the password field protected inside the database. The `title` field cannot be written, because it identifies the entry:

```sh
fnox set API_USER --provider keepass --key-name production/api-service/username
```

## Shared databases

fnox saves through a temporary file that it syncs to disk before replacing the database. That prevents a torn write, but it does not merge changes: if several machines write the same file through a sync service, the last save wins. Back up the database and any key file.

For team secrets, consider [1Password](/providers/1password), [Bitwarden](/providers/bitwarden), or [age](/providers/age) instead.

## Troubleshooting

### `Database password not set`

fnox ran in non-interactive mode, such as from shell integration, and found no password. Set `FNOX_KEEPASS_PASSWORD` or `KEEPASS_PASSWORD` for the fnox process.

### `Could not read database password from terminal`

fnox had no terminal to prompt on. Set `FNOX_KEEPASS_PASSWORD` or `KEEPASS_PASSWORD` instead.

### `Failed to decrypt database`

The password or key file is wrong. Check the `keyfile` path and try opening the database with KeePassXC using the same credentials.

### Entry not found

Check the entry title and group path. A single-segment reference searches all groups and returns the first match; add the group path when several entries share a title.

## See also

- [OS keychain](/providers/keychain): local storage without a database file.
- [password-store](/providers/password-store): GPG-encrypted files synced with git.
- [age](/providers/age): encrypted secrets committed alongside your code.
