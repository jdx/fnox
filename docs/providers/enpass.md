---
description: "Read Enpass vault items with fnox directly from the local vault file, using item titles and field names."
---

# Enpass

Read secrets from an [Enpass](https://www.enpass.io/) vault. Enpass has no CLI or API, so fnox opens the vault files on disk, the same files the Enpass app syncs, and decrypts them with your master password. The provider is read-only and never changes the vault.

The provider keeps no cache, so a change you make in Enpass shows up on the next `fnox get` or `fnox exec`. Values held by the [daemon](/guide/daemon), a loaded [shell hook](/guide/shell-integration), or [`fnox sync`](/guide/sync) stay as they were until those are refreshed.

## Quick start

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
enpass = { type = "enpass", vault = "~/Documents/Enpass/Vaults/primary" }

[secrets]
GITHUB_TOKEN = { provider = "enpass", value = "GitHub/API Token" }
```

```sh
fnox provider test enpass
fnox get GITHUB_TOKEN
```

fnox prompts for the master password without showing what you type. You can also set `FNOX_ENPASS_PASSWORD` to use fnox without a prompt.

## Configuration

```toml
[providers]
enpass = { type = "enpass", vault = "~/Documents/Enpass/Vaults/primary" }

# A vault protected by a keyfile as well as the master password
enpass-work = { type = "enpass", vault = "~/Documents/Enpass/Vaults/primary", keyfile = "~/work.enpasskey" }
```

### Vault directory

`vault` is the directory that holds `vault.enpassdb` and `vault.json`, not either file. Enpass names your first vault `primary`; additional vaults get their own directories next to it. The usual location is `~/Documents/Enpass/Vaults/primary`. If you moved the Enpass data folder or installed Enpass from an app store, find the directory with:

```sh
find ~ -name vault.enpassdb 2>/dev/null
```

Relative paths are resolved from the config file that declares the provider, and `~` expands to your home directory.

### Keyfile (optional)

If your vault uses a keyfile, point `keyfile` at the `.enpasskey` file Enpass created. Relative `keyfile` paths follow the same config-relative rule as `vault`.

## Authentication

When a password is not configured, fnox prompts for the master password in a terminal. One prompt is used for every secret resolved from the same vault during a command. A wrong password is not reused, so a later lookup prompts again. Automatic shell hooks do not prompt; use an environment variable for secrets loaded by `fnox hook-env`.

For unattended use, set the master password via environment variable:

- `FNOX_ENPASS_PASSWORD` (preferred)
- `ENPASS_PASSWORD` (fallback)

```bash
export FNOX_ENPASS_PASSWORD="your-master-password"
```

::: warning
The provider also accepts a `password` field, but avoid storing the master password directly in the provider config. Environment variables take priority over the config value; both take priority over the prompt. In non-interactive mode, a missing password produces an authentication error.
:::

## Reference formats

| Format      | Example            | Returns                              |
| ----------- | ------------------ | ------------------------------------ |
| Item title  | `GitHub`           | The item's first password field      |
| Title/field | `GitHub/username`  | The field with that label or type    |
| Title/field | `GitHub/API Token` | A custom field, matched by its label |

- Titles and field names are case-insensitive.
- A field name matches either the label you see in Enpass (`API Token`) or the field's type (`username`, `email`, `url`, `password`, and so on).
- A title that itself contains `/`, such as `Prod/DB`, is matched as a whole first. If no item has that exact title, the text after the last `/` is used as the field name.
- Items in the trash and deleted items are ignored.
- If two items share a title, fnox reports an error instead of guessing. Rename one of them in Enpass.

```toml
[secrets]
DB_USER = { provider = "enpass", value = "Production DB/username" }
DB_PASS = { provider = "enpass", value = "Production DB" }
DB_HOST = { provider = "enpass", value = "Production DB/Host" }
```

## Limits

The Enpass provider is read-only in `fnox`.

Supported:

- `fnox get`
- `fnox exec` and other commands that resolve configured secrets
- `fnox provider test`

Not supported:

- Creating or updating Enpass items. `fnox set NAME VALUE --provider enpass` only records `VALUE` as the item reference in `fnox.toml`; add or edit the item in Enpass itself.
- Vaults created by Enpass versions before 6.

## How it works

An Enpass 6 vault is an [SQLCipher](https://www.zetetic.net/sqlcipher/) database. fnox derives the database key from your master password (and keyfile, if configured) using the PBKDF2 parameters in `vault.json`, opens the database read-only, and decrypts password fields with each item's own key. The password is not written anywhere, and the vault is not copied.

## Troubleshooting

### "Could not unlock the vault"

Check the master password, and the keyfile if your vault uses one. Make sure `FNOX_ENPASS_PASSWORD` or `ENPASS_PASSWORD` is not set to an old password, since either one takes priority over the prompt.

### "Could not read …/vault.json"

`vault` must point at the vault directory, the one containing `vault.json` and `vault.enpassdb`. See [Vault directory](#vault-directory).

### "No item with that title"

Check the title in Enpass, and make sure the item is not in the trash.

### "Item … has no … field"

The error lists the item's field labels. Use one of them after the `/`.

## Running tests

```bash
mise run test:bats -- test/enpass.bats
```

The tests read a small vault created in Enpass, stored in `test/fixtures/enpass`, so no Enpass installation is needed.

## Next steps

- [KeePass](/providers/keepass) - Local password database with read/write support
- [1Password](/providers/1password) - Password manager with CLI integration
- [Provider catalog](/providers/overview)
