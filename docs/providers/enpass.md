---
description: "Read Enpass vault items with fnox directly from the local vault files, by item title and field name."
---

# Enpass

Read secrets from an [Enpass](https://www.enpass.io/) vault. Enpass has no CLI or API, so fnox opens the vault files on disk, the same files the Enpass app syncs, and decrypts them with your master password. The provider is read-only and never changes the vault.

|                     |                                                 |
| ------------------- | ----------------------------------------------- |
| Config type         | `enpass`                                        |
| Storage             | Local store (Enpass 6+ vault directory)         |
| Writes (`fnox set`) | No (read-only)                                  |
| Requires            | The vault files on disk and the master password |

## Quick start

```toml
[providers.enpass]
type = "enpass"
vault = "~/Documents/Enpass/Vaults/primary"

[secrets]
GITHUB_TOKEN = { provider = "enpass", value = "GitHub/API Token" }
```

```sh
fnox provider test enpass
fnox exec -- gh repo list
```

fnox prompts for the master password without echoing it. The provider keeps no cache, so a change you make in Enpass shows up on the next command. Values held by the [daemon](/guide/daemon), a loaded [shell hook](/guide/shell-integration) or [`fnox sync`](/guide/sync) stay as they were until those are refreshed.

## Authentication

fnox uses the first master password it finds:

1. `FNOX_ENPASS_PASSWORD`
2. `ENPASS_PASSWORD`
3. The provider's `password` field
4. A terminal prompt

- One prompt serves every secret resolved from the same vault during a command. A wrong password is not reused, so the next lookup prompts again.
- Non-interactive runs and automatic shell hooks do not prompt. Set an environment variable for those, or the lookup fails with an authentication error.
- `fnox exec` removes `FNOX_ENPASS_PASSWORD` and `ENPASS_PASSWORD` from the command's environment, so the program it runs does not inherit the master password. A secret you explicitly name `FNOX_ENPASS_PASSWORD` is still passed through.

::: warning
The master password unlocks the whole vault. Do not put it in `password` as plain text; use an environment variable, or `password = { secret = "NAME" }` with an encryption provider.
:::

## Configuration

| Field      | Required | Default | Description                                                            |
| ---------- | -------- | ------- | ---------------------------------------------------------------------- |
| `vault`    | Yes      | none    | Vault directory, the one containing `vault.enpassdb` and `vault.json`. |
| `keyfile`  | No       | none    | `.enpasskey` file, if the vault uses one in addition to the password.  |
| `password` | No       | none    | Master password. Environment variables take priority.                  |

Relative `vault` and `keyfile` paths are resolved from the config file that declares the provider, and `~` expands to your home directory. Each field accepts `{ secret = "NAME" }`.

### Vault directory

`vault` is the directory, not either file inside it. Enpass names the first vault `primary` and puts additional vaults next to it; the usual location is `~/Documents/Enpass/Vaults/primary`. If you moved the Enpass data folder or installed Enpass from an app store, find the directory with:

```sh
find ~ -name vault.enpassdb 2>/dev/null
```

## Reference formats

| `value`            | What fnox reads                      |
| ------------------ | ------------------------------------ |
| `GitHub`           | The item's first password field      |
| `GitHub/username`  | The field with that label or type    |
| `GitHub/API Token` | A custom field, matched by its label |

- Titles and field names are case-insensitive.
- A field name matches the label shown in Enpass (`API Token`) or the field type (`username`, `email`, `url`, `password`, and so on).
- A title that contains `/`, such as `Prod/DB`, is matched as a whole first. If no item has that exact title, the text after the last `/` is the field name.
- Items in the trash and deleted items are ignored.
- If two items share a title, fnox reports an error instead of guessing. Rename one of them in Enpass.

Vaults created by Enpass versions before 6 are not supported.

## How it works

An Enpass 6 vault is an [SQLCipher](https://www.zetetic.net/sqlcipher/) database. fnox derives the database key from your master password (and keyfile, if configured) using the PBKDF2 parameters in `vault.json`, opens the database read-only, and decrypts password fields with each item's own key. The password is not written anywhere, and the vault is not copied.

## Troubleshooting

### Could not unlock the vault

Check the master password, and the keyfile if the vault uses one. Make sure `FNOX_ENPASS_PASSWORD` or `ENPASS_PASSWORD` is not set to an old password, since either takes priority over the prompt.

### Could not read …/vault.json

`vault` must point at the vault directory. See [Vault directory](#vault-directory).

### No item with that title

Check the title in Enpass, and make sure the item is not in the trash.

### Item … has no … field

The error lists the item's field labels. Use one of them after the `/`.

## See also

- [KeePass](/providers/keepass): a local password database that fnox can also write to.
- [1Password](/providers/1password): a password manager read through its CLI.
- [Provider catalog](/providers/overview): compare Enpass with other providers.
