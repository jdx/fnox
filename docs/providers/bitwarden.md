---
description: "Read Bitwarden or Vaultwarden vault items with fnox through bw or rbw, scoped by folder, collection or organization."
---

# Bitwarden

Read items from a Bitwarden or self-hosted Vaultwarden vault through the Bitwarden CLI (`bw`) or the [`rbw`](https://github.com/doy/rbw) client. `fnox.toml` stores item references; values stay in the vault. The provider is read-only: create and edit items in Bitwarden, not with `fnox set`.

|                     |                                                                               |
| ------------------- | ----------------------------------------------------------------------------- |
| Config type         | `bitwarden`                                                                   |
| Storage             | Remote service (Bitwarden vault)                                              |
| Writes (`fnox set`) | No (read-only)                                                                |
| Requires            | [`bw` CLI](https://bitwarden.com/help/cli/) and an unlocked session, or `rbw` |

For machine-account tokens in Bitwarden Secrets Manager, use [`bitwarden-sm`](/providers/bitwarden-sm) instead.

## Quick start

Log in and unlock the vault with `bw`:

```sh
bw login
export BW_SESSION="$(bw unlock --raw)"
```

Reference an existing item:

```toml
[providers.bitwarden]
type = "bitwarden"

[secrets]
DATABASE_PASSWORD = { provider = "bitwarden", value = "Database" }
```

```sh
fnox provider test bitwarden
fnox exec -- npm start
```

For Vaultwarden, point `bw` at your server with `bw config server https://vault.example.com` before `bw login`. References work the same way.

## Authentication

### `bw` backend (default)

fnox passes the session token to every `bw` call with `--session`. It reads, in order:

1. `FNOX_BW_SESSION`
2. `BW_SESSION`

Without either, the provider fails with "Session token not found" before running `bw`. A session lasts until the vault is locked; unlock again and re-export `BW_SESSION` when it stops working.

To avoid unlocking in every shell, store the session with an encryption provider and export it when you start work:

```sh
bw unlock --raw | fnox set BW_SESSION --provider age
export BW_SESSION="$(fnox get BW_SESSION)"
```

In CI, put an unlocked session token in the job's secret store as `BW_SESSION`.

### `rbw` backend

`rbw` keeps its own unlocked state through its agent and does not use `BW_SESSION`. Set it up with `rbw login` outside fnox, then select the backend:

```toml
[providers.bitwarden]
type = "bitwarden"
backend = "rbw"
auth_command = "rbw unlock"
```

The `rbw` backend is experimental. `auth_command` makes fnox offer `rbw unlock` instead of the default `bw login` when authentication fails.

## Configuration

| Field             | Required | Default | Description                                                                          |
| ----------------- | -------- | ------- | ------------------------------------------------------------------------------------ |
| `backend`         | No       | `"bw"`  | `"bw"` or `"rbw"`.                                                                   |
| `folder`          | No       | none    | Folder name, or `Parent/Child` path, that items must be in. See [Folders](#folders). |
| `collection`      | No       | none    | Collection ID passed to `bw --collectionid`. `bw` only.                              |
| `organization_id` | No       | none    | Organization ID passed to `bw --organizationid`. `bw` only.                          |
| `profile`         | No       | none    | Account profile. See [Multiple accounts](#multiple-accounts).                        |

`folder`, `collection`, `organization_id` and `profile` accept `{ secret = "NAME" }` to read their value from another secret. Find IDs with `bw list collections` and `bw list organizations`.

## Reference formats

| `value`             | What fnox reads                                                             |
| ------------------- | --------------------------------------------------------------------------- |
| `Database`          | The item's password                                                         |
| `Database/username` | A standard field: `username`, `password`, `notes`, `uri` (or `url`), `totp` |
| `Database/API Key`  | Any other name is read as a custom field                                    |

- The first `/` separates the item name from the field, so item names cannot contain `/`. Custom field names can.
- With `bw`, custom field names are case-sensitive and must match exactly.
- `totp` returns the current code (`bw get totp`, or `rbw code`).

## Folders

Scope a provider to a folder so items with the same name can live in different folders, for example one provider per environment:

```toml
[providers.bw-prod]
type = "bitwarden"
folder = "MyApp/Production"

[secrets]
DATABASE_PASSWORD = { provider = "bw-prod", value = "Database" } # "Database" inside MyApp/Production
```

- `rbw` passes `--folder` to `rbw get` and `rbw code`.
- `bw` resolves the folder ID with `bw list folders`, then searches that folder with `bw list items --folderid`. For both the folder and the item, an exact name match wins; otherwise a single name that contains the reference (case-insensitive) is used. Matches on usernames, URIs or other fields are ignored.
- Several candidates are an error rather than a guess.
- When `collection` or `organization_id` is also set, the item must be in the folder and match those filters.

## Multiple accounts

Set `profile` to use one of several logged-in accounts, one provider instance per account:

```toml
[providers.bw-work]
type = "bitwarden"
profile = "Business"

[providers.bw-personal]
type = "bitwarden"
profile = "Personal"
```

- With `bw`, fnox sets `BITWARDENCLI_APPDATA_DIR` to `<config dir>/Bitwarden CLI <profile>`, the layout described in Bitwarden's [multiple accounts](https://bitwarden.com/help/cli/#log-in-to-multiple-accounts) guide. If `BITWARDENCLI_APPDATA_DIR` is already set, fnox leaves it alone and logs a warning.
- With `rbw`, fnox sets `RBW_PROFILE`.

## Troubleshooting

### Session token not found

`BW_SESSION` and `FNOX_BW_SESSION` are both unset in fnox's environment. Unlock and export the session:

```sh
export BW_SESSION="$(bw unlock --raw)"
```

### Vault is locked or session expired

The session was invalidated, for example by `bw lock` or a timeout. Unlock again as above. With `rbw`, run `rbw unlock`.

### Item not found or ambiguous

Check the item name, and the folder, collection and organization filters on the provider:

```sh
bw list items --search Database | jq '.[] | {name, id, folderId}'
```

### Custom field not found

The field name after `/` must match the custom field's name exactly, including case.

## See also

- [Use an existing vault](/guide/existing-vault): reference vault items and keep a personal offline cache.
- [Bitwarden Secrets Manager](/providers/bitwarden-sm): machine-account access for CI and servers.
- [Provider catalog](/providers/overview): compare Bitwarden with other providers.
