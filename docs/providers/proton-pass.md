---
description: "Read Proton Pass items with fnox through pass-cli, using item names, item IDs or pass:// references and personal or agent access tokens."
---

# Proton Pass

Read vault items through the Proton Pass CLI (`pass-cli`). `fnox.toml` stores item references; values stay in Proton Pass. The provider is read-only: create and edit items in Proton Pass, not with `fnox set`.

|                     |                                                                                 |
| ------------------- | ------------------------------------------------------------------------------- |
| Config type         | `proton-pass`                                                                   |
| Storage             | Remote service (Proton Pass vault)                                              |
| Writes (`fnox set`) | No (read-only)                                                                  |
| Requires            | [`pass-cli`](https://proton.me/pass/download) on `PATH` and a logged-in session |

## Quick start

Log in once with the CLI's default browser flow:

```sh
pass-cli login
```

Reference an existing item:

```toml
[providers.protonpass]
type = "proton-pass"
vault = "Personal"

[secrets]
DATABASE_PASSWORD = { provider = "protonpass", value = "Database/password" }
```

```sh
fnox provider test protonpass
fnox exec -- npm start
```

`fnox provider test` runs `pass-cli info` to check the session.

## Authentication

fnox runs `pass-cli` and uses its stored session. When the CLI reports that you are not logged in, fnox offers to run `pass-cli login` in a terminal. A locked session needs `pass-cli session unlock` instead.

That prompt runs `pass-cli login` with your environment as-is: fnox does not map its `FNOX_PROTON_PASS_*` aliases for it. To log in with a personal access token, set the native `PROTON_PASS_PERSONAL_ACCESS_TOKEN`.

### Personal access tokens

For CI or headless machines, create a Proton Pass personal access token, supply it as `PROTON_PASS_PERSONAL_ACCESS_TOKEN` from the CI secret store, and log in:

```sh
pass-cli login   # reads PROTON_PASS_PERSONAL_ACCESS_TOKEN from the environment
```

Avoid `--personal-access-token` and inline assignments with a literal token: they expose it in process listings and shell history.

### Agent tokens

Agent tokens are personal access tokens with dedicated access logging. `pass-cli` requires a reason for every audited agent operation, including the reads fnox performs. fnox passes the first of these as `PROTON_PASS_AGENT_REASON`:

1. `FNOX_PROTON_PASS_AGENT_REASON`
2. `PROTON_PASS_AGENT_REASON`
3. The provider's `agent_reason` field

```toml
[providers.protonpass]
type = "proton-pass"
vault = "Personal"
agent_reason = "fnox secret retrieval"
```

### Session and key storage

fnox forwards these `pass-cli` variables. Each has a `FNOX_` alias that takes priority, so you can set project-local values without changing your shell's `PROTON_PASS_*` settings. Empty values are ignored.

| fnox alias                               | Passed to `pass-cli` as             |
| ---------------------------------------- | ----------------------------------- |
| `FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN` | `PROTON_PASS_PERSONAL_ACCESS_TOKEN` |
| `FNOX_PROTON_PASS_AGENT_REASON`          | `PROTON_PASS_AGENT_REASON`          |
| `FNOX_PROTON_PASS_SESSION_DIR`           | `PROTON_PASS_SESSION_DIR`           |
| `FNOX_PROTON_PASS_KEY_PROVIDER`          | `PROTON_PASS_KEY_PROVIDER`          |
| `FNOX_PROTON_PASS_ENCRYPTION_KEY`        | `PROTON_PASS_ENCRYPTION_KEY`        |
| `FNOX_PROTON_PASS_LINUX_KEYRING`         | `PROTON_PASS_LINUX_KEYRING`         |
| `FNOX_PROTON_PASS_PASSWORD`              | `PROTON_PASS_PASSWORD`              |
| `FNOX_PROTON_PASS_TOTP`                  | `PROTON_PASS_TOTP`                  |
| `FNOX_PROTON_PASS_EXTRA_PASSWORD`        | `PROTON_PASS_EXTRA_PASSWORD`        |

The `PASSWORD`, `TOTP` and `EXTRA_PASSWORD` variables also have `_FILE` variants (for example `FNOX_PROTON_PASS_PASSWORD_FILE`), forwarded the same way.

## Configuration

| Field          | Required | Default | Description                                                                                                                           |
| -------------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `vault`        | No       | none    | Vault for `item`, `item/field` and `id:` references. Those forms fail without it.                                                     |
| `agent_reason` | No       | none    | Reason sent for audited agent access when neither environment variable is set. Trimmed; must be non-empty and at most 300 characters. |

Each field accepts `{ secret = "NAME" }`.

## Reference formats

| `value`                         | What fnox reads                                          |
| ------------------------------- | -------------------------------------------------------- |
| `Database`                      | `pass://<vault>/Database/password`                       |
| `Database/username`             | `pass://<vault>/Database/username`                       |
| `Work/Database/password`        | `pass://Work/Database/password`; ignores `vault`         |
| `pass://Work/Database/password` | That reference as written                                |
| `id:ITEM_ID`                    | The `password` field of the item with that ID in `vault` |
| `id:ITEM_ID/username`           | A named field of the item with that ID in `vault`        |

- Common fields are `password`, `username`, `email`, `totp`, `url` and `notes`; which exist depends on the item type.
- Use a full `pass://vault/item/field` reference when a vault or item name contains `/`.
- Use `id:` to tell apart items that share a name in one vault.
- Alias items are not supported, because `pass-cli` does not expose alias addresses as fields.

## Troubleshooting

### Not logged in or session expired

Run `pass-cli login`, or log in again with your access token. `pass-cli info` shows whether the CLI has a session.

### Session is locked

Run `pass-cli session unlock`.

### Agent reason required

The token is an agent token and no reason was supplied. Set `FNOX_PROTON_PASS_AGENT_REASON` or `agent_reason`.

### Could not get local key from keyring

`pass-cli` cannot read its session encryption key. Check `PROTON_PASS_SESSION_DIR`, `PROTON_PASS_KEY_PROVIDER` (`fs`, `env` or `keyring`) and `PROTON_PASS_ENCRYPTION_KEY`.

### Field does not exist

The item type has no field with that name. Name a different field after the `/`.

## See also

- [Profiles](/guide/profiles): use a different vault per environment.
- [Local sync cache](/guide/sync): keep an encrypted offline copy of resolved values.
- [Provider catalog](/providers/overview): compare Proton Pass with other providers.
