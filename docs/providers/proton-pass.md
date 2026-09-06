---
description: "Read Proton Pass vault items with fnox and pass-cli using vault aliases, item names, or pass:// references."
---

# Proton Pass

Integrate with Proton Pass through the Proton Pass CLI (`pass-cli`) to retrieve secrets from vault items.

## Quick start

```sh
# Install Proton Pass CLI
# See https://proton.me/pass/download

# Log in once with the default browser-based flow
pass-cli login
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers.protonpass]
type = "proton-pass"
vault = "Personal"

[secrets]
DATABASE_PASSWORD = { provider = "protonpass", value = "Database/password" }
```

```sh
# Retrieve the secret
fnox get DATABASE_PASSWORD
```

## Configuration

```toml
[providers.protonpass]
type = "proton-pass"
vault = "Personal" # Optional default vault for item-only references
agent_reason = "fnox secret retrieval" # Optional reason for audited agent access
```

`agent_reason` is used only when neither `FNOX_PROTON_PASS_AGENT_REASON` nor `PROTON_PASS_AGENT_REASON` is set.

## References

Supported secret references:

```toml
[secrets]
FROM_DEFAULT_VAULT = { provider = "protonpass", value = "Database" }
FIELD_FROM_DEFAULT_VAULT = { provider = "protonpass", value = "Database/username" }
FIELD_FROM_NAMED_VAULT = { provider = "protonpass", value = "Work/Database/password" }
FULL_URI = { provider = "protonpass", value = "pass://Work/Database/password" }
BY_ITEM_ID = { provider = "protonpass", value = "id:ITEM_ID/password" }
```

Item-only and `id:` references default to the `password` field and require `vault`.

Use full `pass://vault/item/field` references when vault or item names contain `/`.

## Personal access tokens

For CI or headless use, create a Proton Pass personal access token, then log in with `pass-cli`.
The official CLI supports either an environment variable or a login flag:

```bash
export PROTON_PASS_PERSONAL_ACCESS_TOKEN="pst_token::key"
pass-cli login
```

```bash
pass-cli login --personal-access-token "pst_token::key"
```

Run `pass-cli info` after login to verify the session. `fnox` also accepts `FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN` and passes it to `pass-cli` as `PROTON_PASS_PERSONAL_ACCESS_TOKEN`.

## Agent tokens

Proton Pass agent tokens are personal access tokens with dedicated access logging. Current `pass-cli` releases require `PROTON_PASS_AGENT_REASON` for audited agent operations, including item reads performed by `fnox`.

Set the reason with either environment or provider config:

```bash
export FNOX_PROTON_PASS_AGENT_REASON="fnox secret retrieval"
fnox get DATABASE_PASSWORD
```

```toml
[providers.protonpass]
type = "proton-pass"
vault = "Personal"
agent_reason = "fnox secret retrieval"
```

Environment values take priority over provider config. Provider `agent_reason` values are trimmed, must be non-empty, and must be at most 300 characters to match the `pass-cli` agent reason limit.

## Session and key storage

`fnox` passes through these Proton Pass CLI environment variables, with `FNOX_` aliases available for project-local setup:

| fnox env alias                           | pass-cli env                        |
| ---------------------------------------- | ----------------------------------- |
| `FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN` | `PROTON_PASS_PERSONAL_ACCESS_TOKEN` |
| `FNOX_PROTON_PASS_AGENT_REASON`          | `PROTON_PASS_AGENT_REASON`          |
| `FNOX_PROTON_PASS_SESSION_DIR`           | `PROTON_PASS_SESSION_DIR`           |
| `FNOX_PROTON_PASS_KEY_PROVIDER`          | `PROTON_PASS_KEY_PROVIDER`          |
| `FNOX_PROTON_PASS_ENCRYPTION_KEY`        | `PROTON_PASS_ENCRYPTION_KEY`        |
| `FNOX_PROTON_PASS_LINUX_KEYRING`         | `PROTON_PASS_LINUX_KEYRING`         |

Existing `PROTON_PASS_*` login variables such as `PROTON_PASS_PASSWORD`, `PROTON_PASS_TOTP`, and extra-password variants are also supported.

## Limits

The Proton Pass provider is read-only in `fnox`.

Supported:

- `fnox get`
- `fnox exec` and other commands that resolve configured secrets
- `fnox provider test`

Not supported:

- `fnox set` to create or update Proton Pass items
- Remote item listing/import
- Item delete/archive/update flows

## Troubleshooting

Run `pass-cli info` to check the session, then `fnox provider test <provider-name>` for the configured instance. Confirm the vault and field in the reference, and supply an agent reason when the token requires one.

## Next steps

- [Profiles](/guide/profiles): separate vault configuration by environment.
- [Sync a local cache](/guide/sync): use encrypted local copies for repeated reads.
