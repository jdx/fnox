---
description: "Read Passwordstate passwords and fields by ID or title with fnox, an API key, and a password list."
---

# Passwordstate

Read passwords from a Passwordstate server through its HTTP API. This provider is read-only; create and update records in Passwordstate, then commit their references in `fnox.toml`.

## Prerequisites

- A reachable Passwordstate server.
- An API key with access to the required password list and records.
- The password list ID and either a password ID or record title.

No Passwordstate CLI is required.

## Configuration

```toml
[providers.passwordstate]
type = "passwordstate"
base_url = "https://passwordstate.example.com"
password_list_id = "123"

[secrets]
DB_PASSWORD = { provider = "passwordstate", value = "456" }
DB_USER = { provider = "passwordstate", value = "456/username" }
```

Replace the URL and IDs with values from your server. Supply the API key through `FNOX_PASSWORDSTATE_API_KEY` or `PASSWORDSTATE_API_KEY`; the `FNOX_` form takes precedence.

| Field              | Required | Description                                            |
| ------------------ | -------- | ------------------------------------------------------ |
| `base_url`         | Yes      | Passwordstate server URL, without `/api`               |
| `password_list_id` | Yes      | List used for title searches and connection testing    |
| `api_key`          | No       | API key or secret reference; overrides the environment |
| `verify_ssl`       | No       | TLS certificate verification; defaults to `"true"`     |

Keep certificate verification enabled and configure a trusted certificate on the server. Do not commit a plaintext API key.

## Reference formats

| Reference      | Result                                               |
| -------------- | ---------------------------------------------------- |
| `456`          | Password field of the record with this ID            |
| `456/username` | Named field of the record with this ID               |
| `Database`     | Password field found by title in the configured list |
| `Database/url` | Named field found by title in the configured list    |

Supported fields are `password`, `username` (or `user`), `title`, `url`, `description`, and `notes`. Field names are case-insensitive. References accept at most one `/` separator; use IDs when a title cannot be expressed unambiguously.

## Verify and run

```sh
fnox provider test passwordstate
fnox check --all
fnox exec -- npm start
```

`fnox get DB_PASSWORD` prints the resolved value when you need to inspect it directly.

## Troubleshooting

- **Authentication failure:** confirm the API key is valid and has access to the list and record.
- **Record not found:** verify the ID, or check the exact title in the configured list.
- **Field missing:** use one of the supported fields and confirm it has a value.
- **Connection failure:** verify the base URL, TLS certificate, and network access from the machine running fnox.

## Next steps

- [Sync a local cache](/guide/sync): encrypt a personal snapshot for local reads.
- [Profiles](/guide/profiles): use different lists or servers per environment.
- [Configuration reference](/reference/configuration): common provider and secret options.
