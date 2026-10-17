---
description: "Read Passwordstate passwords and fields with fnox over the REST API, by password ID or by title within a password list."
---

# Passwordstate

Read passwords from a Click Studios Passwordstate server through its REST API. `fnox.toml` stores password IDs or titles; values stay in Passwordstate. The provider is read-only: create and edit records in Passwordstate, not with `fnox set`.

|                     |                                                 |
| ------------------- | ----------------------------------------------- |
| Config type         | `passwordstate`                                 |
| Storage             | Remote service (Passwordstate password list)    |
| Writes (`fnox set`) | No (read-only)                                  |
| Requires            | Network access to the server and a list API key |

## Quick start

Export the API key for the password list, then reference records by ID or title:

```sh
export PASSWORDSTATE_API_KEY="..."
```

```toml
[providers.passwordstate]
type = "passwordstate"
base_url = "https://passwordstate.example.com"
password_list_id = "123"

[secrets]
DB_PASSWORD = { provider = "passwordstate", value = "456" }
DB_USER = { provider = "passwordstate", value = "456/username" }
```

```sh
fnox provider test passwordstate
fnox exec -- npm start
```

No Passwordstate CLI is needed.

## Authentication

fnox sends the API key in the `APIKey` header of each request. It uses the first of:

1. The provider's `api_key` field
2. `FNOX_PASSWORDSTATE_API_KEY`
3. `PASSWORDSTATE_API_KEY`

Passwordstate issues API keys per password list, so create one provider instance per list. When several lists need different keys, set `api_key = { secret = "NAME" }` on each instance and store the keys with an encryption provider rather than in plain text.

## Configuration

| Field              | Required | Default  | Description                                                                 |
| ------------------ | -------- | -------- | --------------------------------------------------------------------------- |
| `base_url`         | Yes      | none     | Server URL without `/api`, for example `https://passwordstate.example.com`. |
| `password_list_id` | Yes      | none     | List searched for title references and used by `fnox provider test`.        |
| `api_key`          | No       | env vars | List API key. Overrides the environment variables.                          |
| `verify_ssl`       | No       | `"true"` | Set to `"false"` to skip TLS certificate verification.                      |

Each field accepts `{ secret = "NAME" }`.

::: warning
`verify_ssl = "false"` accepts any certificate, including one presented by an attacker. Install a trusted certificate on the server instead.
:::

## Reference formats

| `value`        | What fnox reads                                                |
| -------------- | -------------------------------------------------------------- |
| `456`          | The password field of record 456                               |
| `456/username` | A named field of record 456                                    |
| `Database`     | The password field of the record titled `Database` in the list |
| `Database/url` | A named field of the record titled `Database` in the list      |

- A numeric first segment is a password ID; anything else is a title, matched exactly but case-insensitively within `password_list_id`.
- Fields: `password`, `username` (or `user`), `title`, `url`, `description`, `notes`. Field names are case-insensitive.
- A reference can contain at most one `/`. Use the ID when a title contains `/`.

## Troubleshooting

### HTTP 401 or 403

The API key is wrong, or it belongs to a different password list. Check which key fnox picks up (see [Authentication](#authentication)).

### Password not found

Check the ID, or the exact title within the configured list.

### Field not found or empty

Use one of the supported field names, and confirm the field has a value on the record.

### Connection failure

Check `base_url`, the server's TLS certificate, and network access from the machine running fnox.

## See also

- [Profiles](/guide/profiles): use different lists or servers per environment.
- [Local sync cache](/guide/sync): keep an encrypted offline copy of resolved values.
- [Provider catalog](/providers/overview): compare Passwordstate with other providers.
