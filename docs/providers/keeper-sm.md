---
description: "Read Keeper Secrets Manager records with fnox using Keeper notation, an application configuration file, or one-time token bootstrap."
---

# Keeper Secrets Manager

Read records from [Keeper Secrets Manager](https://docs.keeper.io/keeperpam/secrets-manager) through Keeper's official Rust SDK. `fnox.toml` holds Keeper notation; values stay in Keeper. The provider is read-only: fnox does not create or update Keeper records.

|                     |                                                                     |
| ------------------- | ------------------------------------------------------------------- |
| Config type         | `keeper-sm`                                                         |
| Storage             | Remote service                                                      |
| Writes (`fnox set`) | No (read-only)                                                      |
| Requires            | A Secrets Manager client configuration and network access to Keeper |

## Quick start

Create a Secrets Manager application with access to the shared folder that holds your records, add a client device, and download its JSON configuration file. Then reference fields by record UID:

```toml
[providers.keeper]
type = "keeper-sm"
config_file = "~/.keeper/ksm-config.json"

[secrets]
DB_USER = { provider = "keeper", value = "RECORD_UID/field/login" }
DB_PASSWORD = { provider = "keeper", value = "RECORD_UID/field/password" }
```

```sh
fnox provider test keeper
fnox exec -- ./start-server.sh
```

## Authentication

The provider loads its client configuration from the first of these sources:

1. `config_file` in the provider configuration.
2. `FNOX_KEEPER_CONFIG`.
3. `KSM_CONFIG`.
4. `~/.keeper/ksm-config.json`.

`FNOX_KEEPER_CONFIG` and `KSM_CONFIG` may contain either the JSON client configuration or its Base64 encoding, which suits CI secret stores.

The configuration contains private client and application keys. Protect it like any other credential. Files created by the Keeper SDK use mode `0600` on Unix.

### One-time token bootstrap

To bind a new client device without downloading a configuration, set `config_file` and provide a one-time token once:

```sh
export KSM_TOKEN="US:..."
fnox provider test keeper
unset KSM_TOKEN
```

Bootstrap requires `config_file` because Keeper writes the bound client credentials there during the first request. The token comes from the provider's `token` field, then `FNOX_KEEPER_TOKEN`, then `KSM_TOKEN`. Remove it after the first successful run.

The `token` field can reference a bootstrap secret managed by another fnox provider:

```toml
[providers.keeper]
type = "keeper-sm"
config_file = "~/.keeper/ksm-config.json"
token = { secret = "KEEPER_BOOTSTRAP_TOKEN" }
```

## Configuration

| Field         | Required | Default                                                         | Description                                                                                                            |
| ------------- | -------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `config_file` | No       | `FNOX_KEEPER_CONFIG`, `KSM_CONFIG`, `~/.keeper/ksm-config.json` | Client configuration file. Relative paths resolve against the config file that declares the provider; `~` is expanded. |
| `token`       | No       | `FNOX_KEEPER_TOKEN`, then `KSM_TOKEN`                           | One-time bootstrap token. Requires `config_file`.                                                                      |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

### Environment variables

| Variable             | Description                                                            |
| -------------------- | ---------------------------------------------------------------------- |
| `FNOX_KEEPER_CONFIG` | JSON or Base64 client configuration. Takes priority over `KSM_CONFIG`. |
| `KSM_CONFIG`         | JSON or Base64 client configuration.                                   |
| `FNOX_KEEPER_TOKEN`  | One-time bootstrap token. Takes priority over `KSM_TOKEN`.             |
| `KSM_TOKEN`          | One-time bootstrap token.                                              |

## Reference formats

A secret's `value` is passed to Keeper's notation resolver. The `keeper://` prefix is optional.

| `value`                              | What fnox reads                |
| ------------------------------------ | ------------------------------ |
| `RECORD_UID/field/login`             | The record's login field       |
| `RECORD_UID/field/password`          | The record's password field    |
| `RECORD_UID/custom_field/API Key`    | A custom field named `API Key` |
| `RECORD_UID/title`                   | The record's title             |
| `keeper://RECORD_UID/field/password` | Same as without the prefix     |

String fields are returned as-is. Structured values are returned as compact JSON, which you can narrow with [`json_path`](/reference/configuration#json-path).

When fnox resolves several secrets from one provider, it looks them up in parallel, up to 10 at a time. During a one-time token bootstrap, it binds the device first.

## Troubleshooting

### Configuration file does not exist

No configuration was found at `config_file` or `~/.keeper/ksm-config.json`, and no one-time token was set. Download the configuration, set `KSM_CONFIG`, or bootstrap with a token.

### Record or field not found

`fnox provider test keeper` asks Keeper for every record the application can access. If it succeeds but a reference fails, check the record UID and field name, and that the application has access to the shared folder that contains the record.

## See also

- [Profiles](/guide/profiles): select an application configuration per environment.
- [Sync](/guide/sync): cache records under a personal encryption key.
- [CI/CD](/guide/ci): supply the client configuration to non-interactive jobs.
