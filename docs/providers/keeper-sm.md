# Keeper Secrets Manager

Use [Keeper Secrets Manager](https://docs.keeper.io/keeperpam/secrets-manager) through Keeper's official Rust SDK. The provider is read-only: fnox retrieves secrets but does not create or update Keeper records.

## Quick Start

Create a Keeper Secrets Manager application and client device, then download its JSON configuration file.

```toml
[providers]
keeper = { type = "keeper-sm", config_file = "~/.keeper/ksm-config.json" }

[secrets]
DB_PASSWORD = { provider = "keeper", value = "HDQTnxkTcPSOsHNAlbI4aQ/field/password" }
DB_USER = { provider = "keeper", value = "HDQTnxkTcPSOsHNAlbI4aQ/field/login" }
```

Keeper notation may include the `keeper://` prefix, but it is optional:

```toml
[secrets]
DB_PASSWORD = { provider = "keeper", value = "keeper://HDQTnxkTcPSOsHNAlbI4aQ/field/password" }
```

## Authentication

The provider checks authentication sources in this order:

1. `config_file` in the provider configuration
2. `FNOX_KEEPER_CONFIG`
3. `KSM_CONFIG`
4. `~/.keeper/ksm-config.json`

`FNOX_KEEPER_CONFIG` and `KSM_CONFIG` may contain either the JSON client configuration or its Base64 encoding.

The Keeper configuration contains private client and application keys. Protect it like any other credential. Files created by the Keeper SDK use mode `0600` on Unix.

### One-time token bootstrap

To bind a new client device, configure a file and provide a one-time token:

```toml
[providers]
keeper = { type = "keeper-sm", config_file = "~/.keeper/ksm-config.json" }
```

```bash
export KSM_TOKEN="US:YOUR_ONE_TIME_TOKEN"
fnox provider test keeper
unset KSM_TOKEN
```

`FNOX_KEEPER_TOKEN` takes priority over `KSM_TOKEN`. Bootstrap requires `config_file` because Keeper writes the bound client credentials during the first network request. Remove the one-time token after successful initialization.

## Configuration

| Field         | Required | Description                                     |
| ------------- | -------- | ----------------------------------------------- |
| `config_file` | No       | JSON client configuration file                  |
| `token`       | No       | One-time bootstrap token; secret refs supported |

The `token` field can reference a bootstrap secret managed by another fnox provider:

```toml
[providers]
keeper = { type = "keeper-sm", config_file = "~/.keeper/ksm-config.json", token = { secret = "KEEPER_BOOTSTRAP_TOKEN" } }
```

## Keeper Notation

The secret `value` is passed to Keeper's notation resolver. Common selectors include:

```toml
[secrets]
LOGIN = { provider = "keeper", value = "RECORD_UID/field/login" }
PASSWORD = { provider = "keeper", value = "RECORD_UID/field/password" }
API_KEY = { provider = "keeper", value = "RECORD_UID/custom_field/API Key" }
TITLE = { provider = "keeper", value = "RECORD_UID/title" }
```

String fields are returned directly. Structured Keeper values are serialized as compact JSON strings.

## Environment Variables

| Variable             | Description                                       |
| -------------------- | ------------------------------------------------- |
| `FNOX_KEEPER_CONFIG` | JSON or Base64 client configuration; first choice |
| `KSM_CONFIG`         | Keeper-standard client configuration fallback     |
| `FNOX_KEEPER_TOKEN`  | One-time bootstrap token; first choice            |
| `KSM_TOKEN`          | Keeper-standard one-time token fallback           |

## Troubleshooting

Run the connection test:

```bash
fnox provider test keeper
```

The test asks Keeper for all records accessible to the configured application. Confirm that the application has access to the shared folder containing the referenced record and that the client configuration is readable.
