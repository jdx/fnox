---
description: "Read Doppler secrets with fnox through the Doppler CLI, scoped to a project and config, with a local login or a service token."
---

# Doppler

Read secrets from a [Doppler](https://www.doppler.com/) project and config through the `doppler` CLI. `fnox.toml` holds secret names; values stay in Doppler. The provider is read-only: manage values in Doppler.

|                     |                                                            |
| ------------------- | ---------------------------------------------------------- |
| Config type         | `doppler`                                                  |
| Storage             | Remote service                                             |
| Writes (`fnox set`) | No (read-only)                                             |
| Requires            | [Doppler CLI](https://docs.doppler.com/docs/cli) on `PATH` |

## Quick start

Sign in with `doppler login`, then add a provider scoped to a project and config:

```toml
[providers.doppler]
type = "doppler"
project = "my-app"
config = "dev"

[secrets]
DATABASE_URL = { provider = "doppler", value = "DATABASE_URL" }
```

```sh
fnox provider test doppler
fnox exec -- npm start
```

## Authentication {#token-management}

fnox uses the first token it finds and passes it to the CLI as `DOPPLER_TOKEN`:

1. The provider's `token` field.
2. `FNOX_DOPPLER_TOKEN`.
3. `DOPPLER_TOKEN`.
4. Otherwise, the CLI's own login session from `doppler login`.

When authentication fails in an interactive terminal, fnox offers to run `doppler login`. Change that command with [`auth_command`](/reference/configuration#auth-command).

### CI

Create a service token scoped to the project and config the job needs, and supply it from the CI secret store:

```yaml
- name: Deploy
  env:
    DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
  run: fnox exec -- ./deploy.sh
```

### Store the token with fnox

Keep a service token encrypted with another provider, such as [age](/providers/age), and reference it from `token`:

```toml
[providers.doppler]
type = "doppler"
project = "my-app"
config = "prd"
token = { secret = "DOPPLER_TOKEN" }

[secrets]
DOPPLER_TOKEN = { provider = "age", value = "YWdl..." } # ciphertext, abbreviated
```

Store the token through the hidden prompt with `fnox set DOPPLER_TOKEN --provider age`.

## Configuration

| Field     | Required | Default                                    | Description                                         |
| --------- | -------- | ------------------------------------------ | --------------------------------------------------- |
| `project` | No       | CLI setting (`doppler setup` or the token) | Doppler project, passed as `--project`.             |
| `config`  | No       | CLI setting (`doppler setup` or the token) | Doppler config (environment), passed as `--config`. |
| `token`   | No       | `FNOX_DOPPLER_TOKEN`, then `DOPPLER_TOKEN` | Service token.                                      |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

## Reference formats

A secret's `value` is the secret name in the provider's project and config.

| `value`        | What fnox reads                                     |
| -------------- | --------------------------------------------------- |
| `DATABASE_URL` | `DATABASE_URL` in the configured project and config |

fnox reads the computed value, with Doppler secret references already expanded. A value that holds JSON can be narrowed with [`json_path`](/reference/configuration#json-path).

When fnox resolves several secrets from one provider, it fetches them with a single `doppler secrets get` call.

## Several projects or configs

Each provider instance reads one project and config. Define one instance per scope:

```toml
[providers]
app = { type = "doppler", project = "my-app", config = "prd" }
infra = { type = "doppler", project = "infra", config = "prd" }

[secrets]
DATABASE_URL = { provider = "app", value = "DATABASE_URL" }
AWS_ACCESS_KEY_ID = { provider = "infra", value = "AWS_ACCESS_KEY_ID" }
```

To switch configs per environment, override the provider in a [profile](/guide/profiles) instead.

## Troubleshooting

### Unauthorized or invalid service token

Run `doppler login`, or check which token fnox picked up: the provider's `token`, `FNOX_DOPPLER_TOKEN` and `DOPPLER_TOKEN` take precedence over the CLI login.

### Could not find project or config

Check the names, and that the token or login can access them:

```sh
doppler configs --project my-app
```

### Secret not found

Check that the secret exists in the selected config:

```sh
doppler secrets --project my-app --config prd --only-names
```

## See also

- [Infisical](/providers/infisical): another hosted secrets manager.
- [CI/CD](/guide/ci): supply tokens to non-interactive jobs.
- [Profiles](/guide/profiles): select a Doppler config per environment.
