---
description: "Read Infisical secrets with fnox using a service token or machine identity, scoped by project, environment and path."
---

# Infisical

Read secrets from Infisical Cloud or a self-hosted instance through the Infisical CLI. `fnox.toml` stores secret names; values stay in Infisical. The provider is read-only: create and edit secrets in Infisical, not with `fnox set`.

|                     |                                                                                                      |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| Config type         | `infisical`                                                                                          |
| Storage             | Remote service (Infisical project)                                                                   |
| Writes (`fnox set`) | No (read-only)                                                                                       |
| Requires            | [`infisical` CLI](https://infisical.com/docs/cli/overview) on `PATH` and a token or machine identity |

## Quick start

Export a token for a machine identity or service token with read access to the project:

```sh
export INFISICAL_TOKEN="..."
```

Reference a secret by its name in Infisical:

```toml
[providers.infisical]
type = "infisical"
project_id = "your-project-id"
environment = "dev"
path = "/"

[secrets]
DATABASE_URL = { provider = "infisical", value = "DATABASE_URL" }
```

```sh
fnox provider test infisical
fnox exec -- npm start
```

## Authentication

fnox does not use the CLI's `infisical login` session. It passes a token to every `infisical` call with `--token`, from the first source that is set:

1. **Token**: `FNOX_INFISICAL_TOKEN`, then `INFISICAL_TOKEN`.
2. **Universal Auth** (machine identity): `FNOX_INFISICAL_CLIENT_ID` or `INFISICAL_CLIENT_ID`, plus `FNOX_INFISICAL_CLIENT_SECRET` or `INFISICAL_CLIENT_SECRET`. fnox runs `infisical login --method universal-auth` once and reuses the resulting token for the rest of the process.

With neither set, the provider fails with "Authentication not found". `fnox provider test` checks only that a token is available or that Universal Auth login succeeds; it does not read a secret.

### Self-hosted instances

Set `FNOX_INFISICAL_API_URL` or `INFISICAL_API_URL`, for example `https://infisical.example.com/api`. fnox strips a trailing `/api` and passes the rest to the CLI as `--domain`, including for Universal Auth login.

### CI

Store the token, or the client ID and secret, in the CI secret store:

```yaml
- run: fnox exec -- npm test
  env:
    INFISICAL_TOKEN: ${{ secrets.INFISICAL_TOKEN }}
```

To bootstrap a token on a workstation, store it with an encryption provider and export it when you start work:

```sh
fnox set INFISICAL_TOKEN --provider age
export INFISICAL_TOKEN="$(fnox get INFISICAL_TOKEN)"
```

## Configuration

| Field         | Required | Default       | Description                                                  |
| ------------- | -------- | ------------- | ------------------------------------------------------------ |
| `project_id`  | No       | CLI's default | Project ID, passed as `--projectId`.                         |
| `environment` | No       | CLI's default | Environment slug such as `dev` or `prod`, passed as `--env`. |
| `path`        | No       | CLI's default | Folder path within the environment, passed as `--path`.      |

Omitted fields are left to the Infisical CLI's own defaults. Set all three when one identity can access several projects or environments. Each field accepts `{ secret = "NAME" }`.

## Reference formats

| `value`        | What fnox reads                                                                 |
| -------------- | ------------------------------------------------------------------------------- |
| `DATABASE_URL` | The secret named `DATABASE_URL` at the provider's project, environment and path |

The provider config sets the scope; the reference is only the secret name. Use one provider instance per folder:

```toml
[providers.infisical-api]
type = "infisical"
project_id = "abc123"
environment = "dev"
path = "/api"

[providers.infisical-db]
type = "infisical"
project_id = "abc123"
environment = "dev"
path = "/database"

[secrets]
API_KEY = { provider = "infisical-api", value = "API_KEY" }           # /api/API_KEY
DATABASE_URL = { provider = "infisical-db", value = "DATABASE_URL" }  # /database/DATABASE_URL
```

For separate environments, override `environment` in a [profile](/guide/profiles) rather than duplicating secrets. When several secrets use the same provider, fnox fetches them in one `infisical secrets get` call.

## Troubleshooting

### Authentication not found

None of the token or Universal Auth variables is set in fnox's environment. Set `INFISICAL_TOKEN`, or both `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET`.

When authentication fails in a terminal, fnox offers to run `infisical login`. That command does not give fnox a token; set `auth_command = ""` on the provider to turn the prompt off.

### Unauthorized or invalid token

The token is expired, revoked, or lacks read access to the project and environment. Create a new one in Infisical and update the variable.

### Project, environment or folder not found

Check `project_id`, `environment` and `path` against the project in Infisical. The error comes from the CLI, so run the same lookup with `infisical secrets get <NAME>` and the matching flags to see its full message.

### Secret not found

The secret must exist at the configured `path` in the configured environment, not in a sub-folder.

## See also

- [Profiles](/guide/profiles): switch the Infisical environment per profile.
- [CI/CD](/guide/ci): supply the token in a pipeline.
- [Provider catalog](/providers/overview): compare Infisical with other providers.
