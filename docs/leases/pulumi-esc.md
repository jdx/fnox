# Pulumi ESC

The `pulumi-esc` lease backend vends short-lived credentials from a Pulumi ESC environment by calling the Pulumi Cloud REST API (`POST /api/esc/environments/{ref}/open` + `GET /open/{id}`) and surfacing entries from the environment's resolved `environmentVariables` block.

This works with any ESC integration that mints dynamic credentials — AWS OIDC, GCP OIDC, Azure, Vault, and more. ESC handles the credential minting; fnox caches and re-issues on expiry. No `esc` CLI is required at runtime.

## Configuration

```toml
[leases.aws-dev]
type = "pulumi-esc"
organization = "my-org"
project = "my-project"
environment = "aws-dev"
env_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
duration = "1h"
```

| Field          | Required | Description                                                                                                               |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------- |
| `organization` | Yes      | Pulumi organization name                                                                                                  |
| `environment`  | Yes      | ESC environment name                                                                                                      |
| `project`      | No       | ESC project name (default `default`, as the `esc` CLI uses for `<org>/<env>` references)                                  |
| `token`        | No       | Pulumi access token (falls back to `FNOX_PULUMI_ACCESS_TOKEN` / `PULUMI_ACCESS_TOKEN` / `~/.pulumi/credentials.json`)     |
| `env_vars`     | No       | Filter: only surface these keys from `environmentVariables`. Required for auto-routing individual env vars to this lease. |
| `duration`     | No       | Lease TTL (e.g. `"1h"`); keep it at or below the lifetime of credentials the environment mints                           |

## Prerequisites

- A Pulumi access token. Either set `PULUMI_ACCESS_TOKEN` / `FNOX_PULUMI_ACCESS_TOKEN`, or run `esc login` once to populate `~/.pulumi/credentials.json` (fnox reads that file directly — the `esc` CLI binary is not required at runtime).

## Credentials Produced

Whatever keys appear under `environmentVariables` in the opened ESC environment. When `env_vars` is set, only those keys are surfaced (missing keys are logged as warnings). Non-string scalars (booleans, numbers) are coerced to their JSON-string form so they can be exported as env vars.

## Limits

- **Max duration:** 1 hour. `duration` sets the ESC open-session length and the lease expiry, but credentials minted inside the environment (e.g. `fn::open::aws-login`) keep the lifetime configured there. If that is shorter than `duration`, fnox will reuse expired credentials until the lease expires — set `duration` no longer than the environment's credential lifetime.
- **Revocation:** No-op. ESC credentials are already short-lived; there is no server-side lease to revoke.

## Examples

### AWS OIDC via ESC

```toml
[leases.aws]
type = "pulumi-esc"
organization = "my-org"
project = "infra"
environment = "aws-dev"
env_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"]
duration = "1h"
```

Listing the keys in `env_vars` is all the routing there is — no `[secrets]` entries needed.

```bash
fnox exec -- aws s3 ls
```

### Surface everything (manual `fnox lease create` only)

Omit `env_vars` to surface every `environmentVariables` entry. fnox won't auto-route individual keys through this lease — you must drive it explicitly:

```toml
[leases.everything]
type = "pulumi-esc"
organization = "my-org"
environment = "bundle"
```

```bash
fnox lease create everything
```

## Notes

- `organization`, `project`, and `environment` combine into the ESC reference `<org>/<project>/<env>`; `project` defaults to `default`.
- fnox opens the environment once per lease creation and reads the `environmentVariables` block from the response.
- The Pulumi Cloud API base URL is `PULUMI_BACKEND_URL`, else the `current` field in `~/.pulumi/credentials.json`, else `https://api.pulumi.com`. Non-HTTP backends (`s3://`, `file://`, ...) are skipped, since they aren't Pulumi Cloud.

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
- [Pulumi ESC provider](/providers/pulumi-esc) — for reading individual values by path
