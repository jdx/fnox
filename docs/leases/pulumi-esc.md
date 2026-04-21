# Pulumi ESC

The `pulumi-esc` lease backend vends short-lived credentials from a Pulumi ESC environment by running `esc env open` and surfacing the environment's resolved `environmentVariables` block.

This works with any ESC integration that mints dynamic credentials — AWS OIDC, GCP OIDC, Azure, Vault, and more. ESC handles the credential minting; fnox caches and re-issues on expiry.

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

| Field          | Required | Description                                                                                                 |
| -------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `organization` | Yes      | Pulumi organization name                                                                                    |
| `environment`  | Yes      | ESC environment name                                                                                        |
| `project`      | No       | ESC project name (omit for legacy `<org>/<env>` envs)                                                       |
| `token`        | No       | Pulumi access token (falls back to `PULUMI_ACCESS_TOKEN`)                                                   |
| `env_vars`     | No       | Filter: only surface these keys from `environmentVariables`. Required for auto-routing individual env vars. |
| `duration`     | No       | Advisory lease TTL (e.g. `"1h"`)                                                                            |

## Prerequisites

- The `esc` CLI installed (`brew install pulumi/tap/esc`)
- Authentication: `esc login` or `PULUMI_ACCESS_TOKEN` / `FNOX_PULUMI_ACCESS_TOKEN`

## Credentials Produced

Whatever keys appear under `environmentVariables` in the opened ESC environment. When `env_vars` is set, only those keys are surfaced (missing keys are logged as warnings).

## Limits

- **Max duration:** 1 hour. ESC-minted credentials are bounded by the underlying integration (AWS STS, GCP IAM, etc.), which typically cap at 1 hour.
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

[secrets]
AWS_ACCESS_KEY_ID     = { lease = "aws" }
AWS_SECRET_ACCESS_KEY = { lease = "aws" }
AWS_SESSION_TOKEN     = { lease = "aws" }
AWS_REGION            = { lease = "aws" }
```

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

- `organization`, `project`, and `environment` combine into the ESC reference: `<org>/<project>/<env>` or legacy `<org>/<env>`.
- fnox runs `esc env open <ref> --format json` once per lease creation and reads the `environmentVariables` map from the response.
- Values that aren't strings (numbers, booleans) are ignored — ESC-surfaced env vars are always strings in practice.

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
- [Pulumi ESC provider](/providers/pulumi-esc) — for reading individual values by path
