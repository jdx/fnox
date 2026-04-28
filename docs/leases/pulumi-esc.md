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

| Field          | Required | Description                                                                                                                 |
| -------------- | -------- | --------------------------------------------------------------------------------------------------------------------------- |
| `organization` | Yes      | Pulumi organization name                                                                                                    |
| `environment`  | Yes      | ESC environment name                                                                                                        |
| `project`      | No       | ESC project name (omit for legacy `<org>/<env>` envs)                                                                       |
| `token`        | No       | Pulumi access token (falls back to `FNOX_PULUMI_ACCESS_TOKEN` / `PULUMI_ACCESS_TOKEN` / `~/.pulumi/credentials.json`)       |
| `env_vars`     | No       | Filter: only surface these keys from `environmentVariables`. Required for auto-routing individual env vars via `[secrets]`. |
| `interpolate`  | No       | Single char sigil (e.g. `"%"`) to enable `<sigil>{path}` reference resolution. See [Interpolation](#interpolation) below.   |
| `duration`     | No       | Advisory lease TTL (e.g. `"1h"`)                                                                                            |

## Prerequisites

- A Pulumi access token. Either set `PULUMI_ACCESS_TOKEN` / `FNOX_PULUMI_ACCESS_TOKEN`, or run `esc login` once to populate `~/.pulumi/credentials.json` (fnox reads that file directly — the `esc` CLI binary is not required at runtime).

## Credentials Produced

Whatever keys appear under `environmentVariables` in the opened ESC environment. When `env_vars` is set, only those keys are surfaced (missing keys are logged as warnings). Non-string scalars (booleans, numbers) are coerced to their JSON-string form so they can be exported as env vars.

## Interpolation

ESC supports composing and importing environments, but variable references like `%{anthropic.api_key}` are resolved at environment-definition time. The `interpolate` option gives you late binding instead: fnox walks the resolved `properties` tree and substitutes references at lease-creation time.

```toml
[leases.clara]
type = "pulumi-esc"
organization = "my-org"
project = "dev"
environment = "main"
interpolate = "%"
env_vars = ["ANTHROPIC_API_KEY"]
```

If the ESC environment defines `ANTHROPIC_API_KEY = "%{anthropic.api_key}"` in its `environmentVariables` block, fnox resolves the reference to the value at `properties.anthropic.value.api_key.value` before handing the credential to the subprocess.

**Rules:**

- The sigil is a single char (`"%"`, `"$"`, etc.) — you choose.
- Missing references are a hard error.
- Single pass only: `%{foo.%{bar}}` parses as `%{foo.%{bar}` (path `foo.%{bar`) and errors on lookup. No recursion into the replaced text.

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
- fnox opens the environment once per lease creation and reads the `environmentVariables` block from the response.
- The Pulumi Cloud API base URL comes from `PULUMI_BACKEND_URL` (env-var auth path) or the `current` field in `~/.pulumi/credentials.json` — self-hosted Pulumi Cloud works without extra config.

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
- [Pulumi ESC provider](/providers/pulumi-esc) — for reading individual values by path
