---
description: "Impersonate a Google Cloud service account to create a temporary access token for a command."
---

# GCP IAM

The `gcp-iam` lease backend calls the [IAM Credentials API](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken) to generate a short-lived OAuth2 access token by impersonating a service account.

## Configuration

```toml
[leases.gcp]
type = "gcp-iam"
service_account_email = "my-sa@my-project.iam.gserviceaccount.com"
duration = "1h"
```

| Field                   | Required | Description                                                                       |
| ----------------------- | -------- | --------------------------------------------------------------------------------- |
| `service_account_email` | Yes      | Service account to impersonate                                                    |
| `scopes`                | No       | OAuth2 scopes (default: `["https://www.googleapis.com/auth/cloud-platform"]`)     |
| `env_var`               | No       | Environment variable name for the token (default: `"CLOUDSDK_AUTH_ACCESS_TOKEN"`) |
| `duration`              | No       | Lease duration (e.g., `"1h"`, `"30m"`; default: `"15m"`)                          |

## Prerequisites

The backend needs GCP credentials to call the IAM Credentials API. fnox looks for them in this order:

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable (path to service account JSON)
2. `GCP_SERVICE_ACCOUNT_KEY` environment variable
3. `~/.config/gcloud/application_default_credentials.json` (from `gcloud auth application-default login`)

If none are found, fnox prints:

```text
GCP credentials not found. Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS.
```

## Credentials produced

| Environment Variable         | Description         |
| ---------------------------- | ------------------- |
| `CLOUDSDK_AUTH_ACCESS_TOKEN` | OAuth2 access token |

The default `CLOUDSDK_AUTH_ACCESS_TOKEN` is used by the `gcloud` CLI. For a custom application, configure an environment variable and explicitly pass its value to the application's authentication library; do not assume every Google Cloud SDK reads an OAuth token from the environment.

```toml
# Field within [leases.gcp]
env_var = "MY_GCP_ACCESS_TOKEN"
```

## Limits

- **Max duration:** 1 hour for this backend
- **Revocation:** No-op — tokens expire automatically

## IAM setup

The calling identity needs the **Service Account Token Creator** role on the target service account:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  my-sa@my-project.iam.gserviceaccount.com \
  --member="user:you@example.com" \
  --role="roles/iam.serviceAccountTokenCreator"
```

The IAM Credentials API must be enabled:

```bash
gcloud services enable iamcredentials.googleapis.com --project=my-project
```

## Examples

### With stored credentials

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
GOOGLE_APPLICATION_CREDENTIALS = { provider = "op", value = "GCP SA/key file", as_file = true, env = false }

[leases.gcp]
type = "gcp-iam"
service_account_email = "my-sa@my-project.iam.gserviceaccount.com"
duration = "1h"
```

```bash
fnox exec -- gcloud storage ls
```

### With gcloud login

```bash
gcloud auth application-default login

# fnox picks up ADC automatically
fnox exec -- gcloud storage ls
```

### Custom scopes

```toml
[leases.gcp]
type = "gcp-iam"
service_account_email = "my-sa@my-project.iam.gserviceaccount.com"
scopes = [
  "https://www.googleapis.com/auth/cloud-platform",
  "https://www.googleapis.com/auth/bigquery"
]
```

## See also

- [Credential Leases](/guide/leases) — overview and approaches
- [GCP Secret Manager provider](/providers/gcp-sm) — for storing secrets in GCP
