---
description: "Impersonate a Google Cloud service account with fnox and inject a short-lived OAuth2 access token into commands."
---

# GCP IAM

The `gcp-iam` lease backend impersonates a service account through the [IAM Credentials API](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken) and injects the resulting access token into `fnox exec`. Use it to run `gcloud` or API calls as a service account without handing out its key.

|              |                                                                     |
| ------------ | ------------------------------------------------------------------- |
| Config type  | `gcp-iam`                                                           |
| Produces     | `CLOUDSDK_AUTH_ACCESS_TOKEN` (configurable with `env_var`)          |
| Max duration | 1 hour                                                              |
| Revocation   | None; tokens expire on their own                                    |
| Needs        | Google credentials with Service Account Token Creator on the target |

## Quick start

```toml
[leases.gcp]
type = "gcp-iam"
service_account_email = "deployer@my-project.iam.gserviceaccount.com"
duration = "1h"
```

```sh
gcloud auth application-default login
fnox exec -- gcloud storage ls
```

`gcloud` reads `CLOUDSDK_AUTH_ACCESS_TOKEN` directly. Other tools and client libraries generally do not read an access token from the environment; set `env_var` and pass the value to them explicitly.

## Bootstrap credentials

fnox gets the caller's token through Google's credential discovery, in this order: a service-account key file named by `GOOGLE_APPLICATION_CREDENTIALS`, the application-default credentials file from `gcloud auth application-default login`, the metadata server, then the `gcloud` CLI.

Before creating a lease, fnox checks that one of these exists, and skips the lease otherwise:

- `GOOGLE_APPLICATION_CREDENTIALS` is set
- `gcloud/application_default_credentials.json` exists in the platform config directory (`~/.config/gcloud/` on Linux)

To keep a service-account key in a provider, store the JSON as a secret with `as_file = true`. fnox writes it to a temporary file for lease creation and points `GOOGLE_APPLICATION_CREDENTIALS` at it; `env = false` keeps it out of the command:

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
GOOGLE_APPLICATION_CREDENTIALS = { provider = "op", value = "GCP SA/key file", as_file = true, env = false }
```

## Configuration

| Field                   | Required | Default                                              | Description                               |
| ----------------------- | -------- | ---------------------------------------------------- | ----------------------------------------- |
| `service_account_email` | Yes      | none                                                 | Service account to impersonate.           |
| `scopes`                | No       | `["https://www.googleapis.com/auth/cloud-platform"]` | OAuth2 scopes for the impersonated token. |
| `env_var`               | No       | `"CLOUDSDK_AUTH_ACCESS_TOKEN"`                       | Variable that receives the token.         |
| `duration`              | No       | `"15m"`                                              | Token lifetime, at most `"1h"`.           |

`scopes` limits what the leased token can do. The caller's own token always uses the `cloud-platform` scope to call the IAM Credentials API.

## Permissions

The calling identity needs `roles/iam.serviceAccountTokenCreator` on the target service account, and the IAM Credentials API must be enabled in the project:

```sh
gcloud iam service-accounts add-iam-policy-binding \
  deployer@my-project.iam.gserviceaccount.com \
  --member="user:you@example.com" \
  --role="roles/iam.serviceAccountTokenCreator"
gcloud services enable iamcredentials.googleapis.com --project=my-project
```

## Troubleshooting

### GCP credentials not found

Neither check above passed. Run `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` to a service-account key file. Under `fnox exec`, the lease is skipped with this warning unless a cached lease is still valid.

### Permission denied impersonating the service account

The caller lacks Service Account Token Creator on the target, or the IAM Credentials API is disabled. See [Permissions](#permissions).

### Lease duration exceeds maximum

`duration` is longer than one hour. Set it to `"1h"` or less.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [Google Cloud Secret Manager](/providers/gcp-sm): store secrets in Google Cloud and read them with the same credentials.
- [Lease commands](/cli/lease): create, list and revoke leases.
