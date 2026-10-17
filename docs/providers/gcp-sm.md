---
description: "Read and write Google Cloud Secret Manager secrets with fnox using Application Default Credentials, name prefixes, and minimal IAM roles."
---

# Google Cloud Secret Manager

Store secrets in Google Cloud Secret Manager and keep only their names in `fnox.toml`. The provider reads and writes: `fnox set` creates the secret if needed and adds a new version.

|                     |                                                                              |
| ------------------- | ---------------------------------------------------------------------------- |
| Config type         | `gcp-sm`                                                                     |
| Storage             | Remote service                                                               |
| Writes (`fnox set`) | Yes                                                                          |
| Requires            | Application Default Credentials and network access to the Secret Manager API |

## Quick start

Create Application Default Credentials, then add a provider and store a value through the hidden prompt:

```sh
gcloud auth application-default login
```

```toml
[providers.gcp]
type = "gcp-sm"
project = "my-project-id"
prefix = "myapp-"
```

```sh
gcloud services enable secretmanager.googleapis.com --project my-project-id   # once per project
fnox set DATABASE_URL --provider gcp
```

This creates the secret `myapp-DATABASE_URL` and adds the reference to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "gcp", value = "DATABASE_URL" }
```

To use a secret that already exists, write the reference yourself with its ID minus the prefix. Then check it:

```sh
fnox provider test gcp
fnox exec -- ./start-server.sh
```

## Authentication

fnox uses [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials), found in this order:

1. The credentials file named by `GOOGLE_APPLICATION_CREDENTIALS`, such as a service account key or a workload identity federation config.
2. The user credentials written by `gcloud auth application-default login`.
3. The attached service account on Google Cloud, including GKE Workload Identity, Cloud Run and Compute Engine.

`gcloud auth login` on its own does not create Application Default Credentials. When authentication fails in an interactive terminal, fnox offers to run `gcloud auth application-default login`. Change that command with [`auth_command`](/reference/configuration#auth-command).

In CI, prefer workload identity federation over a service account key. See [CI/CD](/guide/ci).

## Configuration

| Field     | Required | Default | Description                                                 |
| --------- | -------- | ------- | ----------------------------------------------------------- |
| `project` | Yes      |         | Project ID that holds the secrets.                          |
| `prefix`  | No       |         | Prepended to every secret ID, for reads and for `fnox set`. |

`project` is always taken from the provider configuration, not from the credentials or `gcloud config`. Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

## Reference formats

A secret's `value` is the secret ID. fnox prepends the provider's `prefix` and reads the `latest` version.

| Provider `prefix` | `value`              | Version fnox reads                                                  |
| ----------------- | -------------------- | ------------------------------------------------------------------- |
| (none)            | `myapp-database-url` | `projects/my-project-id/secrets/myapp-database-url/versions/latest` |
| `myapp-`          | `database-url`       | `projects/my-project-id/secrets/myapp-database-url/versions/latest` |

Pinning a specific version is not supported. The payload must be valid UTF-8. A secret that holds JSON can be narrowed with [`json_path`](/reference/configuration#json-path).

When fnox resolves several secrets from one provider, it fetches them in parallel, up to 10 at a time.

## IAM permissions

| Operation            | Permission                                                                         | Predefined role                                      |
| -------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Read secrets         | `secretmanager.versions.access`                                                    | Secret Manager Secret Accessor                       |
| `fnox provider test` | `secretmanager.secrets.list`                                                       | Secret Manager Viewer                                |
| `fnox set`           | `secretmanager.versions.add`, plus `secretmanager.secrets.create` for a new secret | Secret Manager Secret Version Adder; Admin to create |

Grant read access on the project, or on individual secrets for tighter scope:

```sh
gcloud projects add-iam-policy-binding my-project-id \
  --member="user:you@example.com" \
  --role="roles/secretmanager.secretAccessor"
```

Secret Accessor alone cannot list secrets, so `fnox provider test` reports a permission error even when reads work. Use `fnox check` to verify the configured references instead. Secrets created by `fnox set` use automatic replication.

## Troubleshooting

### Credentials not found

Run `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` to a credentials file.

### Permission denied

The error names the missing permission. Check that the role is bound in the project from the provider's `project` field, which can differ from your `gcloud config` project.

### Secret not found

Check the composed ID, the provider's `prefix` followed by the secret's `value`, and confirm the secret has an enabled version:

```sh
gcloud secrets versions list myapp-database-url --project my-project-id
```

## See also

- [Google Cloud KMS](/providers/gcp-kms): keep ciphertext in `fnox.toml` instead of a remote store.
- [GCP IAM](/leases/gcp-iam): lease short-lived Google Cloud credentials to commands.
- [Connect a vault](/guide/existing-vault): add a local cache for offline reads.
