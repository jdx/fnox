---
description: "Read Google Cloud Secret Manager values with fnox. Configure project access, authentication, prefixes, and secret versions."
---

# Google Cloud Secret Manager

GCP Secret Manager provides centralized secret management for Google Cloud workloads.

## Quick start

```sh
# Enable Secret Manager API
gcloud services enable secretmanager.googleapis.com
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
gcp = { type = "gcp-sm", project = "my-project-id", prefix = "myapp-" }
```

```sh
# Create secret
echo -n "postgresql://..." | gcloud secrets create myapp-database-url --data-file=-
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[secrets]
DATABASE_URL = { provider = "gcp", value = "database-url" }
```

```sh
# Get secret
fnox get DATABASE_URL
```

## Authentication

Choose one:

```bash
# gcloud CLI (development)
gcloud auth application-default login

# Service Account (CI/CD)
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"

# Workload Identity (automatic on GKE)
# No configuration needed!
```

## Permissions

Grant IAM permissions:

```bash
gcloud projects add-iam-policy-binding PROJECT-ID \
  --member="user:your-email@example.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Configuration

```toml
[providers]
gcp = { type = "gcp-sm", project = "my-project-id", prefix = "myapp-" }  # prefix is optional
```

## Usage notes

The config stores a secret name in the selected project. The provider prefix is part of that name. Authentication uses Application Default Credentials; a separate gcloud CLI login is not always sufficient.

## Next steps

- [Google Cloud KMS](/providers/gcp-kms) - Encryption alternative
- [AWS Secrets Manager](/providers/aws-sm) - AWS equivalent
