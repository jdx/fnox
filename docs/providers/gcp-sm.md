# Google Cloud Secret Manager

GCP Secret Manager provides centralized secret management for Google Cloud workloads.

## When to Use

- ✅ Running on GCP infrastructure
- ✅ Need centralized secret management
- ✅ GCP IAM integration
- ✅ Audit logs required

::: info Storage Mode
This is **remote storage** - secrets live in GCP Secret Manager, not in your `fnox.toml`.
:::

## Quick Start

```bash
# 1. Enable Secret Manager API
gcloud services enable secretmanager.googleapis.com

# 2. Configure provider
cat >> fnox.toml << 'EOF'
[providers.gcp]
type = "gcp-sm"
project = "my-project-id"
prefix = "myapp/"
EOF

# 3. Create secret
echo -n "postgresql://..." | gcloud secrets create myapp-database-url --data-file=-

# 4. Reference in fnox
cat >> fnox.toml << 'EOF'
[secrets.DATABASE_URL]
provider = "gcp"
value = "database-url"
EOF

# 5. Get secret
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
[providers.gcp]
type = "gcp-sm"
project = "my-project-id"
prefix = "myapp/"  # Optional
```

## Pros

- ✅ Integrated with GCP IAM
- ✅ Audit logs
- ✅ Automatic replication
- ✅ Versioning

## Cons

- ❌ Requires GCP project
- ❌ Costs money
- ❌ Network access required

## Next Steps

- [GCP Cloud KMS](/providers/gcp-kms) - Encryption alternative
- [AWS Secrets Manager](/providers/aws-sm) - AWS equivalent
