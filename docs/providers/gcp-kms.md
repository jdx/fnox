# Google Cloud KMS

Google Cloud KMS encrypts secrets using GCP-managed keys. The encrypted ciphertext is stored in your `fnox.toml` file.

## When to Use

- ✅ Secrets in git (encrypted)
- ✅ GCP-managed encryption keys
- ✅ GCP IAM integration
- ✅ GCP infrastructure

::: info Storage Mode
This is **local encryption** - the encrypted ciphertext lives in `fnox.toml`. Cloud KMS is only called to encrypt/decrypt.
:::

## Quick Start

```bash
# 1. Enable Cloud KMS and create key
gcloud services enable cloudkms.googleapis.com
gcloud kms keyrings create "fnox-keyring" --location="us-central1"
gcloud kms keys create "fnox-key" --keyring="fnox-keyring" --location="us-central1" --purpose="encryption"

# 2. Configure provider
cat >> fnox.toml << 'EOF'
[providers.gcpkms]
type = "gcp-kms"
project = "my-project-id"
location = "us-central1"
keyring = "fnox-keyring"
key = "fnox-key"
EOF

# 3. Encrypt a secret
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider gcpkms

# 4. Get secret (decrypts via KMS)
fnox get DATABASE_URL
```

## Permissions

Grant crypto permissions:

```bash
gcloud kms keys add-iam-policy-binding "fnox-key" \
  --keyring="fnox-keyring" \
  --location="us-central1" \
  --member="user:your-email@example.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
```

## Configuration

```toml
[providers.gcpkms]
type = "gcp-kms"
project = "my-project-id"
location = "us-central1"
keyring = "fnox-keyring"
key = "fnox-key"
```

## How It Works

Similar to [AWS KMS](/providers/aws-kms):

1. **Encryption:** Calls Cloud KMS, stores ciphertext in fnox.toml
2. **Decryption:** Calls Cloud KMS to recover plaintext

## Pros

- ✅ Secrets in git (version control)
- ✅ GCP-managed keys
- ✅ GCP IAM integration

## Cons

- ❌ Requires GCP project
- ❌ Costs money
- ❌ Network access required

## Next Steps

- [GCP Secret Manager](/providers/gcp-sm) - Remote storage alternative
- [Age Encryption](/providers/age) - Free local encryption
