---
description: "Encrypt values in fnox.toml with Google Cloud KMS. Configure a key ring, key, credentials, and IAM permissions."
---

# Google Cloud KMS

Google Cloud KMS encrypts secrets using GCP-managed keys. The encrypted ciphertext is stored in your `fnox.toml` file.

## Quick start

Select your Google Cloud project and configure Application Default Credentials before following this example. The identity running fnox needs access to the key.

```sh
# Enable Cloud KMS and create key
gcloud services enable cloudkms.googleapis.com
gcloud kms keyrings create "fnox-keyring" --location="us-central1"
gcloud kms keys create "fnox-key" --keyring="fnox-keyring" --location="us-central1" --purpose="encryption"
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers.gcpkms]
type = "gcp-kms"
project = "my-project-id"
location = "us-central1"
keyring = "fnox-keyring"
key = "fnox-key"
```

```sh
# Encrypt a secret
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider gcpkms

# Get secret (decrypts via KMS)
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

## How it works

Similar to [AWS KMS](/providers/aws-kms):

1. **Encryption:** Calls Cloud KMS, stores ciphertext in fnox.toml
2. **Decryption:** Calls Cloud KMS to recover plaintext

## Usage notes

Ciphertext lives in your config. Decryption still requires network access and IAM permission on the Cloud KMS key. Keep the required key version available for existing ciphertext.

## Next steps

- [GCP Secret Manager](/providers/gcp-sm) - Remote storage alternative
- [Age Encryption](/providers/age) - Free local encryption
