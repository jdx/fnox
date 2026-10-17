---
description: "Encrypt values in fnox.toml with a Google Cloud KMS key. Configure Application Default Credentials, the key path, and IAM roles."
---

# Google Cloud KMS

The `gcp-kms` provider encrypts values into `fnox.toml` with a Google Cloud KMS symmetric key. The ciphertext lives in your config, but both `fnox set` and every decryption call the Cloud KMS API.

|                     |                                                                 |
| ------------------- | --------------------------------------------------------------- |
| Config type         | `gcp-kms`                                                       |
| Storage             | Encrypted in config                                             |
| Writes (`fnox set`) | Yes                                                             |
| Requires            | Application Default Credentials and network access to Cloud KMS |

To keep values out of git entirely, use [Google Cloud Secret Manager](/providers/gcp-sm).

## Quick start

Create a key ring and an encryption key, or use existing ones:

```sh
gcloud kms keyrings create fnox --location us-central1
gcloud kms keys create fnox-key --keyring fnox --location us-central1 --purpose encryption
```

Add the provider:

```toml
[providers.gcpkms]
type = "gcp-kms"
project = "my-project"
location = "us-central1"
keyring = "fnox"
key = "fnox-key"
```

Store a value through the hidden prompt, then use it:

```sh
fnox set DATABASE_URL --provider gcpkms
fnox provider test gcpkms
fnox exec -- npm start
```

## Authentication

fnox uses [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) (ADC): `GOOGLE_APPLICATION_CREDENTIALS`, your `gcloud` ADC login, or the attached service account on Google Cloud.

### Local development

Run `gcloud auth application-default login`. When authentication fails in an interactive terminal, fnox offers to run that command; override it with [`auth_command`](/reference/configuration#auth-command).

### CI

Prefer [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) through your CI platform's auth step, which sets up ADC for later steps. A service account key file referenced by `GOOGLE_APPLICATION_CREDENTIALS` also works. See [CI/CD](/guide/ci).

## Configuration

| Field      | Required | Default | Description                                           |
| ---------- | -------- | ------- | ----------------------------------------------------- |
| `project`  | Yes      | None    | Google Cloud project ID that owns the key ring.       |
| `location` | Yes      | None    | Key ring location, such as `us-central1` or `global`. |
| `keyring`  | Yes      | None    | Key ring name.                                        |
| `key`      | Yes      | None    | Crypto key name.                                      |

fnox builds the key path `projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<key>`. All fields accept `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

## How values are stored

`fnox set` calls Cloud KMS `Encrypt` on the key and stores the base64-encoded ciphertext as the secret's `value`. Decryption calls `Decrypt` on the same key path:

```toml
[secrets]
DATABASE_URL = { provider = "gcpkms", value = "CiQAk3..." } # ciphertext, abbreviated
```

Encryption uses the key's primary version. Cloud KMS identifies the version from the ciphertext when decrypting, so rotating the key keeps old values readable as long as their versions stay enabled.

## Permissions

| Operation            | Permission                                | Role                                         |
| -------------------- | ----------------------------------------- | -------------------------------------------- |
| `fnox set`           | `cloudkms.cryptoKeyVersions.useToEncrypt` | `roles/cloudkms.cryptoKeyEncrypterDecrypter` |
| Reading secrets      | `cloudkms.cryptoKeyVersions.useToDecrypt` | `roles/cloudkms.cryptoKeyEncrypterDecrypter` |
| `fnox provider test` | `cloudkms.cryptoKeys.get`                 | `roles/cloudkms.viewer`                      |

Grant the encrypter/decrypter role on the key:

```sh
gcloud kms keys add-iam-policy-binding fnox-key \
  --keyring fnox --location us-central1 \
  --member "user:you@example.com" \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter
```

## Troubleshooting

### `PERMISSION_DENIED`

The identity lacks the permission named in the error. Check the key's bindings:

```sh
gcloud kms keys get-iam-policy fnox-key --keyring fnox --location us-central1
```

### `NOT_FOUND`

Check `project`, `location`, `keyring`, and `key` against `gcloud kms keys list --keyring fnox --location us-central1`.

### Could not load credentials

Run `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` for the fnox process.

## See also

- [Google Cloud Secret Manager](/providers/gcp-sm): store values in Google Cloud instead of in config.
- [GCP IAM lease](/leases/gcp-iam): mint short-lived Google Cloud access tokens.
- [age](/providers/age): encryption in config without a cloud dependency.
