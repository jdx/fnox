---
description: "Build an example development, staging, and production setup using age encryption, AWS Secrets Manager, and profiles."
---

# From development to production

Use age-encrypted development and staging values in git, then switch to AWS Secrets Manager for production. This example shows how the pieces fit together without requiring the application to know which provider it uses.

If all environments use an existing vault, start with [connect a vault](/guide/golden-path) instead.

## Prerequisites

- fnox and age installed; see the [quick start](/guide/quick-start).
- A project with a development command, such as `npm start`.
- An age identity for each teammate and for CI.
- AWS credentials, an AWS region, and permission to read the production secrets.

The example uses two secrets, `DATABASE_URL` and `JWT_SECRET`, plus the non-sensitive `LOG_LEVEL` setting. Replace names and commands with those used by your application.

## 1. Configure development encryption

Create the project configuration with `fnox init --skip-wizard`, then edit `fnox.toml`:

```toml
#:schema https://fnox.jdx.dev/schema.json
default_provider = "age"

[providers.age]
type = "age"
recipients = ["age1..."] # Replace with the public recipients of your team and CI

[secrets]
LOG_LEVEL = { default = "debug" }
```

Each teammate keeps their own private identity outside the repository. fnox reads `age.txt` from its configuration directory by default. See [age team setup](/providers/age#team-workflow) for other identity locations and multiple recipients.

Store the development values using hidden prompts:

```sh
fnox set DATABASE_URL
fnox set JWT_SECRET
fnox check --all
fnox exec -- npm start
```

`fnox set` adds encrypted values to `fnox.toml`. Review the file, then commit it. `LOG_LEVEL` remains plaintext because it is a default.

## 2. Add staging values

Select the staging profile when writing:

```sh
fnox set DATABASE_URL --profile staging --provider age
fnox set JWT_SECRET --profile staging --provider age
```

fnox writes under `[profiles.staging.secrets]`. Staging inherits `LOG_LEVEL` and the age provider from the top level.

```sh
fnox check --all --profile staging
fnox exec --profile staging -- ./deploy.sh
```

A profile changes configuration; it does not restrict who can decrypt. Use separate encryption providers and recipients if staging requires a different access boundary.

## 3. Reference production secrets

Create `myapi/database-url` and `myapi/jwt-secret` in AWS Secrets Manager using your normal provisioning process. Add the provider and references:

```toml
[profiles.production.providers.aws]
type = "aws-sm"
region = "us-east-1"
prefix = "myapi/"

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }
JWT_SECRET = { provider = "aws", value = "jwt-secret", if_missing = "error" }
LOG_LEVEL = { default = "info" }
```

These values are names, not ciphertext. No production plaintext goes into the config.

After authenticating to AWS:

```sh
fnox check --all --profile production
fnox exec --profile production --if-missing error -- ./deploy.sh
```

Use [`--no-defaults`](/guide/profiles#profile-inheritance) when you want production to include only its selected profile secrets. Otherwise it inherits any top-level secrets it does not override.

## 4. Keep personal overrides local

Add these patterns to the project's existing `.gitignore`:

```text
fnox.local.toml
.fnox.local.toml
.env
```

A developer can create `fnox.local.toml`:

```toml
[secrets]
DATABASE_URL = { default = "postgresql://localhost/alice_db" }
```

This local example has no password. Use an encryption provider or vault reference for a sensitive override.

Inspect which files and definitions are active:

```sh
fnox config-files
fnox list --sources
```

## 5. Run in CI

Install fnox and the application toolchain in the workflow before these steps. If mise manages the project tools, include fnox in `mise.toml` so the installation step knows to install it.

For development tests, supply the dedicated CI age identity through the CI secret store:

```yaml
- name: Test
  env:
    FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
  run: fnox --non-interactive exec --if-missing error -- npm test
```

The CI public recipient must have been included when the development secrets were encrypted. Adding it later requires re-encryption by someone who can already decrypt.

For production, authenticate the runner to AWS first, then run:

```yaml
- name: Deploy
  run: fnox --non-interactive exec --profile production --if-missing error -- ./deploy.sh
```

The [AWS Secrets Manager guide](/providers/aws-sm) covers credentials and read permissions. Never assume that setting `AWS_REGION` alone authenticates a runner.

## 6. Onboard a teammate

1. The teammate installs fnox and creates a personal age identity.
2. They share only the public recipient, from `age-keygen -y ~/.config/fnox/age.txt`.
3. A teammate with existing decryption access adds the recipient and re-encrypts each affected profile:

   ```sh
   fnox reencrypt --provider age --profile default
   fnox reencrypt --provider age --profile staging
   ```

4. Commit the new recipients and ciphertext. The new teammate pulls the changes and runs `fnox check --all`.
5. Grant production vault access separately if their role requires it.

Removing an age recipient affects future ciphertext only. Previously accessible secrets in git history remain decryptable, so rotate the underlying values when access must end.

## Next steps

- [Shell integration](/guide/shell-integration): load development secrets on directory change.
- [Hierarchical configuration](/guide/hierarchical-config): split common and service-specific settings.
- [Import and export](/guide/import-export): migrate existing `.env` values.
- [Credential leases](/guide/leases): use temporary credentials for supported services.
