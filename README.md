# 🔐 fnox

**Fort Knox for your secrets.**

[![CI](https://github.com/jdx/fnox/actions/workflows/ci.yml/badge.svg)](https://github.com/jdx/fnox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is fnox?

Secrets are done in 2 ways:

1. In git, encrypted (hopefully)
2. Remote, typically a cloud provider like AWS KMS

fnox works with either—or both! They've got their pros and cons. Either way, fnox gives you a
nice front-end to manage secrets and make them easy to work with in dev/ci/prod.

fnox's config file, `fnox.toml`, will either contain the encrypted secrets, or a reference to a secret in a cloud provider. You can either use `fnox exec -- <command>` to run a command with the secrets, or you can use the [shell integration](#shell-integration) to automatically load the secrets into your shell environment when you `cd` into a directory with a `fnox.toml` file.

## Supported Providers

fnox works with all the things:

### 🔐 Encryption (secrets in git, encrypted)

- `age` - Modern encryption (works with SSH keys!)
- `aws-kms` - AWS Key Management Service
- `azure-kms` - Azure Key Vault encryption
- `gcp-kms` - Google Cloud KMS

### ☁️ Cloud Secret Storage (remote, centralized)

- `aws-sm` - AWS Secrets Manager
- `azure-sm` - Azure Key Vault Secrets
- `gcp-sm` - Google Cloud Secret Manager
- `vault` - HashiCorp Vault

### 🔑 Password Managers

- `1password` - 1Password CLI
- `bitwarden` - Bitwarden/Vaultwarden

### 💻 Local Storage

- `keychain` - OS Keychain (macOS/Windows/Linux)
- `plain` - Plain text (for defaults only!)

## Installation

### Using mise (recommended)

The easiest way to install fnox is with [mise](https://mise.jdx.dev):

```bash
mise use -g fnox
```

### Using Cargo

```bash
cargo install fnox
```

### From Source

```bash
git clone https://github.com/jdx/fnox
cd fnox
cargo install --path .
```

## Quick Start

```bash
# Initialize fnox in your project
fnox init

# Set a secret (stores it encrypted in fnox.toml)
fnox set DATABASE_URL

# Get a secret
fnox get DATABASE_URL

# Run commands with secrets loaded as env vars
fnox exec -- npm start

# Enable shell integration (auto-load secrets on cd)
eval "$(fnox activate bash)"  # or zsh, fish
```

## How It Works

fnox uses a simple TOML config file (`fnox.toml`) that you check into git. Secrets are either:

1. **Encrypted inline** - The encrypted ciphertext lives in the config file
2. **Remote references** - The config contains a reference (like "my-db-password") that points to a secret in AWS/1Password/etc.

You configure providers (encryption methods or cloud services), then assign each secret to a provider. fnox handles the rest.

```toml
# fnox.toml
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[secrets.DATABASE_URL]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24uLi4="  # ← encrypted ciphertext, safe to commit

[secrets.API_KEY]
default = "dev-key-12345"  # ← plain default value for local dev
```

When you run `fnox get DATABASE_URL`, it decrypts the value using your age key. When you run `fnox exec`, all secrets are loaded as environment variables.

## Shell Integration

fnox can automatically load secrets when you `cd` into directories with a `fnox.toml` file:

```bash
# Enable it once
eval "$(fnox activate bash)"  # or zsh, fish

# Add to your shell config for persistence
echo 'eval "$(fnox activate bash)"' >> ~/.bashrc
```

Now secrets auto-load on directory changes:

```bash
~/projects $ cd my-app
fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET
~/projects/my-app $ cd ..
fnox: -3 DATABASE_URL, API_KEY, JWT_SECRET
```

Control the output with `FNOX_SHELL_OUTPUT`:

- `export FNOX_SHELL_OUTPUT=none` - Silent mode
- `export FNOX_SHELL_OUTPUT=normal` - Show count and keys (default)
- `export FNOX_SHELL_OUTPUT=debug` - Verbose debugging

Use profiles for different environments:

```bash
export FNOX_PROFILE=production
cd my-app  # Loads production secrets
```

## Why is this a standalone CLI and not part of mise?

mise has support for [encrypted secrets](https://mise.jdx.dev/environments/secrets/) but mise's design makes it a poor fit for remote secrets. mise reloads
its environment too frequently—whenever a directory is changed, `mise x` is run, a shim is called, etc. Any other use-case like this mise leverages caching
but secrets are an area where caching is a bad idea for obvious reasons. It might be possible to change mise's design to retain its environment in part to
better support something like this but that's a huge challenge.

Basically it's just too hard to get remote secrets to work effectively with mise so I made this a standalone tool.

---

## Providers: Complete Getting Started Guides

Each provider below is a complete standalone guide. Choose the ones that fit your workflow.

### Age Encryption

**Use age when:** You want secrets in git, encrypted, with minimal setup. Perfect for development secrets, open source projects, or teams that want secrets in version control.

**What is age?** A modern encryption tool by [@FiloSottile](https://github.com/FiloSottile/age). It's simple, secure, and works beautifully with SSH keys you already have.

#### Setup

1. **Generate an age key** (or use your existing SSH key):

```bash
# Option 1: Generate a new age key
age-keygen -o ~/.config/fnox/age.txt

# Option 2: Use your existing SSH key
# age can encrypt to SSH keys directly, no conversion needed
```

2. **Get your public key** (for encrypting secrets):

```bash
# If you generated an age key:
grep "public key:" ~/.config/fnox/age.txt
# Output: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# If using SSH key:
ssh-keygen -Y find-principals -s ~/.ssh/id_ed25519.pub
# Or just use the SSH public key directly!
```

3. **Configure fnox**:

```bash
fnox init

# Add the age provider (use your public key)
cat >> fnox.toml << 'EOF'
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
# Or for SSH key:
# recipients = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."]
EOF
```

4. **Set the decryption key** (your private key):

```bash
# If using age key:
export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")

# If using SSH key:
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519

# Add to your shell profile for persistence:
echo 'export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519' >> ~/.bashrc
```

#### Usage

```bash
# Encrypt and store a secret (automatically uses age provider)
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider age

# The resulting fnox.toml looks like:
# [secrets.DATABASE_URL]
# provider = "age"
# value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+I..."  # ← encrypted, safe to commit!

# Retrieve and decrypt
fnox get DATABASE_URL

# Run commands with decrypted secrets
fnox exec -- npm run dev
```

#### SSH Key Support

age has first-class support for SSH keys! Instead of managing separate age keys, just use your existing SSH keys:

```bash
# Encrypt to your SSH public key
[providers.age]
type = "age"
recipients = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQs..."]

# Decrypt with your SSH private key
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519
```

**Supported SSH Key Types:**

- **`ssh-ed25519`** - Ed25519 keys (recommended, most secure)
- **`ssh-rsa`** - RSA keys (2048-bit minimum, 4096-bit recommended)

**Key Formats:**

- **Public keys:** Use the full SSH public key format (`ssh-ed25519 AAAA...` or `ssh-rsa AAAA...`)
- **Private keys:** Standard OpenSSH private key format (`-----BEGIN OPENSSH PRIVATE KEY-----`)

> [!WARNING]
>
> Password-protected SSH keys are not supported. If your SSH key has a passphrase, you must create a copy without passphrase.

Works with `ssh-ed25519` and `ssh-rsa` keys. For teams, add multiple recipients:

```bash
[providers.age]
type = "age"
recipients = [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQs... # alice",
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBws... # bob",
  "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2el... # ci-bot"
]
```

Now Alice, Bob, and your CI system can all decrypt the secrets!

#### Team Workflow

1. **Everyone generates/shares public keys** (age or SSH)
2. **Add all public keys to `recipients` array** in fnox.toml
3. **Commit fnox.toml to git** (contains encrypted secrets)
4. **Each person sets their private key** via `FNOX_AGE_KEY` or `FNOX_AGE_KEY_FILE`
5. **Everyone can decrypt secrets** ✨

**Pros:**

- Secrets live in git (version control, code review)
- Works offline
- Zero runtime dependencies
- Free forever

**Cons:**

- Key rotation requires re-encrypting all secrets
- No audit logs
- No centralized access control

---

### 1Password

**Use 1Password when:** Your team already uses 1Password, or you want a polished password manager experience with great audit logs and access control.

#### Prerequisites

- [1Password account](https://1password.com)
- [1Password CLI](https://developer.1password.com/docs/cli) installed: `brew install 1password-cli`

#### Setup

1. **Create a service account** in 1Password:
   - Go to your [1Password account settings](https://my.1password.com)
   - Create a service account with read access to your vault
   - Copy the `OP_SERVICE_ACCOUNT_TOKEN`

2. **Store the token** (bootstrap with age!):

```bash
# First, set up age encryption (see age section above)
fnox init
# ... configure age provider ...

# Store the 1Password token encrypted in fnox
fnox set OP_SERVICE_ACCOUNT_TOKEN "ops_YOUR_TOKEN_HERE" --provider age

# Now you can bootstrap the token from fnox itself:
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
```

3. **Configure 1Password provider**:

```bash
cat >> fnox.toml << 'EOF'
[providers.onepass]
type = "1password"
vault = "Development"  # Your vault name
account = "my.1password.com"  # Optional
EOF
```

4. **Add secrets to 1Password** (via 1Password app or CLI):

```bash
# Create an item in 1Password
op item create --category=login \
  --title="Database" \
  --vault="Development" \
  password="super-secret-password"
```

5. **Reference secrets in fnox**:

```bash
cat >> fnox.toml << 'EOF'
[secrets.DATABASE_URL]
provider = "onepass"
value = "Database"  # ← Item name in 1Password (fetches 'password' field)

[secrets.DB_USERNAME]
provider = "onepass"
value = "Database/username"  # ← Specific field

[secrets.API_KEY]
provider = "onepass"
value = "op://Development/API Keys/credential"  # ← Full op:// URI
EOF
```

#### Usage

```bash
# Export the token (one-time per session)
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)

# Get secrets from 1Password
fnox get DATABASE_URL

# Run commands with 1Password secrets
fnox exec -- ./deploy.sh
```

#### Reference Formats

- `"item-name"` → Gets the `password` field
- `"item-name/field"` → Gets a specific field (username, password, etc.)
- `"op://vault/item/field"` → Full 1Password reference URI

**Pros:**

- Beautiful UI, great mobile apps
- Excellent audit logs and access control
- No encryption key management
- Team-friendly

**Cons:**

- Requires 1Password subscription
- Requires network access
- Service account token management

---

### Bitwarden

**Use Bitwarden when:** You want an open-source password manager, or you're already using Bitwarden/Vaultwarden.

#### Prerequisites

- [Bitwarden account](https://bitwarden.com) (or self-hosted Vaultwarden)
- Bitwarden CLI (automatically installed via mise)

#### Setup

1. **Login to Bitwarden**:

```bash
# Login
bw login

# Unlock and get session token
export BW_SESSION=$(bw unlock --raw)
```

2. **Store the session token** (optional, for bootstrap):

```bash
# Store encrypted with age
fnox set BW_SESSION "$(bw unlock --raw)" --provider age

# Next time, bootstrap from fnox:
export BW_SESSION=$(fnox get BW_SESSION)
```

3. **Configure Bitwarden provider**:

```bash
cat >> fnox.toml << 'EOF'
[providers.bitwarden]
type = "bitwarden"
collection = "my-collection-id"  # Optional
organization_id = "my-org-id"    # Optional
EOF
```

4. **Add secrets to Bitwarden** (via Bitwarden app or CLI):

```bash
# Create an item
bw create item --name "Database" --username "admin" --password "secret"
```

5. **Reference secrets in fnox**:

```bash
cat >> fnox.toml << 'EOF'
[secrets.DATABASE_URL]
provider = "bitwarden"
value = "Database"  # ← Item name (fetches 'password' field)

[secrets.DB_USERNAME]
provider = "bitwarden"
value = "Database/username"  # ← Specific field
EOF
```

#### Usage

```bash
# Unlock Bitwarden (once per session)
export BW_SESSION=$(bw unlock --raw)
# Or bootstrap: export BW_SESSION=$(fnox get BW_SESSION)

# Get secrets
fnox get DATABASE_URL

# Run commands
fnox exec -- npm start
```

#### Reference Formats

- `"item-name"` → Gets the `password` field
- `"item-name/field"` → Gets specific field (username, password, notes, uri, totp)

#### Testing with Vaultwarden

For local development without a Bitwarden account:

```bash
# Start local vaultwarden server
source ./test/setup-bitwarden-test.sh

# Follow on-screen instructions to create account and login
```

**Pros:**

- Open source
- Free for personal use
- Self-hosting option (Vaultwarden)
- Good audit logs

**Cons:**

- UI less polished than 1Password
- Session token expires (need to unlock regularly)

---

### AWS Secrets Manager

**Use AWS Secrets Manager when:** You're running on AWS infrastructure and want centralized secret management with IAM access control, audit logs, and automatic rotation.

**Note:** This is _remote storage_ - secrets live in AWS, not in your config file. Your fnox.toml only contains _references_ to the secret names.

#### Prerequisites

- AWS account
- AWS credentials configured (CLI, environment variables, or IAM role)
- IAM permissions (see below)

#### Setup

1. **Create IAM policy** for secret access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListSecrets",
      "Effect": "Allow",
      "Action": "secretsmanager:ListSecrets",
      "Resource": "*"
    },
    {
      "Sid": "ReadSecrets",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:myapp/*"
    }
  ]
}
```

2. **Configure AWS credentials**:

```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-east-1"

# Option 2: AWS CLI profile
aws configure

# Option 3: IAM role (if running on EC2/ECS/Lambda)
# Credentials are automatic!
```

3. **Configure fnox provider**:

```bash
cat >> fnox.toml << 'EOF'
[providers.aws]
type = "aws-sm"
region = "us-east-1"
prefix = "myapp/"  # Optional: prepended to all secret names
EOF
```

4. **Create secrets in AWS Secrets Manager**:

```bash
# Via AWS CLI
aws secretsmanager create-secret \
  --name "myapp/database-url" \
  --secret-string "postgresql://prod.db.example.com/mydb"

aws secretsmanager create-secret \
  --name "myapp/api-key" \
  --secret-string "sk_live_abc123xyz789"
```

5. **Reference secrets in fnox**:

```bash
cat >> fnox.toml << 'EOF'
[secrets.DATABASE_URL]
provider = "aws"
value = "database-url"  # ← With prefix, becomes "myapp/database-url"

[secrets.API_KEY]
provider = "aws"
value = "api-key"  # ← With prefix, becomes "myapp/api-key"
EOF
```

#### Usage

```bash
# Secrets are fetched from AWS on-demand
fnox get DATABASE_URL

# Run commands (fetches all secrets from AWS)
fnox exec -- ./start-server.sh

# Use different profiles for different environments
fnox exec --profile production -- ./deploy.sh
```

#### How It Works

- **Storage:** Secrets live in AWS Secrets Manager (NOT in fnox.toml)
- **Config:** fnox.toml contains only the secret name/reference
- **Retrieval:** Running `fnox get` calls AWS API to fetch the current value
- **Prefix:** If configured, the prefix is prepended (e.g., `value = "db-url"` → fetches `myapp/db-url`)

**Pros:**

- Centralized secret management
- IAM access control
- CloudTrail audit logs
- Automatic rotation support
- Secrets never in git

**Cons:**

- Requires AWS account and network access
- Costs money ($0.40/secret/month + $0.05/10k API calls)
- More complex setup than encryption

---

### AWS KMS

**Use AWS KMS when:** You want secrets _in git_ (encrypted), but with AWS-managed encryption keys and IAM access control. Different from Secrets Manager - this stores _encrypted ciphertext_ in fnox.toml.

**Note:** This is _local encryption_ - the encrypted ciphertext lives in your fnox.toml file. AWS KMS is only called to encrypt/decrypt.

#### Prerequisites

- AWS account
- AWS credentials configured
- KMS key created
- IAM permissions (see below)

#### Setup

1. **Create KMS key**:

```bash
# Via AWS CLI
aws kms create-key \
  --description "fnox secrets encryption" \
  --key-usage ENCRYPT_DECRYPT

# Note the KeyId from output
```

Or use AWS Console → KMS → Create Key.

2. **Create IAM policy**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"
    }
  ]
}
```

3. **Configure AWS credentials** (same as Secrets Manager above)

4. **Configure fnox provider**:

```bash
cat >> fnox.toml << 'EOF'
[providers.kms]
type = "aws-kms"
key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
region = "us-east-1"
EOF
```

5. **Encrypt and store secrets**:

```bash
# fnox calls AWS KMS to encrypt, then stores ciphertext in config
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider kms

# The resulting fnox.toml contains encrypted ciphertext:
# [secrets.DATABASE_URL]
# provider = "kms"
# value = "AQICAHhw...base64...ciphertext..."  # ← Encrypted, safe to commit!
```

#### Usage

```bash
# Decrypt (calls AWS KMS)
fnox get DATABASE_URL

# Run commands (decrypts all secrets)
fnox exec -- npm start
```

#### How It Works

1. **Encryption (`fnox set`):** Calls AWS KMS `Encrypt` API, stores base64 ciphertext in fnox.toml
2. **Decryption (`fnox get`):** Calls AWS KMS `Decrypt` API to recover plaintext
3. **IAM Control:** Access controlled via KMS key policies and IAM permissions

**Pros:**

- Secrets in git (version control)
- AWS-managed encryption keys
- IAM access control and CloudTrail audit logs
- No monthly per-secret charges

**Cons:**

- Requires AWS account and network access
- Costs money ($1/key/month + $0.03/10k operations)
- More complex than age encryption

**AWS KMS vs AWS Secrets Manager:**

- **KMS:** Encrypted secrets IN your fnox.toml (like age, but with AWS keys)
- **Secrets Manager:** Secrets stored IN AWS, fnox.toml has references only

---

### Azure Key Vault

**Use Azure Key Vault when:** You're on Azure and want centralized secret management.

Azure provides two services: Key Vault **Secrets** (remote storage) and Key Vault **Keys** (encryption). fnox supports both.

#### Azure Key Vault Secrets (Remote Storage)

**Use when:** You want secrets stored in Azure, not in git.

##### Prerequisites

- Azure subscription
- Key Vault created
- Azure credentials configured
- Permissions (see below)

##### Setup

1. **Create Key Vault**:

```bash
# Via Azure CLI
az keyvault create \
  --name "myapp-vault" \
  --resource-group "myapp-rg" \
  --location "eastus"
```

2. **Assign permissions**:

```bash
# Assign yourself access (for testing)
az keyvault set-policy \
  --name "myapp-vault" \
  --upn "your-email@example.com" \
  --secret-permissions get list

# Or use RBAC (recommended):
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "user@example.com" \
  --scope "/subscriptions/SUB-ID/resourceGroups/myapp-rg/providers/Microsoft.KeyVault/vaults/myapp-vault"
```

3. **Configure Azure authentication**:

```bash
# Option 1: Azure CLI (for development)
az login

# Option 2: Service Principal (for CI/CD)
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_TENANT_ID="..."

# Option 3: Managed Identity (automatic on Azure VMs/Functions)
# No configuration needed!
```

4. **Configure fnox provider**:

```bash
cat >> fnox.toml << 'EOF'
[providers.azure]
type = "azure-sm"
vault_url = "https://myapp-vault.vault.azure.net/"
prefix = "myapp/"  # Optional
EOF
```

5. **Create secrets in Key Vault**:

```bash
# Via Azure CLI
az keyvault secret set \
  --vault-name "myapp-vault" \
  --name "myapp-database-url" \
  --value "postgresql://prod.example.com/db"
```

6. **Reference secrets in fnox**:

```bash
cat >> fnox.toml << 'EOF'
[secrets.DATABASE_URL]
provider = "azure"
value = "database-url"  # ← With prefix, becomes "myapp-database-url"
EOF
```

##### Usage

```bash
# Fetch from Azure Key Vault
fnox get DATABASE_URL

# Run commands
fnox exec -- ./app
```

**Pros:**

- Centralized management
- Azure RBAC integration
- Audit logs
- Managed rotation

**Cons:**

- Requires Azure subscription
- Costs money
- Requires network access

#### Azure Key Vault Keys (Encryption)

**Use when:** You want secrets _in git_ (encrypted), but with Azure-managed keys.

##### Setup

1. **Create Key Vault with key**:

```bash
az keyvault key create \
  --vault-name "myapp-vault" \
  --name "encryption-key" \
  --protection software
```

2. **Assign crypto permissions**:

```bash
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee "user@example.com" \
  --scope "/subscriptions/.../vaults/myapp-vault"
```

3. **Configure fnox**:

```bash
cat >> fnox.toml << 'EOF'
[providers.azurekms]
type = "azure-kms"
vault_url = "https://myapp-vault.vault.azure.net/"
key_name = "encryption-key"
EOF
```

4. **Encrypt secrets**:

```bash
# Encrypts with Azure Key Vault, stores ciphertext in fnox.toml
fnox set DATABASE_URL "secret-value" --provider azurekms
```

**How it works:** Similar to AWS KMS - ciphertext stored in config, Azure Key Vault only called for encrypt/decrypt operations.

---

### Google Cloud Secret Manager

**Use GCP Secret Manager when:** You're on Google Cloud and want centralized secret management.

Like AWS, Google provides **Secret Manager** (remote storage) and **Cloud KMS** (encryption). fnox supports both.

#### GCP Secret Manager (Remote Storage)

**Use when:** You want secrets stored in GCP, not in git.

##### Prerequisites

- GCP project
- gcloud CLI or service account
- IAM permissions (see below)

##### Setup

1. **Enable Secret Manager API**:

```bash
gcloud services enable secretmanager.googleapis.com
```

2. **Configure authentication**:

```bash
# Option 1: gcloud CLI (for development)
gcloud auth application-default login

# Option 2: Service Account (for CI/CD)
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"

# Option 3: Workload Identity (automatic on GKE)
# No configuration needed!
```

3. **Grant IAM permissions**:

```bash
# Grant yourself access
gcloud projects add-iam-policy-binding PROJECT-ID \
  --member="user:your-email@example.com" \
  --role="roles/secretmanager.secretAccessor"
```

4. **Configure fnox provider**:

```bash
cat >> fnox.toml << 'EOF'
[providers.gcp]
type = "gcp-sm"
project = "my-project-id"
prefix = "myapp/"  # Optional
EOF
```

5. **Create secrets in Secret Manager**:

```bash
# Via gcloud CLI
echo -n "postgresql://prod.example.com/db" | \
  gcloud secrets create myapp-database-url \
    --data-file=-

# Or via Console: https://console.cloud.google.com/security/secret-manager
```

6. **Reference secrets in fnox**:

```bash
cat >> fnox.toml << 'EOF'
[secrets.DATABASE_URL]
provider = "gcp"
value = "database-url"  # ← With prefix, becomes "myapp-database-url"
EOF
```

##### Usage

```bash
# Fetch from GCP
fnox get DATABASE_URL

# Run commands
fnox exec -- ./app
```

**Pros:**

- Integrated with GCP IAM
- Audit logs
- Automatic replication
- Versioning

**Cons:**

- Requires GCP project
- Costs money
- Requires network access

#### Google Cloud KMS (Encryption)

**Use when:** You want secrets _in git_ (encrypted), but with GCP-managed keys.

##### Setup

1. **Create keyring and key**:

```bash
# Enable Cloud KMS
gcloud services enable cloudkms.googleapis.com

# Create keyring
gcloud kms keyrings create "fnox-keyring" \
  --location="us-central1"

# Create key
gcloud kms keys create "fnox-key" \
  --keyring="fnox-keyring" \
  --location="us-central1" \
  --purpose="encryption"
```

2. **Grant permissions**:

```bash
gcloud kms keys add-iam-policy-binding "fnox-key" \
  --keyring="fnox-keyring" \
  --location="us-central1" \
  --member="user:your-email@example.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
```

3. **Configure fnox**:

```bash
cat >> fnox.toml << 'EOF'
[providers.gcpkms]
type = "gcp-kms"
project = "my-project-id"
location = "us-central1"
keyring = "fnox-keyring"
key = "fnox-key"
EOF
```

4. **Encrypt secrets**:

```bash
# Encrypts with GCP KMS, stores ciphertext in fnox.toml
fnox set DATABASE_URL "secret-value" --provider gcpkms
```

**How it works:** Similar to AWS KMS - ciphertext in config, KMS only for encrypt/decrypt.

---

### HashiCorp Vault

**Use Vault when:** You're already running Vault, or you need advanced features like dynamic secrets, secret leasing, or complex access policies.

#### Prerequisites

- Vault server running (self-hosted or HCP Vault)
- Vault CLI installed: `brew install vault`
- Vault token with appropriate policies

#### Setup

1. **Configure Vault access**:

```bash
# Set Vault address
export VAULT_ADDR="https://vault.example.com:8200"

# Login and get token
vault login -method=userpass username=myuser

# Export token
export VAULT_TOKEN="hvs.CAESIJ..."
```

2. **Create Vault policy**:

```hcl
# policy.hcl
path "secret/data/myapp/*" {
  capabilities = ["read"]
}

path "secret/metadata/myapp/*" {
  capabilities = ["list"]
}
```

```bash
vault policy write fnox-policy policy.hcl
```

3. **Configure fnox provider**:

```bash
cat >> fnox.toml << 'EOF'
[providers.vault]
type = "vault"
address = "https://vault.example.com:8200"
path = "secret/myapp"  # KV v2 mount path
# token = "hvs.CAESIJ..."  # Optional, can use VAULT_TOKEN env var instead
EOF
```

4. **Store secrets in Vault**:

```bash
# Via Vault CLI (KV v2 engine)
vault kv put secret/myapp/database url="postgresql://prod.example.com/db"
vault kv put secret/myapp/api-key value="sk_live_abc123"
```

5. **Reference secrets in fnox**:

```bash
cat >> fnox.toml << 'EOF'
[secrets.DATABASE_URL]
provider = "vault"
value = "database/url"  # ← Vault path + field

[secrets.API_KEY]
provider = "vault"
value = "api-key/value"
EOF
```

#### Usage

```bash
# Set token (once per session, or use VAULT_TOKEN env var)
export VAULT_TOKEN="hvs.CAESIJ..."

# Get secrets from Vault
fnox get DATABASE_URL

# Run commands
fnox exec -- ./app
```

**Pros:**

- Advanced features (dynamic secrets, leasing, rotation)
- Fine-grained access policies
- Audit logging
- Multi-cloud support
- Self-hosted option

**Cons:**

- Complex to set up and operate
- Requires running Vault infrastructure
- Token management

---

### OS Keychain

**Use Keychain when:** You want secrets stored securely on your local machine using the OS native credential store. Perfect for personal projects, local development, or storing tokens that bootstrap other providers.

#### What is it?

fnox can store secrets in your operating system's native secure storage:

- **macOS:** Keychain Access
- **Windows:** Credential Manager
- **Linux:** Secret Service (GNOME Keyring, KWallet, etc.)

Secrets are stored _outside_ fnox.toml, encrypted by the OS.

#### Setup

**Linux only:** Install libsecret:

```bash
# Ubuntu/Debian
sudo apt-get install libsecret-1-0 libsecret-1-dev

# Fedora/RHEL
sudo dnf install libsecret libsecret-devel

# Arch
sudo pacman -S libsecret
```

**All platforms:**

```bash
# Configure provider
cat >> fnox.toml << 'EOF'
[providers.keychain]
type = "keychain"
service = "fnox"  # Namespace for fnox secrets
prefix = "myapp/"  # Optional
EOF
```

#### Usage

```bash
# Store a secret in OS keychain
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keychain

# The fnox.toml only contains a reference:
# [secrets.DATABASE_URL]
# provider = "keychain"
# value = "database-url"  # ← Keychain entry name, not the actual secret

# Retrieve from keychain
fnox get DATABASE_URL

# Run commands
fnox exec -- npm run dev
```

#### How It Works

1. **Storage:** Secrets stored in OS credential manager (encrypted by OS)
2. **Config:** fnox.toml contains only the secret name, not the value
3. **Retrieval:** fnox queries the OS keychain API
4. **Service:** Acts as a namespace (isolates fnox secrets from other apps)
5. **Prefix:** Additional namespacing within the service

**Pros:**

- OS-managed encryption
- Cross-platform
- No external dependencies
- Free

**Cons:**

- Requires GUI/interactive session (doesn't work in headless CI)
- Not suitable for teams (secrets are per-machine)
- Keyring must be unlocked

**Use case example:** Store your `OP_SERVICE_ACCOUNT_TOKEN` in keychain, then bootstrap it for 1Password access:

```toml
[providers.keychain]
type = "keychain"
service = "fnox"

[secrets.OP_SERVICE_ACCOUNT_TOKEN]
provider = "keychain"
value = "op-token"
```

---

## Getting Started: A Real Example

Let's build a complete setup for a typical web app with development and production environments.

### The Scenario

You're building an API that needs:

- Database URL
- API keys
- JWT secret

**Requirements:**

- Development secrets: In git, encrypted (so team can clone and run)
- Production secrets: In AWS Secrets Manager (never in git)

### Step 1: Initialize

```bash
cd my-api
fnox init
```

This creates a `fnox.toml` file.

### Step 2: Set Up Age Encryption (for dev secrets)

```bash
# Generate age key
age-keygen -o ~/.config/fnox/age.txt

# Get your public key
grep "public key:" ~/.config/fnox/age.txt
# age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Configure age provider
cat >> fnox.toml << 'EOF'
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
EOF

# Set your private key in shell profile
echo 'export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")' >> ~/.bashrc
source ~/.bashrc
```

### Step 3: Add Dev Secrets

```bash
# Encrypt development secrets
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider age
fnox set JWT_SECRET "dev-jwt-secret-$(openssl rand -hex 32)" --provider age
fnox set STRIPE_KEY "sk_test_abc123" --provider age
```

Your `fnox.toml` now looks like:

```toml
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[secrets.DATABASE_URL]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..."  # encrypted

[secrets.JWT_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..."  # encrypted

[secrets.STRIPE_KEY]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..."  # encrypted
```

**Commit this!** It's encrypted, so it's safe to push to git.

### Step 4: Set Up Production (AWS Secrets Manager)

```bash
# Add production profile
cat >> fnox.toml << 'EOF'

[profiles.production]

[profiles.production.providers.aws]
type = "aws-sm"
region = "us-east-1"
prefix = "myapi/"

[profiles.production.secrets.DATABASE_URL]
provider = "aws"
value = "database-url"

[profiles.production.secrets.JWT_SECRET]
provider = "aws"
value = "jwt-secret"

[profiles.production.secrets.STRIPE_KEY]
provider = "aws"
value = "stripe-key"
EOF
```

Now create the secrets in AWS:

```bash
aws secretsmanager create-secret \
  --name "myapi/database-url" \
  --secret-string "postgresql://prod.rds.amazonaws.com/mydb"

aws secretsmanager create-secret \
  --name "myapi/jwt-secret" \
  --secret-string "$(openssl rand -base64 64)"

aws secretsmanager create-secret \
  --name "myapi/stripe-key" \
  --secret-string "sk_live_REAL_KEY_HERE"
```

### Step 5: Use It

**Development:**

```bash
# Enable shell integration (one time)
eval "$(fnox activate bash)"
echo 'eval "$(fnox activate bash)"' >> ~/.bashrc

# Now just cd into the project
cd my-api
# fnox: +3 DATABASE_URL, JWT_SECRET, STRIPE_KEY

# Run your app (secrets are already loaded!)
npm run dev

# Or explicitly:
fnox exec -- npm run dev
```

**Production:**

```bash
# Set AWS credentials (IAM role, or env vars)
export AWS_REGION=us-east-1

# Run with production profile
fnox exec --profile production -- node server.js
```

**CI/CD:**

```yaml
# .github/workflows/deploy.yml
name: Deploy
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v3 # you'll need a mise.toml with fnox configured

      - name: Setup age key
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
        run: |
          mkdir -p ~/.config/fnox
          echo "$FNOX_AGE_KEY" > ~/.config/fnox/age.txt
          chmod 600 ~/.config/fnox/age.txt

      - name: Deploy to production
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          fnox exec --profile production -- ./deploy.sh
```

### What Just Happened?

1. ✅ **Dev secrets** are encrypted in git → Team can clone and run immediately
2. ✅ **Prod secrets** are in AWS → Never in git, centrally managed
3. ✅ **Shell integration** → Secrets auto-load on `cd`
4. ✅ **CI/CD ready** → GitHub Actions can decrypt dev secrets and access AWS for prod
5. ✅ **Profiles** → Same fnox.toml, different environments

---

## Advanced Features

### Profiles

Organize secrets by environment:

```toml
# Default profile (dev)
[secrets.API_URL]
default = "http://localhost:3000"

# Staging profile
[profiles.staging.secrets.API_URL]
default = "https://staging.example.com"

# Production profile
[profiles.production.secrets.API_URL]
provider = "aws"
value = "api-url"
```

```bash
fnox get API_URL                           # dev
fnox get API_URL --profile staging         # staging
fnox get API_URL --profile production      # production
```

#### Profile Secret Inheritance

Profiles automatically inherit secrets defined at the top level, reducing configuration verbosity:

```toml
# Define secrets once at top level - all profiles inherit these
[secrets.LOG_LEVEL]
default = "info"

[secrets.API_TIMEOUT]
default = "30"

[secrets.DATABASE_URL]
provider = "age"
value = "encrypted-dev-db-url..."

# Staging profile inherits all top-level secrets
[profiles.staging]
# Automatically gets LOG_LEVEL, API_TIMEOUT, DATABASE_URL

# Production overrides specific secrets, inherits the rest
[profiles.production.secrets.DATABASE_URL]
provider = "aws"
value = "prod-db-url"  # Overrides top-level DATABASE_URL

[profiles.production.secrets.LOG_LEVEL]
default = "warn"  # Overrides top-level LOG_LEVEL
# Still inherits API_TIMEOUT from top level
```

**How it works:**

- Top-level `[secrets.*]` are inherited by all profiles
- Profile-specific secrets override inherited values
- Reduces duplication for secrets shared across environments

This is especially useful when managing many secrets where only a few differ between environments.

### Hierarchical Configuration

fnox searches parent directories for `fnox.toml` files and merges them:

```
project/
├── fnox.toml              # Root: age encryption, common secrets
└── services/
    └── api/
        └── fnox.toml      # API-specific secrets, inherits age config
```

Child configs override parent values. Great for monorepos!

### Configuration Imports

Split configs across files:

```toml
# fnox.toml
imports = ["./secrets/dev.toml", "./secrets/prod.toml"]

[providers.age]
type = "age"
recipients = ["age1..."]
```

```toml
# secrets/dev.toml
[secrets.DATABASE_URL]
provider = "age"
value = "encrypted..."
```

### Secret Resolution

fnox resolves secrets in this order:

1. **Encrypted value** (`provider = "age"`, `value = "encrypted..."`)
2. **Provider reference** (`provider = "aws"`, `value = "secret-name"`)
3. **Environment variable** (if `$ENV_VAR` exists)
4. **Default value** (`default = "fallback"`)

First match wins!

### Default Values

Set fallbacks for optional secrets:

```toml
[secrets.NODE_ENV]
default = "development"  # Used if not found elsewhere

[secrets.LOG_LEVEL]
default = "info"
if_missing = "warn"  # "error", "warn", or "ignore"
```

### Handling Missing Secrets

Control what happens when a secret can't be resolved using the `if_missing` setting. This is especially useful for CI environments or when some secrets are optional.

#### Available Modes

- `error` - Fail the command if a secret cannot be resolved (strictest)
- `warn` - Print a warning and continue (default)
- `ignore` - Silently skip missing secrets

#### Priority Chain

You can set `if_missing` at multiple levels. fnox uses the first match:

1. **CLI flag** (highest priority): `--if-missing error`
2. **Environment variable**: `FNOX_IF_MISSING=warn`
3. **Secret-level config**: `[secrets.MY_SECRET]` with `if_missing = "error"`
4. **Top-level config**: Global default for all secrets
5. **Base default environment variable**: `FNOX_IF_MISSING_DEFAULT=error`
6. **Default**: `warn` (lowest priority)

#### Examples

**Per-secret configuration:**

```toml
# Critical secrets must exist (fail if missing)
[secrets.DATABASE_URL]
provider = "aws"
value = "database-url"
if_missing = "error"

# Optional secrets (continue if missing)
[secrets.ANALYTICS_KEY]
provider = "aws"
value = "analytics-key"
if_missing = "ignore"
```

**Top-level default for all secrets:**

```toml
# Make all secrets strict by default
if_missing = "error"

[secrets.DATABASE_URL]
provider = "age"
value = "encrypted..."

[secrets.API_KEY]
provider = "age"
value = "encrypted..."
# ↑ Both inherit if_missing = "error"
```

**Runtime override with CLI:**

```bash
# Override config to be lenient (useful in CI with missing secrets)
fnox exec --if-missing ignore -- npm test

# Override to be strict (ensure all secrets are present)
fnox exec --if-missing error -- ./deploy.sh
```

**Runtime override with environment variable:**

```bash
# Set globally for a session
export FNOX_IF_MISSING=warn
fnox exec -- npm start

# Or inline
FNOX_IF_MISSING=error fnox exec -- ./critical-task.sh
```

**Set a base default behavior (when nothing is configured):**

```bash
# Change the default behavior when if_missing is not specified in config
# Useful for setting strict or lenient defaults across all projects
export FNOX_IF_MISSING_DEFAULT=error  # Strict: fail on missing secrets by default

# This affects only secrets without explicit if_missing configuration
# Config file settings (top-level or secret-level) will override this
fnox exec -- ./my-app
```

**CI/CD example:**

```yaml
# .github/workflows/test.yml
name: Test
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run tests (some secrets may be missing in forks)
        env:
          FNOX_IF_MISSING: ignore # Don't fail on missing secrets in CI
        run: |
          fnox exec -- npm test
```

### Import/Export

Migrate from `.env` files:

```bash
# Import from .env
fnox import --format env --source .env

# Export to various formats
fnox export --format json > secrets.json
fnox export --format yaml > secrets.yaml
fnox export --format toml > secrets.toml
```

### Commands Reference

#### Core Commands

- `fnox init` - Initialize fnox.toml
- `fnox get <KEY>` - Get a secret value
- `fnox set <KEY> [VALUE]` - Set a secret (encrypts if provider supports it)
- `fnox list` - List all secrets
- `fnox remove <KEY>` - Remove a secret
- `fnox exec -- <COMMAND>` - Run command with secrets as env vars
- `fnox export` - Export secrets in various formats
- `fnox import` - Import secrets from files

#### Management Commands

- `fnox provider list` - List all providers
- `fnox provider test <NAME>` - Test provider connection
- `fnox profiles` - List all profiles
- `fnox edit` - Open config in editor

#### Diagnostic Commands

- `fnox doctor` - Show diagnostic info
- `fnox check` - Verify all secrets are configured
- `fnox scan` - Scan for plaintext secrets in code

#### Shell Integration

- `fnox activate <SHELL>` - Generate shell activation code
- `fnox hook-env` - Internal command for shell hooks
- `fnox completion <SHELL>` - Generate completions

#### Developer Tools

- `fnox ci-redact` - Mask secrets in CI logs

## Environment Variables

- `FNOX_PROFILE` - Active profile (default: `default`)
- `FNOX_CONFIG_DIR` - Config directory (default: `~/.config/fnox`)
- `FNOX_AGE_KEY` - Age encryption key (alternative to file)
- `FNOX_AGE_KEY_FILE` - Path to age key file
- `FNOX_IF_MISSING` - Runtime override for missing secrets behavior (`error`, `warn`, `ignore`)
- `FNOX_IF_MISSING_DEFAULT` - Base default for missing secrets when not configured (`error`, `warn`, `ignore`)
- `FNOX_SHELL_OUTPUT` - Shell integration output (`none`, `normal`, `debug`)
