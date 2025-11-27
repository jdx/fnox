# Fnox Development Guide

## Build & Test Commands

```bash
# Build (use mise tasks instead of direct cargo commands)
mise run build

# Run tests
mise run test

# Run cargo tests only
mise run test:cargo

# Run bats tests only
mise run test:bats

# Run full CI check (build, test, lint)
mise run ci

# Lint code
mise run lint

# Fix linting issues
mise run lint-fix
```

> **IMPORTANT**: Never use `--release` when building fnox locally. Always use `mise run build` or `cargo build` without the release flag for local development.

## Mise Tasks

The project uses mise for task management. Here are the available tasks:

- `mise run build` - Build the project (debug mode)
- `mise run test` - Run both cargo and bats tests
- `mise run test:cargo` - Run cargo tests only
- `mise run test:bats` - Run bats tests only (requires build)
- `mise run test:bats -- test/init.bats` - Run specific bats test file
- `mise run cargo-test` - Alias for cargo tests
- `mise run lint` - Run hk linting checks
- `mise run lint-fix` - Auto-fix linting issues
- `mise run ci` - Run full CI pipeline (build, test, lint)

### Task Dependencies

- `test` depends on `test:*` (runs both cargo and bats tests)
- `test:bats` depends on `build` (ensures project is built first)
- `ci` depends on `build`, `test`, and `lint`

### Running Specific Tests

You can run individual bats test files using the `test` argument:

```bash
# Run a specific test file
mise run test:bats -- test/init.bats

# Run multiple specific test files
mise run test:bats -- test/init.bats test/set.bats

# Run all tests in a subdirectory
mise run test:bats -- test/onepassword/
```

### Running 1Password Tests

The 1Password integration tests require the 1Password CLI and a valid service account token:

```bash
# 1. Install 1Password CLI
brew install 1password-cli

# 2. Run the 1Password tests
#    The mise task automatically decrypts and loads secrets via fnox exec
mise run test:bats -- test/onepassword.bats
```

**Note**:

- Tests will automatically skip if `OP_SERVICE_ACCOUNT_TOKEN` is not available
- The token can be stored encrypted in fnox.toml using the age provider
- `mise run test:bats` automatically runs `fnox exec` which decrypts provider-based secrets
- Tests create and delete temporary items in the "fnox" vault during execution

### Running Bitwarden Tests

The Bitwarden integration tests use a local vaultwarden server for testing without requiring a Bitwarden account:

```bash
# 1. Start local vaultwarden server and configure bw CLI
source ./test/setup-bitwarden-test.sh

# 2. Follow on-screen instructions to:
#    - Create account at http://localhost:8080
#    - Login: bw login
#    - Unlock: export BW_SESSION=$(bw unlock --raw)

# 3. Run the Bitwarden tests
mise run test:bats -- test/bitwarden.bats
```

**Note**:

- Tests will automatically skip if `BW_SESSION` is not available
- The `list` test runs without authentication
- Vaultwarden is a lightweight, open-source Bitwarden-compatible server
- Tests create and delete temporary items in your vault during execution
- See test/BITWARDEN_TESTING.md for detailed documentation

**CI Behavior**:

- On Ubuntu runners: vaultwarden service starts, tests run if account is pre-created
- On macOS runners: Tests skip (Docker services not available)
- Tests skip gracefully when BW_SESSION is not available (similar to 1Password tests)

### Running Infisical Tests

The Infisical integration tests require an Infisical account and service token:

```bash
# 1. Install Infisical CLI
brew install infisical/get-cli/infisical

# 2. Get a service token from Infisical
#    - Go to your Infisical project settings
#    - Navigate to "Service Tokens"
#    - Create a new token with read/write permissions for dev environment
#    - Copy the token (st.xxx.yyy.zzz format)

# 3. Export the token
export INFISICAL_TOKEN="st.xxx.yyy.zzz"

# 4. Optionally store it encrypted for reuse
fnox set INFISICAL_TOKEN "st.xxx.yyy.zzz" --provider age

# 5. Run the Infisical tests
mise run test:bats -- test/infisical.bats
```

**Note**:

- Tests will automatically skip if `INFISICAL_TOKEN` is not available
- The `list` test runs without authentication
- Tests create and delete temporary secrets in your Infisical project
- Secret names are prefixed with `FNOX_TEST_` and include timestamps for uniqueness

**CI Behavior**:

- GitHub Actions uses self-hosted Infisical (similar to Vaultwarden for Bitwarden):
  - On Ubuntu runners:
    1. Docker Compose starts Infisical with PostgreSQL and Redis
    2. Setup script (`test/setup-infisical-ci.sh`) creates test account and project
    3. Service token is automatically generated and exported
    4. Tests run against local Infisical instance (no external dependencies)
  - On macOS runners: Tests skip (Docker Compose services not available)
- Self-hosted setup ensures:
  - No external Infisical account needed for CI
  - Tests are isolated and reproducible
  - Faster test execution (local instance)
  - No risk of API rate limits or token exposure
- Tests clean up created secrets, but orphaned secrets may remain if tests fail

## Code Style Guidelines

### Imports & Dependencies

- Use `anyhow::Result` for error handling in commands
- Use `thiserror` for custom error types
- Prefer `tracing` over `println!` for logging
- Use `async-trait` for provider interfaces
- Keep dependencies minimal

### Naming Conventions

- Modules: `snake_case` (e.g., `age_encryption.rs`)
- Structs/Enums: `PascalCase` (e.g., `GetCommand`)
- Functions/Variables: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- CLI args: `kebab-case` with `--` prefix

### Error Handling

- Use `FnoxError` enum for domain-specific errors
- Implement `From` traits for automatic conversions
- Use `anyhow` for command-level error context
- Always return `Result<T>` from async functions

### Code Organization

- Commands in `src/commands/` - one file per command
- Providers in `src/providers/` - implement `Provider` trait
- Encryption methods in `src/encryption/`
- Config parsing in `src/config.rs`
- Environment variables in `src/env.rs` - centralized env var handling
- Use `mod.rs` for module exports

### Environment Variables

- Use centralized `env.rs` module following the pattern from mise/hk
- All environment variables use `FNOX_` prefix
- Use `LazyLock` for lazy initialization and caching
- Available environment variables:
  - `FNOX_PROFILE`: Profile to use (default: "default")
  - `FNOX_CONFIG_DIR`: Configuration directory (default: ~/.config/fnox)
  - `FNOX_AGE_KEY`: Age encryption key
- Import with `use crate::env;` and access via `env::FNOX_*` constants
- Avoid direct `std::env::` calls throughout the codebase

### Config Structure

- Use `profiles` for environment-specific configuration
- Default secrets go in top-level `[secrets]` section
- Named profiles in `[profiles.name]` sections
- Each profile can have its own providers and encryption
- Environment variable: `FNOX_PROFILE`
- Local overrides: `fnox.local.toml` (gitignored) is loaded alongside `fnox.toml` and takes precedence
- Profile-specific config files: `fnox.$FNOX_PROFILE.toml` (e.g., `fnox.production.toml`, `fnox.staging.toml`)
- Config recursion: searches parent directories for `fnox.toml` files
- Local config works with config recursion: both files are merged in each directory before recursing upward

**Config file loading order (later files override earlier ones):**

1. `fnox.toml` (base config)
2. `fnox.$FNOX_PROFILE.toml` (profile-specific config, if `FNOX_PROFILE` is set and not "default")
3. `fnox.local.toml` (local overrides)

Note: Profile-specific config files (`fnox.$FNOX_PROFILE.toml`) work with the default profile's secrets, not `[profiles.xxx]` sections. They're useful for environment-specific overrides that you want to commit to version control, while `fnox.local.toml` is for machine-specific overrides that should be gitignored.

### Secret Configuration

Secrets support an `if_missing` field to control behavior when a secret cannot be resolved:

```toml
[secrets]
MY_SECRET = { provider = "age", value = "...", if_missing = "warn" }  # Options: "error", "warn", "ignore"
```

**Default behavior**: When `if_missing` is not specified, fnox defaults to `"warn"`. This means:

- Missing secrets will print a warning message
- Commands will continue execution (useful for CI environments where some secrets may not be available)
- The secret will not be set in the environment

**Available options**:

- `"error"` - Fail the command if the secret cannot be resolved (use for required secrets)
- `"warn"` - Print a warning and continue (default, useful for optional secrets)
- `"ignore"` - Silently skip the secret if it cannot be resolved

**Example use case**: In forked PRs, CI environments don't have access to secrets. Using `if_missing = "warn"` (or omitting it for the default) allows tests to run without failing on missing secrets.

### CLI Flags

- `-P, --profile` for profile selection
- `-p, --provider` for provider specification
- `-d, --description` for secret descriptions
- `-k, --key-name` for provider key names

### Async Patterns

- All commands are async functions
- Use `tokio::main` for entry point
- Provider methods should be async
- Handle cancellation properly

### Testing

- Integration tests in `tests/` directory
- Use `tempfile` for test isolation
- Test both success and error cases
- Mock external services in tests
- Bats tests in `test/` directory for CLI integration testing

## Provider Implementation

### 1Password Provider

The 1Password provider integrates with the 1Password CLI (`op`) to retrieve secrets from 1Password vaults.

**Configuration:**

```toml
[providers]
onepass = { type = "1password", vault = "my-vault", account = "my.1password.com" }  # account is optional

[secrets]
# Retrieves password field
MY_SECRET = { provider = "onepass", value = "item-name" }

# OR retrieves specific field
MY_SECRET = { provider = "onepass", value = "item-name/username" }

# OR full op:// reference
MY_SECRET = { provider = "onepass", value = "op://vault/item/field" }
```

**Requirements:**

- 1Password CLI installed: `brew install 1password-cli`
- Service account token set in environment: `export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)`
- Or store token encrypted in fnox config using age provider

**Reference Formats:**

- `item-name` - Gets the `password` field from the item
- `item-name/field` - Gets a specific field (e.g., `username`, `password`)
- `op://vault/item/field` - Full 1Password reference URI

**Usage:**

```bash
# Export the token first
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)

# Then retrieve secrets
fnox get MY_SECRET
```

**Implementation Notes:**

- Uses `op read` command to fetch secrets
- Automatically constructs `op://` references from vault + value
- Supports custom fields and full op:// URIs
- Token can be stored encrypted with age provider for bootstrapping

### Bitwarden Provider

The Bitwarden provider integrates with the Bitwarden CLI (`bw`) to retrieve secrets from Bitwarden or compatible servers (like vaultwarden).

**Configuration:**

```toml
[providers]
bitwarden = { type = "bitwarden", collection = "my-collection-id", organization_id = "my-org-id" }  # collection and organization_id are optional

[secrets]
# Retrieves password field
MY_SECRET = { provider = "bitwarden", value = "item-name" }

# OR retrieves specific field
MY_SECRET = { provider = "bitwarden", value = "item-name/username" }
```

**Requirements:**

- Bitwarden CLI installed (installed via mise)
- Session token set in environment: `export BW_SESSION=$(bw unlock --raw)`
- Or store token encrypted in fnox config: `fnox set BW_SESSION "$(bw unlock --raw)" --provider age`

**Reference Formats:**

- `item-name` - Gets the `password` field from the item
- `item-name/field` - Gets a specific field (e.g., `username`, `password`, `notes`, `uri`, `totp`)

**Usage:**

```bash
# Login to Bitwarden
bw login

# Unlock and export session
export BW_SESSION=$(bw unlock --raw)

# Retrieve secrets
fnox get MY_SECRET

# Use in shell commands
fnox exec -- ./my-app
```

**Implementation Notes:**

- Uses `bw get` command to fetch secrets
- Supports standard fields: password, username, notes, uri, totp
- Custom field extraction not yet implemented
- Session token can be stored encrypted for bootstrapping
- Supports collection and organization filtering

**Testing with Vaultwarden:**

For local development and testing without a Bitwarden account:

```bash
# Start local vaultwarden server
source ./test/setup-bitwarden-test.sh

# Follow on-screen instructions to create account and login
# Then run tests
mise run test:bats -- test/bitwarden.bats
```

See test/BITWARDEN_TESTING.md for complete testing documentation.

### AWS KMS Provider

The AWS KMS provider uses AWS Key Management Service to encrypt and decrypt secrets using customer-managed keys.

**Configuration:**

```toml
[providers.kms]
type = "aws-kms"
key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
region = "us-east-1"

[secrets]
MY_SECRET = { provider = "kms", value = "base64-encoded-ciphertext" }  # Encrypted value stored in config
```

**Requirements:**

- AWS credentials configured (via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, AWS CLI profile, or IAM role)
- KMS key with appropriate permissions:
  - `kms:Encrypt` - for encrypting secrets with `fnox set`
  - `kms:Decrypt` - for decrypting secrets with `fnox get`
  - `kms:DescribeKey` - for connection testing

**Usage:**

```bash
# Set up provider in fnox.toml
fnox provider add kms --type aws-kms \
  --key-id "arn:aws:kms:us-east-1:123456789012:key/..." \
  --region us-east-1

# Encrypt and store a secret (encrypts with KMS and stores ciphertext)
fnox set MY_SECRET "my-secret-value" --provider kms

# Retrieve and decrypt a secret
fnox get MY_SECRET

# Use in shell commands
fnox exec -- ./my-app
```

**How it works:**

1. **Encryption (`fnox set`)**: When setting a secret with an AWS KMS provider, fnox:
   - Calls KMS `Encrypt` API with the plaintext value and specified key
   - Stores the base64-encoded ciphertext in the config file
   - The plaintext never touches the config file

2. **Decryption (`fnox get`)**: When retrieving a secret:
   - Decodes the base64 ciphertext from config
   - Calls KMS `Decrypt` API to recover the plaintext
   - Returns the decrypted value

**Implementation Notes:**

- Uses AWS SDK for Rust (`aws-sdk-kms`)
- Ciphertext is stored as base64 in config files for readability
- Respects standard AWS credential chain (environment variables, profiles, IAM roles)
- Region must be specified in provider config
- Key ID can be ARN, key ID, or alias (e.g., `alias/my-key`)
- Connection testing via `DescribeKey` API call

### AWS Secrets Manager Provider

The AWS Secrets Manager provider retrieves secrets stored remotely in AWS Secrets Manager.

**Configuration:**

```toml
[providers]
sm = { type = "aws-sm", region = "us-east-1", prefix = "fnox/" }  # prefix is optional

[secrets]
MY_SECRET = { provider = "sm", value = "my-secret-name" }  # Name of secret in AWS Secrets Manager
```

**Requirements:**

- AWS credentials configured (via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, AWS CLI profile, or IAM role)
- IAM permissions:
  - `secretsmanager:GetSecretValue` - for retrieving secrets (can be scoped to specific ARNs)
  - `secretsmanager:DescribeSecret` - for connection testing (can be scoped to specific ARNs)
  - `secretsmanager:ListSecrets` - for connection testing (**must use `"Resource": "*"`**, cannot be scoped)
  - For testing: `secretsmanager:CreateSecret`, `secretsmanager:PutSecretValue`, `secretsmanager:DeleteSecret`

**Example IAM Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListSecretsPermission",
      "Effect": "Allow",
      "Action": "secretsmanager:ListSecrets",
      "Resource": "*"
    },
    {
      "Sid": "SecretsManagerPermissions",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:PutSecretValue",
        "secretsmanager:CreateSecret",
        "secretsmanager:UpdateSecret",
        "secretsmanager:DeleteSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:fnox/*",
        "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:fnox-test/*"
      ]
    }
  ]
}
```

**Usage:**

```bash
# Set up provider in fnox.toml
fnox provider add sm --type aws-sm \
  --region us-east-1 \
  --prefix fnox/

# Add secret reference (fnox just stores the reference, not the value)
cat >> fnox.toml << EOF
[secrets]
MY_SECRET = { provider = "sm", value = "my-secret-name" }
EOF

# Retrieve secret from AWS Secrets Manager
fnox get MY_SECRET

# Use in shell commands
fnox exec -- ./my-app
```

**How it works:**

1. **Storage**: Secrets are stored remotely in AWS Secrets Manager
2. **Config**: fnox.toml only contains the secret name/reference (not the actual value)
3. **Retrieval**: When you run `fnox get`, it calls AWS Secrets Manager API to fetch the current value
4. **Prefix**: If configured, the prefix is prepended to the secret name (e.g., `value = "db-password"` becomes `fnox/db-password`)

**Implementation Notes:**

- Uses AWS SDK for Rust (`aws-sdk-secretsmanager`)
- Supports JSON secrets (returns the full JSON string)
- Only supports string secrets (binary secrets not supported)
- Respects standard AWS credential chain
- Region must be specified in provider config
- Prefix is optional but recommended for namespacing
- Connection testing via `ListSecrets` API call

### AWS Parameter Store Provider

The AWS Parameter Store provider retrieves secrets stored remotely in AWS Systems Manager Parameter Store.

**Configuration:**

```toml
[providers]
ps = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/prod/" }  # prefix is optional

[secrets]
DATABASE_URL = { provider = "ps", value = "database/url" }  # Resolves to /myapp/prod/database/url
```

**Requirements:**

- AWS credentials configured (via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, AWS CLI profile, or IAM role)
- IAM permissions:
  - `ssm:GetParameter` - for retrieving individual parameters
  - `ssm:GetParameters` - for batch retrieval (more efficient)
  - `ssm:DescribeParameters` - for connection testing
  - For storing: `ssm:PutParameter`

**Example IAM Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ParameterStoreRead",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:DescribeParameters"
      ],
      "Resource": ["arn:aws:ssm:REGION:ACCOUNT_ID:parameter/myapp/*"]
    },
    {
      "Sid": "ParameterStoreWrite",
      "Effect": "Allow",
      "Action": ["ssm:PutParameter"],
      "Resource": ["arn:aws:ssm:REGION:ACCOUNT_ID:parameter/myapp/*"]
    }
  ]
}
```

**Usage:**

```bash
# Set up provider in fnox.toml
fnox provider add ps aws-ps

# Add secret reference
cat >> fnox.toml << EOF
[secrets]
DATABASE_URL = { provider = "ps", value = "database/url" }
EOF

# Store a secret in Parameter Store
fnox set MY_SECRET "my-secret-value" --provider ps

# Retrieve secret from AWS Parameter Store
fnox get MY_SECRET

# Use in shell commands
fnox exec -- ./my-app
```

**How it works:**

1. **Storage**: Secrets are stored remotely in AWS Parameter Store as SecureString parameters
2. **Config**: fnox.toml only contains the parameter name/reference (not the actual value)
3. **Retrieval**: When you run `fnox get`, it calls Parameter Store API with automatic decryption
4. **Prefix**: If configured, the prefix is prepended to the parameter path (e.g., `value = "database/url"` becomes `/myapp/prod/database/url`)
5. **Hierarchical**: Supports path-based organization for logical grouping

**Implementation Notes:**

- Uses AWS SDK for Rust (`aws-sdk-ssm`)
- Automatically decrypts SecureString parameters
- Stores new values as SecureString type for security
- Supports batch retrieval (up to 10 parameters per call)
- Respects standard AWS credential chain
- Region must be specified in provider config
- Prefix is optional but recommended for namespacing
- Connection testing via `DescribeParameters` API call

**Comparison with AWS Secrets Manager:**

| Feature    | Parameter Store               | Secrets Manager                 |
| ---------- | ----------------------------- | ------------------------------- |
| Cost       | Free for standard params      | ~$0.40/secret/month             |
| Max size   | 4KB (8KB for advanced)        | 64KB                            |
| Rotation   | Manual                        | Built-in rotation               |
| Versioning | Limited                       | Full versioning                 |
| Hierarchy  | Path-based (`/a/b/c`)         | Flat with tags                  |
| Best for   | Config values, simple secrets | Complex secrets, rotation needs |

### Keychain Provider

The Keychain provider stores secrets in the operating system's native secure storage (macOS Keychain, Windows Credential Manager, Linux Secret Service).

**Configuration:**

```toml
[providers]
keychain = { type = "keychain", service = "fnox", prefix = "myapp/" }  # prefix is optional

[secrets]
MY_SECRET = { provider = "keychain", value = "my-secret-name" }  # Key name in keychain, not the actual value
```

**Requirements:**

- macOS: Keychain Access (built-in)
- Windows: Credential Manager (built-in)
- Linux: Secret Service (via libsecret)
- Interactive session with keychain access (may not work in headless/CI environments)

**Usage:**

```bash
# Set up provider in fnox.toml
cat >> fnox.toml << EOF
[providers]
keychain = { type = "keychain", service = "fnox", prefix = "myapp/" }
EOF

# Store a secret in OS keychain (encrypts and stores in keychain)
fnox set MY_SECRET "my-secret-value" --provider keychain

# Retrieve secret from OS keychain
fnox get MY_SECRET

# Use in shell commands
fnox exec -- ./my-app
```

**How it works:**

1. **Storage**: Secrets are stored remotely in the OS native keychain/credential manager
2. **Config**: fnox.toml only contains the secret name/reference (not the actual value)
3. **Retrieval**: When you run `fnox get`, it calls the OS keychain API to fetch the current value
4. **Prefix**: If configured, the prefix is prepended to the secret name (e.g., `value = "api-key"` becomes `myapp/api-key`)
5. **Service**: The service name acts as a namespace to isolate fnox secrets from other applications

**Implementation Notes:**

- Uses `keyring` crate v3 with platform-specific features
- Cross-platform: Works on macOS, Windows, and Linux
- Supports both read and write operations (RemoteStorage capability)
- Service name provides isolation between different applications
- Prefix provides additional namespacing within a service
- Connection testing via keychain read/write/delete test
- May require GUI/interactive session on some platforms
- Tests automatically skip in CI/headless environments where keychain isn't accessible

### Password-Store Provider

The password-store provider integrates with the standard Unix password manager (`pass`) to store and retrieve secrets from GPG-encrypted files.

**Configuration:**

```toml
[providers]
pass = { type = "password-store", prefix = "fnox/", store_dir = "/path/to/custom/store" }  # all fields optional

[secrets]
MY_SECRET = { provider = "pass", value = "my-secret-name" }  # Path to secret in password-store
```

**Requirements:**

- `pass` CLI installed (password-store): `brew install pass` or `apt install pass`
- GPG key configured for encryption
- Initialized password store: `pass init <gpg-key-id>`

**Reference Format:**

- `secret-name` - Gets the secret at the path (e.g., `~/.password-store/secret-name.gpg`)
- `path/to/secret` - Gets the secret at a nested path (e.g., `~/.password-store/path/to/secret.gpg`)
- Prefix is automatically prepended if configured

**Usage:**

```bash
# Initialize password-store (one time setup)
pass init <your-gpg-key-id>

# Set up provider in fnox.toml
cat >> fnox.toml << EOF
[providers]
pass = { type = "password-store", prefix = "fnox/" }
EOF

# Store a secret in password-store
fnox set MY_SECRET "my-secret-value" --provider pass

# Retrieve secret from password-store
fnox get MY_SECRET

# Use in shell commands
fnox exec -- ./my-app

# Store with nested path
fnox set DB_PASSWORD "db-pass" --provider pass --key-name "database/production"
```

**How it works:**

1. **Storage**: Secrets are stored as GPG-encrypted files in `~/.password-store/` (or custom `PASSWORD_STORE_DIR`)
2. **Config**: fnox.toml only contains the secret path/reference (not the actual value)
3. **Encryption**: When you run `fnox set`, it calls `pass insert` to GPG-encrypt and store the secret
4. **Retrieval**: When you run `fnox get`, it calls `pass show` to decrypt and retrieve the secret
5. **Prefix**: If configured, the prefix is prepended to the secret path (e.g., `value = "api-key"` becomes `fnox/api-key`)
6. **Hierarchy**: Supports nested paths for organizing secrets (e.g., `work/github/token`)

**Implementation Notes:**

- Uses `pass` CLI for all operations (consistent with 1Password/Bitwarden approach)
- Cross-platform: Works on macOS, Linux, and Windows (with WSL or Cygwin)
- Supports both read and write operations (RemoteStorage capability)
- Respects `PASSWORD_STORE_DIR` environment variable for custom locations
- Respects `PASSWORD_STORE_GPG_OPTS` for custom GPG options
- Multiline secrets are fully supported
- Connection testing via `pass ls`
- Git integration: password-store can automatically commit changes to a git repo

**Environment Variables:**

- `FNOX_PASSWORD_STORE_DIR` or `PASSWORD_STORE_DIR` - Custom password store directory
- `FNOX_PASSWORD_STORE_GPG_OPTS` or `PASSWORD_STORE_GPG_OPTS` - Custom GPG options
- Pass inherits all standard GPG environment variables

**Advantages:**

- Local-first: No cloud service required
- Open standard: Uses GPG encryption (widely trusted)
- Git-friendly: Encrypted files can be safely committed to version control
- Portable: Easy to sync across machines using git
- Transparent: Files are just GPG-encrypted text files
- Ecosystem: Many third-party tools and integrations exist

### Infisical Provider

The Infisical provider integrates with Infisical using the official Rust SDK to retrieve secrets from Infisical projects and environments.

**Configuration:**

```toml
[providers]
infisical = { type = "infisical", project_id = "your-project-id", environment = "dev", path = "/" }  # all fields optional; if omitted, Infisical CLI uses its own defaults (project from auth, environment="dev", path="/")

[secrets]
# Retrieves secret from Infisical
MY_SECRET = { provider = "infisical", value = "SECRET_NAME" }
```

**Requirements:**

- Machine identity with Universal Auth configured in Infisical
- Client ID set in environment: `export INFISICAL_CLIENT_ID="your-client-id"`
- Client secret set in environment: `export INFISICAL_CLIENT_SECRET="your-client-secret"`
- Or store credentials encrypted in fnox config using age provider
- Project ID must be configured in the provider

**Creating Universal Auth Credentials:**

1. In Infisical, go to Project Settings → Machine Identities
2. Create a new Machine Identity
3. Attach "Universal Auth" authentication method
4. Note the Client ID and create a Client Secret
5. Add the identity to your project with appropriate permissions

**Reference Format:**

- `SECRET_NAME` - Gets the secret with this name from the configured project/environment/path

**Usage:**

```bash
# Export the credentials first
export INFISICAL_CLIENT_ID=$(fnox get INFISICAL_CLIENT_ID)
export INFISICAL_CLIENT_SECRET=$(fnox get INFISICAL_CLIENT_SECRET)

# Then retrieve secrets
fnox get MY_SECRET

# Use in shell commands
fnox exec -- ./my-app
```

**How it works:**

1. **Storage**: Secrets are stored remotely in Infisical
2. **Config**: fnox.toml only contains the secret name/reference (not the actual value)
3. **Authentication**: Uses Universal Auth (Client ID + Client Secret) to authenticate
4. **Retrieval**: When you run `fnox get`, the CLI authenticates and fetches the current value
5. **Scoping**: Project ID (optional), environment, and path can be configured in the provider to scope secret lookups

**Implementation Notes:**

- Uses official Infisical CLI (consistent with 1Password/Bitwarden providers)
- Supports project-level, environment-level, and path-level scoping
- Credentials can be stored encrypted with age provider for bootstrapping
- Connection testing via CLI authentication
- For self-hosted Infisical instances, set `INFISICAL_API_URL` environment variable
- Token caching avoids repeated authentication

### KeePass Provider

The KeePass provider stores secrets in a local KeePass database file (`.kdbx`), supporting KDBX4 format with read/write operations.

**Configuration:**

```toml
[providers]
keepass = { type = "keepass", database = "~/secrets.kdbx" }
# OR with keyfile
keepass = { type = "keepass", database = "~/secrets.kdbx", keyfile = "~/keyfile.key" }

[secrets]
# Retrieves password field (default)
MY_SECRET = { provider = "keepass", value = "entry-name" }

# OR retrieves specific field
MY_SECRET = { provider = "keepass", value = "entry-name/username" }

# OR with group path
MY_SECRET = { provider = "keepass", value = "group/subgroup/entry-name" }

# OR group path with specific field
MY_SECRET = { provider = "keepass", value = "group/entry-name/notes" }
```

**Requirements:**

- KeePass database password set via environment variable:
  - `FNOX_KEEPASS_PASSWORD` (preferred), or
  - `KEEPASS_PASSWORD`
- Or password configured in provider config (not recommended for security)
- Optional keyfile for additional security

**Reference Formats:**

- `entry-name` - Gets the `password` field from the entry (searches all groups)
- `entry-name/field` - Gets a specific field (e.g., `username`, `password`, `url`, `notes`)
- `group/entry-name` - Gets password from entry in specific group
- `group/subgroup/entry-name/field` - Full path with group hierarchy and field

**Supported Fields:**

- `password` (default) - Entry password
- `username` - Entry username
- `url` - Entry URL
- `notes` - Entry notes
- `title` - Entry title (read-only)

**Usage:**

```bash
# Set the database password
export FNOX_KEEPASS_PASSWORD="my-master-password"

# Store a secret in KeePass database
fnox set MY_SECRET "my-secret-value" --provider keepass

# Store with specific entry/field path
fnox set MY_SECRET "my-username" --provider keepass --key-name "myapp/username"

# Retrieve secret from KeePass
fnox get MY_SECRET

# Use in shell commands
fnox exec -- ./my-app
```

**How it works:**

1. **Storage**: Secrets are stored in a local `.kdbx` database file
2. **Config**: fnox.toml contains the entry name/path (not the actual secret value)
3. **Auto-creation**: Database and group structure are created automatically if they don't exist
4. **Atomic writes**: Uses temporary files with sync-to-disk before rename to prevent data loss
5. **Protected fields**: Password fields are stored encrypted within KDBX format

**Implementation Notes:**

- Uses `keepass-rs` crate with KDBX4 save support
- Supports both read and write operations (RemoteStorage capability)
- Shell expansion supported for database path (`~` expands to home directory)
- Single-part entry names search recursively across all groups
- Title field is read-only (reserved for entry identification)
- Connection testing via database open/read test

### Running KeePass Tests

The KeePass integration tests use a temporary database created during test execution:

```bash
# Set the test password
export KEEPASS_PASSWORD="test-password"

# Run the KeePass tests
mise run test:bats -- test/keepass.bats
```

**Note**:

- Tests will automatically skip if `KEEPASS_PASSWORD` is not available
- Tests create and delete temporary databases during execution
- No external services required - tests are fully self-contained
