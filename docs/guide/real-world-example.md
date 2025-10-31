# Real-World Example

Let's build a complete setup for a typical web application with development, staging, and production environments.

## The Scenario

You're building an API that needs:

- Database URL
- API keys (Stripe, SendGrid)
- JWT secret
- External service URLs

**Requirements:**

- **Development:** Secrets in git (encrypted) so team can clone and run
- **Staging:** Secrets in git (encrypted) with staging values
- **Production:** Secrets in AWS Secrets Manager (never in git)

## Step 1: Initialize

```bash
cd my-api
fnox init
git init
```

## Step 2: Set Up Age Encryption (for Dev/Staging)

```bash
# Generate age key
age-keygen -o ~/.config/fnox/age.txt

# Get your public key
grep "public key:" ~/.config/fnox/age.txt
# Output: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# For teams: collect everyone's public keys and add them all
```

Add to `fnox.toml`:

```toml
# Shared age provider for dev and staging
[providers.age]
type = "age"
recipients = [
  "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",  # alice
  "age1pr3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqabc123",  # bob
  "age1zr3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqdxf456"   # ci
]
```

Set decryption key:

```bash
# Add to ~/.bashrc or ~/.zshrc
export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")
```

## Step 3: Add Development Secrets

```bash
# Encrypt development secrets
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider age
fnox set JWT_SECRET "$(openssl rand -hex 32)" --provider age
fnox set STRIPE_KEY "sk_test_abc123" --provider age
fnox set SENDGRID_KEY "SG.test123" --provider age
```

Your `fnox.toml` now contains encrypted secrets:

```toml
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }

[secrets]
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }
JWT_SECRET = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }
STRIPE_KEY = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }
SENDGRID_KEY = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }
```

**Commit this!** It's encrypted and safe.

```bash
git add fnox.toml
git commit -m "Add encrypted development secrets"
```

## Step 4: Add Staging Profile

Add staging secrets (also encrypted):

```bash
# Switch to staging profile
fnox set DATABASE_URL "postgresql://staging.db.example.com/mydb" \
  --provider age \
  --profile staging

fnox set JWT_SECRET "$(openssl rand -hex 32)" \
  --provider age \
  --profile staging

fnox set STRIPE_KEY "sk_test_staging_xyz" \
  --provider age \
  --profile staging

fnox set SENDGRID_KEY "SG.staging456" \
  --provider age \
  --profile staging
```

Your `fnox.toml` now has a staging profile:

```toml
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }

# Development (default profile)
[secrets]
DATABASE_URL = { provider = "age", value = "..." }
JWT_SECRET = { provider = "age", value = "..." }
# ... other dev secrets ...

# Staging profile
[profiles.staging.secrets]
DATABASE_URL = { provider = "age", value = "..." }
JWT_SECRET = { provider = "age", value = "..." }
# ... other staging secrets ...
```

## Step 5: Add Production Profile (AWS Secrets Manager)

Add production configuration (secrets stored in AWS):

```toml
# Add to fnox.toml

[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapi/" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }  # Critical secret
JWT_SECRET = { provider = "aws", value = "jwt-secret", if_missing = "error" }
STRIPE_KEY = { provider = "aws", value = "stripe-key", if_missing = "error" }
SENDGRID_KEY = { provider = "aws", value = "sendgrid-key", if_missing = "error" }
```

Create secrets in AWS:

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

aws secretsmanager create-secret \
  --name "myapi/sendgrid-key" \
  --secret-string "SG.REAL_KEY_HERE"
```

Commit the production references:

```bash
git add fnox.toml
git commit -m "Add production profile (AWS Secrets Manager)"
```

## Step 6: Local Overrides

Create `.gitignore`:

```bash
cat > .gitignore << 'EOF'
fnox.local.toml
.env
EOF
```

Each developer can create personal overrides:

```toml
# fnox.local.toml (not committed)

[secrets]
DATABASE_URL = { default = "postgresql://localhost/alice_db" }  # Personal DB
DEBUG_MODE = { default = "true" }  # Enable debugging
```

## Step 7: Use It

### Development

```bash
# Enable shell integration
eval "$(fnox activate bash)"
echo 'eval "$(fnox activate bash)"' >> ~/.bashrc

# Navigate to project (secrets auto-load)
cd my-api
# fnox: +4 DATABASE_URL, JWT_SECRET, STRIPE_KEY, SENDGRID_KEY

# Run the app
npm run dev
```

Or explicitly:

```bash
fnox exec -- npm run dev
```

### Staging

```bash
# Deploy to staging
fnox exec --profile staging -- ./deploy.sh

# Or set profile for session
export FNOX_PROFILE=staging
fnox exec -- ./deploy.sh
```

### Production

```bash
# Ensure AWS credentials are set
export AWS_REGION=us-east-1

# Deploy to production
fnox exec --profile production -- ./deploy.sh
```

## Step 8: CI/CD Setup

### GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v3 # Installs fnox via mise

      # Decrypt dev secrets for testing
      - name: Setup fnox
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
        run: |
          # Use the CI age key to decrypt secrets
          echo "FNOX_AGE_KEY is already set from secrets"

      - name: Run tests
        run: |
          fnox exec -- npm test

  deploy-staging:
    if: github.ref == 'refs/heads/develop'
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v3

      - name: Deploy to staging
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
        run: |
          fnox exec --profile staging -- ./deploy.sh

  deploy-production:
    if: github.ref == 'refs/heads/main'
    needs: test
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v3

      - name: Deploy to production
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_REGION: us-east-1
          FNOX_IF_MISSING: error # Fail if any secret is missing
        run: |
          fnox exec --profile production -- ./deploy.sh
```

### Set GitHub Secrets

1. Go to your repo → Settings → Secrets → Actions
2. Add `FNOX_AGE_KEY`:
   ```bash
   # Copy the CI age secret key (from the CI recipient's age.txt)
   cat ~/.config/fnox/ci-age.txt | grep "AGE-SECRET-KEY"
   ```
3. Add `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for production

## Step 9: Team Onboarding

New team member joins:

```bash
# 1. Clone the repo
git clone https://github.com/myorg/my-api
cd my-api

# 2. Install fnox (via mise)
mise install

# 3. Generate age key
age-keygen -o ~/.config/fnox/age.txt

# 4. Share public key with team
grep "public key:" ~/.config/fnox/age.txt
# Send to team lead to add to fnox.toml recipients

# 5. Set decryption key
echo 'export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")' >> ~/.bashrc
source ~/.bashrc

# 6. Enable shell integration
echo 'eval "$(fnox activate bash)"' >> ~/.bashrc

# 7. Team lead updates fnox.toml with new recipient
# Then re-encrypts all secrets:
fnox set DATABASE_URL "$(fnox get DATABASE_URL)" --provider age
# ... repeat for all secrets

# 8. New team member pulls and runs
git pull
cd my-api
# fnox: +4 DATABASE_URL, JWT_SECRET, STRIPE_KEY, SENDGRID_KEY
npm run dev  # Just works!
```

## File Structure

```
my-api/
├── .gitignore                 # fnox.local.toml, .env
├── fnox.toml                  # Committed (encrypted dev/staging, AWS refs for prod)
├── fnox.local.toml           # Gitignored (personal overrides)
├── package.json
├── src/
└── .github/
    └── workflows/
        └── ci.yml            # CI/CD with fnox
```

## Next Steps

- [Providers](/providers/overview) - Explore other providers
- [Shell Integration](/guide/shell-integration) - Advanced shell setup
- [Hierarchical Config](/guide/hierarchical-config) - Organize larger projects
