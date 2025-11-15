# Bitwarden Testing with Vaultwarden

This directory contains tools for testing fnox's Bitwarden integration using a local vaultwarden server.

## Quick Start

```bash
# 1. Start the local vaultwarden server and configure bw CLI
source ./test/setup-bitwarden-test.sh

# 2. If this is your first time, follow the on-screen instructions to:
#    - Open https://localhost:8080 in your browser (accept self-signed certificate)
#    - Create an account
#    - Login with: bw login
#    - Unlock: export BW_SESSION=$(bw unlock --raw)

# 3. Run the tests
mise run test:bats -- test/bitwarden.bats
```

## What is Vaultwarden?

[Vaultwarden](https://github.com/dani-garcia/vaultwarden) is an unofficial, lightweight Bitwarden-compatible server written in Rust. It's perfect for:

- Local development and testing
- Self-hosting
- Running in resource-constrained environments

The official Bitwarden CLI (`bw`) works seamlessly with vaultwarden servers.

## Files

- `docker-compose.bitwarden.yml` - Docker Compose configuration for vaultwarden
- `setup-bitwarden-test.sh` - Helper script to start server and configure bw CLI
- `bitwarden.bats` - Integration tests for Bitwarden provider

## Manual Setup

If you prefer to set things up manually:

```bash
# Start vaultwarden
docker compose -f test/docker-compose.bitwarden.yml up -d

# Configure bw CLI to use local server (HTTPS required)
# Note: NODE_TLS_REJECT_UNAUTHORIZED=0 is set by the setup script to allow self-signed certificates
bw config server https://localhost:8080

# Create account via web UI (accept self-signed certificate warning)
open https://localhost:8080

# Login with bw CLI
bw login

# Unlock and export session
export BW_SESSION=$(bw unlock --raw)

# Run tests
mise run test:bats -- test/bitwarden.bats
```

## Cleanup

```bash
# Stop the server (preserves data)
docker compose -f test/docker-compose.bitwarden.yml down

# Stop and remove all data
docker compose -f test/docker-compose.bitwarden.yml down -v

# Reset bw CLI to official servers
bw config server bitwarden.com
```

## CI/CD Integration

The project includes automated Bitwarden testing in GitHub Actions using vaultwarden.

### How it works

On **Ubuntu runners** (Linux):

1. GitHub Actions starts a vaultwarden service container
2. The `setup-bitwarden-ci.sh` script runs before tests:
   - Waits for vaultwarden to be ready
   - Configures `bw` CLI to use the local server
   - Attempts to login with test credentials
   - If account exists: Logs in and exports `BW_SESSION`
   - If account doesn't exist: Exits gracefully, tests skip
3. Tests run with full Bitwarden integration (if account exists)

On **macOS runners**:

- Docker services are not available on macOS GitHub runners
- Tests automatically skip when `BW_SESSION` is not available
- This is expected behavior

### Database Pre-Seeding (Automated)

Bitwarden tests use a **pre-seeded database** for fully automated CI testing.

**How it works:**

1. A test database (`test/fixtures/vaultwarden-test.db`) is committed to the repository
2. The database contains a pre-created test account:
   - Email: `test@fnox.ci`
   - Password: `TestCIPassword123!`
3. The CI setup script automatically:
   - Copies the database into the vaultwarden container
   - Restarts vaultwarden to load the database
   - Logs in with the test account
   - Exports `BW_SESSION` for tests
4. Tests run with full authentication

**Benefits:**

- ✅ No manual setup required
- ✅ Fully automated testing
- ✅ Reproducible on every CI run
- ✅ Fast execution
- ✅ No secrets needed in CI configuration

**Regenerating the database:**

If you need to update the test database (e.g., after vaultwarden version changes):

```bash
# 1. Start fresh vaultwarden
docker compose -f test/docker-compose.bitwarden.yml up -d

# 2. Create account via web UI (accept self-signed certificate warning)
open https://localhost:8080
# Register with: test@fnox.ci / TestCIPassword123!

# 3. Extract database with WAL checkpoint
./test/extract-db-with-wal.sh

# 4. Commit the updated database
git add test/fixtures/vaultwarden-test.db
git commit -m "Update vaultwarden test database"
```

See `test/fixtures/README.md` for more details.

### GitHub Actions Setup

The workflow includes:

```yaml
services:
  vaultwarden:
    image: vaultwarden/server:latest
    ports:
      - 8080:80
    env:
      SIGNUPS_ALLOWED: "true"
      DISABLE_ADMIN_TOKEN: "true"

steps:
  - name: Setup Bitwarden for tests
    if: matrix.os == 'ubuntu-latest'
    run: |
      source ./test/setup-bitwarden-ci.sh
      echo "BW_SESSION=$BW_SESSION" >> $GITHUB_ENV
```

### Files

- `.github/workflows/ci.yml` - GitHub Actions workflow with vaultwarden service
- `test/setup-bitwarden-ci.sh` - Automated setup script for CI environments

### Testing CI changes locally

You can simulate the CI environment locally:

```bash
# Start vaultwarden
docker compose -f test/docker-compose.bitwarden.yml up -d

# Run the CI setup script
source ./test/setup-bitwarden-ci.sh

# Run tests
mise run test:bats -- test/bitwarden.bats

# Cleanup
docker compose -f test/docker-compose.bitwarden.yml down -v
```

## Troubleshooting

### "BW_SESSION not available"

Make sure you've:

1. Started vaultwarden: `docker compose -f test/docker-compose.bitwarden.yml up -d`
2. Configured bw CLI: `export NODE_TLS_REJECT_UNAUTHORIZED=0 && bw config server https://localhost:8080`
3. Created an account at https://localhost:8080 (accept self-signed certificate)
4. Logged in: `bw login`
5. Unlocked: `export BW_SESSION=$(bw unlock --raw)`

### "Cannot authenticate with Bitwarden"

Your session may have expired. Run:

```bash
export BW_SESSION=$(bw unlock --raw)
```

### "bw CLI not installed"

The Bitwarden CLI should be installed via mise. Check:

```bash
which bw
# Should show: ~/.local/share/mise/installs/bitwarden/*/bw
```

### Docker not running

Make sure Docker Desktop is running:

```bash
docker info
```
