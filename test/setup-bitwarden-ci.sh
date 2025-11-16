#!/usr/bin/env bash
#
# Setup script for Bitwarden testing in CI environments with pre-seeded database
#
# This script:
# 1. Detects environment (GHA service vs local docker)
# 2. Seeds vaultwarden with test database containing pre-created account
# 3. Waits for vaultwarden to be ready
# 4. Configures bw CLI to use the CI vaultwarden server
# 5. Logs in with test account and exports BW_SESSION
#
# Usage: source ./test/setup-bitwarden-ci.sh
#

set -e

# Configuration
BW_SERVER="${BW_SERVER:-https://localhost:8080}"
BW_EMAIL="${BW_EMAIL:-test@fnox.ci}"
BW_PASSWORD="${BW_PASSWORD:-TestCIPassword123!}"
# Allow self-signed certificates for localhost testing
export NODE_TLS_REJECT_UNAUTHORIZED=0

# Find the script directory (handles both sourced and executed)
if [ -n "${BASH_SOURCE[0]}" ]; then
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
	SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi

TEST_DB="$SCRIPT_DIR/fixtures/vaultwarden-test.db"

echo "Setting up Bitwarden for CI..."

# Check if test database exists
if [ ! -f "$TEST_DB" ]; then
	echo "Error: Pre-seeded test database not found at: $TEST_DB"
	echo "Run: test/create-test-account.sh to create it"
	exit 1
fi

# Detect if we're in GitHub Actions with docker service
if [ -n "$GITHUB_ACTIONS" ]; then
	echo "Detected GitHub Actions environment"
	CONTAINER_NAME="vaultwarden"

	# In GHA, the service container is named based on the job
	# We need to find the actual container name
	ACTUAL_CONTAINER=$(docker ps --filter "ancestor=vaultwarden/server:latest" --format "{{.Names}}" | head -1)

	if [ -n "$ACTUAL_CONTAINER" ]; then
		CONTAINER_NAME="$ACTUAL_CONTAINER"
		echo "Found vaultwarden container: $CONTAINER_NAME"
	fi
else
	echo "Local environment - using docker compose"
	CONTAINER_NAME="fnox-vaultwarden-ci"

	# Start vaultwarden if not already running
	if ! docker ps | grep -q "$CONTAINER_NAME"; then
		echo "Starting vaultwarden with docker compose..."
		docker compose -f "$SCRIPT_DIR/docker-compose.bitwarden-ci.yml" up -d
	fi
fi

# Wait for initial startup
echo "Waiting for vaultwarden initial startup..."
sleep 3

# Seed the database
echo "Seeding database with test account..."
docker exec "$CONTAINER_NAME" sh -c 'rm -f /data/db.sqlite3 /data/db.sqlite3-shm /data/db.sqlite3-wal' || true
docker cp "$TEST_DB" "$CONTAINER_NAME:/data/db.sqlite3"
docker exec "$CONTAINER_NAME" chmod 644 /data/db.sqlite3

# Restart vaultwarden to pick up the new database
echo "Restarting vaultwarden..."
docker restart "$CONTAINER_NAME"

# Wait for vaultwarden to be ready after restart
echo "Waiting for vaultwarden to be ready..."
for i in {1..60}; do
	if curl -skf "$BW_SERVER" >/dev/null 2>&1; then
		echo "✓ Vaultwarden is ready with seeded database"
		break
	fi
	if [ "$i" -eq 60 ]; then
		echo "Error: Vaultwarden failed to start after 60 seconds"
		docker logs "$CONTAINER_NAME"
		docker ps -a
		exit 1
	fi
	sleep 1
done

# Configure bw CLI to use CI server
echo "Configuring bw CLI..."
# Logout first if already logged in to allow server config change
bw logout >/dev/null 2>&1 || true
# Note: NODE_TLS_REJECT_UNAUTHORIZED=0 is set above to allow self-signed certificates
bw config server "$BW_SERVER"

# Login with pre-created test account
echo "Logging in with test account..."
if SESSION=$(bw login "$BW_EMAIL" "$BW_PASSWORD" --raw 2>/dev/null); then
	echo "✓ Logged in successfully with pre-seeded account"
	export BW_SESSION="$SESSION"
else
	echo "Error: Failed to login with test account"
	echo "Email: $BW_EMAIL"
	echo "This should not happen with the pre-seeded database."
	exit 1
fi

# Verify session works
if [ -z "$BW_SESSION" ]; then
	echo "Error: BW_SESSION is empty"
	exit 1
fi

if ! bw status --session "$BW_SESSION" >/dev/null 2>&1; then
	echo "Error: Session verification failed"
	exit 1
fi

echo "✓ Bitwarden CI setup complete"
echo "✓ BW_SESSION exported"
