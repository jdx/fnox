#!/usr/bin/env bash
#
# Setup script for Infisical testing in CI environments
#
# This script:
# 1. Starts self-hosted Infisical with PostgreSQL and Redis
# 2. Waits for services to be ready
# 3. Creates a test account via API
# 4. Creates a test project and workspace
# 5. Creates a service token for testing
# 6. Exports INFISICAL_TOKEN for tests
#
# Usage: source ./test/setup-infisical-ci.sh
#

set -e

# Configuration
INFISICAL_URL="${INFISICAL_URL:-http://localhost:8081}"
INFISICAL_EMAIL="${INFISICAL_EMAIL:-test@fnox.ci}"
INFISICAL_PASSWORD="${INFISICAL_PASSWORD:-TestCIPassword123!}"
INFISICAL_ORG_NAME="${INFISICAL_ORG_NAME:-fnox-test}"
INFISICAL_PROJECT_NAME="${INFISICAL_PROJECT_NAME:-fnox-ci-test}"

# Find the script directory
if [ -n "${BASH_SOURCE[0]}" ]; then
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
	SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi

echo "Setting up Infisical for CI..."

# Detect if we're in GitHub Actions with docker service
if [ -n "$GITHUB_ACTIONS" ]; then
	echo "Detected GitHub Actions environment"
	CONTAINER_NAME="fnox-infisical"

	# Services should already be running in GHA
	# Just need to wait for them to be ready
else
	echo "Local environment - using docker compose"
	CONTAINER_NAME="fnox-infisical"

	# Start services if not already running
	if ! docker ps | grep -q "$CONTAINER_NAME"; then
		echo "Starting Infisical services with docker compose..."
		docker compose -f "$SCRIPT_DIR/docker-compose.infisical-ci.yml" up -d
	fi
fi

# Wait for Infisical to be ready
echo "Waiting for Infisical to be ready..."
for i in {1..120}; do
	if curl -sf "$INFISICAL_URL/api/status" >/dev/null 2>&1; then
		echo "✓ Infisical is ready"
		break
	fi
	if [ "$i" -eq 120 ]; then
		echo "Error: Infisical failed to start after 120 seconds"
		echo "Container logs:"
		docker logs "$CONTAINER_NAME" || true
		exit 1
	fi
	sleep 1
done

# Create test account
echo "Creating test account..."
SIGNUP_RESPONSE=$(curl -s -X POST "$INFISICAL_URL/api/v3/signup/complete-account/signup" \
	-H "Content-Type: application/json" \
	-d "{
		\"email\": \"$INFISICAL_EMAIL\",
		\"password\": \"$INFISICAL_PASSWORD\",
		\"firstName\": \"Test\",
		\"lastName\": \"User\",
		\"organizationName\": \"$INFISICAL_ORG_NAME\",
		\"useDefaultOrg\": false
	}")

# Check if signup was successful
if echo "$SIGNUP_RESPONSE" | grep -q '"token"\|"accessToken"'; then
	echo "✓ Test account created successfully"
else
	# Account might already exist, try to login
	echo "Account may already exist, attempting login..."
fi

# Login to get JWT token (using simple /login endpoint)
echo "Logging in to get access token..."
LOGIN_RESPONSE=$(curl -s -X POST "$INFISICAL_URL/api/v3/auth/login" \
	-H "Content-Type: application/json" \
	-d "{
		\"email\": \"$INFISICAL_EMAIL\",
		\"password\": \"$INFISICAL_PASSWORD\"
	}")

# Extract JWT token (check both 'token' and 'accessToken' fields)
JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)
if [ -z "$JWT_TOKEN" ]; then
	JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
fi

if [ -z "$JWT_TOKEN" ]; then
	echo "Error: Failed to login and get JWT token"
	echo "Response: $LOGIN_RESPONSE"
	exit 1
fi

echo "✓ Logged in successfully"

# Get organization ID
echo "Getting organization ID..."
ORG_RESPONSE=$(curl -s "$INFISICAL_URL/api/v2/users/me/organizations" \
	-H "Authorization: Bearer $JWT_TOKEN")

ORG_ID=$(echo "$ORG_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$ORG_ID" ]; then
	echo "Error: Failed to get organization ID"
	echo "Response: $ORG_RESPONSE"
	exit 1
fi

echo "✓ Organization ID: $ORG_ID"

# Create a project/workspace
echo "Creating test project..."
PROJECT_RESPONSE=$(curl -s -X POST "$INFISICAL_URL/api/v3/workspaces" \
	-H "Authorization: Bearer $JWT_TOKEN" \
	-H "Content-Type: application/json" \
	-d "{
		\"projectName\": \"$INFISICAL_PROJECT_NAME\",
		\"kmsKeyId\": null
	}")

PROJECT_ID=$(echo "$PROJECT_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$PROJECT_ID" ]; then
	# Project might already exist, try to get it
	echo "Project may already exist, trying to retrieve..."
	WORKSPACES_RESPONSE=$(curl -s "$INFISICAL_URL/api/v2/organizations/$ORG_ID/workspaces" \
		-H "Authorization: Bearer $JWT_TOKEN")

	PROJECT_ID=$(echo "$WORKSPACES_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

	if [ -z "$PROJECT_ID" ]; then
		echo "Error: Failed to create or retrieve project"
		echo "Response: $PROJECT_RESPONSE"
		exit 1
	fi
fi

echo "✓ Project ID: $PROJECT_ID"

# Create a machine identity (modern approach, replaces service tokens)
echo "Creating machine identity..."
IDENTITY_RESPONSE=$(curl -s -X POST "$INFISICAL_URL/api/v1/identities" \
	-H "Authorization: Bearer $JWT_TOKEN" \
	-H "Content-Type: application/json" \
	-d "{
		\"name\": \"fnox-ci-test-identity\",
		\"organizationId\": \"$ORG_ID\",
		\"role\": \"admin\"
	}")

IDENTITY_ID=$(echo "$IDENTITY_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$IDENTITY_ID" ]; then
	echo "Error: Failed to create machine identity"
	echo "Response: $IDENTITY_RESPONSE"
	exit 1
fi

echo "✓ Machine Identity ID: $IDENTITY_ID"

# Attach universal auth to the identity
echo "Configuring universal auth..."
UNIVERSAL_AUTH_RESPONSE=$(curl -s -X PATCH "$INFISICAL_URL/api/v1/auth/universal-auth/identities/$IDENTITY_ID" \
	-H "Authorization: Bearer $JWT_TOKEN" \
	-H "Content-Type: application/json" \
	-d "{
		\"clientSecretTrustedIps\": [{\"ipAddress\": \"0.0.0.0/0\"}],
		\"accessTokenTrustedIps\": [{\"ipAddress\": \"0.0.0.0/0\"}],
		\"accessTokenTTL\": 7200,
		\"accessTokenMaxTTL\": 7200,
		\"accessTokenNumUsesLimit\": 0
	}")

# Get the client secret from the universal auth
CLIENT_ID=$(echo "$UNIVERSAL_AUTH_RESPONSE" | grep -o '"clientId":"[^"]*"' | cut -d'"' -f4)
CLIENT_SECRET=$(echo "$UNIVERSAL_AUTH_RESPONSE" | grep -o '"clientSecret":"[^"]*"' | cut -d'"' -f4)

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
	echo "Error: Failed to get client credentials"
	echo "Response: $UNIVERSAL_AUTH_RESPONSE"
	exit 1
fi

echo "✓ Client credentials created"

# Login with the machine identity to get access token
echo "Getting machine identity access token..."
MACHINE_LOGIN_RESPONSE=$(curl -s -X POST "$INFISICAL_URL/api/v1/auth/universal-auth/login" \
	-H "Content-Type: application/json" \
	-d "{
		\"clientId\": \"$CLIENT_ID\",
		\"clientSecret\": \"$CLIENT_SECRET\"
	}")

MACHINE_TOKEN=$(echo "$MACHINE_LOGIN_RESPONSE" | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)

if [ -z "$MACHINE_TOKEN" ]; then
	echo "Error: Failed to get machine identity access token"
	echo "Response: $MACHINE_LOGIN_RESPONSE"
	exit 1
fi

echo "✓ Machine identity access token obtained"

# Export the token (use the machine identity token for API access)
export INFISICAL_TOKEN="$MACHINE_TOKEN"

# Verify the token works with CLI
echo "Verifying token with Infisical CLI..."
if command -v infisical >/dev/null 2>&1; then
	# Configure CLI to use local instance
	export INFISICAL_API_URL="$INFISICAL_URL/api"

	if infisical user >/dev/null 2>&1; then
		echo "✓ Token verified with CLI"
	else
		echo "Warning: Token verification with CLI failed, but token is exported"
	fi
else
	echo "Infisical CLI not found, skipping verification"
fi

echo "✓ Infisical CI setup complete"
echo "✓ INFISICAL_TOKEN exported"
echo "✓ Project ID: $PROJECT_ID"
echo "✓ API URL: $INFISICAL_URL/api"
