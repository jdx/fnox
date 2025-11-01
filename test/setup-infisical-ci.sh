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

# Bootstrap Infisical with initial admin user using CLI
echo "Bootstrapping Infisical with admin user..."
export INFISICAL_API_URL="$INFISICAL_URL/api"

# Bootstrap and capture JSON output
# Redirect stderr to separate file to keep JSON clean
BOOTSTRAP_OUTPUT=$(infisical bootstrap \
	--domain "$INFISICAL_URL" \
	--email "$INFISICAL_EMAIL" \
	--password "$INFISICAL_PASSWORD" \
	--organization "$INFISICAL_ORG_NAME" \
	--output json \
	2>/tmp/infisical-bootstrap-stderr.log)
BOOTSTRAP_EXIT_CODE=$?

# Check if bootstrap was successful
if [ $BOOTSTRAP_EXIT_CODE -ne 0 ] || [ -z "$BOOTSTRAP_OUTPUT" ]; then
	echo "Error: Failed to bootstrap Infisical"
	echo "Bootstrap stderr:"
	cat /tmp/infisical-bootstrap-stderr.log
	exit 1
fi

# Extract token and org ID
MACHINE_TOKEN=$(echo "$BOOTSTRAP_OUTPUT" | jq -r '.identity.credentials.token')
ORG_ID=$(echo "$BOOTSTRAP_OUTPUT" | jq -r '.organization.id')

# Check if token and org ID were successfully extracted
if [ -z "$MACHINE_TOKEN" ] || [ "$MACHINE_TOKEN" = "null" ]; then
	echo "Error: Failed to extract machine identity token from bootstrap"
	echo "Bootstrap output: $BOOTSTRAP_OUTPUT"
	exit 1
fi

if [ -z "$ORG_ID" ] || [ "$ORG_ID" = "null" ]; then
	echo "Error: Failed to extract organization ID from bootstrap"
	echo "Bootstrap output: $BOOTSTRAP_OUTPUT"
	exit 1
fi

echo "✓ Infisical bootstrapped successfully"
echo "✓ Machine identity access token obtained"
echo "✓ Organization ID: $ORG_ID"

# Export the token for CLI usage (test helpers)
export INFISICAL_TOKEN="$MACHINE_TOKEN"

# Create a test project using the API
echo "Creating test project..."
PROJECT_RESPONSE=$(curl -sf "$INFISICAL_URL/api/v2/workspace" \
	-H "Authorization: Bearer $MACHINE_TOKEN" \
	-H "Content-Type: application/json" \
	-d "{
		\"projectName\": \"$INFISICAL_PROJECT_NAME\",
		\"type\": \"secret-manager\",
		\"shouldCreateDefaultEnvs\": true
	}")

if [ -z "$PROJECT_RESPONSE" ]; then
	echo "Error: Failed to create project"
	exit 1
fi

# Extract project ID from response
PROJECT_ID=$(echo "$PROJECT_RESPONSE" | jq -r '.workspace.id // .project.id // .id')

if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" = "null" ]; then
	echo "Error: Failed to extract project ID from response"
	echo "Response: $PROJECT_RESPONSE"
	exit 1
fi

echo "✓ Test project created with ID: $PROJECT_ID"
export INFISICAL_PROJECT_ID="$PROJECT_ID"

# Create a machine identity with Universal Auth for the SDK
echo "Creating machine identity with Universal Auth..."
IDENTITY_RESPONSE=$(curl -sf "$INFISICAL_URL/api/v1/identities" \
	-H "Authorization: Bearer $MACHINE_TOKEN" \
	-H "Content-Type: application/json" \
	-d "{
		\"name\": \"fnox-ci-test-identity\",
		\"organizationId\": \"$ORG_ID\",
		\"role\": \"admin\"
	}")

IDENTITY_ID=$(echo "$IDENTITY_RESPONSE" | jq -r '.identity.id')

if [ -z "$IDENTITY_ID" ] || [ "$IDENTITY_ID" = "null" ]; then
	echo "Error: Failed to create machine identity"
	echo "Response: $IDENTITY_RESPONSE"
	exit 1
fi

echo "✓ Machine identity created with ID: $IDENTITY_ID"

# Attach Universal Auth to the identity
echo "Attaching Universal Auth to identity..."
UNIVERSAL_AUTH_RESPONSE=$(curl -sf "$INFISICAL_URL/api/v1/auth/universal-auth/identities/$IDENTITY_ID" \
	-H "Authorization: Bearer $MACHINE_TOKEN" \
	-H "Content-Type: application/json" \
	-X POST \
	-d '{
		"clientSecretTrustedIps": [{"ipAddress": "0.0.0.0/0"}],
		"accessTokenTrustedIps": [{"ipAddress": "0.0.0.0/0"}],
		"accessTokenTTL": 3600,
		"accessTokenMaxTTL": 3600,
		"accessTokenNumUsesLimit": 0
	}')

# Check if the response is empty or contains an error
if [ -z "$UNIVERSAL_AUTH_RESPONSE" ]; then
	echo "Error: Failed to attach Universal Auth (empty response)"
	exit 1
fi

CLIENT_ID=$(echo "$UNIVERSAL_AUTH_RESPONSE" | jq -r '.identityUniversalAuth.clientId // .universalAuth.clientId // .clientId')

if [ -z "$CLIENT_ID" ] || [ "$CLIENT_ID" = "null" ]; then
	echo "Error: Failed to attach Universal Auth"
	echo "Response: $UNIVERSAL_AUTH_RESPONSE"
	exit 1
fi

echo "✓ Universal Auth attached, Client ID: $CLIENT_ID"

# Create a client secret
echo "Creating client secret..."
CLIENT_SECRET_RESPONSE=$(curl -sf "$INFISICAL_URL/api/v1/auth/universal-auth/identities/$IDENTITY_ID/client-secrets" \
	-H "Authorization: Bearer $MACHINE_TOKEN" \
	-H "Content-Type: application/json" \
	-d '{
		"description": "CI test client secret",
		"numUsesLimit": 0,
		"ttl": 0
	}')

CLIENT_SECRET=$(echo "$CLIENT_SECRET_RESPONSE" | jq -r '.clientSecret')

if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" = "null" ]; then
	echo "Error: Failed to create client secret"
	echo "Response: $CLIENT_SECRET_RESPONSE"
	exit 1
fi

echo "✓ Client secret created"

# Add the identity to the project
# Note: Skipping this for now as the API endpoint varies by Infisical version
# The identity should still be able to access the project via organization-level permissions
echo "⚠ Skipping explicit identity-to-project assignment (not required for organization admin role)"

# Export the Universal Auth credentials
export INFISICAL_CLIENT_ID="$CLIENT_ID"
export INFISICAL_CLIENT_SECRET="$CLIENT_SECRET"

echo "✓ Infisical CI setup complete"
echo "✓ INFISICAL_CLIENT_ID exported"
echo "✓ INFISICAL_CLIENT_SECRET exported"
echo "✓ INFISICAL_PROJECT_ID exported"
echo "✓ INFISICAL_API_URL exported: $INFISICAL_API_URL"
