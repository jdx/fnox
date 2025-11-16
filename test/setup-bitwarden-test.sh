#!/usr/bin/env bash
#
# Setup script for Bitwarden testing with local vaultwarden server
#
# This script:
# 1. Starts a local vaultwarden server via Docker
# 2. Configures bw CLI to use the local server
# 3. Creates a test account
# 4. Logs in and unlocks the vault
# 5. Exports BW_SESSION for testing
#
# Usage: source ./test/setup-bitwarden-test.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up Bitwarden test environment...${NC}"

# Configuration
BW_SERVER="https://localhost:8080"
export BW_EMAIL="test@fnox.local"
export BW_PASSWORD="TestPassword123!"
COMPOSE_FILE="test/docker-compose.bitwarden.yml"
# Allow self-signed certificates for localhost testing
export NODE_TLS_REJECT_UNAUTHORIZED=0

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
	echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
	exit 1
fi

# Start vaultwarden server
echo -e "${YELLOW}Starting vaultwarden server...${NC}"
docker compose -f "$COMPOSE_FILE" up -d

# Wait for server to be ready
echo -e "${YELLOW}Waiting for vaultwarden to be ready...${NC}"
for i in {1..30}; do
	if curl -sk "$BW_SERVER" >/dev/null 2>&1; then
		echo -e "${GREEN}Vaultwarden is ready!${NC}"
		break
	fi
	if [ "$i" -eq 30 ]; then
		echo -e "${RED}Error: Vaultwarden failed to start${NC}"
		exit 1
	fi
	sleep 1
done

# Configure bw CLI to use local server
echo -e "${YELLOW}Configuring bw CLI for local server...${NC}"
# Note: NODE_TLS_REJECT_UNAUTHORIZED=0 is set above to allow self-signed certificates
bw config server "$BW_SERVER"

# Check if already logged in
if bw login --check 2>/dev/null; then
	echo -e "${GREEN}Already logged in to Bitwarden${NC}"

	# Unlock vault and get session
	echo -e "${YELLOW}Unlocking vault...${NC}"
	# NODE_TLS_REJECT_UNAUTHORIZED=0 is already set to allow self-signed certificates
	BW_SESSION=$(bw unlock "$BW_PASSWORD" --raw 2>/dev/null)
	export BW_SESSION

	if [ -z "$BW_SESSION" ]; then
		echo -e "${RED}Error: Failed to unlock vault with password${NC}"
		echo -e "${YELLOW}You may need to unlock manually:${NC}"
		# shellcheck disable=SC2016
		echo -e '  export BW_SESSION=$(bw unlock --raw)'
		exit 1
	fi

	# Verify session works
	if ! bw status --session "$BW_SESSION" >/dev/null 2>&1; then
		echo -e "${RED}Error: Session verification failed${NC}"
		exit 1
	fi

	echo -e "${GREEN}✓ Bitwarden test environment ready!${NC}"
	echo -e "${GREEN}✓ BW_SESSION exported${NC}"
else
	# Not logged in - provide instructions
	echo -e "${YELLOW}Not logged in yet. Please complete setup:${NC}"
	echo ""
	echo -e "${YELLOW}1. Create an account:${NC}"
	echo -e "   Open: $BW_SERVER"
	echo -e "   Register with any email/password"
	echo ""
	echo -e "${YELLOW}2. Login with bw CLI:${NC}"
	echo -e "   bw login"
	echo ""
	echo -e "${YELLOW}3. Unlock and export session:${NC}"
	# shellcheck disable=SC2016
	echo -e '   export BW_SESSION=$(bw unlock --raw)'
	echo ""
	echo -e "${YELLOW}4. Re-run this script or run tests directly:${NC}"
	echo -e "   source ./test/setup-bitwarden-test.sh"
	echo -e "   # OR"
	echo -e "   mise run test:bats -- test/bitwarden.bats"
	exit 0
fi
echo ""
echo -e "${YELLOW}To run tests:${NC}"
echo -e "  mise run test:bats -- test/bitwarden.bats"
echo ""
echo -e "${YELLOW}To stop the server:${NC}"
echo -e "  docker compose -f $COMPOSE_FILE down"
echo ""
echo -e "${YELLOW}To stop and remove all data:${NC}"
echo -e "  docker compose -f $COMPOSE_FILE down -v"
