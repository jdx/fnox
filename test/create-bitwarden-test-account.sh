#!/usr/bin/env bash
#
# Create a test account in Bitwarden for fnox testing
#

set -e

BW_SERVER="https://localhost:8080"
BW_EMAIL="${BW_TEST_EMAIL:-test@fnox.local}"
BW_PASSWORD="${BW_TEST_PASSWORD:-TestPassword123!}"

echo "Creating Bitwarden test account..."
echo "Email: $BW_EMAIL"

# The bw CLI doesn't have a register command, so users need to:
# 1. Go to https://localhost:8080 (accept self-signed certificate)
# 2. Click "Create Account"
# 3. Enter email: test@fnox.local
# 4. Enter password: TestPassword123!
# 5. Click "Create Account"

# Then login and unlock:
echo ""
echo "Please create an account at: $BW_SERVER"
echo "  Email: $BW_EMAIL"
echo "  Password: $BW_PASSWORD"
echo ""
echo "After creating the account, run:"
echo "  bw login $BW_EMAIL"
# shellcheck disable=SC2016  # Intentionally using single quotes to show literal command
echo '  export BW_SESSION=$(bw unlock --raw)'
