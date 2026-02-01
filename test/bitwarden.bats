#!/usr/bin/env bats
#
# Bitwarden Provider Tests
#
# These tests verify the Bitwarden provider integration with fnox.
#
# Prerequisites:
#   1. Install Bitwarden CLI: npm install -g @bitwarden/cli
#   2. Login and unlock: bw login && bw unlock
#   3. Export session: export BW_SESSION=$(bw unlock --raw)
#      OR store encrypted in fnox.toml with age provider
#   4. Run tests: mise run test:bats -- test/bitwarden.bats
#
# Note: Tests will automatically skip if BW_SESSION is not available.
#       These tests create and delete temporary items in your Bitwarden vault.
#

# Serialize tests within this file to prevent concurrent bw CLI state corruption
export BATS_NO_PARALLELIZE_WITHIN_FILE=true

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Allow self-signed certificates for localhost testing (required for vaultwarden HTTPS)
	export NODE_TLS_REJECT_UNAUTHORIZED=0

	# Check if bw CLI is installed
	if ! command -v bw >/dev/null 2>&1; then
		skip "Bitwarden CLI (bw) not installed. Install with: npm install -g @bitwarden/cli"
	fi

	# Some tests don't need BW_SESSION (like 'fnox list')
	# Only skip if this test actually needs authentication
	if [[ $BATS_TEST_DESCRIPTION != *"list"* ]]; then
		# Check if BW_SESSION is available
		if [ -z "$BW_SESSION" ]; then
			skip 'BW_SESSION not available. Run: export BW_SESSION=$(bw unlock --raw)'
		fi

		# Verify we can authenticate with Bitwarden by checking status
		if ! bw status --session "$BW_SESSION" >/dev/null 2>&1; then
			skip "Cannot authenticate with Bitwarden. Session may be invalid or expired."
		fi
	fi
}

teardown() {
	_common_teardown
}

# Helper function to create a Bitwarden test config
create_bitwarden_config() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.bitwarden]
type = "bitwarden"

[secrets]
EOF
}

# Helper function to create a test item in Bitwarden
# Returns the item ID
create_test_bw_item() {
	local item_name
	item_name="fnox-test-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local password
	password="test-secret-value-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local username="testuser"

	# Create item with bw CLI
	# Note: This is a simplified version - real implementation would need proper JSON encoding
	local template
	template=$(
		cat <<EOF
{
  "organizationId": null,
  "folderId": null,
  "type": 1,
  "name": "$item_name",
  "notes": "Created by fnox test",
  "favorite": false,
  "login": {
    "username": "$username",
    "password": "$password",
    "totp": null
  }
}
EOF
	)

	local item_id
	item_id=$(echo "$template" | bw encode | bw create item --session "$BW_SESSION" | bw get item - --session "$BW_SESSION" | jq -r '.id')
	echo "$item_id|$item_name"
}

# Helper function to delete a test item from Bitwarden
delete_test_bw_item() {
	local item_id="${1}"
	bw delete item "$item_id" --session "$BW_SESSION" >/dev/null 2>&1 || true
}

@test "fnox get retrieves secret from Bitwarden" {
	create_bitwarden_config

	# Create a test item
	item_info=$(create_test_bw_item)
	item_id=$(echo "$item_info" | cut -d'|' -f1)
	item_name=$(echo "$item_info" | cut -d'|' -f2)

	# Add secret reference to config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_BW_SECRET]
provider = "bitwarden"
value = "$item_name"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_BW_SECRET
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_bw_item "$item_id"
}

@test "fnox get retrieves specific field from Bitwarden item" {
	create_bitwarden_config

	# Create a test item
	item_info=$(create_test_bw_item)
	item_id=$(echo "$item_info" | cut -d'|' -f1)
	item_name=$(echo "$item_info" | cut -d'|' -f2)

	# Add secret reference to config (fetch username field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_USERNAME]
provider = "bitwarden"
value = "$item_name/username"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_USERNAME
	assert_success
	assert_output "testuser"

	# Cleanup
	delete_test_bw_item "$item_id"
}

@test "fnox get retrieves password field from Bitwarden item" {
	create_bitwarden_config

	# Create a test item
	item_info=$(create_test_bw_item)
	item_id=$(echo "$item_info" | cut -d'|' -f1)
	item_name=$(echo "$item_info" | cut -d'|' -f2)

	# Add secret reference to config (explicit password field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_PASSWORD]
provider = "bitwarden"
value = "$item_name/password"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_PASSWORD
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_bw_item "$item_id"
}

@test "fnox get fails with invalid item name" {
	create_bitwarden_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_ITEM]
provider = "bitwarden"
value = "nonexistent-item-$(date +%s)"
EOF

	# Try to get non-existent secret
	run "$FNOX_BIN" get INVALID_ITEM
	assert_failure
	assert_output --partial "cli_failed"
}

@test "fnox get handles invalid secret reference format" {
	create_bitwarden_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_FORMAT]
provider = "bitwarden"
value = "invalid/format/with/too/many/slashes"
EOF

	run "$FNOX_BIN" get INVALID_FORMAT
	assert_failure
	assert_output --partial "Invalid secret reference format"
}

@test "fnox list shows Bitwarden secrets" {
	# This test doesn't need BW_SESSION since list just reads the config file
	create_bitwarden_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.BW_SECRET_1]
description = "First Bitwarden secret"
provider = "bitwarden"
value = "item1"

[secrets.BW_SECRET_2]
description = "Second Bitwarden secret"
provider = "bitwarden"
value = "item2/username"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "BW_SECRET_1"
	assert_output --partial "BW_SECRET_2"
	assert_output --partial "First Bitwarden secret"
}

@test "Bitwarden provider works with session token from environment" {
	# This test verifies that bw CLI uses BW_SESSION from environment
	# The token should be set by setup() from fnox config or environment

	create_bitwarden_config

	item_info=$(create_test_bw_item)
	item_id=$(echo "$item_info" | cut -d'|' -f1)
	item_name=$(echo "$item_info" | cut -d'|' -f2)

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_WITH_ENV_TOKEN]
provider = "bitwarden"
value = "$item_name"
EOF

	# The BW_SESSION should be set by setup()
	run "$FNOX_BIN" get TEST_WITH_ENV_TOKEN
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_bw_item "$item_id"
}

@test "Bitwarden provider with collection filter" {
	skip "Bitwarden provider collection filtering not yet implemented"

	# Create config with collection parameter
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.bitwarden]
type = "bitwarden"
collection = "my-collection-id"

[secrets.TEST_SECRET]
provider = "bitwarden"
value = "test-item"
EOF

	# This should pass collection filter to bw CLI
	run "$FNOX_BIN" get TEST_SECRET
	# Will fail if collection doesn't exist, but that's expected
	assert_failure
}

@test "Bitwarden provider with organization filter" {
	skip "Bitwarden provider organization filtering not yet implemented"

	# Create config with organization parameter
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.bitwarden]
type = "bitwarden"
organization_id = "my-org-id"

[secrets.TEST_SECRET]
provider = "bitwarden"
value = "test-item"
EOF

	# This should pass organization filter to bw CLI
	run "$FNOX_BIN" get TEST_SECRET
	# Will fail if organization doesn't exist, but that's expected
	assert_failure
}
