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
	# Preserve bw CLI config dir before _common_setup changes HOME.
	# The bw CLI stores server URL and login state in data.json under
	# this directory; without it, bw reports "You are not logged in".
	if [ -z "$BITWARDENCLI_APPDATA_DIR" ]; then
		export BITWARDENCLI_APPDATA_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/Bitwarden CLI"
	fi

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
	cleanup_registered_bw_objects
	_common_teardown
}

register_bw_cleanup() {
	echo "$1 $2" >>"$TEST_TEMP_DIR/.bw-cleanup"
}

cleanup_registered_bw_objects() {
	local file="$TEST_TEMP_DIR/.bw-cleanup"
	[ -f "$file" ] || return 0
	local kind id
	for kind in item folder; do
		while read -r entry_kind id; do
			if [ "$entry_kind" = "$kind" ] && [ -n "$id" ] && [ "$id" != "null" ]; then
				bw delete "$kind" "$id" --session "$BW_SESSION" >/dev/null 2>&1 || true
			fi
		done <"$file"
	done
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
# Returns "item_id|item_name"
create_test_bw_item() {
	local folder_id="${1:-}"
	local item_name="${2:-fnox-test-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}}"
	local password="${3:-test-secret-value-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}}"
	local username="testuser"
	local folder_json="null"
	if [ -n "$folder_id" ]; then
		folder_json="\"$folder_id\""
	fi

	# Create item with bw CLI
	# Note: This is a simplified version - real implementation would need proper JSON encoding
	local template
	template=$(
		cat <<EOF
{
  "organizationId": null,
  "folderId": $folder_json,
  "type": 1,
  "name": "$item_name",
  "notes": "Created by fnox test",
  "favorite": false,
  "login": {
    "username": "$username",
    "password": "$password",
    "totp": null
  },
  "fields": [
    {
      "name": "API Key",
      "value": "custom-secret-value-${BATS_TEST_NUMBER:-0}",
      "type": 1
    },
    {
      "name": "API/Key",
      "value": "slash-field-value-${BATS_TEST_NUMBER:-0}",
      "type": 1
    }
  ]
}
EOF
	)

	local item_id
	item_id=$(echo "$template" | bw encode | bw create item --session "$BW_SESSION" | bw get item - --session "$BW_SESSION" | jq -r '.id')
	register_bw_cleanup item "$item_id"
	echo "$item_id|$item_name"
}

# Returns "folder_id|folder_name"
create_test_bw_folder() {
	local folder_name
	folder_name="fnox-test-$$-${BATS_TEST_NUMBER:-0}/${1:-Production}"
	local folder_id
	folder_id=$(echo "{\"name\": \"$folder_name\"}" | bw encode | bw create folder --session "$BW_SESSION" | jq -r '.id')
	register_bw_cleanup folder "$folder_id"
	echo "$folder_id|$folder_name"
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

@test "fnox get retrieves custom field from Bitwarden item" {
	create_bitwarden_config

	item_info=$(create_test_bw_item)
	item_id=$(echo "$item_info" | cut -d'|' -f1)
	item_name=$(echo "$item_info" | cut -d'|' -f2)

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_CUSTOM_FIELD]
provider = "bitwarden"
value = "$item_name/API Key"
EOF

	run "$FNOX_BIN" get TEST_CUSTOM_FIELD
	assert_success
	assert_output "custom-secret-value-${BATS_TEST_NUMBER:-0}"

	delete_test_bw_item "$item_id"
}

@test "fnox get retrieves custom field containing a slash" {
	create_bitwarden_config

	item_info=$(create_test_bw_item)
	item_id=$(echo "$item_info" | cut -d'|' -f1)
	item_name=$(echo "$item_info" | cut -d'|' -f2)

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SLASH_FIELD]
provider = "bitwarden"
value = "$item_name/API/Key"
EOF

	run "$FNOX_BIN" get TEST_SLASH_FIELD
	assert_success
	assert_output "slash-field-value-${BATS_TEST_NUMBER:-0}"

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

@test "fnox get retrieves secret scoped by folder with bw backend" {
	folder_info=$(create_test_bw_folder)
	folder_id=$(echo "$folder_info" | cut -d'|' -f1)
	folder_name=$(echo "$folder_info" | cut -d'|' -f2)

	item_name=$(create_test_bw_item "$folder_id" | cut -d'|' -f2)

	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.bitwarden]
type = "bitwarden"
folder = "$folder_name"

[secrets.TEST_FOLDER_PASSWORD]
provider = "bitwarden"
value = "$item_name"

[secrets.TEST_FOLDER_CUSTOM]
provider = "bitwarden"
value = "$item_name/API Key"
EOF

	run "$FNOX_BIN" get TEST_FOLDER_PASSWORD
	assert_success
	assert_output --partial "test-secret-value-"

	run "$FNOX_BIN" get TEST_FOLDER_CUSTOM
	assert_success
	assert_output "custom-secret-value-${BATS_TEST_NUMBER:-0}"
}

@test "fnox get picks same-named item from the configured folder" {
	prod_info=$(create_test_bw_folder Production)
	prod_folder_id=$(echo "$prod_info" | cut -d'|' -f1)
	prod_folder_name=$(echo "$prod_info" | cut -d'|' -f2)

	staging_info=$(create_test_bw_folder Staging)
	staging_folder_id=$(echo "$staging_info" | cut -d'|' -f1)
	staging_folder_name=$(echo "$staging_info" | cut -d'|' -f2)

	item_name="fnox-test-shared-$$-${BATS_TEST_NUMBER:-0}"
	create_test_bw_item "$prod_folder_id" "$item_name" "prod-password-$$" >/dev/null
	create_test_bw_item "$staging_folder_id" "$item_name" "staging-password-$$" >/dev/null

	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.bw-prod]
type = "bitwarden"
folder = "$prod_folder_name"

[providers.bw-staging]
type = "bitwarden"
folder = "$staging_folder_name"

[secrets.PROD_PASSWORD]
provider = "bw-prod"
value = "$item_name"

[secrets.STAGING_PASSWORD]
provider = "bw-staging"
value = "$item_name"
EOF

	run "$FNOX_BIN" get PROD_PASSWORD
	assert_success
	assert_output "prod-password-$$"

	run "$FNOX_BIN" get STAGING_PASSWORD
	assert_success
	assert_output "staging-password-$$"
}

@test "fnox get fails when item is not in the configured folder" {
	folder_name=$(create_test_bw_folder | cut -d'|' -f2)
	item_name=$(create_test_bw_item | cut -d'|' -f2)

	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.bitwarden]
type = "bitwarden"
folder = "$folder_name"

[secrets.TEST_OUTSIDE_FOLDER]
provider = "bitwarden"
value = "$item_name"
EOF

	run "$FNOX_BIN" get TEST_OUTSIDE_FOLDER
	assert_failure
	assert_output --partial "not found"
}

@test "fnox get retrieves secret scoped by folder with rbw backend" {
	if ! command -v rbw >/dev/null 2>&1; then
		skip "rbw not installed"
	fi
	if ! rbw unlocked >/dev/null 2>&1; then
		skip "rbw is not unlocked. Run: rbw unlock"
	fi

	folder_info=$(create_test_bw_folder)
	folder_id=$(echo "$folder_info" | cut -d'|' -f1)
	folder_name=$(echo "$folder_info" | cut -d'|' -f2)

	item_name=$(create_test_bw_item "$folder_id" | cut -d'|' -f2)

	if ! rbw sync >/dev/null 2>&1 || ! rbw get "$item_name" --folder "$folder_name" >/dev/null 2>&1; then
		skip "rbw is not configured against the same vault as bw"
	fi

	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.bitwarden]
type = "bitwarden"
backend = "rbw"
folder = "$folder_name"

[secrets.TEST_RBW_FOLDER_PASSWORD]
provider = "bitwarden"
value = "$item_name"

[secrets.TEST_RBW_FOLDER_USERNAME]
provider = "bitwarden"
value = "$item_name/username"
EOF

	run "$FNOX_BIN" get TEST_RBW_FOLDER_PASSWORD
	assert_success
	assert_output --partial "test-secret-value-"

	run "$FNOX_BIN" get TEST_RBW_FOLDER_USERNAME
	assert_success
	assert_output "testuser"
}
