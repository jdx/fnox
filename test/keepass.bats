#!/usr/bin/env bats
#
# KeePass Provider Tests
#
# These tests verify the KeePass provider integration with fnox.
#
# Prerequisites:
#   - The keepass crate with save_kdbx4 feature (built into fnox)
#   - Run tests: mise run test:bats -- test/keepass.bats
#
# Note: Tests create a temporary KeePass database for isolation.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Set up test KeePass database path
	export KEEPASS_DB="$BATS_TEST_TMPDIR/test.kdbx"
	export KEEPASS_PASSWORD="fnox-test-password"

	# Track secrets for cleanup (entry names)
	export TEST_ENTRY_NAMES=""
}

teardown() {
	# Clean up test database
	rm -f "$KEEPASS_DB" 2>/dev/null || true

	_common_teardown
}

# Helper function to create a keepass provider config
create_keepass_config() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.keepass]
type = "keepass"
database = "$KEEPASS_DB"

[secrets]
EOF
}

# Helper to track entry names for cleanup
track_entry_name() {
	local name="$1"
	TEST_ENTRY_NAMES="${TEST_ENTRY_NAMES} $name"
}

@test "fnox set creates new KeePass database and stores secret" {
	create_keepass_config

	# Set a secret - this should create a new database
	run "$FNOX_BIN" set MY_SECRET "my-secret-value" --provider keepass
	assert_success
	assert_output --partial "Set secret MY_SECRET"

	track_entry_name "MY_SECRET"

	# Verify the config contains only a reference (not the value)
	run cat "${FNOX_CONFIG_FILE}"
	assert_success
	assert_output --partial 'MY_SECRET'
	assert_output --partial 'provider = "keepass"'
	assert_output --partial 'value = "MY_SECRET"'
	refute_output --partial "my-secret-value"

	# Verify the database file was created
	[ -f "$KEEPASS_DB" ]
}

@test "fnox get retrieves secret from KeePass database" {
	create_keepass_config

	# Set a secret
	run "$FNOX_BIN" set TEST_GET "test-value-123" --provider keepass
	assert_success
	track_entry_name "TEST_GET"

	# Get the secret back
	run "$FNOX_BIN" get TEST_GET
	assert_success
	assert_output "test-value-123"
}

@test "fnox set and get with username field" {
	create_keepass_config

	# Set a secret with custom key-name that includes field
	run "$FNOX_BIN" set USER_SECRET "admin@example.com" --provider keepass --key-name "my-entry/username"
	assert_success
	track_entry_name "my-entry"

	# Get the username field back
	run "$FNOX_BIN" get USER_SECRET
	assert_success
	assert_output "admin@example.com"
}

@test "fnox set and get with url field" {
	create_keepass_config

	# Set a URL
	run "$FNOX_BIN" set URL_SECRET "https://api.example.com" --provider keepass --key-name "api-entry/url"
	assert_success
	track_entry_name "api-entry"

	# Get the URL back
	run "$FNOX_BIN" get URL_SECRET
	assert_success
	assert_output "https://api.example.com"
}

@test "fnox set and get with notes field" {
	create_keepass_config

	# Set notes
	run "$FNOX_BIN" set NOTES_SECRET "This is a test note" --provider keepass --key-name "notes-entry/notes"
	assert_success
	track_entry_name "notes-entry"

	# Get the notes back
	run "$FNOX_BIN" get NOTES_SECRET
	assert_success
	assert_output "This is a test note"
}

@test "fnox get fails with non-existent entry" {
	create_keepass_config

	# First create the database with at least one entry
	run "$FNOX_BIN" set EXISTING "existing-value" --provider keepass
	assert_success
	track_entry_name "EXISTING"

	# Manually add a reference to a non-existent entry
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.NONEXISTENT]
provider = "keepass"
value = "does-not-exist"
EOF

	# Try to get non-existent entry
	run "$FNOX_BIN" get NONEXISTENT
	assert_failure
	assert_output --partial "not found"
}

@test "fnox set with special characters" {
	create_keepass_config

	local secret_value='p@ssw0rd!#$%^&*()_+-={}[]|\:";'\''<>?,./~`'

	# Set a secret with special characters
	run "$FNOX_BIN" set SPECIAL_CHARS "$secret_value" --provider keepass
	assert_success
	track_entry_name "SPECIAL_CHARS"

	# Get it back
	run "$FNOX_BIN" get SPECIAL_CHARS
	assert_success
	assert_output "$secret_value"
}

@test "fnox set updates existing entry" {
	create_keepass_config

	# Set initial value
	run "$FNOX_BIN" set UPDATE_TEST "initial-value" --provider keepass
	assert_success
	track_entry_name "UPDATE_TEST"

	# Update the value
	run "$FNOX_BIN" set UPDATE_TEST "updated-value" --provider keepass
	assert_success

	# Get the updated value
	run "$FNOX_BIN" get UPDATE_TEST
	assert_success
	assert_output "updated-value"
}

@test "fnox list shows KeePass secrets" {
	create_keepass_config

	# Set multiple secrets
	run "$FNOX_BIN" set SECRET1 "value1" --provider keepass --description "First secret"
	assert_success
	track_entry_name "SECRET1"

	run "$FNOX_BIN" set SECRET2 "value2" --provider keepass --description "Second secret"
	assert_success
	track_entry_name "SECRET2"

	# List secrets
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "SECRET1"
	assert_output --partial "SECRET2"
	assert_output --partial "First secret"
	assert_output --partial "Second secret"
}

@test "fnox exec with KeePass secrets" {
	create_keepass_config

	# Set a secret
	run "$FNOX_BIN" set EXEC_TEST "exec-value" --provider keepass
	assert_success
	track_entry_name "EXEC_TEST"

	# Use it in exec (redirect stderr to filter warnings)
	run bash -c "'$FNOX_BIN' exec -- bash -c 'echo \$EXEC_TEST' 2>/dev/null"
	assert_success
	assert_output "exec-value"
}

@test "fnox set with description metadata" {
	create_keepass_config

	# Set secret with description
	run "$FNOX_BIN" set DESCRIBED "value" --provider keepass --description "Test description"
	assert_success
	track_entry_name "DESCRIBED"

	# Verify description in list
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "DESCRIBED"
	assert_output --partial "Test description"
}

@test "fnox get with JSON-like value" {
	create_keepass_config

	local json_value='{"api_key":"test123","endpoint":"https://api.example.com"}'

	# Set JSON value
	run "$FNOX_BIN" set JSON_SECRET "$json_value" --provider keepass
	assert_success
	track_entry_name "JSON_SECRET"

	# Get it back
	run "$FNOX_BIN" get JSON_SECRET
	assert_success
	assert_output "$json_value"
}

@test "fnox set reads from stdin" {
	create_keepass_config

	# Set secret from stdin (using bash -c for stdin pipe)
	run bash -c "echo 'stdin-value' | '$FNOX_BIN' set STDIN_SECRET --provider keepass"
	assert_success
	track_entry_name "STDIN_SECRET"

	# Get it back
	run "$FNOX_BIN" get STDIN_SECRET
	assert_success
	assert_output "stdin-value"
}

@test "keepass provider with long values" {
	create_keepass_config

	# Create a long value (4KB)
	local long_value
	long_value=$(python3 -c "print('a' * 4096)")

	# Set long value
	run "$FNOX_BIN" set LONG_SECRET "$long_value" --provider keepass
	assert_success
	track_entry_name "LONG_SECRET"

	# Get it back
	run "$FNOX_BIN" get LONG_SECRET
	assert_success
	assert_output "$long_value"
}

@test "fnox check detects missing KeePass entries" {
	create_keepass_config

	# First create the database with at least one entry
	run "$FNOX_BIN" set EXISTING "existing-value" --provider keepass
	assert_success
	track_entry_name "EXISTING"

	# Add reference without actually storing in KeePass
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.MISSING_SECRET]
provider = "keepass"
value = "not-in-keepass"
if_missing = "error"
EOF

	# Check should detect the missing secret
	run "$FNOX_BIN" check
	assert_failure
	assert_output --partial "MISSING_SECRET"
}

@test "fnox set with group path" {
	create_keepass_config

	# Set a secret with group path
	run "$FNOX_BIN" set GROUPED_SECRET "grouped-value" --provider keepass --key-name "work/api-key"
	assert_success
	track_entry_name "work/api-key"

	# Get it back
	run "$FNOX_BIN" get GROUPED_SECRET
	assert_success
	assert_output "grouped-value"
}

@test "fnox set with nested group path" {
	create_keepass_config

	# Set a secret with nested group path
	run "$FNOX_BIN" set NESTED_SECRET "nested-value" --provider keepass --key-name "company/project/database/password"
	assert_success
	track_entry_name "company/project/database"

	# Get it back
	run "$FNOX_BIN" get NESTED_SECRET
	assert_success
	assert_output "nested-value"
}

@test "fnox fails with wrong password" {
	create_keepass_config

	# First create the database
	run "$FNOX_BIN" set CREATE_DB "test" --provider keepass
	assert_success
	track_entry_name "CREATE_DB"

	# Change password env var to wrong value
	export KEEPASS_PASSWORD="wrong-password"

	# Try to get - should fail
	run "$FNOX_BIN" get CREATE_DB
	assert_failure
	assert_output --partial "auth_failed"
}

@test "fnox fails with missing database file for get" {
	# Create config pointing to non-existent database
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.keepass]
type = "keepass"
database = "$BATS_TEST_TMPDIR/nonexistent.kdbx"

[secrets.MISSING_DB]
provider = "keepass"
value = "some-entry"
EOF

	# Try to get - should fail because database doesn't exist
	run "$FNOX_BIN" get MISSING_DB
	assert_failure
	assert_output --partial "api_error"
}

@test "keepass provider respects FNOX_KEEPASS_PASSWORD" {
	create_keepass_config

	# Use FNOX_KEEPASS_PASSWORD instead of KEEPASS_PASSWORD
	unset KEEPASS_PASSWORD
	export FNOX_KEEPASS_PASSWORD="fnox-test-password"

	# Set a secret
	run "$FNOX_BIN" set FNOX_ENV_TEST "fnox-env-value" --provider keepass
	assert_success
	track_entry_name "FNOX_ENV_TEST"

	# Get it back
	run "$FNOX_BIN" get FNOX_ENV_TEST
	assert_success
	assert_output "fnox-env-value"
}

@test "fnox set fails when writing to title field" {
	create_keepass_config

	# Try to set a secret with title field - should fail
	run "$FNOX_BIN" set TITLE_SECRET "some-title-value" --provider keepass --key-name "my-entry/title"
	assert_failure
	assert_output --partial "Cannot write to 'Title' field"
}

@test "fnox set updates entry in subgroup using just name" {
	create_keepass_config

	# Create an entry in a subgroup
	run "$FNOX_BIN" set SUBGROUP_ENTRY "initial-value" --provider keepass --key-name "mygroup/nested-entry"
	assert_success
	track_entry_name "mygroup/nested-entry"

	# Update using just the entry name (should find it recursively)
	run "$FNOX_BIN" set SUBGROUP_ENTRY "updated-value" --provider keepass --key-name "nested-entry"
	assert_success

	# Verify the update worked (should get updated value)
	run "$FNOX_BIN" get SUBGROUP_ENTRY
	assert_success
	assert_output "updated-value"
}

@test "fnox set creates parent directories for new database" {
	# Use a nested path that doesn't exist
	local nested_db="$BATS_TEST_TMPDIR/nested/dirs/test.kdbx"

	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.keepass]
type = "keepass"
database = "$nested_db"

[secrets]
EOF

	# Set a secret - should create parent directories and database
	run "$FNOX_BIN" set NESTED_DIR_SECRET "nested-value" --provider keepass
	assert_success
	assert_output --partial "Set secret NESTED_DIR_SECRET"

	# Verify the database file was created in the nested directory
	[ -f "$nested_db" ]

	# Verify we can read the secret back
	run "$FNOX_BIN" get NESTED_DIR_SECRET
	assert_success
	assert_output "nested-value"
}
