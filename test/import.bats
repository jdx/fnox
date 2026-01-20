#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# Helper function to setup age provider
setup_age_provider() {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with age provider
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF
}

@test "fnox import requires --provider flag" {
	setup_age_provider

	# Create a .env file
	cat >.env <<EOF
TEST_SECRET=value123
EOF

	# Import without --provider should fail
	assert_fnox_failure import -i .env --force
	assert_output --partial "required arguments were not provided"
	assert_output --partial "--provider"
}

@test "fnox import reads from .env file with -i flag" {
	setup_age_provider

	# Create a .env file with test secrets
	cat >.env <<EOF
DATABASE_URL=postgresql://localhost:5432/mydb
API_KEY=secret-key-123
DEBUG_MODE=true
EOF

	# Import from .env file with age provider
	assert_fnox_success import -i .env --provider age --force

	# Verify secrets were imported and encrypted (not plaintext)
	assert_config_not_contains "postgresql://localhost:5432/mydb"
	assert_config_not_contains "secret-key-123"

	# Verify secrets can be retrieved with age key
	assert_fnox_success get DATABASE_URL --age-key-file key.txt
	assert_output "postgresql://localhost:5432/mydb"

	assert_fnox_success get API_KEY --age-key-file key.txt
	assert_output "secret-key-123"

	assert_fnox_success get DEBUG_MODE --age-key-file key.txt
	assert_output "true"
}

@test "fnox import handles quoted values in .env file" {
	setup_age_provider

	# Create a .env file with quoted values
	cat >.env <<EOF
SINGLE_QUOTED='value with spaces'
DOUBLE_QUOTED="another value with spaces"
UNQUOTED=no_spaces
EOF

	assert_fnox_success import -i .env --provider age --force

	assert_fnox_success get SINGLE_QUOTED --age-key-file key.txt
	assert_output "value with spaces"

	assert_fnox_success get DOUBLE_QUOTED --age-key-file key.txt
	assert_output "another value with spaces"

	assert_fnox_success get UNQUOTED --age-key-file key.txt
	assert_output "no_spaces"
}

@test "fnox import handles export statements in .env file" {
	setup_age_provider

	# Create a .env file with export statements
	cat >.env <<EOF
export DATABASE_URL=postgresql://localhost:5432/mydb
export API_KEY=secret-key-456
REGULAR_VAR=regular-value
EOF

	assert_fnox_success import -i .env --provider age --force

	assert_fnox_success get DATABASE_URL --age-key-file key.txt
	assert_output "postgresql://localhost:5432/mydb"

	assert_fnox_success get API_KEY --age-key-file key.txt
	assert_output "secret-key-456"

	assert_fnox_success get REGULAR_VAR --age-key-file key.txt
	assert_output "regular-value"
}

@test "fnox import skips comments and empty lines" {
	setup_age_provider

	# Create a .env file with comments and empty lines
	cat >.env <<EOF
# This is a comment
DATABASE_URL=postgresql://localhost:5432/mydb

# Another comment
API_KEY=secret-key-789

EOF

	assert_fnox_success import -i .env --provider age --force

	# Should only import the two actual variables
	assert_fnox_success list
	assert_output --partial "DATABASE_URL"
	assert_output --partial "API_KEY"
	refute_output --partial "#"
}

@test "fnox import with --filter flag filters secrets by regex" {
	setup_age_provider

	# Create a .env file
	cat >.env <<EOF
DATABASE_URL=postgresql://localhost:5432/mydb
DATABASE_PASSWORD=secret123
API_KEY=secret-key-abc
API_SECRET=secret-abc-456
DEBUG_MODE=true
EOF

	# Import only DATABASE_* secrets
	assert_fnox_success import -i .env --filter "^DATABASE_" --provider age --force

	# Should have DATABASE_* secrets
	assert_fnox_success get DATABASE_URL --age-key-file key.txt
	assert_output "postgresql://localhost:5432/mydb"

	assert_fnox_success get DATABASE_PASSWORD --age-key-file key.txt
	assert_output "secret123"

	# Should not have API_* or DEBUG_MODE
	assert_fnox_failure get API_KEY
	assert_fnox_failure get DEBUG_MODE
}

@test "fnox import with --prefix flag adds prefix to secret names" {
	setup_age_provider

	# Create a .env file
	cat >.env <<EOF
DATABASE_URL=postgresql://localhost:5432/mydb
API_KEY=secret-key-xyz
EOF

	# Import with prefix
	assert_fnox_success import -i .env --prefix "MYAPP_" --provider age --force

	# Should be accessible with prefix
	assert_fnox_success get MYAPP_DATABASE_URL --age-key-file key.txt
	assert_output "postgresql://localhost:5432/mydb"

	assert_fnox_success get MYAPP_API_KEY --age-key-file key.txt
	assert_output "secret-key-xyz"

	# Should not be accessible without prefix
	assert_fnox_failure get DATABASE_URL
	assert_fnox_failure get API_KEY
}

@test "fnox import requires confirmation by default" {
	setup_age_provider

	# Create a .env file
	cat >.env <<EOF
DATABASE_URL=postgresql://localhost:5432/mydb
EOF

	# Import without --force should prompt for confirmation
	run bash -c "echo 'n' | $FNOX_BIN import -i .env --provider age"
	assert_output --partial "Continue? [y/N]"
	assert_output --partial "Import cancelled"

	# Secret should not have been imported
	assert_fnox_failure get DATABASE_URL
}

@test "fnox import reads from stdin when -i is not specified" {
	setup_age_provider

	# Import from stdin
	run bash -c "echo -e 'DATABASE_URL=postgresql://localhost:5432/mydb\nAPI_KEY=secret-key' | $FNOX_BIN import --provider age --force"
	assert_success

	# Verify secrets were imported
	assert_fnox_success get DATABASE_URL --age-key-file key.txt
	assert_output "postgresql://localhost:5432/mydb"

	assert_fnox_success get API_KEY --age-key-file key.txt
	assert_output "secret-key"
}

@test "fnox import from stdin requires --force flag" {
	setup_age_provider

	# FIXED: stdin imports now require --force to avoid double-stdin consumption bug
	# Without --force, importing from stdin would consume stdin twice:
	#   1. First to read import data (read_input)
	#   2. Then to read confirmation (stdin.read_line)
	# This would cause the import to fail because stdin is at EOF after reading data

	# First test: import without --provider should fail with missing provider error
	run bash -c "echo -e 'TEST_VAR=test123' | $FNOX_BIN import"
	assert_failure
	assert_output --partial "required arguments were not provided"
	assert_output --partial "--provider"

	# Second test: import with --provider but without --force should fail with stdin consumption error
	run bash -c "echo -e 'TEST_VAR=test456' | $FNOX_BIN import --provider age"
	assert_failure
	assert_output --partial "--force"
	assert_output --partial "Stdin is consumed during import"

	# Verify secrets were NOT imported
	assert_fnox_failure get TEST_VAR

	# Now try with both --provider and --force - should succeed
	run bash -c "echo -e 'TEST_VAR=test123' | $FNOX_BIN import --provider age --force"
	assert_success

	# Verify secret WAS imported
	assert_fnox_success get TEST_VAR --age-key-file key.txt
	assert_output "test123"
}

@test "fnox import supports json format" {
	setup_age_provider

	# Create a JSON file
	cat >secrets.json <<EOF
{
  "DATABASE_URL": "postgresql://localhost:5432/mydb",
  "API_KEY": "secret-key-json"
}
EOF

	assert_fnox_success import -i secrets.json json --provider age --force

	assert_fnox_success get DATABASE_URL --age-key-file key.txt
	assert_output "postgresql://localhost:5432/mydb"

	assert_fnox_success get API_KEY --age-key-file key.txt
	assert_output "secret-key-json"
}

@test "fnox import shows helpful error when file does not exist" {
	setup_age_provider

	# Try to import from non-existent file
	assert_fnox_failure import -i nonexistent.env --provider age --force
	assert_output --partial "Failed to read import source"
}

@test "fnox import fails with non-existent provider" {
	setup_age_provider

	# Create a .env file
	cat >.env <<EOF
SECRET=value
EOF

	# Try to import with non-existent provider
	assert_fnox_failure import -i .env --provider nonexistent --force
	assert_output --partial "Provider 'nonexistent' not configured"
}
