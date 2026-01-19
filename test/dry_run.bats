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
EXISTING_SECRET = { provider = "age", value = "test" }
EOF
}

# ============================================================================
# SET COMMAND DRY-RUN TESTS
# ============================================================================

@test "fnox set --dry-run shows what would be done without modifying config" {
	setup_age_provider

	# Save original config
	cp fnox.toml fnox.toml.orig

	# Run dry-run set
	assert_fnox_success set MY_SECRET "test-value" --provider age --dry-run
	assert_output --partial "[dry-run]"
	assert_output --partial "Would set secret"
	assert_output --partial "MY_SECRET"

	# Verify config was NOT modified
	diff fnox.toml fnox.toml.orig
}

@test "fnox set -n is alias for --dry-run" {
	setup_age_provider

	# Save original config
	cp fnox.toml fnox.toml.orig

	# Run with -n
	assert_fnox_success set MY_SECRET "test-value" --provider age -n
	assert_output --partial "[dry-run]"
	assert_output --partial "Would set secret"

	# Verify config was NOT modified
	diff fnox.toml fnox.toml.orig
}

@test "fnox set --dry-run shows provider info" {
	setup_age_provider

	assert_fnox_success set MY_SECRET "test-value" --provider age --dry-run
	assert_output --partial "provider: age"
}

@test "fnox set --dry-run shows target file path" {
	setup_age_provider

	assert_fnox_success set MY_SECRET "test-value" --provider age --dry-run
	assert_output --partial "fnox.toml"
}

@test "fnox set --dry-run with description shows description field" {
	setup_age_provider

	assert_fnox_success set MY_SECRET "test-value" --provider age --description "A test secret" --dry-run
	assert_output --partial "[dry-run]"
	assert_output --partial "description:"
	assert_output --partial "A test secret"
}

# ============================================================================
# REMOVE COMMAND DRY-RUN TESTS
# ============================================================================

@test "fnox remove --dry-run shows what would be removed without modifying config" {
	setup_age_provider

	# Save original config
	cp fnox.toml fnox.toml.orig

	# Run dry-run remove
	assert_fnox_success remove EXISTING_SECRET --dry-run
	assert_output --partial "[dry-run]"
	assert_output --partial "Would remove secret"
	assert_output --partial "EXISTING_SECRET"

	# Verify config was NOT modified
	diff fnox.toml fnox.toml.orig
}

@test "fnox remove -n is alias for --dry-run" {
	setup_age_provider

	# Save original config
	cp fnox.toml fnox.toml.orig

	# Run with -n
	assert_fnox_success remove EXISTING_SECRET -n
	assert_output --partial "[dry-run]"
	assert_output --partial "Would remove secret"

	# Verify config was NOT modified
	diff fnox.toml fnox.toml.orig
}

@test "fnox remove --dry-run still fails for non-existent secrets" {
	setup_age_provider

	assert_fnox_failure remove NONEXISTENT_SECRET --dry-run
	assert_output --partial "not found"
}

# ============================================================================
# IMPORT COMMAND DRY-RUN TESTS
# ============================================================================

@test "fnox import --dry-run shows what would be imported without modifying config" {
	setup_age_provider

	# Create a .env file
	cat >.env <<EOF
NEW_SECRET1=value1
NEW_SECRET2=value2
NEW_SECRET3=value3
EOF

	# Save original config
	cp fnox.toml fnox.toml.orig

	# Run dry-run import
	assert_fnox_success import -i .env --provider age --dry-run
	assert_output --partial "[dry-run]"
	assert_output --partial "Would import 3 secrets"
	assert_output --partial "NEW_SECRET1"
	assert_output --partial "NEW_SECRET2"
	assert_output --partial "NEW_SECRET3"

	# Verify config was NOT modified
	diff fnox.toml fnox.toml.orig
}

@test "fnox import -n is alias for --dry-run" {
	setup_age_provider

	cat >.env <<EOF
SECRET=value
EOF

	cp fnox.toml fnox.toml.orig

	assert_fnox_success import -i .env --provider age -n
	assert_output --partial "[dry-run]"

	diff fnox.toml fnox.toml.orig
}

@test "fnox import --dry-run shows provider name" {
	setup_age_provider

	cat >.env <<EOF
SECRET=value
EOF

	assert_fnox_success import -i .env --provider age --dry-run
	assert_output --partial "provider"
	assert_output --partial "age"
}

@test "fnox import --dry-run with --filter shows filtered secrets" {
	setup_age_provider

	cat >.env <<EOF
DATABASE_URL=postgresql://localhost
DATABASE_PASSWORD=secret
API_KEY=key123
EOF

	assert_fnox_success import -i .env --provider age --filter "^DATABASE_" --dry-run
	assert_output --partial "Would import 2 secrets"
	assert_output --partial "DATABASE_URL"
	assert_output --partial "DATABASE_PASSWORD"
	refute_output --partial "API_KEY"
}

@test "fnox import --dry-run with --prefix shows prefixed secrets" {
	setup_age_provider

	cat >.env <<EOF
SECRET=value
EOF

	assert_fnox_success import -i .env --provider age --prefix "MYAPP_" --dry-run
	assert_output --partial "MYAPP_SECRET"
}

@test "fnox import --dry-run from stdin works without --force" {
	setup_age_provider

	# Dry-run should work with stdin without requiring --force
	# (since there's no confirmation prompt in dry-run mode)
	run bash -c 'echo "SECRET=value" | fnox import --provider age --dry-run'
	[ "$status" -eq 0 ]
	[[ $output =~ \[dry-run\] ]]
	[[ $output =~ "Would import 1 secrets" ]]
}

@test "fnox import --dry-run fails on non-existent provider" {
	setup_age_provider

	cat >.env <<EOF
SECRET=value
EOF

	# Should fail because provider doesn't exist (validation before dry-run output)
	assert_fnox_failure import -i .env --provider nonexistent --dry-run
	assert_output --partial "Provider 'nonexistent' not found"
}

# ============================================================================
# EXPORT COMMAND DRY-RUN TESTS
# ============================================================================

@test "fnox export --dry-run with -o shows what would be written without creating file" {
	setup_age_provider

	# Run dry-run export to file
	assert_fnox_success export -o secrets.env --dry-run
	assert_output --partial "[dry-run]"
	assert_output --partial "Would export"
	assert_output --partial "secrets.env"

	# Verify file was NOT created
	assert [ ! -f secrets.env ]
}

@test "fnox export -n is alias for --dry-run" {
	setup_age_provider

	assert_fnox_success export -o secrets.env -n
	assert_output --partial "[dry-run]"

	assert [ ! -f secrets.env ]
}

@test "fnox export --dry-run to stdout still outputs normally" {
	setup_age_provider

	# When outputting to stdout (no -o flag), dry-run just outputs normally
	# because there's nothing to "protect"
	assert_fnox_success export --dry-run
	# Should output env format (default)
	assert_output --partial "EXISTING_SECRET"
}

@test "fnox export --dry-run shows secret names without values" {
	setup_age_provider

	assert_fnox_success export -o secrets.env --dry-run
	# Should show the key name
	assert_output --partial "EXISTING_SECRET"
}
