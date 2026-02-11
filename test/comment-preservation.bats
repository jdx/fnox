#!/usr/bin/env bats

load 'test_helper/common_setup'

# Test that fnox import and fnox remove preserve TOML comments

setup() {
	_common_setup
}

teardown() {
	_common_teardown
}

# Helper function to setup age provider with comments in config
setup_age_with_comments() {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with comments throughout
	cat >fnox.toml <<EOF
# Main configuration file for the project
root = true

# Age encryption provider
[providers.age]
type = "age"
recipients = ["$public_key"]

# Application secrets
[secrets]
# Database connection string
DB_URL= { provider = "age", value = "plaintext-db-url" }
# API key for external service
API_KEY= { provider = "age", value = "plaintext-api-key" }
# End of secrets section
EOF
}

@test "fnox remove preserves comments in fnox.toml" {
	setup_age_with_comments

	# Remove one secret
	assert_fnox_success remove API_KEY

	# Verify all comments are preserved
	run cat fnox.toml
	assert_output --partial "# Main configuration file for the project"
	assert_output --partial "# Age encryption provider"
	assert_output --partial "# Application secrets"
	assert_output --partial "# Database connection string"
	assert_output --partial "# End of secrets section"

	# Verify the removed secret is gone
	refute_output --partial "API_KEY"

	# Verify the remaining secret is still there
	assert_output --partial "DB_URL"
}

@test "fnox remove preserves comments when removing last secret" {
	setup_age_with_comments

	# Remove both secrets
	assert_fnox_success remove DB_URL
	assert_fnox_success remove API_KEY

	# Verify comments are still preserved
	run cat fnox.toml
	assert_output --partial "# Main configuration file for the project"
	assert_output --partial "# Age encryption provider"
	assert_output --partial "# Application secrets"
}

@test "fnox import preserves existing comments in fnox.toml" {
	setup_age_with_comments

	# Create a .env file with new secrets to import
	cat >.env <<EOF
NEW_SECRET=new-secret-value
ANOTHER_SECRET=another-value
EOF

	# Import new secrets
	assert_fnox_success import -i .env --provider age --force

	# Verify all original comments are preserved
	run cat fnox.toml
	assert_output --partial "# Main configuration file for the project"
	assert_output --partial "# Age encryption provider"
	assert_output --partial "# Application secrets"
	assert_output --partial "# Database connection string"
	assert_output --partial "# API key for external service"
	assert_output --partial "# End of secrets section"

	# Verify new secrets were added
	assert_output --partial "NEW_SECRET"
	assert_output --partial "ANOTHER_SECRET"

	# Verify existing secrets are still there
	assert_output --partial "DB_URL"
	assert_output --partial "API_KEY"
}

@test "fnox import preserves comments when config file has no existing secrets" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with comments but no secrets section
	cat >fnox.toml <<EOF
# Project config
root = true

# Encryption provider
[providers.age]
type = "age"
recipients = ["$public_key"]
EOF

	cat >.env <<EOF
MY_SECRET=my-value
EOF

	assert_fnox_success import -i .env --provider age --force

	# Verify comments preserved
	run cat fnox.toml
	assert_output --partial "# Project config"
	assert_output --partial "# Encryption provider"
	assert_output --partial "MY_SECRET"
}

@test "fnox import followed by remove preserves comments" {
	setup_age_with_comments

	# Import a new secret
	cat >.env <<EOF
TEMP_SECRET=temp-value
EOF
	assert_fnox_success import -i .env --provider age --force

	# Then remove it
	assert_fnox_success remove TEMP_SECRET

	# All original comments should still be there
	run cat fnox.toml
	assert_output --partial "# Main configuration file for the project"
	assert_output --partial "# Age encryption provider"
	assert_output --partial "# Application secrets"
	assert_output --partial "# Database connection string"
	assert_output --partial "# API key for external service"
	assert_output --partial "# End of secrets section"

	# Original secrets should still be there
	assert_output --partial "DB_URL"
	assert_output --partial "API_KEY"

	# Temp secret should be gone
	refute_output --partial "TEMP_SECRET"
}
