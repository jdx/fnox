#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox set in child directory should not duplicate parent config" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config with provider and secrets
	cat >parent/fnox.toml <<EOF
[providers.age_provider]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[secrets]
PARENT_SECRET = { provider = "age_provider", value = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p:encrypted:parent" }
EOF

	# Change to child directory
	cd parent/child

	# Set a new secret in child directory
	run "$FNOX_BIN" set CHILD_SECRET "child-value" --provider age_provider
	assert_success

	# Check that child fnox.toml was created
	assert [ -f fnox.toml ]

	# Check that child config does NOT contain parent secrets
	run cat fnox.toml
	assert_success
	refute_output --partial "PARENT_SECRET"

	# Check that child config DOES contain the new secret
	assert_output --partial "CHILD_SECRET"

	# Verify parent config is unchanged
	run cat ../fnox.toml
	assert_success
	assert_output --partial "PARENT_SECRET"
	refute_output --partial "CHILD_SECRET"
}

@test "fnox set in child directory with existing child config should not duplicate parent config" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config with provider and secrets
	cat >parent/fnox.toml <<EOF
[providers.age_provider]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[secrets]
PARENT_SECRET = { provider = "age_provider", value = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p:encrypted:parent" }
PARENT_SECRET_2 = { provider = "age_provider", value = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p:encrypted:parent2" }
EOF

	# Create child config with one secret
	cat >parent/child/fnox.toml <<EOF
[secrets]
EXISTING_CHILD_SECRET = { default = "existing-value" }
EOF

	# Change to child directory
	cd parent/child

	# Set a new secret in child directory
	run "$FNOX_BIN" set NEW_CHILD_SECRET "new-child-value" --provider age_provider
	assert_success

	# Check that child config does NOT contain parent secrets
	run cat fnox.toml
	assert_success
	refute_output --partial "PARENT_SECRET"
	refute_output --partial "PARENT_SECRET_2"

	# Check that child config contains both child secrets
	assert_output --partial "EXISTING_CHILD_SECRET"
	assert_output --partial "NEW_CHILD_SECRET"

	# Verify parent config is unchanged
	run cat ../fnox.toml
	assert_success
	assert_output --partial "PARENT_SECRET"
	assert_output --partial "PARENT_SECRET_2"
	refute_output --partial "EXISTING_CHILD_SECRET"
	refute_output --partial "NEW_CHILD_SECRET"
}

@test "fnox set in child with parent provider does not duplicate provider" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config with a provider
	cat >parent/fnox.toml <<EOF
root = true

[providers.plain]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[secrets]
PARENT_SECRET = { default = "parent-value" }
EOF

	# Change to child directory
	cd parent/child

	# Set a new secret (uses default provider from parent)
	run "$FNOX_BIN" set TEST_SECRET "test-value-123"
	assert_success

	# Verify child config was created with only the new secret, NOT the provider config
	run cat fnox.toml
	assert_success
	assert_output --partial "TEST_SECRET"
	refute_output --partial "PARENT_SECRET"
	# The secret may reference the provider name, but should not duplicate the [providers] section
	refute_output --partial "[providers"

	# Verify parent config is unchanged
	run cat ../fnox.toml
	assert_success
	assert_output --partial "PARENT_SECRET"
	assert_output --partial "providers"
	refute_output --partial "TEST_SECRET"
}

@test "fnox set creates local override for parent secrets" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config
	cat >parent/fnox.toml <<EOF
[providers.age_provider]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[secrets]
PARENT_SECRET = { default = "original-parent-value" }
EOF

	# Create child config
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { default = "original-child-value" }
EOF

	# Change to child directory
	cd parent/child

	# Setting a parent secret from child should create a LOCAL override
	# NOT modify the parent config (this is the fix for #104 and #121)
	run "$FNOX_BIN" set PARENT_SECRET "child-override-value"
	assert_success

	# Verify parent config was NOT modified (should keep original value)
	run cat ../fnox.toml
	assert_success
	assert_output --partial 'PARENT_SECRET'
	assert_output --partial 'original-parent-value'
	refute_output --partial "child-override-value"

	# Verify child config now has local override
	run cat fnox.toml
	assert_success
	assert_output --partial 'CHILD_SECRET'
	assert_output --partial 'PARENT_SECRET'
	assert_output --partial 'child-override-value'

	# Update the child secret (should update child file)
	run "$FNOX_BIN" set CHILD_SECRET "updated-child-value"
	assert_success

	# Verify child config was updated
	run cat fnox.toml
	assert_success
	assert_output --partial 'CHILD_SECRET'
	assert_output --partial 'updated-child-value'
	assert_output --partial 'PARENT_SECRET'

	# Verify parent config was still NOT modified
	run cat ../fnox.toml
	assert_success
	assert_output --partial 'PARENT_SECRET'
	assert_output --partial 'original-parent-value'
	refute_output --partial "CHILD_SECRET"
	refute_output --partial "updated-child-value"
}
