#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox set fails when no default provider is configured" {
	# Create a minimal config with no providers and no default provider set
	# Use a custom config name to avoid recursive search finding project config
	cat >test-config.toml <<EOF
[secrets]
EOF

	# Try to set a secret without specifying a provider
	# This should fail because there's no default provider
	run "$FNOX_BIN" --config test-config.toml set TEST_SECRET "some-secret-value"
	assert_failure

	# Should contain an error message about no providers
	assert_output --partial "No providers configured"
	assert_output --partial "provider"
}

@test "fnox set fails when no default provider and no providers exist" {
	# Create an empty config (no providers section)
	# Use a custom config name to avoid recursive search finding project config
	cat >test-config2.toml <<EOF
[secrets]
EOF

	# Try to set a secret without specifying a provider
	run "$FNOX_BIN" --config test-config2.toml set ANOTHER_SECRET "another-value"
	assert_failure

	# Should contain an error about no provider
	assert_output --partial "No providers configured"
	assert_output --partial "provider"
}

@test "fnox set succeeds when provider is explicitly specified" {
	# Generate age key
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with age provider but no default
	cat >test-config3.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	# This should succeed because we explicitly specify the provider
	run "$FNOX_BIN" --config test-config3.toml set EXPLICIT_SECRET "explicit-value" --provider age
	assert_success

	# Verify the secret was encrypted
	assert_file_contains test-config3.toml "EXPLICIT_SECRET"
	assert_file_contains test-config3.toml 'provider = "age"'
	assert_file_not_contains test-config3.toml "explicit-value"
}

@test "fnox set fails when default provider is configured but no providers exist" {
	# Create config with a default provider but no providers section
	# Use a custom config name to avoid recursive search finding project config
	cat >test-config4.toml <<EOF
default_provider = "nonexistent"

[secrets]
EOF

	# Try to set a secret without specifying a provider
	run "$FNOX_BIN" --config test-config4.toml set BROKEN_SECRET "broken-value"
	assert_failure

	# Should contain an error about no providers (takes precedence over default provider)
	assert_output --partial "No providers configured"
	assert_output --partial "provider"
}

@test "fnox set succeeds with valid default provider" {
	# Generate age key
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with age provider and default_provider set
	# Use a custom config name to avoid recursive search finding project config
	cat >test-config5.toml <<EOF
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	# This should succeed because default_provider is properly configured
	run "$FNOX_BIN" --config test-config5.toml set DEFAULT_SECRET "default-value"
	assert_success

	# Verify the secret was encrypted with the default provider
	assert_file_contains test-config5.toml "DEFAULT_SECRET"
	assert_file_contains test-config5.toml 'provider = "age"'
	assert_file_not_contains test-config5.toml "default-value"
}

@test "fnox set falls back to current provider when updating secrets" {
	# With multiple providers configured and no default_provider, `fnox set`
	# previously stored the new value as plaintext while leaving the original
	# `provider` key in place. Subsequent `fnox get` calls then failed, since
	# fnox would try to decrypt a value that was no longer encrypted.
	#
	# This test ensures `fnox set` reuses the secret's existing provider before
	# falling back to `default_provider` or plaintext.

	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output1
	keygen_output1=$(age-keygen -o key1.txt 2>&1)
	local public_key1
	public_key1=$(echo "$keygen_output1" | grep "^Public key:" | cut -d' ' -f3)

	local keygen_output2
	keygen_output2=$(age-keygen -o key2.txt 2>&1)
	local public_key2
	public_key2=$(echo "$keygen_output2" | grep "^Public key:" | cut -d' ' -f3)

	cat >test-config-multi.toml <<EOF
root = true

[providers.provider1]
type = "age"
recipients = ["$public_key1"]

[providers.provider2]
type = "age"
recipients = ["$public_key2"]

[secrets]
EOF

	# Explicitly create MY_SECRET using --provider provider1.
	run "$FNOX_BIN" --config test-config-multi.toml set --provider provider1 MY_SECRET "original-value"
	assert_success
	assert_file_contains test-config-multi.toml 'provider = "provider1"'
	assert_file_not_contains test-config-multi.toml "original-value"

	# Update without --provider: should reuse the secret's existing provider.
	run "$FNOX_BIN" --config test-config-multi.toml set MY_SECRET "new-value"
	assert_success
	assert_file_contains test-config-multi.toml 'provider = "provider1"'
	assert_file_not_contains test-config-multi.toml "new-value"

	# Round-trip decrypts to the new value with the provider1 key.
	run "$FNOX_BIN" --config test-config-multi.toml get MY_SECRET --age-key-file key1.txt
	assert_success
	assert_output "new-value"
}
