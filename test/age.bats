#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "decrypts using FNOX_AGE_KEY environment variable" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	local private_key
	private_key=$(grep "^AGE-SECRET-KEY" key.txt)

	# Create config with single provider
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	# Set a secret without specifying provider - should use the only one available
	run "$FNOX_BIN" set MY_SECRET "secret-value"
	assert_success

	# Verify the secret was encrypted with the age provider
	assert_config_contains "MY_SECRET"
	assert_config_not_contains "secret-value"

	# Should be able to get it back
	export FNOX_AGE_KEY=$private_key
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "secret-value"
}

@test "decrypts using post-quantum age keys" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Check if age supports -pq flag (version 1.3.0+)
	if ! age-keygen --help 2>&1 | grep -q "\-pq"; then
		skip "age does not support post-quantum keys (need age >= 1.3.0)"
	fi

	# Generate post-quantum age key
	local keygen_output
	keygen_output=$(age-keygen -pq -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	local private_key
	private_key=$(grep "^AGE-SECRET-KEY-PQ" key.txt)

	# Create config with post-quantum provider
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	# Set a secret
	run "$FNOX_BIN" set MY_SECRET "secret-value"
	assert_success

	# Verify the secret was encrypted
	assert_config_contains "MY_SECRET"
	assert_config_not_contains "secret-value"

	# Should be able to get it back
	export FNOX_AGE_KEY=$private_key
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "secret-value"
}

@test "supports mixed recipient types (x25519 and post-quantum)" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	if ! age-keygen --help 2>&1 | grep -q "\-pq"; then
		skip "age does not support post-quantum keys (need age >= 1.3.0)"
	fi

	# Generate regular age key
	local regular_output
	regular_output=$(age-keygen -o regular.txt 2>&1)
	local regular_public
	regular_public=$(echo "$regular_output" | grep "^Public key:" | cut -d' ' -f3)
	local _regular_private
	_regular_private=$(grep "^AGE-SECRET-KEY-1" regular.txt)

	# Generate post-quantum age key
	local pq_output
	pq_output=$(age-keygen -pq -o pq.txt 2>&1)
	local pq_public
	pq_public=$(echo "$pq_output" | grep "^Public key:" | cut -d' ' -f3)
	local _pq_private
	_pq_private=$(grep "^AGE-SECRET-KEY-PQ" pq.txt)

	# Create config with both recipient types
	# Note: The age library currently does not support mixing x25519 and post-quantum
	# recipients in the same encryption operation due to incompatible labels
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$regular_public", "$pq_public"]

[secrets]
EOF

	# This is expected to fail with IncompatibleRecipients error
	# The age format requires all recipients to have compatible labels
	run "$FNOX_BIN" set MY_SECRET "secret-value"
	assert_failure
}
