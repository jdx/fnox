#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox set -k prompts for secret value (reads from stdin)" {
	# Generate age key
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	cat >test-config.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	# Pipe secret value via stdin with -k flag — should encrypt and store
	run bash -c 'echo "my-secret-value" | "$FNOX_BIN" --config test-config.toml set -p age -k custom-key-name MY_SECRET'
	assert_success

	# The config should reference the secret
	assert_file_contains test-config.toml "MY_SECRET"
	# The plaintext secret value should NOT appear in the config (it should be encrypted)
	assert_file_not_contains test-config.toml "my-secret-value"
}

@test "fnox set -k with explicit value stores the secret" {
	# Generate age key
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	cat >test-config.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	# Provide value as argument with -k flag
	run "$FNOX_BIN" --config test-config.toml set -p age -k custom-key-name MY_SECRET "my-secret-value"
	assert_success

	# The config should reference the secret
	assert_file_contains test-config.toml "MY_SECRET"
	# The plaintext secret value should NOT appear (it should be encrypted)
	assert_file_not_contains test-config.toml "my-secret-value"
}
