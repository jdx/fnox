#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "config with no providers returns error" {
	# Create config with no providers
	cat >fnox.toml <<'EOF'
root = true

[secrets]
MY_SECRET = { value = "test" }
EOF

	# Any command that loads the config should fail
	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "No providers configured"
}

@test "single provider is auto-selected as default" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

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
	run "$FNOX_BIN" get MY_SECRET --age-key-file key.txt
	assert_success
	assert_output "secret-value"
}

@test "explicit default_provider is used when set" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with multiple providers and explicit default
	cat >fnox.toml <<EOF
root = true
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$public_key"]

[providers.vault]
type = "vault"
address = "https://vault.example.com"

[secrets]
EOF

	# Set a secret without specifying provider - should use default_provider
	run "$FNOX_BIN" set MY_SECRET "secret-value"
	assert_success

	# Verify the secret was encrypted with the age provider
	assert_config_contains "MY_SECRET"
	assert_config_not_contains "secret-value"

	# Should be able to get it back
	run "$FNOX_BIN" get MY_SECRET --age-key-file key.txt
	assert_success
	assert_output "secret-value"
}

@test "profile default_provider overrides global default_provider" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate two age keys
	local keygen_output1
	keygen_output1=$(age-keygen -o key1.txt 2>&1)
	local public_key1
	public_key1=$(echo "$keygen_output1" | grep "^Public key:" | cut -d' ' -f3)

	local keygen_output2
	keygen_output2=$(age-keygen -o key2.txt 2>&1)
	local public_key2
	public_key2=$(echo "$keygen_output2" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with global default and profile override
	cat >fnox.toml <<EOF
root = true
default_provider = "age1"

[providers.age1]
type = "age"
recipients = ["$public_key1"]

[providers.age2]
type = "age"
recipients = ["$public_key2"]

[secrets]

[profiles.prod]
default_provider = "age2"

[profiles.prod.secrets]
EOF

	# Set a secret in default profile - should use age1
	run "$FNOX_BIN" set DEFAULT_SECRET "default-value"
	assert_success

	# Set a secret in prod profile - should use age2
	run "$FNOX_BIN" set --profile prod PROD_SECRET "prod-value"
	assert_success

	# Verify we can get them back with the right keys
	run "$FNOX_BIN" get DEFAULT_SECRET --age-key-file key1.txt
	assert_success
	assert_output "default-value"

	run "$FNOX_BIN" get --profile prod PROD_SECRET --age-key-file key2.txt
	assert_success
	assert_output "prod-value"
}

@test "multiple providers without default_provider requires explicit provider" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with multiple providers and NO default
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[providers.vault]
type = "vault"
address = "https://vault.example.com"

[secrets]
EOF

	# Set a secret without specifying provider - should store as plaintext since no default
	run "$FNOX_BIN" set MY_SECRET "secret-value"
	assert_success

	# Verify the secret was stored as plaintext (not encrypted)
	assert_config_contains "secret-value"

	# Get should work
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "secret-value"
}

@test "invalid default_provider returns error" {
	# Create config with invalid default_provider
	cat >fnox.toml <<'EOF'
root = true
default_provider = "nonexistent"

[providers.age]
type = "age"
recipients = ["age1test"]

[secrets]
EOF

	# Should fail to validate
	run "$FNOX_BIN" get MY_SECRET 2>&1 || true
	assert_failure
	assert_output --partial "Default provider 'nonexistent' not found"
}

@test "profile with no providers (and no global providers) returns error" {
	# Create config with profile that has no providers
	# Set if_missing = "error" to require the secret
	cat >fnox.toml <<'EOF'
root = true

[secrets]

[profiles.test]

[profiles.test.secrets]
MY_SECRET = { description = "test secret", if_missing = "error" }
EOF

	# Should fail because profile has no providers and secret has no value
	run "$FNOX_BIN" get --profile test MY_SECRET
	assert_failure
}

@test "profile inherits global providers" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with global provider only
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]

[profiles.test]

[profiles.test.secrets]
EOF

	# Set a secret in test profile - should use inherited provider
	run "$FNOX_BIN" set --profile test TEST_SECRET "test-value"
	assert_success

	# Verify it was encrypted
	assert_config_not_contains "test-value"

	# Should be able to get it back
	run "$FNOX_BIN" get --profile test TEST_SECRET --age-key-file key.txt
	assert_success
	assert_output "test-value"
}

@test "explicit provider overrides default_provider" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate two age keys
	local keygen_output1
	keygen_output1=$(age-keygen -o key1.txt 2>&1)
	local public_key1
	public_key1=$(echo "$keygen_output1" | grep "^Public key:" | cut -d' ' -f3)

	local keygen_output2
	keygen_output2=$(age-keygen -o key2.txt 2>&1)
	local public_key2
	public_key2=$(echo "$keygen_output2" | grep "^Public key:" | cut -d' ' -f3)

	# Create config with default_provider
	cat >fnox.toml <<EOF
root = true
default_provider = "age1"

[providers.age1]
type = "age"
recipients = ["$public_key1"]

[providers.age2]
type = "age"
recipients = ["$public_key2"]

[secrets]
EOF

	# Set a secret with explicit provider (should override default)
	run "$FNOX_BIN" set MY_SECRET "secret-value" --provider age2
	assert_success

	# Should need key2 to decrypt (not key1)
	run "$FNOX_BIN" get MY_SECRET --age-key-file key2.txt
	assert_success
	assert_output "secret-value"

	# Should fail with key1
	run "$FNOX_BIN" get MY_SECRET --age-key-file key1.txt
	assert_failure
}
