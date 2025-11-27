#!/usr/bin/env bats

# Tests for secret references in provider configuration
# This allows provider config properties to reference secrets using:
#   property = { secret = "SECRET_NAME" }

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test 'provider config can reference secret via { secret = "NAME" } syntax' {
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

	# Create config where age provider's key_file references a secret
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]
key_file = { secret = "AGE_KEY_PATH" }

[secrets]
AGE_KEY_PATH = { default = "./key.txt" }
MY_SECRET = { provider = "age", value = "test" }
EOF

	# Set a secret
	run "$FNOX_BIN" set MY_SECRET "secret-value"
	assert_success

	# Should be able to get it back - key_file resolved from AGE_KEY_PATH secret
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "secret-value"
}

@test "secret ref falls back to environment variable" {
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

	# Create config where key_file references a secret not defined in config
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]
key_file = { secret = "MY_AGE_KEY_FILE" }

[secrets]
MY_SECRET = { provider = "age", value = "test" }
EOF

	# Set the secret ref via environment variable
	export MY_AGE_KEY_FILE="./key.txt"

	# Set a secret
	run "$FNOX_BIN" set MY_SECRET "env-fallback-value"
	assert_success

	# Should be able to get it back
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "env-fallback-value"
}

@test "secret ref error when secret not found in config or env" {
	# Create config with secret ref that doesn't exist
	cat >fnox.toml <<EOF
root = true

[providers.vault]
type = "vault"
address = "http://localhost:8200"
token = { secret = "NONEXISTENT_SECRET" }

[secrets]
MY_SECRET = { provider = "vault", value = "test" }
EOF

	# Unset the env var if it exists
	unset NONEXISTENT_SECRET 2>/dev/null || true

	# Should fail when trying to resolve the provider config
	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "NONEXISTENT_SECRET"
}

@test "secret ref can chain providers (age-encrypted token for vault)" {
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

	# Create config where vault token is stored encrypted with age
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[providers.vault]
type = "vault"
address = "http://localhost:8200"
token = { secret = "VAULT_TOKEN" }

[secrets]
EOF

	# Store the vault token encrypted with age
	export FNOX_AGE_KEY=$private_key
	run "$FNOX_BIN" set VAULT_TOKEN "my-vault-token" --provider age
	assert_success

	# Verify VAULT_TOKEN is encrypted in config
	assert_config_contains "VAULT_TOKEN"
	assert_config_not_contains "my-vault-token"
	assert_config_contains 'provider = "age"'

	# Now the vault provider should be able to resolve its token from the age-encrypted secret
	# (We can't actually connect to vault, but we can verify the config is valid)
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "VAULT_TOKEN"
}

@test "cycle detection prevents infinite loops" {
	# Create config with circular dependency:
	# provider_a needs SECRET_A which uses provider_b
	# provider_b needs SECRET_B which uses provider_a
	cat >fnox.toml <<EOF
root = true

[providers.vault_a]
type = "vault"
address = "http://localhost:8200"
token = { secret = "TOKEN_A" }

[providers.vault_b]
type = "vault"
address = "http://localhost:8201"
token = { secret = "TOKEN_B" }

[secrets]
TOKEN_A = { provider = "vault_b", value = "token-a" }
TOKEN_B = { provider = "vault_a", value = "token-b" }
MY_SECRET = { provider = "vault_a", value = "test" }
EOF

	# Should detect the cycle and fail with a clear error
	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	# Should mention cycle in error
	assert_output --partial "cycle"
}

@test "literal string syntax still works (backward compatibility)" {
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

	# Create config with literal string syntax (old style)
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]
key_file = "./key.txt"

[secrets]
MY_SECRET = { provider = "age", value = "test" }
EOF

	# Set a secret
	run "$FNOX_BIN" set MY_SECRET "literal-style-value"
	assert_success

	# Should be able to get it back
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "literal-style-value"
}

@test "fnox doctor shows providers with secret refs" {
	cat >fnox.toml <<EOF
root = true

[providers.vault]
type = "vault"
address = "http://localhost:8200"
token = { secret = "VAULT_TOKEN" }

[secrets]
VAULT_TOKEN = { default = "test-token" }
MY_SECRET = { provider = "vault", value = "test" }
EOF

	run "$FNOX_BIN" doctor
	assert_success
	assert_output --partial "vault"
	assert_output --partial "Providers"
}

@test "fnox check validates configs with secret refs" {
	cat >fnox.toml <<EOF
root = true

[providers.vault]
type = "vault"
address = "http://localhost:8200"
token = { secret = "VAULT_TOKEN" }

[secrets]
VAULT_TOKEN = { default = "test-token" }
EOF

	run "$FNOX_BIN" check
	assert_success
}

@test "provider add creates config with literal strings (not secret refs)" {
	cat >fnox.toml <<EOF
root = true
EOF

	run "$FNOX_BIN" provider add myvault vault
	assert_success

	# Should have literal address, not a secret ref
	assert_config_contains 'address = "http://localhost:8200"'
	# Token should be optional/not set, not a secret ref
	assert_config_not_contains "{ secret"
}
