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

@test "decrypts using provider-backed identity" {
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

	# Use plain as a deterministic stand-in for keychain so this test does not
	# depend on OS keychain access in CI.
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[providers.age]
type = "age"
recipients = ["$public_key"]
identity = { provider = "plain", value = "$private_key" }

[secrets]
EOF

	run "$FNOX_BIN" set MY_SECRET "secret-value" --provider age
	assert_success

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "secret-value"
}

@test "decrypts multiple provider-backed identity secrets in exec" {
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

	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[providers.age]
type = "age"
recipients = ["$public_key"]
identity = { provider = "plain", value = "$private_key" }

[secrets]
EOF

	run "$FNOX_BIN" set FIRST_SECRET "first-value" --provider age
	assert_success

	run "$FNOX_BIN" set SECOND_SECRET "second-value" --provider age
	assert_success

	run "$FNOX_BIN" exec -- sh -c 'echo "$FIRST_SECRET|$SECOND_SECRET"'
	assert_success
	assert_output "first-value|second-value"
}

@test "provider-backed identity is not resolved during encryption" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]
identity = { provider = "missing-provider", value = "age-key" }

[secrets]
EOF

	run "$FNOX_BIN" set MY_SECRET "secret-value" --provider age
	assert_success

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "missing-provider"
}

@test "decrypts using nested provider-backed age identity" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1 || ! command -v age >/dev/null 2>&1; then
		skip "age tools not installed"
	fi

	# Generate bootstrap age key
	local bootstrap_keygen_output
	bootstrap_keygen_output=$(age-keygen -o bootstrap-key.txt 2>&1)
	local bootstrap_public_key
	bootstrap_public_key=$(echo "$bootstrap_keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	local bootstrap_private_key
	bootstrap_private_key=$(grep "^AGE-SECRET-KEY" bootstrap-key.txt)

	# Generate main age key
	local main_keygen_output
	main_keygen_output=$(age-keygen -o main-key.txt 2>&1)
	local main_public_key
	main_public_key=$(echo "$main_keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	local main_private_key
	main_private_key=$(grep "^AGE-SECRET-KEY" main-key.txt)

	local encrypted_main_private_key
	encrypted_main_private_key=$(printf "%s" "$main_private_key" | age -r "$bootstrap_public_key" | base64 | tr -d '\n')

	# The main age provider gets its identity from another age provider. That
	# nested age provider gets its own identity from plain, which stands in for
	# keychain without requiring OS keychain access in CI.
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[providers.bootstrap-age]
type = "age"
recipients = ["$bootstrap_public_key"]
identity = { provider = "plain", value = "$bootstrap_private_key" }

[providers.age]
type = "age"
recipients = ["$main_public_key"]
identity = { provider = "bootstrap-age", value = "$encrypted_main_private_key" }

[secrets]
EOF

	run "$FNOX_BIN" set MY_SECRET "secret-value" --provider age
	assert_success

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "secret-value"
}

@test "mutual provider-backed age identities fail with cycle error" {
	cat >fnox.toml <<EOF
root = true

[providers.age-a]
type = "age"
recipients = ["age1test"]
identity = { provider = "age-b", value = "unused" }

[providers.age-b]
type = "age"
recipients = ["age1test"]
identity = { provider = "age-a", value = "unused" }

[secrets]
MY_SECRET = { provider = "age-a", value = "unused" }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "Circular dependency detected in provider configuration"
	assert_output --partial "age-a -> age-b -> age-a"
}
