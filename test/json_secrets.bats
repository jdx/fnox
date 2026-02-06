#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "get: extracts JSON path from age-encrypted secret" {
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

	# Encrypt the JSON secret using age CLI
	local encrypted_value
	encrypted_value=$(echo -n '{"username":"admin","password":"secret123"}' | age -r "$public_key" | base64)

	# Create config with JSON extraction
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
DB_USER = { provider = "age", value = "$encrypted_value", json_path = "username" }
DB_PASS = { provider = "age", value = "$encrypted_value", json_path = "password" }
EOF

	# Should be able to extract the username
	export FNOX_AGE_KEY=$private_key
	run "$FNOX_BIN" get DB_USER
	assert_success
	assert_output "admin"

	# Should be able to extract the password
	run "$FNOX_BIN" get DB_PASS
	assert_success
	assert_output "secret123"
}

@test "get: extracts nested JSON path with dot notation" {
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

	# Encrypt the nested JSON secret
	local encrypted_value
	encrypted_value=$(echo -n '{"database":{"host":"localhost","port":5432},"api":{"key":"abc123"}}' | age -r "$public_key" | base64)

	# Create config with nested key extraction
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
DB_HOST = { provider = "age", value = "$encrypted_value", json_path = "database.host" }
DB_PORT = { provider = "age", value = "$encrypted_value", json_path = "database.port" }
API_KEY = { provider = "age", value = "$encrypted_value", json_path = "api.key" }
EOF

	export FNOX_AGE_KEY=$private_key

	run "$FNOX_BIN" get DB_HOST
	assert_success
	assert_output "localhost"

	# Numbers are returned as-is
	run "$FNOX_BIN" get DB_PORT
	assert_success
	assert_output "5432"

	run "$FNOX_BIN" get API_KEY
	assert_success
	assert_output "abc123"
}

@test "get: fails with clear error for invalid JSON" {
	# Create config with invalid JSON
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = "not valid json", json_path = "foo" }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "Failed to parse JSON secret"
}

@test "get: fails with clear error when key not found in JSON" {
	# Create config with missing key
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = '{"foo":"bar"}', json_path = "missing" }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "JSON path 'missing' not found"
}

@test "get: handles JSON null values" {
	# Create config with null value
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = '{"value":null}', json_path = "value" }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "null"
}

@test "get: handles JSON boolean values" {
	# Create config with boolean values
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
ENABLED = { provider = "plain", value = '{"enabled":true}', json_path = "enabled" }
DISABLED = { provider = "plain", value = '{"disabled":false}', json_path = "disabled" }
EOF

	run "$FNOX_BIN" get ENABLED
	assert_success
	assert_output "true"

	run "$FNOX_BIN" get DISABLED
	assert_success
	assert_output "false"
}

@test "exec: resolves JSON secrets in batch" {
	# Create config with multiple JSON secrets from same source
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
DB_USER = { provider = "plain", value = '{"user":"admin","pass":"secret"}', json_path = "user" }
DB_PASS = { provider = "plain", value = '{"user":"admin","pass":"secret"}', json_path = "pass" }
EOF

	run "$FNOX_BIN" exec -- sh -c 'echo "$DB_USER:$DB_PASS"'
	assert_success
	assert_output "admin:secret"
}

@test "get: without json_path returns raw value" {
	# Create config without type field - should return raw value
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = '{"foo":"bar"}' }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output '{"foo":"bar"}'
}

@test "get: extracts JSON path containing literal dot using escape" {
	# Create config with escaped dot in key path
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
# The JSON has a key "foo.bar" (literal dot in the key name)
MY_SECRET = { provider = "plain", value = '{"foo.bar":"value1","nested":{"key":"value2"}}', json_path = 'foo\.bar' }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "value1"
}

@test "get: mixed escaped and unescaped dots in key path" {
	# Test a.b\.c.d -> access json["a"]["b.c"]["d"]
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = '{"a":{"b.c":{"d":"found"}}}', json_path = 'a.b\.c.d' }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "found"
}
