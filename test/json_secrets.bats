#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "get: extracts JSON path from plain secret" {
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = '{"username":"admin","password":"secret123"}', json_path = "username" }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "admin"
}

@test "get: extracts nested JSON path with dot notation from plain secret" {
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = '{"database":{"host":"localhost","port":5432},"api":{"key":"abc123"}}', json_path = "database.host" }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "localhost"
}

@test "get: fails with clear error for invalid JSON" {
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

@test "exec: json_path with as_file writes extracted value to temp file" {
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
DB_PASS = { provider = "plain", value = '{"user":"admin","pass":"secret"}', json_path = "pass", as_file = true }
EOF

	run "$FNOX_BIN" exec -- sh -c 'cat "$DB_PASS"'
	assert_success
	assert_output "secret"
}

@test "get: fails with clear error for empty json_path" {
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = '{"foo":"bar"}', json_path = "" }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "json_path must not be empty"
}

@test "get: without json_path returns raw value" {
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
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = '{"foo.bar":"value1","nested":{"key":"value2"}}', json_path = 'foo\.bar' }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "value1"
}

@test "get: mixed escaped and unescaped dots in key path" {
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

@test "get: extracts JSON path from default value" {
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { default = '{"user":"admin","pass":"secret"}', json_path = "user" }
EOF

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "admin"
}

# resolve_secret applies json_path to all three value sources (provider, default, env var).
# This test exercises the env var fallback path to ensure post-processing works there too.
@test "get: extracts JSON path from environment variable" {
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { json_path = "host" }
EOF

	MY_SECRET='{"host":"localhost","port":5432}' run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "localhost"
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

	# Store config header for reuse
	local config_header
	config_header=$(
		cat <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF
	)

	# Create config for fnox set
	cat >fnox.toml <<EOF
${config_header}
EOF

	# Set the encrypted JSON secret using fnox set
	export FNOX_AGE_KEY=$private_key
	run "$FNOX_BIN" set JSON_SECRET '{"username":"admin","password":"secret123"}'
	assert_success

	# Extract encrypted value, rewrite config with json_path
	local encrypted_value
	encrypted_value=$(grep -o 'value = "[^"]*"' fnox.toml | grep -o '"[^"]*"')
	cat >fnox.toml <<EOF
${config_header}
JSON_SECRET = { provider = "age", value = ${encrypted_value}, json_path = "username" }
EOF

	# Should be able to extract the username
	run "$FNOX_BIN" get JSON_SECRET
	assert_success
	assert_output "admin"
}
