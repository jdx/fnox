#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox check passes with valid config" {
	create_test_config
	assert_fnox_success check
}

@test "fnox check fails with missing required secret" {
	create_test_config

	# Add a required secret without value
	cat >>"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF

[secrets.required_secret]
if_missing = "error"
EOF

	assert_fnox_failure check
	assert_output --partial "required_secret"
}

@test "fnox check warns about missing optional secret" {
	create_test_config

	# Add an optional secret without value
	cat >>"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF

[secrets.optional_secret]
if_missing = "warn"
EOF

	assert_fnox_success check
	assert_output --partial "optional_secret"
}

@test "fnox check with profile" {
	create_test_config
	assert_fnox_success check --profile test
}

@test "fnox check fails with unknown profile" {
	create_test_config
	assert_fnox_failure check --profile unknown
	assert_output --partial "Profile 'unknown' not found"
}

@test "fnox check warns about unknown provider" {
	create_test_config

	# Add a secret with unknown provider
	cat >>"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF

[secrets.bad_secret]
provider = "unknown"
value = "test"
EOF

	assert_fnox_success check
	assert_output --partial "unknown"
}

@test "fnox check with empty config" {
	# Create empty config with root=true to prevent recursion
	echo "root = true" >"${FNOX_CONFIG_FILE:-fnox.toml}"

	assert_fnox_success check
	assert_output --partial "No secrets"
}

@test "fnox check resolves a direct age batch with one identity read" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output public_key
	keygen_output=$(age-keygen -o key.txt 2>&1)
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export AGE_IDENTITY
	AGE_IDENTITY=$(grep "^AGE-SECRET-KEY" key.txt)

	mkdir -p "$TEST_TEMP_DIR/bin"
	cat >"$TEST_TEMP_DIR/bin/pass" <<'EOF'
#!/bin/sh
printf '%s\n' "$2" >>"$PASS_CALLS_FILE"
if [ "$2" = "age-key" ]; then
	printf '%s\n' "$AGE_IDENTITY"
	exit 0
fi
printf '%s\n' "secret is not in the password store" >&2
exit 1
EOF
	chmod +x "$TEST_TEMP_DIR/bin/pass"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"
	export PASS_CALLS_FILE="$TEST_TEMP_DIR/pass-calls"
	unset FNOX_AGE_KEY FNOX_AGE_KEY_FILE
	unset FIRST SECOND
	: >"$PASS_CALLS_FILE"

	cat >fnox.toml <<EOF
root = true

[providers.identity]
type = "password-store"

[providers.source]
type = "plain"

[providers.age]
type = "age"
recipients = ["$public_key"]
identity = { provider = "identity", value = "age-key" }

[secrets]
FIRST = { provider = "source", value = "first", if_missing = "error" }
SECOND = { provider = "source", value = "second", if_missing = "error" }
EOF

	assert_fnox_success sync -p age --force
	perl -i -pe 'if (/^(FIRST|SECOND) = .*sync = \{ provider = "age", value = "([^"]+)" \}.*$/) { $_ = "$1 = { provider = \"age\", value = \"$2\", if_missing = \"error\" }\n" }' fnox.toml
	assert_equal "$(grep -c 'provider = "age", value = "fnox-age-batch-v1:' fnox.toml)" "2"
	: >"$PASS_CALLS_FILE"
	assert_fnox_success check
	assert_equal "$(grep -c '^age-key$' "$PASS_CALLS_FILE")" "1"

	: >"$PASS_CALLS_FILE"
	local second_line second_value shared_prefix
	second_line=$(grep 'SECOND.*value = ' fnox.toml)
	second_value=${second_line##*value = \"}
	second_value=${second_value%%\"*}
	shared_prefix=${second_value%:*}
	sed -i.bak "s|$second_value|$shared_prefix:invalid|" fnox.toml
	assert_fnox_failure check
	assert_output --partial "Found 1 error(s):"
	assert_output --partial "SECOND"
	assert_output --partial "Invalid base64"
	refute_output --partial "Secret 'FIRST' failed to resolve"
	assert_equal "$(grep -c '^age-key$' "$PASS_CALLS_FILE")" "1"
}

@test "fnox check isolates sequential age sync batches" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output public_key
	keygen_output=$(age-keygen -o key.txt 2>&1)
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export AGE_IDENTITY
	AGE_IDENTITY=$(grep "^AGE-SECRET-KEY" key.txt)

	mkdir -p "$TEST_TEMP_DIR/bin"
	cat >"$TEST_TEMP_DIR/bin/pass" <<'EOF'
#!/bin/sh
printf '%s\n' "$2" >>"$PASS_CALLS_FILE"
if [ "$2" = "second-age-key" ] && [ -n "${FIRST+x}" ]; then
	printf '%s\n' "FIRST was exposed to the second identity provider" >&2
	exit 1
fi
printf '%s\n' "$AGE_IDENTITY"
EOF
	chmod +x "$TEST_TEMP_DIR/bin/pass"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"
	export PASS_CALLS_FILE="$TEST_TEMP_DIR/pass-calls"
	unset FNOX_AGE_KEY FNOX_AGE_KEY_FILE
	unset FIRST SECOND
	: >"$PASS_CALLS_FILE"

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[providers.identity]
type = "password-store"

[providers.first-age]
type = "age"
recipients = ["$public_key"]
identity = { provider = "identity", value = "first-age-key" }

[providers.second-age]
type = "age"
recipients = ["$public_key"]
identity = { provider = "identity", value = "second-age-key" }

[secrets]
FIRST = { provider = "source", value = "first", if_missing = "error" }
SECOND = { provider = "source", value = "second", if_missing = "error" }
EOF

	assert_fnox_success sync FIRST -p first-age --force
	assert_fnox_success sync SECOND -p second-age --force
	: >"$PASS_CALLS_FILE"
	assert_fnox_success check
	assert_equal "$(grep -c '^first-age-key$' "$PASS_CALLS_FILE")" "1"
	assert_equal "$(grep -c '^second-age-key$' "$PASS_CALLS_FILE")" "1"
}
