#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	"$FNOX_BIN" daemon stop >/dev/null 2>&1 || true
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

@test "fnox check batch resolves secrets sharing an age key" {
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
	: >"$PASS_CALLS_FILE"

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[providers.identity]
type = "password-store"

[providers.age]
type = "age"
recipients = ["$public_key"]
identity = { provider = "identity", value = "age-key" }

[secrets]
FIRST = { provider = "source", value = "first", if_missing = "error", env = "exec" }
SECOND = { provider = "source", value = "second", if_missing = "error", env = false }
EOF

	assert_fnox_success sync -p age --force
	assert_fnox_success check
	assert_equal "$(grep -c '^age-key$' "$PASS_CALLS_FILE")" "1"

	: >"$PASS_CALLS_FILE"
	echo 'THIRD = { provider = "identity", value = "missing", if_missing = "error" }' >>fnox.toml
	assert_fnox_failure check
	assert_output --partial "THIRD"
	assert_equal "$(grep -c '^age-key$' "$PASS_CALLS_FILE")" "1"
}

@test "fnox check retains diagnostics when batch resolution fails" {
	mkdir -p "$TEST_TEMP_DIR/bin"
	cat >"$TEST_TEMP_DIR/bin/pass" <<'EOF'
#!/bin/sh
printf '%s\n' "secret is not in the password store" >&2
exit 1
EOF
	chmod +x "$TEST_TEMP_DIR/bin/pass"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"

	cat >fnox.toml <<'EOF'
root = true

[providers.pass]
type = "password-store"

[secrets]
FIRST = { provider = "pass", value = "first", if_missing = "error" }
SECOND = { provider = "pass", value = "second", if_missing = "error" }
EOF

	assert_fnox_failure check
	assert_output --partial "Secret 'FIRST' failed to resolve: password-store: secret 'first' not found"
	assert_output --partial "Secret 'SECOND' failed to resolve: password-store: secret 'second' not found"
}

@test "fnox check all includes optional provider secrets" {
	mkdir -p "$TEST_TEMP_DIR/bin"
	cat >"$TEST_TEMP_DIR/bin/pass" <<'EOF'
#!/bin/sh
printf '%s\n' "$2" >>"$PASS_CALLS_FILE"
printf 'value\n'
EOF
	chmod +x "$TEST_TEMP_DIR/bin/pass"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"
	export PASS_CALLS_FILE="$TEST_TEMP_DIR/pass-calls"
	: >"$PASS_CALLS_FILE"

	cat >fnox.toml <<'EOF'
root = true

[providers.pass]
type = "password-store"

[secrets]
REQUIRED = { provider = "pass", value = "required", if_missing = "error" }
WARN = { provider = "pass", value = "warn", if_missing = "warn" }
IGNORE = { provider = "pass", value = "ignore", if_missing = "ignore" }
EOF

	assert_fnox_success check
	assert_equal "$(wc -l <"$PASS_CALLS_FILE" | tr -d ' ')" "1"

	: >"$PASS_CALLS_FILE"
	assert_fnox_success check --all
	assert_equal "$(wc -l <"$PASS_CALLS_FILE" | tr -d ' ')" "3"
}

@test "fnox check does not use the daemon cache" {
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR" "$TEST_TEMP_DIR/bin"
	cat >"$TEST_TEMP_DIR/bin/pass" <<'EOF'
#!/bin/sh
printf 'called\n' >>"$PASS_CALLS_FILE"
printf 'value\n'
EOF
	chmod +x "$TEST_TEMP_DIR/bin/pass"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"
	export PASS_CALLS_FILE="$TEST_TEMP_DIR/pass-calls"
	: >"$PASS_CALLS_FILE"

	cat >fnox.toml <<'EOF'
root = true

[daemon]
enabled = true

[providers.pass]
type = "password-store"

[secrets]
REQUIRED = { provider = "pass", value = "required", if_missing = "error" }
EOF

	assert_fnox_success check
	assert_fnox_success check
	assert_equal "$(wc -l <"$PASS_CALLS_FILE" | tr -d ' ')" "2"

	assert_fnox_success daemon status
	assert_output --partial "cached_entries: 0"
}
