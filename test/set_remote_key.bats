#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup

	mkdir -p mock-bin
	cat >mock-bin/pass <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >"$PASS_ARGS_FILE"
cat >"$PASS_VALUE_FILE"
EOF
	chmod +x mock-bin/pass
	export PATH="$PWD/mock-bin:$PATH"
	export PASS_ARGS_FILE="$PWD/pass-args"
	export PASS_VALUE_FILE="$PWD/pass-value"
}

teardown() {
	_common_teardown
}

@test "fnox set reuses an existing remote key in the write target" {
	cat >fnox.toml <<EOF
[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "custom-name" }
EOF

	run "$FNOX_BIN" set TOKEN "updated-value"
	assert_success
	assert_file_contains "$PASS_ARGS_FILE" "insert -m -f custom-name"
	assert_file_contains "$PASS_VALUE_FILE" "updated-value"
	assert_file_contains fnox.toml 'value = "custom-name"'
}

@test "fnox set dry-run preserves an existing remote key without writing" {
	cat >fnox.toml <<EOF
[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "custom-name" }
EOF
	cp fnox.toml fnox.toml.orig

	run "$FNOX_BIN" set TOKEN "updated-value" --dry-run
	assert_success
	assert_output --partial "value: custom-name"
	assert_file_not_exist "$PASS_ARGS_FILE"
	diff fnox.toml fnox.toml.orig
}

@test "fnox set does not reuse an inherited remote key for a local override" {
	mkdir -p parent/child
	cat >parent/fnox.toml <<EOF
[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "shared-name" }
EOF
	cat >parent/child/fnox.toml <<EOF
[secrets]
EOF
	cd parent/child

	run "$FNOX_BIN" set TOKEN "local-value"
	assert_success
	assert_file_contains "$PASS_ARGS_FILE" "insert -m -f TOKEN"
	assert_file_contains fnox.toml 'value = "TOKEN"'
	assert_file_contains ../fnox.toml 'value = "shared-name"'
}

@test "fnox set resolves providers from the write profile" {
	cat >fnox.toml <<EOF
[profiles.source.providers.pass]
type = "password-store"
prefix = "source/"

[profiles.source.secrets]
TOKEN = { provider = "pass", value = "source-name" }

[profiles.target.providers.pass]
type = "password-store"
prefix = "target/"

[profiles.target.secrets]
TOKEN = { provider = "pass", value = "target-name" }
EOF

	run "$FNOX_BIN" -P source --write-profile target set TOKEN "target-value"
	assert_success
	assert_file_contains "$PASS_ARGS_FILE" "insert -m -f target/target-name"
	assert_file_contains fnox.toml 'value = "target-name"'
}
