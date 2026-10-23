#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR"
	export FNOX_STATE_DIR="$TEST_TEMP_DIR/state"
}

teardown() {
	"$FNOX_BIN" daemon stop >/dev/null 2>&1 || true
	_common_teardown
}

audit_config() {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
FOO = { provider = "plain", value = "super-secret-value" }
TOML
}

@test "audit log is off by default" {
	audit_config

	run "$FNOX_BIN" get FOO
	assert_success
	[ ! -e "$FNOX_STATE_DIR/audit.log" ]
}

@test "audit log records reads without values" {
	audit_config
	export FNOX_AUDIT=on

	run "$FNOX_BIN" get FOO
	assert_success
	run "$FNOX_BIN" exec -- true
	assert_success

	log="$FNOX_STATE_DIR/audit.log"
	[ "$(wc -l <"$log")" -eq 2 ]
	run grep -c super-secret-value "$log"
	assert_output "0"
	run grep '"command":"get"' "$log"
	assert_success
	assert_output --partial '"secret":"FOO"'
	assert_output --partial '"provider":"plain"'
	assert_output --partial '"cached":false'
	[ "$(stat -c %a "$log" 2>/dev/null || stat -f %Lp "$log")" = "600" ]
}

@test "audit log honors [audit] config and fnox audit filters" {
	audit_config
	cat >>fnox.toml <<TOML

[audit]
enabled = true
path = "$TEST_TEMP_DIR/custom.log"
TOML

	run "$FNOX_BIN" get FOO
	assert_success
	[ -s "$TEST_TEMP_DIR/custom.log" ]

	run "$FNOX_BIN" audit --secret FOO --command get
	assert_success
	assert_output --partial "FOO"
	run "$FNOX_BIN" audit --secret NOPE
	assert_success
	refute_output --partial "FOO"
}

@test "audit log marks daemon cache hits" {
	audit_config
	cat >>fnox.toml <<'TOML'

[daemon]
enabled = true
TOML
	export FNOX_AUDIT=on

	run "$FNOX_BIN" get FOO
	assert_success
	run "$FNOX_BIN" get FOO
	assert_success

	run "$FNOX_BIN" audit --json
	assert_success
	assert_output --partial '"cached":true'
	assert_output --partial '"cached":false'
}

@test "audit log names secrets read through default interpolation" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
TOKEN = { provider = "plain", value = "tok" }
URL = { default = "https://x/${TOKEN}" }
TOML
	export FNOX_AUDIT=on

	run "$FNOX_BIN" get URL
	assert_success
	run "$FNOX_BIN" audit --secret TOKEN
	assert_success
	assert_output --partial "TOKEN"
}

@test "fnox audit works outside a project" {
	export FNOX_AUDIT_PATH="$TEST_TEMP_DIR/elsewhere.log"
	echo '{"ts":"2026-01-01T00:00:00.000Z","command":"get","profile":["default"],"config":"x","secret":"S","provider":null,"cached":false}' >"$FNOX_AUDIT_PATH"
	mkdir empty && cd empty

	run "$FNOX_BIN" audit
	assert_success
	assert_output --partial " S "
}
