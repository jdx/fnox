#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR"
}

teardown() {
	"$FNOX_BIN" daemon stop >/dev/null 2>&1 || true
	_common_teardown
}

daemon_config() {
	cat >fnox.toml <<'EOF'
root = true

[daemon]
enabled = true

[providers.plain]
type = "plain"

[secrets]
FOO = { provider = "plain", value = "bar" }
FILE_SECRET = { provider = "plain", value = "file-value", as_file = true }
HIDDEN = { provider = "plain", value = "hidden-value", env = false }
EOF
}

@test "daemon auto-starts for enabled get and caches value" {
	daemon_config

	run "$FNOX_BIN" get FOO
	assert_success
	assert_output "bar"

	run "$FNOX_BIN" daemon status
	assert_success
	assert_output --partial "fnox daemon running"
	assert_output --partial "cached_entries: 1"
}

@test "daemon clear removes cached entries" {
	daemon_config

	run "$FNOX_BIN" get FOO
	assert_success

	run "$FNOX_BIN" daemon clear
	assert_success

	run "$FNOX_BIN" daemon status
	assert_success
	assert_output --partial "cached_entries: 0"
}

@test "no-daemon bypass does not start daemon" {
	daemon_config

	run "$FNOX_BIN" --no-daemon get FOO
	assert_success
	assert_output "bar"

	run "$FNOX_BIN" daemon status
	assert_success
	assert_output "fnox daemon not running"
}

@test "FNOX_DAEMON=off bypasses daemon" {
	daemon_config

	run env FNOX_DAEMON=off "$FNOX_BIN" get FOO
	assert_success
	assert_output "bar"

	run "$FNOX_BIN" daemon status
	assert_success
	assert_output "fnox daemon not running"
}

@test "hook-env excludes env false secrets with daemon enabled" {
	daemon_config

	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output --partial "export FOO=bar"
	refute_output --partial "HIDDEN"
}

@test "daemon loads profile-specific config files" {
	cat >fnox.toml <<'EOF'
root = true

[daemon]
enabled = true

[providers.plain]
type = "plain"

[secrets]
FOO = { provider = "plain", value = "base" }
EOF

	cat >fnox.staging.toml <<'EOF'
[secrets]
FOO = { provider = "plain", value = "staging" }
STAGING_ONLY = { provider = "plain", value = "yes" }
EOF

	run "$FNOX_BIN" --profile staging get STAGING_ONLY
	assert_success
	assert_output "yes"

	run "$FNOX_BIN" --profile staging get FOO
	assert_success
	assert_output "staging"
}

@test "daemon honors no-defaults for profile secrets" {
	cat >fnox.toml <<'EOF'
root = true

[daemon]
enabled = true

[providers.plain]
type = "plain"

[secrets]
BASE_ONLY = { provider = "plain", value = "base" }

[profiles.staging.secrets]
PROFILE_ONLY = { provider = "plain", value = "profile" }
EOF

	run "$FNOX_BIN" --profile staging --no-defaults get PROFILE_ONLY
	assert_success
	assert_output "profile"

	run "$FNOX_BIN" --profile staging --no-defaults get BASE_ONLY
	assert_failure
	assert_output --partial "Secret 'BASE_ONLY' not found"
}
