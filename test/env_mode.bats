#!/usr/bin/env bats
#
# Tests for the three-state `env` mode (true / "exec" / false) and the
# top-level `env` default, which keeps secrets out of the interactive shell
# (e.g. away from AI coding agents) while still injecting them into
# `fnox exec` subprocesses.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# root = true stops config recursion into parent directories (the test
	# temp dir lives inside the fnox repo, which has its own fnox.toml)
	cat >fnox.toml <<'EOF'
root = true
env = "exec"

[providers.plain]
type = "plain"

[secrets]
SHELL_OK = { provider = "plain", value = "shell-value", env = true }
EXEC_ONLY = { provider = "plain", value = "exec-value" }
HIDDEN = { provider = "plain", value = "hidden-value", env = false }
EOF
}

teardown() {
	_common_teardown
}

@test "hook-env only injects env=true secrets under top-level env=exec" {
	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output --partial "shell-value"
	refute_output --partial "exec-value"
	refute_output --partial "hidden-value"
}

@test "exec injects inherited exec-mode secrets but not env=false" {
	run "$FNOX_BIN" exec -- sh -c 'echo "${SHELL_OK}:${EXEC_ONLY}:${HIDDEN:-unset}"'
	assert_success
	assert_output "shell-value:exec-value:unset"
}

@test "export excludes exec-only and hidden secrets by default" {
	run "$FNOX_BIN" export
	assert_success
	assert_output --partial "SHELL_OK=shell-value"
	refute_output --partial "exec-value"
	refute_output --partial "hidden-value"
}

@test "export --all includes every secret" {
	run "$FNOX_BIN" export --all
	assert_success
	assert_output --partial "SHELL_OK=shell-value"
	assert_output --partial "EXEC_ONLY=exec-value"
	assert_output --partial "HIDDEN=hidden-value"
}

@test "get retrieves secrets regardless of env mode" {
	run "$FNOX_BIN" get EXEC_ONLY
	assert_success
	assert_output "exec-value"

	run "$FNOX_BIN" get HIDDEN
	assert_success
	assert_output "hidden-value"
}

@test "per-secret env=exec works without a top-level default" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
NORMAL = { provider = "plain", value = "normal-value" }
EXEC_ONLY = { provider = "plain", value = "exec-value", env = "exec" }
EOF

	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output --partial "normal-value"
	refute_output --partial "exec-value"

	run "$FNOX_BIN" exec -- sh -c 'echo "${NORMAL}:${EXEC_ONLY}"'
	assert_success
	assert_output "normal-value:exec-value"
}

@test "local override can flip the top-level env default" {
	# fnox.local.toml loads after fnox.toml, so its top-level env wins
	cat >fnox.local.toml <<'EOF'
env = true
EOF

	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output --partial "shell-value"
	assert_output --partial "exec-value"
	refute_output --partial "hidden-value"
}
