#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
SECRET = { provider = "plain", value = "s3cr3t-value" }
SHORT = { provider = "plain", value = "ab" }
TOML
}

teardown() {
	_common_teardown
}

@test "exec does not redact piped output by default" {
	run bash -c "'$FNOX_BIN' exec -- sh -c 'echo \$SECRET' | cat"
	assert_success
	assert_output "s3cr3t-value"
}

@test "exec --redact redacts piped stdout" {
	run bash -c "'$FNOX_BIN' exec --redact -- sh -c 'echo \$SECRET' | cat"
	assert_success
	assert_output "[REDACTED]"
}

@test "exec --redact redacts stderr and leaves short values alone" {
	run bash -c "'$FNOX_BIN' exec --redact -- sh -c 'echo \"\$SECRET \$SHORT\" >&2' 2>&1 | cat"
	assert_success
	assert_output "[REDACTED] ab"
}

@test "exec redacts when enabled in config" {
	sed -i '1a redact_exec = true' fnox.toml
	run bash -c "'$FNOX_BIN' exec -- sh -c 'echo \$SECRET' | cat"
	assert_success
	assert_output "[REDACTED]"
}

@test "FNOX_EXEC_REDACT enables redaction and --no-redact overrides it" {
	export FNOX_EXEC_REDACT=1
	run bash -c "'$FNOX_BIN' exec -- sh -c 'echo \$SECRET' | cat"
	assert_output "[REDACTED]"
	run bash -c "'$FNOX_BIN' exec --no-redact -- sh -c 'echo \$SECRET' | cat"
	assert_output "s3cr3t-value"
}

@test "exec --redact preserves the exit code" {
	run "$FNOX_BIN" exec --redact -- sh -c 'echo $SECRET; exit 7'
	assert_failure 7
	assert_output "[REDACTED]"
}

@test "exec --redact rejects --replace" {
	run "$FNOX_BIN" exec --redact --replace -- true
	assert_failure
}

@test "exec --replace is rejected when config enables redaction and output is piped" {
	export FNOX_EXEC_REDACT=1
	run bash -c "set -o pipefail; '$FNOX_BIN' exec --replace -- echo hi | cat"
	assert_failure
	run bash -c "'$FNOX_BIN' exec --replace --no-redact -- echo hi | cat"
	assert_success
}

@test "exec --redact does not wait for background processes holding the pipe" {
	start=$SECONDS
	run bash -c "'$FNOX_BIN' exec --redact -- sh -c 'sleep 30 & echo \$SECRET' | cat"
	assert_output --partial "[REDACTED]"
	[ $((SECONDS - start)) -lt 15 ]
}
