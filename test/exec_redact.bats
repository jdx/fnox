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
	{
		echo 'redact_exec = true'
		cat fnox.toml
	} >fnox.new
	mv fnox.new fnox.toml
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

@test "exec --redact delivers all output to a slow consumer" {
	# 200000 bytes overflow the pipe buffer, so output is still in flight when
	# the command exits and the consumer only starts reading after 3s.
	run bash -c "'$FNOX_BIN' exec --redact -- sh -c 'head -c 200000 /dev/zero | tr \"\\0\" x; echo; echo \$SECRET' | (sleep 3; wc -c | tr -d ' ')"
	assert_success
	# 200000 x's + newline + "[REDACTED]\n"
	assert_output "200012"
}

@test "exec --redact redacts a literal default unless sensitive = false" {
	cat >fnox.toml <<'TOML'
root = true

[secrets]
LOCAL_TOKEN = { default = "dev-token-123" }
LOG_LEVEL = { default = "INFO", sensitive = false }
SCHEMA = { default = "public", sensitive = false }
TOML
	run bash -c "'$FNOX_BIN' exec --redact -- sh -c 'echo \"\$LOG_LEVEL \$SCHEMA publication \$LOCAL_TOKEN\"' | cat"
	assert_success
	assert_output "INFO public publication [REDACTED]"
}

@test "exec --redact leaves a provider value readable with sensitive = false" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
API_ENDPOINT = { provider = "plain", value = "https://api.example.com", sensitive = false }
API_KEY = { provider = "plain", value = "s3cr3t-value" }
TOML
	run bash -c "'$FNOX_BIN' exec --redact -- sh -c 'echo \"\$API_ENDPOINT \$API_KEY\"' | cat"
	assert_success
	assert_output "https://api.example.com [REDACTED]"
}
