#!/usr/bin/env bats
#
# 1Password Environments
#
# Uses a stub `op` on PATH so these run without a 1Password account.

setup() {
	load 'test_helper/common_setup'
	_common_setup

	mkdir -p "$TEST_TEMP_DIR/bin"
	cat >"$TEST_TEMP_DIR/bin/op" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$OP_STUB_LOG"
if [ "$1 $2" = "environment read" ]; then
	if [ "$3" = "env_unterminated" ]; then
		printf 'DB_URL="unterminated\n'
		exit 0
	fi
	if [ "$3" = "env_garbage" ]; then
		echo '{"variables": []}'
		exit 0
	fi
	if [ "$3" = "env_abc" ]; then
		# A user-set OP_FORMAT would change the real CLI's output; fnox must not pass it on.
		if [ -n "$OP_FORMAT" ]; then
			echo '[{"name": "DB_URL"}]'
			exit 0
		fi
		cat <<'ENV'
# fnox test environment
DB_URL=postgres://u:p@host/db?sslmode=require
API_KEY="quoted value"
CERT="line1
line2"
ENV
		exit 0
	fi
	echo "[ERROR] 2026/10/08 00:00:00 environment not found" >&2
	exit 1
fi
if [ "$1" = "whoami" ]; then exit 0; fi
if [ "$1" = "inject" ]; then
	# KEY=op://vault/item/field  ->  KEY=value-of-item-field
	sed -E 's#=op://[^/]+/([^/]+)/(.+)$#=value-of-\1-\2#'
	exit 0
fi
if [ "$1" = "read" ]; then
	echo "$2" | sed -E 's#^op://[^/]+/([^/]+)/(.+)$#value-of-\1-\2#'
	exit 0
fi
echo "[ERROR] 2026/10/08 00:00:00 unexpected op call: $*" >&2
exit 1
STUB
	chmod +x "$TEST_TEMP_DIR/bin/op"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"
	export OP_STUB_LOG="$TEST_TEMP_DIR/op.log"
	: >"$OP_STUB_LOG"

	cat >fnox.toml <<'TOML'
[providers.op]
type = "1password"

[secrets]
DB_URL = { provider = "op", value = "environment://env_abc/DB_URL" }
API_KEY = { provider = "op", value = "environment://env_abc/API_KEY" }
CERT = { provider = "op", value = "environment://env_abc/CERT" }
MISSING = { provider = "op", value = "environment://env_abc/NOPE" }
TOML
}

teardown() {
	_common_teardown
}

@test "get reads one variable from a 1Password Environment" {
	run "$FNOX_BIN" get DB_URL
	assert_success
	assert_output "postgres://u:p@host/db?sslmode=require"
}

@test "get handles quoted and multi-line variables" {
	run "$FNOX_BIN" get API_KEY
	assert_success
	assert_output "quoted value"

	run "$FNOX_BIN" get CERT
	assert_success
	assert_output $'line1\nline2'
}

@test "variables of one environment share a single op environment read" {
	run "$FNOX_BIN" exec --if-missing ignore -- sh -c 'echo "$DB_URL|$API_KEY"'
	assert_success
	assert_output --partial "postgres://u:p@host/db?sslmode=require|quoted value"

	run grep -c '^environment read env_abc' "$OP_STUB_LOG"
	assert_output "1"
}

@test "get fails for a variable the environment does not contain" {
	run "$FNOX_BIN" get MISSING
	assert_failure
	assert_output --partial "no variable named 'NOPE'"
}

@test "get fails for an unknown environment" {
	cat >fnox.toml <<'TOML'
[providers.op]
type = "1password"

[secrets]
X = { provider = "op", value = "environment://env_nope/X" }
TOML
	run "$FNOX_BIN" get X
	assert_failure
	assert_output --partial "environment not found"
}

@test "get rejects a malformed environment reference" {
	cat >fnox.toml <<'TOML'
[providers.op]
type = "1password"

[secrets]
X = { provider = "op", value = "environment://env_abc" }
TOML
	run "$FNOX_BIN" get X
	assert_failure
	assert_output --partial "environment://<environment-id>/<VARIABLE>"
}

@test "failed environment read is shared by every variable of that environment" {
	cat >fnox.toml <<'TOML'
[providers.op]
type = "1password"

[secrets]
A = { provider = "op", value = "environment://env_nope/A" }
B = { provider = "op", value = "environment://env_nope/B" }
C = { provider = "op", value = "environment://env_nope/C" }
TOML
	run "$FNOX_BIN" exec --if-missing ignore -- true
	assert_success

	run grep -c '^environment read env_nope' "$OP_STUB_LOG"
	assert_output "1"
}

@test "environment variables and vault item references resolve together" {
	cat >fnox.toml <<'TOML'
[providers.op]
type = "1password"

[secrets]
DB_URL = { provider = "op", value = "environment://env_abc/DB_URL" }
API_KEY = { provider = "op", value = "environment://env_abc/API_KEY" }
USER = { provider = "op", value = "op://Vault/db/username" }
PASS = { provider = "op", value = "op://Vault/db/password" }
TOML
	run "$FNOX_BIN" exec --if-missing ignore -- sh -c 'echo "$DB_URL|$API_KEY|$USER|$PASS"'
	assert_success
	assert_output --partial "postgres://u:p@host/db?sslmode=require|quoted value|value-of-db-username|value-of-db-password"

	run grep -c '^environment read env_abc' "$OP_STUB_LOG"
	assert_output "1"
	run grep -c '^inject' "$OP_STUB_LOG"
	assert_output "1"
}

@test "OP_FORMAT from the user's shell does not change how an environment is read" {
	OP_FORMAT=json run "$FNOX_BIN" get DB_URL
	assert_success
	assert_output "postgres://u:p@host/db?sslmode=require"
}

@test "get reports unparseable environment output instead of a missing variable" {
	cat >fnox.toml <<'TOML'
[providers.op]
type = "1password"

[secrets]
X = { provider = "op", value = "environment://env_garbage/X" }
TOML
	run "$FNOX_BIN" get X
	assert_failure
	assert_output --partial "dotenv-style KEY=value"
}

@test "get rejects environment output with an unterminated quote" {
	cat >fnox.toml <<'TOML'
[providers.op]
type = "1password"

[secrets]
DB_URL = { provider = "op", value = "environment://env_unterminated/DB_URL" }
TOML
	run "$FNOX_BIN" get DB_URL
	assert_failure
	assert_output --partial "unterminated quote"
}
