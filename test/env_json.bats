#!/usr/bin/env bats
#
# Tests for `fnox env --json`: the machine-readable environment that
# `fnox exec` would give a command, for tools that start processes themselves.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup
	# A private runtime dir keeps teardown from stopping a real daemon
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR"

	# root = true stops config recursion into parent directories (the test
	# temp dir lives inside the fnox repo, which has its own fnox.toml)
	cat >fnox.toml <<'TOML'
root = true
env = "exec"

[providers.plain]
type = "plain"

[secrets]
SHELL_OK = { provider = "plain", value = "shell-value", env = true }
EXEC_ONLY = { provider = "plain", value = "exec-value" }
HIDDEN = { provider = "plain", value = "hidden-value", env = false }
TOML
}

teardown() {
	"$FNOX_BIN" daemon stop >/dev/null 2>&1 || true
	_common_teardown
}

# Run fnox with stdout and stderr captured separately into out/err files.
# Sets $status to the exit code.
run_env() {
	status=0
	"$FNOX_BIN" "$@" >out 2>err || status=$?
}

# A recording `pass` stub: appends the secret path (its last argument) to
# $PASS_CALLS and prints v-<path>. Fails for paths containing "missing".
install_pass_stub() {
	mkdir -p "$TEST_TEMP_DIR/bin"
	cat >"$TEST_TEMP_DIR/bin/pass" <<'STUB'
#!/bin/sh
for last; do :; done
printf '%s\n' "$last" >>"$PASS_CALLS"
case "$last" in
*missing*)
	echo "Error: $last is not in the password store." >&2
	exit 1
	;;
esac
printf 'v-%s\n' "$last"
STUB
	chmod +x "$TEST_TEMP_DIR/bin/pass"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"
	export PASS_CALLS="$TEST_TEMP_DIR/pass-calls"
}

@test "env --json default scope exec sets exec secrets and removes the rest" {
	run_env env --json
	assert_equal "$status" 0
	jq -e . out >/dev/null
	assert_equal "$(jq -r .schema out)" 1
	assert_equal "$(jq -r .scope out)" exec
	assert_equal "$(jq -r '.set.SHELL_OK' out)" shell-value
	assert_equal "$(jq -r '.set.EXEC_ONLY' out)" exec-value
	assert_equal "$(jq -r '.set | has("HIDDEN")' out)" false
	assert_equal "$(jq -r '.remove | index("HIDDEN") != null' out)" true
	assert_equal "$(jq -r '.remove | index("FNOX_AGE_KEY") != null' out)" true
	assert_equal "$(jq -r '.remove | index("FNOX_AGE_KEY_FILE") != null' out)" true
	assert_equal "$(jq -r '.remove | index("ENPASS_PASSWORD") != null' out)" true
	assert_equal "$(jq -r '.profile[0]' out)" default
	assert_equal "$(wc -l <out | tr -d ' ')" 1
}

@test "env --json --for shell leaves exec-only secrets out of set" {
	run_env env --json --for shell
	assert_equal "$status" 0
	assert_equal "$(jq -r .scope out)" shell
	assert_equal "$(jq -r '.set | keys | join(",")' out)" SHELL_OK
	assert_equal "$(jq -r '.remove | index("EXEC_ONLY") != null' out)" true
	assert_equal "$(jq -r '.leases | length' out)" 0
}

@test "env --json --keys sets exactly the requested keys" {
	run_env env --json --keys SHELL_OK
	assert_equal "$status" 0
	assert_equal "$(jq -r '.set | keys | join(",")' out)" SHELL_OK
	# Out-of-scope secrets are still removed from the inherited environment
	assert_equal "$(jq -r '.remove | index("HIDDEN") != null' out)" true
}

@test "env --json --keys accepts commas and repeats and drops duplicates" {
	run_env env --json --keys SHELL_OK,EXEC_ONLY --keys SHELL_OK
	assert_equal "$status" 0
	assert_equal "$(jq -r '.set | keys | join(",")' out)" "EXEC_ONLY,SHELL_OK"
}

@test "env --json --keys with an unknown key fails with a JSON error" {
	run_env env --json --keys NOPE
	assert_equal "$status" 1
	jq -e . out >/dev/null
	assert_equal "$(jq -r .error.kind out)" invalid_keys
	assert_equal "$(jq -c .error.unknown out)" '["NOPE"]'
	grep -q "fnox env cannot provide" err
}

@test "env --json suggests similar keys" {
	run_env env --json --keys SHEL_OK
	assert_equal "$status" 1
	assert_equal "$(jq -c '.error.suggestions.SHEL_OK' out)" '["SHELL_OK"]'
}

@test "env --json --keys rejects env=false and out-of-scope keys" {
	run_env env --json --keys HIDDEN
	assert_equal "$status" 1
	assert_equal "$(jq -c '.error.not_injectable[0]' out)" '{"key":"HIDDEN","env":false}'
	grep -q "fnox get" err

	run_env env --json --for shell --keys EXEC_ONLY
	assert_equal "$status" 1
	assert_equal "$(jq -c '.error.not_injectable[0]' out)" '{"key":"EXEC_ONLY","env":"exec"}'
}

@test "env --json resolves an env=false dependency without printing it" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
DB_PASS = { provider = "plain", value = "s3cret", env = false }
APP_URL = { default = "pg://${DB_PASS}@db" }
TOML
	run_env env --json --keys APP_URL
	assert_equal "$status" 0
	assert_equal "$(jq -r '.set.APP_URL' out)" "pg://s3cret@db"
	assert_equal "$(jq -r '.set | has("DB_PASS")' out)" false
	assert_equal "$(jq -r '.remove | index("DB_PASS") != null' out)" true
}

@test "env --json does not resolve unrequested env=false secrets" {
	install_pass_stub
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[providers.pass]
type = "password-store"

[secrets]
SHELL_OK = { provider = "plain", value = "shell-value" }
HIDDEN = { provider = "pass", value = "hidden/path", env = false }
TOML
	run_env env --json --keys SHELL_OK
	assert_equal "$status" 0
	[ ! -e "$PASS_CALLS" ]

	run_env env --json
	assert_equal "$status" 0
	[ ! -e "$PASS_CALLS" ]
}

@test "env --json returns as_file contents without writing files" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
CERT = { provider = "plain", value = "-----BEGIN-----", as_file = true }
TOML
	mkdir empty-tmp
	TMPDIR="$PWD/empty-tmp" run_env env --json --keys CERT
	assert_equal "$status" 0
	assert_equal "$(jq -r '.files.CERT' out)" "-----BEGIN-----"
	assert_equal "$(jq -r '.set | has("CERT")' out)" false
	[ -z "$(ls -A empty-tmp)" ]
}

@test "env --json reports missing secrets under if_missing warn and fails under error" {
	install_pass_stub
	cat >fnox.toml <<'TOML'
root = true

[providers.pass]
type = "password-store"

[secrets]
GONE = { provider = "pass", value = "missing/path", if_missing = "warn" }
TOML
	run_env env --json --keys GONE
	assert_equal "$status" 0
	assert_equal "$(jq -c .missing out)" '["GONE"]'
	assert_equal "$(jq -r '.set | length' out)" 0
	[ -s err ]

	cat >fnox.toml <<'TOML'
root = true

[providers.pass]
type = "password-store"

[secrets]
GONE = { provider = "pass", value = "missing/path", if_missing = "error" }
TOML
	run_env env --json --keys GONE
	assert_equal "$status" 1
	assert_equal "$(jq -r .error.kind out)" resolution
}

@test "env --json --describe lists metadata without resolving" {
	install_pass_stub
	cat >fnox.toml <<'TOML'
root = true
env = "exec"

[providers.pass]
type = "password-store"

[secrets]
SHELL_OK = { provider = "pass", value = "shell/path", env = true, description = "A shell secret" }
EXEC_ONLY = { provider = "pass", value = "exec/path" }
HIDDEN = { provider = "pass", value = "hidden/path", env = false }
TOML
	run_env env --json --describe
	assert_equal "$status" 0
	[ ! -e "$PASS_CALLS" ]
	assert_equal "$(jq -r '.keys | length' out)" 3
	assert_equal "$(jq -c '.keys[0].injectable' out)" '{"exec":true,"shell":true}'
	assert_equal "$(jq -r '.keys[0].description' out)" "A shell secret"
	assert_equal "$(jq -c '.keys[1].injectable' out)" '{"exec":true,"shell":false}'
	assert_equal "$(jq -r '.keys[1].env' out)" exec
	assert_equal "$(jq -c '.keys[2].injectable' out)" '{"exec":false,"shell":false}'
	assert_equal "$(jq -r '.keys[2].env' out)" false
	assert_equal "$(grep -c 'v-' out || true)" 0
	assert_equal "$(jq -c .dynamic_leases out)" '[]'

	run_env env --json --describe --keys HIDDEN
	assert_equal "$status" 1
	assert_equal "$(jq -r .error.kind out)" invalid_keys
	[ ! -e "$PASS_CALLS" ]

	run_env env --json --describe --keys EXEC_ONLY
	assert_equal "$status" 0
	assert_equal "$(jq -r '.keys | map(.key) | join(",")' out)" EXEC_ONLY
}

@test "env --json --describe reports whether the daemon would be used" {
	printf 'root = true\n[secrets]\nA = { default = "a" }\n' >fnox.toml
	run_env env --json --describe
	assert_equal "$status" 0
	assert_equal "$(jq -c .daemon_enabled out)" false

	printf 'root = true\n[daemon]\nenabled = true\n[secrets]\nA = { default = "a" }\n' >fnox.toml
	run_env env --json --describe
	assert_equal "$status" 0
	assert_equal "$(jq -c .daemon_enabled out)" true

	FNOX_DAEMON=0 run_env env --json --describe
	assert_equal "$(jq -c .daemon_enabled out)" false
}

@test "env --json reports a broken config as a config error" {
	printf 'root = true\n[secrets\n' >fnox.toml
	run_env env --json
	assert_equal "$status" 1
	jq -e . out >/dev/null
	assert_equal "$(jq -r .error.kind out)" config
	[ -s err ]
}

@test "env without --json fails with no JSON output" {
	run_env env
	assert_equal "$status" 1
	[ ! -s out ]
	grep -q "fnox env requires --json" err
}

@test "env --json runs a command lease only when its keys are needed" {
	cat >create-creds.sh <<'SCRIPT'
#!/usr/bin/env bash
touch "$PWD/lease-ran"
cat <<JSON
{
  "credentials": {
    "MY_TOKEN": "tok-abc123"
  },
  "expires_at": "2099-01-01T00:00:00Z",
  "lease_id": "cmd-test-lease-1"
}
JSON
SCRIPT
	chmod +x create-creds.sh
	cat >fnox.toml <<TOML
root = true

[providers.plain]
type = "plain"

[leases.test_cmd]
type = "command"
create_command = "$PWD/create-creds.sh"

[secrets]
FOO = { provider = "plain", value = "foo-value" }
TOML

	run_env env --json --keys FOO
	assert_equal "$status" 0
	[ ! -e lease-ran ]
	assert_equal "$(jq -c .leases out)" '[]'

	run_env env --json --keys MY_TOKEN
	assert_equal "$status" 1
	assert_equal "$(jq -c .error.unknown out)" '["MY_TOKEN"]'
	[ ! -e lease-ran ]

	run_env env --json
	assert_equal "$status" 0
	[ -e lease-ran ]
	assert_equal "$(jq -r '.set.MY_TOKEN' out)" tok-abc123
	assert_equal "$(jq -c .leases out)" '["test_cmd"]'

	run_env env --json --describe
	assert_equal "$(jq -c .dynamic_leases out)" '["test_cmd"]'
}

@test "env --json shares the daemon cache with exec" {
	install_pass_stub
	cat >fnox.toml <<'TOML'
root = true

[daemon]
enabled = true

[providers.pass]
type = "password-store"

[secrets]
FOO = { provider = "pass", value = "foo" }
TOML

	run_env env --json --keys FOO
	assert_equal "$status" 0
	assert_equal "$(jq -r '.set.FOO' out)" v-foo
	run "$FNOX_BIN" daemon status
	assert_output --partial "fnox daemon running"
	assert_equal "$(wc -l <"$PASS_CALLS" | tr -d ' ')" 1

	run "$FNOX_BIN" exec -- printenv FOO
	assert_success
	assert_output "v-foo"
	assert_equal "$(wc -l <"$PASS_CALLS" | tr -d ' ')" 1
}

@test "env --json --no-daemon does not start an enabled daemon" {
	install_pass_stub
	cat >fnox.toml <<'TOML'
root = true

[daemon]
enabled = true

[providers.pass]
type = "password-store"

[secrets]
FOO = { provider = "pass", value = "foo" }
TOML

	run_env --non-interactive --no-daemon env --json --keys FOO
	assert_equal "$status" 0
	assert_equal "$(jq -r '.set.FOO' out)" v-foo
	run "$FNOX_BIN" daemon status
	assert_output --partial "not running"
}

@test "env --json lets a command lease read an env=false secret without printing it" {
	cat >create-creds.sh <<'SCRIPT'
#!/usr/bin/env bash
cat <<JSON
{
  "credentials": {
    "MY_TOKEN": "tok-${LEASE_INPUT}"
  },
  "expires_at": "2099-01-01T00:00:00Z",
  "lease_id": "cmd-test-lease-2"
}
JSON
SCRIPT
	chmod +x create-creds.sh
	cat >fnox.toml <<TOML
root = true

[providers.plain]
type = "plain"

[leases.test_cmd]
type = "command"
create_command = "$PWD/create-creds.sh"

[secrets]
LEASE_INPUT = { provider = "plain", value = "hidden-input", env = false }
FOO = { provider = "plain", value = "foo-value" }
TOML

	run_env env --json
	assert_equal "$status" 0
	assert_equal "$(jq -r '.set.MY_TOKEN' out)" tok-hidden-input
	assert_equal "$(jq -r '.set | has("LEASE_INPUT")' out)" false
	assert_equal "$(jq -r '.remove | index("LEASE_INPUT") != null' out)" true
}
