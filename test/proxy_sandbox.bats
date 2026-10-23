#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
API_TOKEN = { provider = "plain", value = "real-secret" }

[proxy]
sandbox_deny_read = ["decoy.txt"]

[[proxy.rules]]
secret = "API_TOKEN"
domain = "api.example.com"
TOML
	echo "decoy-contents" >decoy.txt
}

teardown() {
	_common_teardown
}

# The sandbox needs bwrap with user namespaces on Linux and sandbox-exec on
# macOS; skip where the machine cannot provide that.
_require_sandbox() {
	local output
	if ! output="$("$FNOX_BIN" proxy run --sandbox -- true 2>&1)"; then
		skip "sandbox unavailable: ${output:0:200}"
	fi
}

@test "proxy run --sandbox hides the config and denied paths" {
	_require_sandbox
	run "$FNOX_BIN" proxy run --sandbox -- sh -c '
		[ -s fnox.toml ] && echo config-readable || echo config-hidden
		[ -s decoy.txt ] && echo decoy-readable || echo decoy-hidden
	'
	assert_success
	assert_line "config-hidden"
	assert_line "decoy-hidden"
}

@test "proxy run --sandbox allows writes only to the working directory" {
	_require_sandbox
	run "$FNOX_BIN" proxy run --sandbox -- sh -c '
		touch inside && echo inside-ok
		touch ../outside 2>/dev/null && echo outside-ok || echo outside-denied
	'
	assert_success
	assert_line "inside-ok"
	assert_line "outside-denied"
	assert_file_exists inside
	assert_file_not_exists ../outside
}

@test "proxy run --sandbox blocks direct network access but reaches the proxy" {
	_require_sandbox
	run "$FNOX_BIN" proxy run --sandbox -- bash -c '
		if (timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/80") 2>/dev/null; then
			echo direct-reached
		else
			echo direct-blocked
		fi
		port="${HTTPS_PROXY##*:}"
		if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
			echo proxy-reached
		else
			echo proxy-unreachable
		fi
	'
	assert_success
	assert_line "direct-blocked"
	assert_line "proxy-reached"
}

@test "proxy run --sandbox passes placeholders and the exit status through" {
	_require_sandbox
	run "$FNOX_BIN" proxy run --sandbox -- sh -c 'test "$API_TOKEN" != real-secret && exit 7'
	assert_failure 7
}

@test "proxy run --sandbox refuses to run when the sandbox tool is missing" {
	if [[ "$(uname)" != "Linux" ]]; then
		skip "bwrap is Linux-only"
	fi
	PATH=/nonexistent run "$FNOX_BIN" proxy run --sandbox -- true
	assert_failure
	assert_output --partial "bwrap"
}

@test "sandbox = true in [proxy] enables it and --no-sandbox turns it off" {
	_require_sandbox
	sed -i.bak 's/^\[proxy\]$/[proxy]\nsandbox = true/' fnox.toml
	run "$FNOX_BIN" proxy run -- sh -c '[ -s fnox.toml ] && echo readable || echo hidden'
	assert_success
	assert_output "hidden"
	run "$FNOX_BIN" proxy run --no-sandbox -- sh -c '[ -s fnox.toml ] && echo readable || echo hidden'
	assert_success
	assert_line "readable"
}
