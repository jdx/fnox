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
		# macOS has no coreutils `timeout`; perl bounds a connection that hangs.
		bounded() {
			if command -v timeout >/dev/null 2>&1; then
				timeout 5 "$@"
			elif command -v perl >/dev/null 2>&1; then
				perl -e "alarm 5; exec @ARGV" -- "$@"
			else
				"$@"
			fi
		}
		bounded bash -c "exec 3<>/dev/tcp/1.1.1.1/80" 2>/dev/null
		# 1 is a refused or unroutable connection; anything else (success, a
		# timeout) means the connection was not blocked.
		if [ "$?" -eq 1 ]; then echo direct-blocked; else echo direct-open; fi
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
	awk '{print} /^\[proxy\]$/ {print "sandbox = true"}' fnox.toml >fnox.toml.new && mv fnox.toml.new fnox.toml
	run "$FNOX_BIN" proxy run -- sh -c '[ -s fnox.toml ] && echo readable || echo hidden'
	assert_success
	assert_output "hidden"
	run "$FNOX_BIN" proxy run --no-sandbox -- sh -c '[ -s fnox.toml ] && echo readable || echo hidden'
	assert_success
	assert_line "readable"
}

@test "proxy run --sandbox keeps the command from creating config or git hooks" {
	_require_sandbox
	mkdir -p .git
	run "$FNOX_BIN" proxy run --sandbox -- sh -c '
		(echo "[proxy]" >fnox.local.toml) 2>/dev/null && echo local-created || echo local-blocked
		(mkdir -p .git/hooks && echo "#!/bin/sh" >.git/hooks/pre-commit) 2>/dev/null && echo hook-created || echo hook-blocked
	'
	assert_success
	assert_line "local-blocked"
	assert_line "hook-blocked"
	# The empty files bwrap mounts over become nothing once the command exits.
	assert_file_not_exists fnox.local.toml
	assert_file_not_exists .git/hooks/pre-commit
}

@test "interrupting proxy run --sandbox removes the placeholder files" {
	_require_sandbox
	"$FNOX_BIN" proxy run --sandbox -- sleep 30 &
	local pid=$!
	# On Linux bwrap creates the placeholders as it starts; wait for one.
	for _ in $(seq 1 50); do
		[[ -e fnox.local.toml ]] && break
		sleep 0.1
	done
	kill -INT "$pid"
	local status=0
	wait "$pid" || status=$?
	assert_equal "$status" 130
	assert_file_not_exists fnox.local.toml
}
