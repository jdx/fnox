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

# Probes a TCP port on this machine's loopback, bounded so it cannot hang.
# macOS has no coreutils `timeout`, so perl's alarm stands in.
_can_connect() {
	if command -v timeout >/dev/null 2>&1; then
		timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null
	else
		perl -e 'alarm 5; exec @ARGV' -- bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null
	fi
}

@test "proxy run --sandbox blocks direct network access but reaches the proxy" {
	_require_sandbox
	command -v python3 >/dev/null 2>&1 || skip "python3 is needed to open a local port"
	command -v timeout >/dev/null 2>&1 || command -v perl >/dev/null 2>&1 || skip "timeout or perl is needed to bound the probe"

	# A port that is open on the host, which the sandbox must not reach.
	python3 -c 'import socket, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(8)
print(s.getsockname()[1], flush=True)
time.sleep(60)' >listener.port &
	local listener=$!
	for _ in $(seq 1 50); do
		[[ -s listener.port ]] && break
		sleep 0.1
	done
	local port
	port="$(cat listener.port)"
	_can_connect "$port" || {
		kill "$listener"
		skip "the local listener is not reachable outside the sandbox"
	}

	export OPEN_PORT="$port"
	run "$FNOX_BIN" proxy run --sandbox -- bash -c '
		# The proxy variable names a port that is reachable; the host one is not.
		if (exec 3<>/dev/tcp/127.0.0.1/"$OPEN_PORT") 2>/dev/null; then
			echo direct-open
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
	kill "$listener" 2>/dev/null || true
	assert_success
	assert_line "direct-blocked"
	assert_line "proxy-reached"
}

@test "proxy run --sandbox passes placeholders and the exit status through" {
	_require_sandbox
	run "$FNOX_BIN" proxy run --sandbox -- sh -c 'test -n "$API_TOKEN" && test "$API_TOKEN" != real-secret && exit 7'
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
	if [[ "$(uname)" != "Linux" ]]; then
		skip "bwrap placeholders are Linux-only"
	fi
	_require_sandbox
	"$FNOX_BIN" proxy run --sandbox -- sleep 30 &
	local pid=$!
	# On Linux bwrap creates the placeholders as it starts; wait for one.
	for _ in $(seq 1 50); do
		[[ -e fnox.local.toml ]] && break
		sleep 0.1
	done
	assert_file_exists fnox.local.toml
	kill -INT "$pid"
	local status=0
	wait "$pid" || status=$?
	assert_equal "$status" 130
	assert_file_not_exists fnox.local.toml
}

@test "proxy run --sandbox blocks launching apps with open on macOS" {
	[ "$(uname)" = "Darwin" ] || skip "Launch Services is macOS-only"
	_require_sandbox
	local marker="$PWD/launched-marker"
	mkdir -p Probe.app/Contents/MacOS
	cat >Probe.app/Contents/Info.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>probe</string>
<key>CFBundleIdentifier</key><string>local.fnox.sandboxprobe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSBackgroundOnly</key><true/>
</dict></plist>
PLIST
	printf '#!/bin/sh\ntouch "%s"\n' "$marker" >Probe.app/Contents/MacOS/probe
	chmod +x Probe.app/Contents/MacOS/probe
	# Control: without the sandbox the probe launches and leaves the marker, so
	# a failure below can only come from the sandbox.
	"$FNOX_BIN" proxy run --no-sandbox -- open -g -j ./Probe.app || true
	local tries=20
	while [ ! -e "$marker" ] && [ "$tries" -gt 0 ]; do
		sleep 0.5
		tries=$((tries - 1))
	done
	[ -e "$marker" ] || skip "Launch Services cannot launch the probe app here"
	rm -f "$marker"

	run "$FNOX_BIN" proxy run --sandbox -- open -g -j ./Probe.app
	assert_failure
	assert_output --partial "-54"
	sleep 3
	assert_file_not_exists "$marker"
}
