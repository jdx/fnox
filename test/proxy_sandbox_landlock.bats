#!/usr/bin/env bats

# The `landlock` sandbox backend: Landlock and a seccomp filter instead of
# bwrap's namespaces.

load 'test_helper/common_setup'

setup() {
	_common_setup
	if [[ "$(uname)" != "Linux" ]]; then
		skip "the landlock backend is Linux-only"
	fi
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
API_TOKEN = { provider = "plain", value = "real-secret" }

[proxy]
sandbox_deny_read = ["decoy.txt"]
sandbox_allow_write = ["out"]

[[proxy.rules]]
secret = "API_TOKEN"
domain = "api.example.com"
TOML
	echo "decoy-contents" >decoy.txt
	echo "readme-contents" >readme.txt
	mkdir out
	local output
	if ! output="$("$FNOX_BIN" proxy run --sandbox-backend landlock -- true 2>&1)"; then
		# Only a machine that cannot run the backend skips; any other failure
		# is a bug in it.
		case "$output" in
		*"needs Landlock ABI"* | *"ptrace_scope"* | *"only supported on x86_64 and aarch64"*)
			skip "landlock sandbox unavailable: ${output:0:200}"
			;;
		*)
			echo "$output" >&2
			return 1
			;;
		esac
	fi
}

teardown() {
	_common_teardown
}

@test "landlock sandbox hides the config and denied paths" {
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- sh -c '
		cat readme.txt
		cat fnox.toml >/dev/null 2>&1 && echo config-readable || echo config-hidden
		cat decoy.txt >/dev/null 2>&1 && echo decoy-readable || echo decoy-hidden
	'
	assert_success
	assert_line "readme-contents"
	assert_line "config-hidden"
	assert_line "decoy-hidden"
}

@test "landlock sandbox keeps the working directory read-only" {
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- sh -c '
		touch inside 2>/dev/null && echo cwd-written || echo cwd-readonly
		touch out/built && echo allowed-written
		touch "$TMPDIR/scratch" && echo tmp-written
		(echo "[proxy]" >fnox.local.toml) 2>/dev/null && echo local-created || echo local-blocked
	'
	assert_success
	assert_line "cwd-readonly"
	assert_line "allowed-written"
	assert_line "tmp-written"
	assert_line "local-blocked"
	assert_file_not_exists inside
	assert_file_exists out/built
	assert_file_not_exists fnox.local.toml
}

@test "landlock sandbox refuses a writable path that holds the config" {
	sed -i 's/^sandbox_allow_write = .*/sandbox_allow_write = ["."]/' fnox.toml
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- true
	assert_failure
	assert_output --partial "sandbox_allow_write"
}

@test "landlock sandbox refuses a writable path inside a hidden one" {
	mkdir -p secrets/cache
	sed -i 's/^sandbox_deny_read = .*/sandbox_deny_read = ["decoy.txt", "secrets"]/; s/^sandbox_allow_write = .*/sandbox_allow_write = ["secrets\/cache"]/' fnox.toml
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- true
	assert_failure
	assert_output --partial "is or is inside"
}

@test "landlock sandbox keeps other terminals out of reach" {
	command -v python3 >/dev/null 2>&1 || skip "python3 is needed to open a terminal"
	python3 -c 'import os, pty, time
primary, secondary = pty.openpty()
print(os.ttyname(secondary), flush=True)
time.sleep(60)' >pty.path &
	local holder=$!
	for _ in $(seq 1 50); do
		[[ -s pty.path ]] && break
		sleep 0.1
	done
	OTHER_TTY="$(cat pty.path)"
	export OTHER_TTY
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- sh -c '
		(: <"$OTHER_TTY") 2>/dev/null && echo tty-readable || echo tty-blocked
		(: >"$OTHER_TTY") 2>/dev/null && echo tty-writable || echo tty-blocked
	'
	kill "$holder" 2>/dev/null || true
	assert_success
	refute_line "tty-readable"
	refute_line "tty-writable"
}

@test "landlock sandbox lets the command reopen its own terminal" {
	command -v script >/dev/null 2>&1 || skip "script is needed to give the command a terminal"
	run script -qec "\"$FNOX_BIN\" proxy run --sandbox-backend landlock -- sh -c 'echo to-stderr >/dev/stderr && echo reopened'" /dev/null
	assert_success
	assert_output --partial "to-stderr"
	assert_output --partial "reopened"
}

@test "landlock sandbox reaches only the proxy" {
	command -v python3 >/dev/null 2>&1 || skip "python3 is needed to open a local port"
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
	OPEN_PORT="$(cat listener.port)"
	[[ "$OPEN_PORT" =~ ^[0-9]+$ ]] || fail "the listener did not start"
	export OPEN_PORT
	# The port is open outside the sandbox, so being blocked inside means
	# the sandbox refused it.
	(exec 3<>/dev/tcp/127.0.0.1/"$OPEN_PORT") || fail "the listener is not reachable"
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- bash -c '
		(exec 3<>/dev/tcp/127.0.0.1/"$OPEN_PORT") 2>/dev/null && echo direct-open || echo direct-blocked
		port="${HTTPS_PROXY##*:}"
		(exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null && echo proxy-reached || echo proxy-unreachable
		python3 -c "
import socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(\"udp-open\")
except PermissionError:
    print(\"udp-blocked\")
"
		test -r "$SSL_CERT_FILE" && echo ca-readable
	'
	kill "$listener" 2>/dev/null || true
	assert_success
	assert_line "direct-blocked"
	assert_line "proxy-reached"
	assert_line "udp-blocked"
	assert_line "ca-readable"
}

@test "sandbox_backend = landlock in [proxy] selects it" {
	awk '{print} /^\[proxy\]$/ {print "sandbox = true\nsandbox_backend = \"landlock\""}' fnox.toml >fnox.toml.new && mv fnox.toml.new fnox.toml
	run "$FNOX_BIN" proxy run -- sh -c 'touch inside 2>/dev/null && echo cwd-written || echo cwd-readonly; test -n "$API_TOKEN" && test "$API_TOKEN" != real-secret && exit 7'
	assert_failure 7
	assert_line "cwd-readonly"
}

@test "landlock sandbox stops processes the command leaves behind" {
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- sh -c 'sleep 313 </dev/null >/dev/null 2>&1 & echo $!'
	assert_success
	local pid="$output"
	sleep 0.2
	run kill -0 "$pid"
	assert_failure
}

@test "interrupting the landlock sandbox exits with the signal" {
	"$FNOX_BIN" proxy run --sandbox-backend landlock -- sh -c 'touch out/ready; exec sleep 30' &
	local pid=$!
	for _ in $(seq 1 100); do
		[[ -e out/ready ]] && break
		sleep 0.1
	done
	[[ -e out/ready ]] || fail "the sandboxed command did not start"
	kill -INT "$pid"
	local status=0
	for _ in $(seq 1 100); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	if kill -0 "$pid" 2>/dev/null; then
		kill -KILL "$pid"
		fail "fnox did not exit after SIGINT"
	fi
	wait "$pid" || status=$?
	assert_equal "$status" 130
}

@test "landlock sandbox keeps a working directory in or of /tmp readable" {
	local dir
	dir="$(mktemp -d /tmp/fnox-landlock-cwd.XXXXXX)"
	cp fnox.toml "$dir/"
	echo "tmp-contents" >"$dir/readme.txt"
	cd "$dir"
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- sh -c '
		cat readme.txt
		cat fnox.toml >/dev/null 2>&1 && echo config-readable || echo config-hidden
	'
	cd /tmp
	local inside="$output"
	run "$FNOX_BIN" -c "$dir/fnox.toml" proxy run --sandbox-backend landlock -- sh -c "
		cat '$dir/readme.txt'
		cat '$dir/fnox.toml' >/dev/null 2>&1 && echo config-readable || echo config-hidden
	"
	local status_of_tmp="$status" of_tmp="$output"
	cd "$TEST_TEMP_DIR"
	rm -r "$dir"
	output="$inside"
	assert_line "tmp-contents"
	assert_line "config-hidden"
	assert_equal "$status_of_tmp" 0
	output="$of_tmp"
	assert_line "tmp-contents"
	assert_line "config-hidden"
}

@test "landlock sandbox passes on only standard descriptors" {
	run "$FNOX_BIN" proxy run --sandbox-backend landlock -- sh -c '
		(: <&7) 2>/dev/null && echo fd-inherited || echo fd-closed
	' 7<decoy.txt
	assert_success
	assert_line "fd-closed"
}
