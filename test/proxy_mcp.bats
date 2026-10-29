#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
	export NO_COLOR=1
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi
	local keygen_output public_key
	keygen_output=$(age-keygen -o key.txt 2>&1)
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	# The rule targets loopback so no request leaves the machine
	cat >fnox.toml <<EOF
root = true
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$public_key"]
key_file = "key.txt"

[secrets]
API_TOKEN = { description = "not set yet" }

[mcp]
tools = ["get_secret", "exec", "request_secret"]

[proxy]
allow_private = ["127.0.0.1"]

[[proxy.rules]]
secret = "API_TOKEN"
domain = "127.0.0.1"
EOF
}

teardown() {
	_common_teardown
}

# macOS has no coreutils `timeout`; fall back to perl's alarm so a hang stays bounded.
run_with_timeout() {
	local seconds="$1"
	shift
	if command -v timeout >/dev/null 2>&1; then
		timeout "$seconds" "$@"
	elif command -v gtimeout >/dev/null 2>&1; then
		gtimeout "$seconds" "$@"
	else
		perl -e 'alarm shift; exec @ARGV or exit 127' "$seconds" "$@"
	fi
}

# mcp_client_under_proxy ELICIT PAGE CALLS: test/mcp_client.py, started by
# fnox proxy run, so its `fnox mcp` relays to the proxy
mcp_client_under_proxy() {
	run "$FNOX_BIN" proxy run -- \
		"${PYTHON3:-python3}" "$BATS_TEST_DIRNAME/mcp_client.py" "$FNOX_BIN" "$@"
}

@test "fnox mcp under proxy run offers no exec tool" {
	mcp_client_under_proxy url none list
	assert_success
	assert_line '["get_secret", "request_secret"]'
}

@test "get_secret under proxy run returns the placeholder, not the value" {
	echo real-value | "$FNOX_BIN" set API_TOKEN
	mcp_client_under_proxy url none '[["get_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_output --regexp 'Its placeholder is fnox_proxy_[0-9a-f]+ \(in \$API_TOKEN\)'
	refute_output --partial real-value
}

@test "exec can't be called under proxy run" {
	mcp_client_under_proxy url none '[["exec", {"command": ["true"]}]]'
	assert_success
	assert_output --partial "Tool 'exec' is not enabled"
}

@test "request_secret under proxy run stores the value and the proxy injects it" {
	if ! command -v curl >/dev/null 2>&1; then
		skip "curl not installed"
	fi
	mcp_client_under_proxy url save:entered-on-page '[
		["get_secret", {"name": "API_TOKEN"}],
		["request_secret", {"name": "API_TOKEN"}],
		["$", ["sh", "-c", "curl --noproxy \"\" -sS -o /dev/null -w \"%{http_code}\" -H \"authorization: Bearer $API_TOKEN\" https://127.0.0.1/ >status.txt"]]
	]'
	assert_success
	assert_output --partial "It isn't set yet"
	assert_output --regexp 'The user entered .API_TOKEN.\. fnox stored it .*Its placeholder is fnox_proxy_'
	assert_output --partial 'injected=["API_TOKEN"]'
	refute_output --partial entered-on-page
	# Nothing listens on 127.0.0.1:443, so the injected request fails upstream
	run cat status.txt
	assert_output 502
	run "$FNOX_BIN" get API_TOKEN
	assert_output entered-on-page
}

@test "fnox mcp relay reports a missing proxy" {
	FNOX_PROXY_MCP=1 run "$FNOX_BIN" mcp </dev/null
	assert_failure
	assert_output --partial "HTTPS_PROXY is not"
}

@test "fnox mcp relays to the proxy from inside --sandbox, where the config is hidden" {
	local output
	# Skip only when this machine can't sandbox; any other failure is a bug
	if ! output="$("$FNOX_BIN" proxy run --sandbox -- true 2>&1)"; then
		if [[ $output =~ bwrap|bubblewrap|sandbox-exec|"sandbox could not start"|"not supported" ]]; then
			skip "sandbox unavailable: ${output:0:200}"
		fi
		fail "proxy run --sandbox failed: $output"
	fi
	echo real-value | "$FNOX_BIN" set API_TOKEN
	run "$FNOX_BIN" proxy run --sandbox -- \
		"${PYTHON3:-python3}" "$BATS_TEST_DIRNAME/mcp_client.py" "$FNOX_BIN" url none \
		'[["get_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_output --regexp 'Its placeholder is fnox_proxy_[0-9a-f]+'
	refute_output --partial real-value
}

@test "fnox mcp relay exits when the proxy closes the connection" {
	# A stand-in proxy that accepts the MCP CONNECT, then hangs up
	cat >fake_proxy.py <<'PY'
import socket, sys
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(1)
print(s.getsockname()[1], flush=True)
c, _ = s.accept()
data = b""
while b"\r\n\r\n" not in data:
    data += c.recv(1024)
c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
c.close()
PY
	coproc FAKE_PROXY { "${PYTHON3:-python3}" fake_proxy.py; }
	local port
	read -r port <&"${FAKE_PROXY[0]}"
	# The client keeps stdin open; the relay must still end
	FNOX_PROXY_MCP=1 HTTPS_PROXY="http://fnox:token@127.0.0.1:$port" \
		run run_with_timeout 10 "$FNOX_BIN" mcp < <(sleep 30)
	assert_success
}

@test "proxy rules can't use the relay's reserved environment names" {
	printf '\n[[proxy.rules]]\nsecret = "API_TOKEN"\nenv = "FNOX_PROXY_MCP"\ndomain = "api.example.com"\n' >>fnox.toml
	run "$FNOX_BIN" proxy run -- true
	assert_failure
	assert_output --partial "'FNOX_PROXY_MCP', which fnox reserves"
}

@test "fnox mcp under proxy run refuses another profile or config" {
	run "$FNOX_BIN" proxy run -- "$FNOX_BIN" -P staging mcp </dev/null
	assert_failure
	assert_output --partial "'default', not 'staging'"
	run "$FNOX_BIN" proxy run -- "$FNOX_BIN" -c ./other.toml mcp </dev/null
	assert_failure
	assert_output --partial "pass -c to fnox proxy run"
}

@test "request_secret under proxy run refuses a value the proxy can't use" {
	sed -i.bak 's/^domain = "127.0.0.1"/&\nplaceholder = "fnox_ph_api"/' fnox.toml
	mcp_client_under_proxy url save:has-fnox_ph_api-inside '[["request_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_output --partial "the proxy can't use this value"
	assert_output --partial '{"page": 500}'
	run "$FNOX_BIN" get API_TOKEN
	refute_output --partial has-fnox_ph_api-inside
}
