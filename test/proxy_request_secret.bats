#!/usr/bin/env bats

load 'test_helper/common_setup'
bats_require_minimum_version 1.5.0

setup() {
	_common_setup
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi
	command -v curl >/dev/null 2>&1 || skip "curl not installed"
	local keygen_output public_key
	keygen_output=$(age-keygen -o key.txt 2>&1)
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	# No server listens on localhost:443, so a request the proxy lets through
	# ends in "upstream request failed" after its audit line says what it
	# injected.
	cat >fnox.toml <<EOF
root = true
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$public_key"]
key_file = "key.txt"

[mcp]
tools = ["exec", "request_secret"]

[proxy]
allow_private = ["127.0.0.0/8", "::1"]

[[proxy.rules]]
secret = "API_TOKEN"
domain = "localhost"
EOF
	export MCP_CLIENT="$BATS_TEST_DIRNAME/mcp_client.py"
	export PYTHON3="${PYTHON3:-python3}"
}

teardown() {
	_common_teardown
}

# curl ignores NO_PROXY (which lists localhost) so the request goes through
# the proxy
CURL='curl -sS --noproxy "" -H "Authorization: Bearer $API_TOKEN" https://localhost/v1; echo'

@test "proxy run serves request_secret and injects the value without a restart" {
	run --separate-stderr "$FNOX_BIN" proxy run -- sh -c "
		$CURL
		\"\$PYTHON3\" \"\$MCP_CLIENT\" \"$FNOX_BIN\" url save:tskey-12345 '[[\"request_secret\", {\"name\": \"API_TOKEN\"}]]'
		$CURL
		echo \"env=\$API_TOKEN\"
	"
	assert_success
	assert_line --index 0 --partial "has no value yet"
	assert_line --index 1 --partial "The proxy now sends it in place of its placeholder"
	assert_line --index 2 '{"page": 200}'
	assert_line --index 3 "upstream request failed"
	assert_line --index 4 --regexp '^env=fnox_proxy_'
	refute_output --partial "tskey-12345"
	local audit
	audit=$(printf '%s' "$stderr" | sed $'s/\x1b\\[[0-9;]*m//g')
	[[ "$audit" == *'injected=["API_TOKEN"]'* ]]
	[[ "$audit" != *"tskey-12345"* ]]

	run grep -c tskey-12345 fnox.toml
	assert_output 0
	run "$FNOX_BIN" get API_TOKEN
	assert_output "tskey-12345"
}

@test "fnox mcp inside proxy run offers only request_secret" {
	run --separate-stderr "$FNOX_BIN" proxy run -- "$PYTHON3" "$MCP_CLIENT" "$FNOX_BIN" url none list
	assert_success
	assert_line --index 0 '["request_secret"]'
}

@test "request_secret inside proxy run refuses a secret without a rule" {
	run --separate-stderr "$FNOX_BIN" proxy run -- "$PYTHON3" "$MCP_CLIENT" "$FNOX_BIN" url none \
		'[["request_secret", {"name": "OTHER_TOKEN"}]]'
	assert_success
	assert_line --index 0 --partial "No [[proxy.rules]] entry names 'OTHER_TOKEN'"
	assert_line --index 1 '{"page": null}'
}

@test "proxy run still requires rule secrets when request_secret is off" {
	sed -i.bak 's/^tools = .*/tools = ["exec"]/' fnox.toml
	run "$FNOX_BIN" proxy run -- sh -c 'echo "mcp=${FNOX_PROXY_MCP:-unset}"'
	assert_failure
	assert_output --partial "unknown secret 'API_TOKEN'"
}

@test "proxy run leaves fnox mcp alone when request_secret is off" {
	sed -i.bak 's/^tools = .*/tools = ["exec"]/' fnox.toml
	echo "existing" | "$FNOX_BIN" set API_TOKEN
	run --separate-stderr "$FNOX_BIN" proxy run -- sh -c 'echo "mcp=${FNOX_PROXY_MCP:-unset}"'
	assert_success
	assert_output "mcp=unset"
}

@test "proxy run --sandbox serves request_secret on a page the command can't reach" {
	local output
	if ! output="$("$FNOX_BIN" proxy run --sandbox -- true 2>&1)"; then
		skip "sandbox unavailable: ${output:0:200}"
	fi
	export PAGE_URL_FILE="$PWD/page-url"
	"$FNOX_BIN" proxy run --sandbox -- sh -c "
		$CURL
		\"\$PYTHON3\" \"\$MCP_CLIENT\" \"$FNOX_BIN\" url none '[[\"request_secret\", {\"name\": \"API_TOKEN\"}]]' &
		client=\$!
		while [ ! -s \"\$PAGE_URL_FILE\" ]; do sleep 0.1; done
		curl -sS --noproxy '*' --max-time 5 \"\$(cat \"\$PAGE_URL_FILE\")\" >/dev/null 2>&1 && echo page-reachable || echo page-unreachable
		wait \$client
		$CURL
	" >sandbox.out 2>sandbox.err &
	local proxy=$!
	local waited=0
	while [ ! -s page-url ] && [ $waited -lt 300 ]; do
		sleep 0.1
		waited=$((waited + 1))
	done
	assert_file_exists page-url
	# The user, outside the sandbox, submits the page
	curl -sS --noproxy '*' --max-time 30 -d action=save -d value=tskey-12345 "$(cat page-url)" >/dev/null
	wait $proxy

	run cat sandbox.out
	assert_line --index 0 --partial "has no value yet"
	assert_line --index 1 "page-unreachable"
	assert_line --index 2 --partial "The proxy now sends it in place of its placeholder"
	assert_line --index 4 "upstream request failed"
	refute_output --partial "tskey-12345"
	run sed $'s/\x1b\\[[0-9;]*m//g' sandbox.err
	assert_output --partial 'injected=["API_TOKEN"]'
	run "$FNOX_BIN" get API_TOKEN
	assert_output "tskey-12345"
}
