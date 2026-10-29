#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi
	local keygen_output public_key
	keygen_output=$(age-keygen -o key.txt 2>&1)
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	cat >fnox.toml <<EOF
root = true
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$public_key"]
key_file = "key.txt"

[mcp]
tools = ["exec", "request_secret"]

[secrets]
EOF
}

teardown() {
	_common_teardown
}

# mcp_client ELICIT PAGE CALLS: see test/mcp_client.py
mcp_client() {
	run "${PYTHON3:-python3}" "$BATS_TEST_DIRNAME/mcp_client.py" "$FNOX_BIN" "$@"
}

@test "request_secret is not offered unless enabled" {
	sed -i.bak 's/^tools = .*/tools = ["exec"]/' fnox.toml
	mcp_client url none list
	assert_success
	assert_line --index 0 '["exec"]'
}

@test "request_secret stores the value entered on the page and exec can use it" {
	mcp_client url save:tskey-auth-12345 \
		'[["request_secret", {"name": "API_TOKEN", "reason": "joins test VMs"}], ["exec", {"command": ["printenv", "API_TOKEN"]}]]'
	assert_success
	assert_line --index 0 --partial "fnox stored it with provider 'age'"
	assert_line --index 1 --partial '[REDACTED]'
	assert_line --index 2 '{"page": 200}'
	refute_output --partial "tskey-auth-12345"

	run grep -c tskey-auth-12345 fnox.toml
	assert_output 0
	run "$FNOX_BIN" get API_TOKEN
	assert_success
	assert_output "tskey-auth-12345"
}

@test "request_secret reports an existing value without asking again" {
	echo "existing" | "$FNOX_BIN" set API_TOKEN
	mcp_client url none '[["request_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_line --index 0 --partial "already has a value"
	assert_line --index 1 '{"page": null}'
}

@test "request_secret falls back to fnox set when the client lacks URL elicitation" {
	mcp_client none none '[["request_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_line --index 0 --partial '"isError": true'
	assert_line --index 0 --partial "fnox set API_TOKEN"
	run "$FNOX_BIN" list
	refute_output --partial API_TOKEN
}

@test "request_secret picks up a value set in the terminal during the session" {
	mcp_client none none '[
		["request_secret", {"name": "API_TOKEN"}],
		["$", ["sh", "-c", "echo from-terminal | \"$FNOX_BIN\" set API_TOKEN"]],
		["request_secret", {"name": "API_TOKEN"}],
		["exec", {"command": ["printenv", "API_TOKEN"]}]
	]'
	assert_success
	assert_line --index 0 --partial "fnox set API_TOKEN"
	assert_line --index 1 '{"ran": 0}'
	assert_line --index 2 --partial "already has a value"
	assert_line --index 3 --partial '[REDACTED]'
}

@test "request_secret applies the top-level env default to a new secret" {
	sed -i.bak 's/^default_provider = .*/&\nenv = false/' fnox.toml
	mcp_client url save:hidden-value \
		'[["request_secret", {"name": "API_TOKEN"}], ["exec", {"command": ["printenv", "API_TOKEN"]}]]'
	assert_success
	assert_line --index 0 --partial "fnox stored it"
	assert_line --index 1 --partial '[exit code: 1]'
	refute_output --partial hidden-value
}

@test "request_secret replaces a value and keeps json_path" {
	echo '{"token":"old-token"}' | "$FNOX_BIN" set API_TOKEN
	sed -i.bak 's/^API_TOKEN *= *{ /API_TOKEN = { json_path = "token", /' fnox.toml
	grep -q 'json_path = "token"' fnox.toml
	mcp_client url 'save:{"token":"new-token"}' '[
		["request_secret", {"name": "API_TOKEN", "replace": true}],
		["exec", {"command": ["sh", "-c", "test \"$API_TOKEN\" = new-token && echo matched"]}]
	]'
	assert_success
	assert_line --index 0 --partial "fnox stored it"
	assert_line --index 1 --partial matched
	run "$FNOX_BIN" get API_TOKEN
	assert_output "new-token"
}

@test "request_secret reports a decline on the page" {
	mcp_client url decline '[["request_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_line --index 0 --partial "declined"
	assert_line --index 1 '{"page": 200}'
	run "$FNOX_BIN" list
	refute_output --partial API_TOKEN
}

@test "request_secret refuses a provider that would store plain text" {
	sed -i.bak 's/^default_provider = .*/default_provider = "plain"/' fnox.toml
	printf '\n[providers.plain]\ntype = "plain"\n' >>fnox.toml
	mcp_client url none '[["request_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_line --index 0 --partial "plain text"
	assert_line --index 1 '{"page": null}'
}

@test "request_secret refuses plain text before suggesting fnox set" {
	sed -i.bak 's/^default_provider = .*/default_provider = "plain"/' fnox.toml
	printf '\n[providers.plain]\ntype = "plain"\n' >>fnox.toml
	mcp_client none none '[["request_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_line --index 0 --partial "plain text"
	refute_output --partial "fnox set"
}

@test "request_secret stores nothing if the secret is set while the page is open" {
	export BEFORE_SUBMIT="echo from-terminal | '$FNOX_BIN' set API_TOKEN"
	mcp_client url save:from-page '[["request_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_line --index 0 --partial "was set while this page was open"
	assert_line --index 1 '{"page": 500}'
	run "$FNOX_BIN" get API_TOKEN
	assert_output "from-terminal"
}

@test "request_secret only asks for names in mcp.secrets" {
	sed -i.bak 's/^tools = .*/&\nsecrets = ["OTHER"]/' fnox.toml
	mcp_client url none '[["request_secret", {"name": "API_TOKEN"}]]'
	assert_success
	assert_line --index 0 --partial "not in mcp.secrets"
}
