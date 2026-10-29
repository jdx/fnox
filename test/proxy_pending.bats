#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
	export NO_COLOR=1
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi
	if ! command -v curl >/dev/null 2>&1; then
		skip "curl not installed"
	fi
	local keygen_output public_key
	keygen_output=$(age-keygen -o key.txt 2>&1)
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	# The rule targets loopback so no request leaves the machine: while the
	# secret is pending the proxy refuses it, and once set it tries the
	# upstream, where nothing listens.
	cat >fnox.toml <<EOF
root = true
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$public_key"]
key_file = "key.txt"

[secrets]
API_TOKEN = { description = "not set yet" }

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

@test "proxy run starts with a rule whose secret isn't set and hands out its placeholder" {
	run "$FNOX_BIN" proxy run -- printenv API_TOKEN
	assert_success
	assert_output --partial "'API_TOKEN' is not set"
	assert_output --regexp 'fnox_proxy_[0-9a-f]+'
}

@test "proxy run refuses a pending secret, then injects it once it is set" {
	run "$FNOX_BIN" proxy run -- sh -c '
		request() {
			curl --noproxy "" -sS -o /dev/null -w "%{http_code}\n" \
				-H "authorization: Bearer $API_TOKEN" https://127.0.0.1/
		}
		echo "first $(request)"
		echo set-during-run | "$FNOX_BIN" set API_TOKEN >/dev/null
		# A pending secret is resolved again at most every few seconds
		sleep 3
		echo "second $(request)"
	'
	assert_success
	assert_output --partial "not set yet"
	assert_line "first 403"
	assert_output --partial "pending secret is now set"
	assert_output --partial 'injected=["API_TOKEN"]'
	assert_line "second 502"
	refute_output --partial set-during-run
}

@test "proxy run still rejects a rule for a secret that isn't declared" {
	sed -i.bak '/^API_TOKEN = /d' fnox.toml
	run "$FNOX_BIN" proxy run -- true
	assert_failure
	assert_output --partial "unknown secret 'API_TOKEN'"
}
