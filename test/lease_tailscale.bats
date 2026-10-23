#!/usr/bin/env bats
#
# Tailscale Lease Backend Tests
#
# These tests use a mock Tailscale API to avoid requiring a real tailnet.

export BATS_NO_PARALLELIZE_WITHIN_FILE=true

setup() {
	load 'test_helper/common_setup'
	_common_setup
	load 'test_helper/mock_server'
	export TAILSCALE_OAUTH_CLIENT_ID="client-id"
	export TAILSCALE_OAUTH_CLIENT_SECRET="client-secret"
	unset TAILSCALE_API_KEY
}

teardown() {
	stop_mock_server
	_common_teardown
}

start_tailscale_server() {
	start_mock_server '
def respond(method, path, body):
    if path == "/api/v2/oauth/token":
        return 200, {"access_token": "ts-oauth-token", "token_type": "Bearer", "expires_in": 3600}
    if method == "POST" and path == "/api/v2/tailnet/-/keys":
        return 200, {"id": "kABC123", "key": "tskey-auth-mock", "expires": "2099-01-01T00:00:00Z"}
    if method == "DELETE" and path == "/api/v2/tailnet/-/keys/kABC123":
        return 200, {}
    return 404, {"message": "not found"}
'
}

write_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.ts]
type = "tailscale"
api_base = "http://127.0.0.1:$MOCK_PORT"
$1
EOF
}

@test "tailscale: auth key is available via fnox exec" {
	start_tailscale_server
	write_config 'tags = ["tag:ci"]'

	run fnox exec -- printenv TS_AUTHKEY
	assert_success
	assert_line "tskey-auth-mock"
}

@test "tailscale: custom env_var" {
	start_tailscale_server
	write_config 'env_var = "TAILSCALE_AUTH_KEY"'

	run fnox exec -- printenv TAILSCALE_AUTH_KEY
	assert_success
	assert_line "tskey-auth-mock"
}

@test "tailscale: exchanges the OAuth client for a bearer token" {
	start_tailscale_server
	write_config 'tags = ["tag:ci"]'

	run fnox lease create ts
	assert_success

	run mock_requests
	assert_output --partial "\"path\": \"/api/v2/oauth/token\""
	assert_output --partial "client_id=client-id"
	assert_output --partial "client_secret=client-secret"
	assert_output --partial "\"authorization\": \"Bearer ts-oauth-token\""
}

@test "tailscale: sends the requested key capabilities" {
	start_tailscale_server
	write_config 'tags = ["tag:ci", "tag:build"]
duration = "1h"
reusable = true
ephemeral = false'

	run fnox lease create ts
	assert_success

	local body
	body=$(mock_requests | python3 -c '
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if request["path"].endswith("/keys"):
        print(request["body"])
')
	run python3 -c '
import json, sys
body = json.loads(sys.argv[1])
create = body["capabilities"]["devices"]["create"]
assert create == {"reusable": True, "ephemeral": False, "preauthorized": True, "tags": ["tag:ci", "tag:build"]}, create
assert body["expirySeconds"] == 3600, body
assert body["description"].startswith("fnox-"), body
' "$body"
	assert_success
}

@test "tailscale: an API key authenticates with Basic auth and skips OAuth" {
	start_tailscale_server
	unset TAILSCALE_OAUTH_CLIENT_ID TAILSCALE_OAUTH_CLIENT_SECRET
	export TAILSCALE_API_KEY="tskey-api-xyz"
	write_config ''

	run fnox lease create ts
	assert_success

	run mock_requests
	assert_output --partial "\"authorization\": \"Basic $(printf 'tskey-api-xyz:' | base64)\""
	refute_output --partial "/oauth/token"
}

@test "tailscale: revoke deletes the key" {
	start_tailscale_server
	write_config ''

	run fnox lease create ts
	assert_success

	run fnox lease revoke "$(first_lease_id)"
	assert_success
	assert_output --partial "revoked"

	run mock_requests
	assert_output --partial "\"method\": \"DELETE\""
	assert_output --partial "/api/v2/tailnet/-/keys/kABC123"
}

@test "tailscale: fails without credentials" {
	unset TAILSCALE_OAUTH_CLIENT_ID TAILSCALE_OAUTH_CLIENT_SECRET

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.ts]
type = "tailscale"
EOF

	run fnox lease create ts
	assert_failure
	assert_output --partial "TAILSCALE_OAUTH_CLIENT_ID"
}

@test "tailscale: reports API errors" {
	start_mock_server '
def respond(method, path, body):
    if path == "/api/v2/oauth/token":
        return 200, {"access_token": "ts-oauth-token"}
    return 403, {"message": "requested tags are invalid or not permitted"}
'
	write_config 'tags = ["tag:nope"]'

	run fnox lease create ts
	assert_failure
	assert_output --partial "requested tags are invalid"
}
