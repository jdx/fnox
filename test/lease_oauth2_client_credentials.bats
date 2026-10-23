#!/usr/bin/env bats
#
# OAuth2 Client Credentials Lease Backend Tests
#
# These tests use a mock token endpoint to avoid requiring a real identity provider.

export BATS_NO_PARALLELIZE_WITHIN_FILE=true

setup() {
	load 'test_helper/common_setup'
	_common_setup
	load 'test_helper/mock_server'
	export OAUTH2_CLIENT_SECRET="s3cret"
}

teardown() {
	stop_mock_server
	_common_teardown
}

start_token_server() {
	start_mock_server '
def respond(method, path, body):
    if path == "/token":
        return 200, {"access_token": "tok-abc123", "token_type": "Bearer", "expires_in": 3600}
    if path == "/revoke":
        return 200, None
    return 404, {"error": "not_found"}
'
}

@test "oauth2-client-credentials: token is available via fnox exec" {
	start_token_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
client_id = "cid"
EOF

	run fnox exec -- printenv OAUTH2_ACCESS_TOKEN
	assert_success
	assert_line "tok-abc123"
}

@test "oauth2-client-credentials: custom env_var" {
	start_token_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
client_id = "cid"
env_var = "API_TOKEN"
EOF

	run fnox exec -- printenv API_TOKEN
	assert_success
	assert_line "tok-abc123"
}

@test "oauth2-client-credentials: sends credentials as HTTP Basic by default" {
	start_token_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
client_id = "cid"
scope = "read:things write:things"
audience = "https://api.example.com"
EOF

	run fnox lease create idp
	assert_success

	run mock_requests
	assert_output --partial "\"authorization\": \"Basic $(printf 'cid:s3cret' | base64)\""
	assert_output --partial "grant_type=client_credentials"
	assert_output --partial "scope=read%3Athings+write%3Athings"
	assert_output --partial "audience=https%3A%2F%2Fapi.example.com"
	refute_output --partial "client_secret"
}

@test "oauth2-client-credentials: auth_method post sends credentials in the body" {
	start_token_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
client_id = "cid"
auth_method = "post"
EOF

	run fnox lease create idp
	assert_success

	run mock_requests
	assert_output --partial "client_id=cid"
	assert_output --partial "client_secret=s3cret"
	assert_output --partial "\"authorization\": \"\""
}

@test "oauth2-client-credentials: forwards extra params" {
	start_token_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
client_id = "cid"

[leases.idp.params]
resource = "urn:example:api"
EOF

	run fnox lease create idp
	assert_success

	run mock_requests
	assert_output --partial "resource=urn%3Aexample%3Aapi"
}

@test "oauth2-client-credentials: lease is recorded in ledger" {
	start_token_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
client_id = "cid"
EOF

	run fnox lease create idp
	assert_success

	run fnox lease list --active
	assert_success
	assert_output --partial "idp"
}

@test "oauth2-client-credentials: reports the token endpoint's error" {
	start_mock_server '
def respond(method, path, body):
    return 401, {"error": "invalid_client", "error_description": "Client authentication failed"}
'

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
client_id = "cid"
EOF

	run fnox lease create idp
	assert_failure
	assert_output --partial "invalid_client"
}

@test "oauth2-client-credentials: fails without a client secret" {
	unset OAUTH2_CLIENT_SECRET

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:1/token"
client_id = "cid"
EOF

	run fnox lease create idp
	assert_failure
	assert_output --partial "OAUTH2_CLIENT_SECRET"
}

@test "oauth2-client-credentials: revoke posts to revocation_url" {
	start_token_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
revocation_url = "http://127.0.0.1:$MOCK_PORT/revoke"
client_id = "cid"
EOF

	run fnox lease create idp
	assert_success

	run fnox lease revoke "$(first_lease_id)"
	assert_success
	assert_output --partial "revoked"

	run mock_requests
	assert_output --partial "\"path\": \"/revoke\""
	assert_output --partial "token=tok-abc123"
	assert_output --partial "token_type_hint=access_token"
}

@test "oauth2-client-credentials: revoke without revocation_url only marks the ledger" {
	start_token_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.idp]
type = "oauth2-client-credentials"
token_url = "http://127.0.0.1:$MOCK_PORT/token"
client_id = "cid"
EOF

	run fnox lease create idp
	assert_success

	run fnox lease revoke "$(first_lease_id)"
	assert_success

	run mock_requests
	refute_output --partial "/revoke"
}
