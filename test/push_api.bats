#!/usr/bin/env bats
#
# fnox push tests for API-based targets, against a mock HTTP server
#

export BATS_NO_PARALLELIZE_WITHIN_FILE=true

setup() {
	load 'test_helper/common_setup'
	_common_setup
	load 'test_helper/mock_server'
}

teardown() {
	stop_mock_server
	_common_teardown
}

write_config() {
	cat >fnox.toml <<TOML
[providers.plain]
type = "plain"

[targets.t]
$1

[secrets]
KEY = { provider = "plain", value = "s3cret", push = ["t"] }
TOML
}

@test "forgejo-actions puts a repository secret" {
	start_mock_server '
def respond(method, path, body):
    if method == "PUT" and path == "/api/v1/repos/acme/api/actions/secrets/KEY":
        return 201, None
    return 404, {"message": "not found"}
'
	export FORGEJO_TOKEN=fj-token
	write_config "type = \"forgejo-actions\"
url = \"http://127.0.0.1:$MOCK_PORT\"
repo = \"acme/api\""
	run "$FNOX_BIN" push --force
	assert_success
	run mock_requests
	assert_output --partial '"method": "PUT"'
	assert_output --partial '"authorization": "token fj-token"'
	assert_output --partial '"body": "{\"data\":\"s3cret\"}"'
}

@test "forgejo-actions falls back to GITEA_TOKEN and reports API errors" {
	start_mock_server '
def respond(method, path, body):
    return 403, {"message": "token does not have required scope"}
'
	export GITEA_TOKEN=gt-token
	write_config "type = \"forgejo-actions\"
url = \"http://127.0.0.1:$MOCK_PORT\"
org = \"acme\""
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "token does not have required scope"
	run mock_requests
	assert_output --partial '"path": "/api/v1/orgs/acme/actions/secrets/KEY"'
	assert_output --partial '"authorization": "token gt-token"'
}

@test "forgejo-actions needs a token" {
	unset FORGEJO_TOKEN GITEA_TOKEN
	write_config 'type = "forgejo-actions"
url = "https://codeberg.org"
repo = "acme/api"'
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "set FORGEJO_TOKEN or GITEA_TOKEN"
}

start_tfc_server() {
	start_mock_server '
import json
def respond(method, path, body):
    if method == "GET" and path == "/api/v2/organizations/acme/workspaces/prod":
        return 200, {"data": {"id": "ws-1"}}
    if method == "GET" and path == "/api/v2/workspaces/ws-1/vars":
        return 200, {"data": [
            {"id": "var-env", "attributes": {"key": "KEY", "category": "env"}},
            {"id": "var-other", "attributes": {"key": "OTHER", "category": "terraform"}},
        ]}
    if method == "PATCH" and path == "/api/v2/workspaces/ws-1/vars/var-env":
        return 200, {"data": {}}
    if method == "POST" and path == "/api/v2/workspaces/ws-1/vars":
        return 201, {"data": {}}
    return 404, {"errors": ["not found"]}
'
}

@test "hcp-terraform updates an existing variable" {
	start_tfc_server
	export TF_TOKEN_127_0_0_1=tf-token
	write_config "type = \"hcp-terraform\"
url = \"http://127.0.0.1:$MOCK_PORT\"
organization = \"acme\"
workspace = \"prod\"
category = \"env\""
	run "$FNOX_BIN" push --force
	assert_success
	run mock_requests
	assert_output --partial '"method": "PATCH", "path": "/api/v2/workspaces/ws-1/vars/var-env"'
	assert_output --partial '"authorization": "Bearer tf-token"'
	assert_output --partial '\"value\":\"s3cret\"'
	assert_output --partial '\"sensitive\":true'
	refute_output --partial '"method": "POST"'
}

@test "hcp-terraform creates a variable in another category" {
	start_tfc_server
	export TFE_TOKEN=tfe-token
	write_config "type = \"hcp-terraform\"
url = \"http://127.0.0.1:$MOCK_PORT\"
organization = \"acme\"
workspace = \"prod\"
category = \"terraform\"
hcl = true"
	run "$FNOX_BIN" push --force
	assert_success
	run mock_requests
	assert_output --partial '"method": "POST", "path": "/api/v2/workspaces/ws-1/vars"'
	assert_output --partial '"authorization": "Bearer tfe-token"'
	assert_output --partial '\"key\":\"KEY\"'
	assert_output --partial '\"category\":\"terraform\"'
	assert_output --partial '\"hcl\":true'
}

@test "hcp-terraform reads the token terraform login saved" {
	start_tfc_server
	unset TFE_TOKEN
	mkdir -p "$HOME/.terraform.d"
	cat >"$HOME/.terraform.d/credentials.tfrc.json" <<'JSON'
{"credentials": {"127.0.0.1": {"token": "login-token"}}}
JSON
	write_config "type = \"hcp-terraform\"
url = \"http://127.0.0.1:$MOCK_PORT\"
organization = \"acme\"
workspace = \"prod\"
category = \"env\""
	run "$FNOX_BIN" push --force
	assert_success
	run mock_requests
	assert_output --partial '"authorization": "Bearer login-token"'
}

@test "hcp-terraform reports a missing workspace" {
	start_tfc_server
	export TFE_TOKEN=tfe-token
	write_config "type = \"hcp-terraform\"
url = \"http://127.0.0.1:$MOCK_PORT\"
organization = \"acme\"
workspace = \"nope\"
category = \"env\""
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "HTTP 404"
}
