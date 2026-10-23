#!/usr/bin/env bats
#
# GitLab Lease Backend Tests
#
# These tests use a mock GitLab API to avoid requiring real credentials.

export BATS_NO_PARALLELIZE_WITHIN_FILE=true

setup() {
	load 'test_helper/common_setup'
	_common_setup
	load 'test_helper/mock_server'
	export GITLAB_TOKEN="glpat-parent"
}

teardown() {
	stop_mock_server
	_common_teardown
}

start_gitlab_server() {
	start_mock_server '
def respond(method, path, body):
    if method == "POST" and path.endswith("/access_tokens"):
        return 201, {"id": 77, "token": "glpat-child", "expires_at": "2099-01-01"}
    if method == "DELETE" and path.endswith("/access_tokens/77"):
        return 204, None
    return 404, {"message": "404 Not Found"}
'
}

@test "gitlab: project token is available via fnox exec" {
	start_gitlab_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"
EOF

	# The child token replaces the parent in GITLAB_TOKEN.
	run fnox exec -- printenv GITLAB_TOKEN
	assert_success
	assert_line "glpat-child"
}

@test "gitlab: custom env_var" {
	start_gitlab_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"
env_var = "GL_CHILD"
EOF

	run fnox exec -- printenv GL_CHILD
	assert_success
	assert_line "glpat-child"
}

@test "gitlab: authenticates with the parent token and requests the configured token" {
	start_gitlab_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"
scopes = ["api", "read_registry"]
access_level = "maintainer"
EOF

	run fnox lease create gl
	assert_success

	run mock_requests
	assert_output --partial "\"path\": \"/api/v4/projects/group%2Fapp/access_tokens\""
	assert_output --partial "\"private_token\": \"glpat-parent\""
	assert_output --partial '\"scopes\":[\"api\",\"read_registry\"]'
	assert_output --partial '\"access_level\":40'
	assert_output --partial 'fnox-lease-'
}

@test "gitlab: expires_at is a date after the lease ends" {
	start_gitlab_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"
duration = "1h"
EOF

	run fnox lease create gl
	assert_success

	local sent_date
	sent_date=$(mock_requests | python3 -c 'import json,sys; print(json.loads(json.loads(sys.stdin.readline())["body"])["expires_at"])')
	[[ $sent_date =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]
	# Strictly after today (UTC): GitLab rejects a token that expires today.
	[[ $sent_date > $(date -u +%Y-%m-%d) ]]
}

@test "gitlab: group tokens use the groups API" {
	start_gitlab_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
group = "platform"
EOF

	run fnox lease create gl
	assert_success

	run mock_requests
	assert_output --partial "\"path\": \"/api/v4/groups/platform/access_tokens\""
}

@test "gitlab: revoke deletes the token" {
	start_gitlab_server

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"
EOF

	run fnox lease create gl
	assert_success

	run fnox lease revoke "$(first_lease_id)"
	assert_success
	assert_output --partial "revoked"

	run mock_requests
	assert_output --partial "\"method\": \"DELETE\""
	assert_output --partial "/api/v4/projects/group%2Fapp/access_tokens/77"
}

@test "gitlab: fails without project or group" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
EOF

	run fnox lease create gl
	assert_failure
	assert_output --partial "exactly one of"
}

@test "gitlab: fails without a parent token" {
	unset GITLAB_TOKEN

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
project = "group/app"
EOF

	run fnox lease create gl
	assert_failure
	assert_output --partial "GITLAB_TOKEN"
}

@test "gitlab: reports API errors" {
	start_mock_server '
def respond(method, path, body):
    return 403, {"message": "403 Forbidden"}
'

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"
EOF

	run fnox lease create gl
	assert_failure
	assert_output --partial "403 Forbidden"
}

@test "gitlab: revoke loads the parent token from configured secrets" {
	start_gitlab_server
	unset GITLAB_TOKEN

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[providers.p]
type = "plain"

[secrets]
GITLAB_TOKEN = { provider = "p", value = "glpat-from-secret", env = false }

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"
EOF

	run fnox lease create gl
	assert_success

	run fnox lease revoke "$(first_lease_id)"
	assert_success

	# The DELETE must carry the secret, not an empty or missing token.
	run python3 -c '
import json, sys
requests = [json.loads(line) for line in open(sys.argv[1])]
deletes = [r for r in requests if r["method"] == "DELETE"]
assert len(deletes) == 1 and deletes[0]["private_token"] == "glpat-from-secret", deletes
' "$TEST_TEMP_DIR/mock_requests.log"
	assert_success
}

@test "gitlab: rejects a cleartext url" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://gitlab.example.com"
project = "group/app"
EOF

	run fnox lease create gl
	assert_failure
	assert_output --partial "must use https"
}
