#!/usr/bin/env bats
#
# git credential helper tests
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
    return 404, {"message": "404 Not Found"}
'
}

write_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"
EOF
}

@test "git-credential get: returns the lease token for the matching host" {
	start_gitlab_server
	write_config

	run bash -c "printf 'protocol=http\nhost=127.0.0.1:$MOCK_PORT\npath=group/app.git\n\n' | fnox git-credential get"
	assert_success
	assert_line "username=oauth2"
	assert_line "password=glpat-child"
}

@test "git-credential get: prints nothing for a host no backend serves" {
	start_gitlab_server
	write_config

	run bash -c "printf 'protocol=https\nhost=example.com\n\n' | fnox git-credential get"
	assert_success
	assert_output ""
}

@test "git-credential store and erase do nothing" {
	start_gitlab_server
	write_config

	run bash -c "printf 'protocol=http\nhost=127.0.0.1:$MOCK_PORT\nusername=u\npassword=p\n\n' | fnox git-credential store"
	assert_success
	assert_output ""
	run bash -c "printf 'protocol=http\nhost=127.0.0.1:$MOCK_PORT\n\n' | fnox git-credential erase"
	assert_success
	assert_output ""
}

@test "git-credential get: --backend that does not serve the host prints nothing" {
	start_gitlab_server
	write_config

	run bash -c "printf 'protocol=http\nhost=127.0.0.1:$MOCK_PORT\n\n' | fnox git-credential get --backend other"
	assert_success
	assert_output ""
}

@test "git-credential get: uses the backend that serves the host, not another with the same env var" {
	start_gitlab_server
	# Both backends produce GITLAB_TOKEN; the later one must not answer for the
	# mock server's host (it would fail, as nothing listens there).
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
url = "http://127.0.0.1:$MOCK_PORT"
project = "group/app"

[leases.other]
type = "gitlab"
url = "https://gitlab.invalid"
project = "group/app"
EOF

	run bash -c "printf 'protocol=http\nhost=127.0.0.1:$MOCK_PORT\n\n' | fnox git-credential get"
	assert_success
	assert_line "password=glpat-child"
}

@test "git-credential get: plain HTTP to a non-loopback host gets no token" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.gl]
type = "gitlab"
project = "group/app"
EOF

	run bash -c "printf 'protocol=http\nhost=gitlab.com\n\n' | fnox git-credential get"
	assert_success
	assert_output ""
}

@test "git-credential get: no config anywhere prints nothing" {
	rm -f "$FNOX_CONFIG_FILE"
	cd "$TEST_TEMP_DIR"

	run bash -c "printf 'protocol=https\nhost=github.com\n\n' | fnox git-credential get"
	assert_success
	assert_output ""
}
