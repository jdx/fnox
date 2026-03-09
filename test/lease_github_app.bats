#!/usr/bin/env bats
#
# GitHub App Lease Backend Tests
#
# These tests verify the GitHub App installation token lease backend.
# They use a mock HTTP server to avoid requiring real GitHub credentials.

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	# Kill mock server if running
	if [[ -n "${MOCK_PID:-}" ]]; then
		kill "$MOCK_PID" 2>/dev/null || true
		wait "$MOCK_PID" 2>/dev/null || true
	fi
	_common_teardown
}

# Helper: generate a test RSA private key
generate_test_key() {
	openssl genrsa 2048 2>/dev/null >"$TEST_TEMP_DIR/test-app.pem"
}

# Helper: start a mock GitHub API server that returns a valid token response
start_mock_github_api() {
	local port="${1:-9876}"
	local token="${2:-ghs_mock_installation_token_abc123}"
	local expires_at="${3:-2099-01-01T00:00:00Z}"

	cat >"$TEST_TEMP_DIR/mock_github.py" <<PYEOF
import http.server, json, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.dumps({
            "token": "$token",
            "expires_at": "$expires_at",
            "permissions": {"contents": "read"}
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())
    def log_message(self, format, *args):
        pass

http.server.HTTPServer(("127.0.0.1", $port), Handler).serve_forever()
PYEOF

	python3 "$TEST_TEMP_DIR/mock_github.py" &
	MOCK_PID=$!
	# Wait for server to start
	for _ in $(seq 1 20); do
		if curl -s "http://127.0.0.1:$port" >/dev/null 2>&1; then
			break
		fi
		sleep 0.1
	done
}

@test "github-app: creates installation token with private key file" {
	generate_test_key
	start_mock_github_api 9876

	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "$TEST_TEMP_DIR/test-app.pem"
api_base = "http://127.0.0.1:9876"
EOF

	run fnox lease create github
	assert_success
	assert_output --partial "github"
}

@test "github-app: creates installation token via env var" {
	generate_test_key
	start_mock_github_api 9877

	export FNOX_GITHUB_APP_PRIVATE_KEY
	FNOX_GITHUB_APP_PRIVATE_KEY="$(cat "$TEST_TEMP_DIR/test-app.pem")"

	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
api_base = "http://127.0.0.1:9877"
EOF

	run fnox lease create github
	assert_success
}

@test "github-app: token is available via fnox exec" {
	generate_test_key
	start_mock_github_api 9878

	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "$TEST_TEMP_DIR/test-app.pem"
api_base = "http://127.0.0.1:9878"
EOF

	run fnox exec -- printenv GITHUB_TOKEN
	assert_success
	assert_line "ghs_mock_installation_token_abc123"
}

@test "github-app: custom env_var" {
	generate_test_key
	start_mock_github_api 9879

	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "$TEST_TEMP_DIR/test-app.pem"
env_var = "GH_TOKEN"
api_base = "http://127.0.0.1:9879"
EOF

	run fnox exec -- printenv GH_TOKEN
	assert_success
	assert_line "ghs_mock_installation_token_abc123"
}

@test "github-app: lease is recorded in ledger after create" {
	generate_test_key
	start_mock_github_api 9880

	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "$TEST_TEMP_DIR/test-app.pem"
api_base = "http://127.0.0.1:9880"
EOF

	run fnox lease create github
	assert_success

	# Verify the lease shows up as active
	run fnox lease list --active
	assert_success
	assert_output --partial "github"
}

@test "github-app: fails with missing private key" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "$TEST_TEMP_DIR/nonexistent.pem"
EOF

	run fnox lease create github
	assert_failure
	assert_output --partial "private key"
}

@test "github-app: supports permissions config" {
	generate_test_key
	start_mock_github_api 9881

	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "$TEST_TEMP_DIR/test-app.pem"
api_base = "http://127.0.0.1:9881"

[leases.github.permissions]
contents = "read"
pull_requests = "write"
EOF

	run fnox lease create github
	assert_success
}

@test "github-app: supports repositories config" {
	generate_test_key
	start_mock_github_api 9882

	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "$TEST_TEMP_DIR/test-app.pem"
api_base = "http://127.0.0.1:9882"
repositories = ["my-repo"]
EOF

	run fnox lease create github
	assert_success
}

@test "github-app: lease list shows created lease" {
	generate_test_key
	start_mock_github_api 9883

	cat >"$FNOX_CONFIG_FILE" <<EOF
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "$TEST_TEMP_DIR/test-app.pem"
api_base = "http://127.0.0.1:9883"
EOF

	run fnox lease create github
	assert_success

	run fnox lease list
	assert_success
	assert_output --partial "github"
}
