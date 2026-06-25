#!/usr/bin/env bats
#
# GitHub OAuth Lease Backend Tests
#
# These tests verify the GitHub OAuth device-flow lease backend against a mock
# HTTP server, so no real GitHub credentials or browser interaction are needed.

export BATS_NO_PARALLELIZE_WITHIN_FILE=true

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	if [[ -n ${MOCK_PID:-} ]]; then
		kill "$MOCK_PID" 2>/dev/null || true
		wait "$MOCK_PID" 2>/dev/null || true
		unset MOCK_PID
	fi
	_common_teardown
}

start_mock_github_oauth() {
	local token="${1:-ghu_mock_user_token_abc123}"
	local expires_in="${2:-28800}"

	cat >"$TEST_TEMP_DIR/mock_github_oauth.py" <<PYEOF
import http.server, json, os, urllib.parse

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        form = urllib.parse.parse_qs(body)

        if self.path == "/login/device/code":
            payload = {
                "device_code": "device_mock_123",
                "user_code": "ABCD-1234",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 600,
                "interval": 1,
            }
        elif self.path == "/login/oauth/access_token":
            grant_type = form.get("grant_type", [""])[0]
            if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
                payload = {
                    "access_token": "$token",
                    "token_type": "bearer",
                    "scope": "repo",
                    "expires_in": $expires_in,
                    "refresh_token": "ghr_mock_refresh_token",
                    "refresh_token_expires_in": 15897600,
                }
            elif grant_type == "refresh_token":
                payload = {
                    "access_token": "${token}_refreshed",
                    "token_type": "bearer",
                    "scope": "repo",
                    "expires_in": $expires_in,
                }
            else:
                payload = {"error": "unsupported_grant_type"}
        else:
            self.send_response(404)
            self.end_headers()
            return

        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/user":
            payload = {"login": "octocat"}
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open("$TEST_TEMP_DIR/mock_port", "w") as f:
    f.write(str(server.server_address[1]))
    f.flush()
    os.fsync(f.fileno())
server.serve_forever()
PYEOF

	local mock_log="$TEST_TEMP_DIR/mock_github_oauth.log"
	python3 -u "$TEST_TEMP_DIR/mock_github_oauth.py" >"$mock_log" 2>&1 &
	MOCK_PID=$!
	for _ in $(seq 1 300); do
		if [[ -s "$TEST_TEMP_DIR/mock_port" ]]; then
			MOCK_PORT=$(cat "$TEST_TEMP_DIR/mock_port")
			export MOCK_PORT
			return 0
		fi
		local mock_state
		mock_state=$(ps -p "$MOCK_PID" -o stat= 2>/dev/null || true)
		if [[ -z "$mock_state" || $mock_state == *Z* ]]; then
			wait "$MOCK_PID" 2>/dev/null || true
			echo "mock GitHub OAuth server exited before writing port" >&2
			if [[ -s "$mock_log" ]]; then
				cat "$mock_log" >&2
			fi
			unset MOCK_PID
			return 1
		fi
		sleep 0.1
	done
	echo "timed out waiting for mock GitHub OAuth server to write port" >&2
	if [[ -s "$mock_log" ]]; then
		cat "$mock_log" >&2
	fi
	kill "$MOCK_PID" 2>/dev/null || true
	wait "$MOCK_PID" 2>/dev/null || true
	unset MOCK_PID
	return 1
}

@test "github-oauth: creates user access token via device flow" {
	start_mock_github_oauth

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.github]
type = "github-oauth"
client_id = "Iv1.mockclientid"
scope = "repo"
keyring_cache = false
open_browser = false
auth_base = "http://127.0.0.1:$MOCK_PORT/login/oauth"
api_base = "http://127.0.0.1:$MOCK_PORT/api"
EOF

	run fnox lease create github
	assert_success
	assert_output --partial "github"
}

@test "github-oauth: token is available via fnox exec" {
	start_mock_github_oauth

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.github]
type = "github-oauth"
client_id = "Iv1.mockclientid"
scope = "repo"
keyring_cache = false
open_browser = false
auth_base = "http://127.0.0.1:$MOCK_PORT/login/oauth"
api_base = "http://127.0.0.1:$MOCK_PORT/api"
EOF

	run fnox exec -- printenv GITHUB_TOKEN
	assert_success
	assert_line "ghu_mock_user_token_abc123"
}

@test "github-oauth: non-interactive exec fails before device flow without cached token" {
	start_mock_github_oauth

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.github]
type = "github-oauth"
client_id = "Iv1.mockclientid"
scope = "repo"
keyring_cache = false
open_browser = false
auth_base = "http://127.0.0.1:$MOCK_PORT/login/oauth"
api_base = "http://127.0.0.1:$MOCK_PORT/api"
EOF

	run fnox --non-interactive exec -- printenv GITHUB_TOKEN
	assert_failure
	assert_output --partial "interactive auth required for GitHub"
	refute_output --partial "ABCD-1234"
}

@test "github-oauth: non-interactive exec reuses cached lease" {
	start_mock_github_oauth

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.github]
type = "github-oauth"
client_id = "Iv1.mockclientid"
scope = "repo"
keyring_cache = false
open_browser = false
auth_base = "http://127.0.0.1:$MOCK_PORT/login/oauth"
api_base = "http://127.0.0.1:$MOCK_PORT/api"
EOF

	run fnox lease create github
	assert_success

	kill "$MOCK_PID" 2>/dev/null || true
	wait "$MOCK_PID" 2>/dev/null || true
	unset MOCK_PID

	run fnox --non-interactive exec -- printenv GITHUB_TOKEN
	assert_success
	assert_line "ghu_mock_user_token_abc123"
}

@test "github-oauth: custom env_var" {
	start_mock_github_oauth

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.github]
type = "github-oauth"
client_id = "Iv1.mockclientid"
scope = "repo"
env_var = "GH_TOKEN"
keyring_cache = false
open_browser = false
auth_base = "http://127.0.0.1:$MOCK_PORT/login/oauth"
api_base = "http://127.0.0.1:$MOCK_PORT/api"
EOF

	run fnox exec -- printenv GH_TOKEN
	assert_success
	assert_line "ghu_mock_user_token_abc123"
}
