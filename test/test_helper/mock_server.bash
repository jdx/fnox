#!/usr/bin/env bash

# Minimal JSON HTTP mock server for lease backend tests.
#
# Usage:
#   start_mock_server 'def respond(method, path, body): return 200, {"ok": True}'
#   ... use "http://127.0.0.1:$MOCK_PORT" ...
#   mock_requests         # one JSON object per received request
#   stop_mock_server      # call from teardown
#
# `respond(method, path, body)` receives the path without its query string and
# returns (status, payload) or (status, payload, headers), where payload is None,
# a raw string, or JSON-serializable data. Every request
# is appended to "$TEST_TEMP_DIR/mock_requests.log" as a JSON line with
# method, path, authorization, private_token and body, so tests can assert on
# what fnox actually sent.

start_mock_server() {
	local respond_src="$1"
	printf '%s\n' "$respond_src" >"$TEST_TEMP_DIR/mock_respond.py"

	cat >"$TEST_TEMP_DIR/mock_server.py" <<'PYEOF'
import http.server, json, os

LOG = os.environ["MOCK_LOG"]
PORT_FILE = os.environ["MOCK_PORT_FILE"]
exec(open(os.environ["MOCK_RESPOND"]).read())

class Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        with open(LOG, "a") as f:
            f.write(json.dumps({
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization", ""),
                "private_token": self.headers.get("PRIVATE-TOKEN", ""),
                "body": body,
            }) + "\n")
        result = respond(self.command, self.path.split("?")[0], body)
        status, payload = result[0], result[1]
        extra_headers = result[2] if len(result) > 2 else {}
        if payload is None:
            data = b""
        elif isinstance(payload, str):
            data = payload.encode()
        else:
            data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, value in extra_headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = _handle

    def log_message(self, format, *args):
        pass

# Bind to port 0 so the OS picks a free port, then publish it for the test.
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(PORT_FILE, "w") as f:
    f.write(str(server.server_address[1]))
    f.flush()
    os.fsync(f.fileno())
server.serve_forever()
PYEOF

	: >"$TEST_TEMP_DIR/mock_requests.log"
	rm -f "$TEST_TEMP_DIR/mock_port"
	local mock_log="$TEST_TEMP_DIR/mock_server.log"
	MOCK_LOG="$TEST_TEMP_DIR/mock_requests.log" \
		MOCK_PORT_FILE="$TEST_TEMP_DIR/mock_port" \
		MOCK_RESPOND="$TEST_TEMP_DIR/mock_respond.py" \
		python3 -u "$TEST_TEMP_DIR/mock_server.py" >"$mock_log" 2>&1 &
	MOCK_PID=$!

	for _ in $(seq 1 300); do
		if [[ -s "$TEST_TEMP_DIR/mock_port" ]]; then
			MOCK_PORT=$(cat "$TEST_TEMP_DIR/mock_port")
			export MOCK_PORT
			return 0
		fi
		local mock_state
		mock_state=$(ps -p "$MOCK_PID" -o stat= 2>/dev/null || true)
		if [[ -z $mock_state || $mock_state == *Z* ]]; then
			wait "$MOCK_PID" 2>/dev/null || true
			echo "mock server exited before writing port" >&2
			[[ -s $mock_log ]] && cat "$mock_log" >&2
			return 1
		fi
		sleep 0.1
	done
	echo "timed out waiting for mock server to write port" >&2
	[[ -s $mock_log ]] && cat "$mock_log" >&2
	stop_mock_server
	return 1
}

stop_mock_server() {
	if [[ -n ${MOCK_PID:-} ]]; then
		kill "$MOCK_PID" 2>/dev/null || true
		wait "$MOCK_PID" 2>/dev/null || true
		unset MOCK_PID
	fi
}

mock_requests() {
	cat "$TEST_TEMP_DIR/mock_requests.log"
}

# Print the lease ID of the first ledger entry.
first_lease_id() {
	grep 'lease_id' "$HOME"/.local/state/fnox/leases/*.toml | head -1 | sed 's/.*= *"//;s/".*//'
}
