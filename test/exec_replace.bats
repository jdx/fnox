#!/usr/bin/env bats
#
# Exec Replacement Tests
#
# These tests verify the process lifecycle and compatibility constraints of
# `fnox exec --replace`. PID files and side-effect markers make behavior
# observable after fnox replaces itself and can no longer perform cleanup.

# Bound background-process regressions so one test cannot consume the CI job.
export BATS_TEST_TIMEOUT=30

setup() {
	load 'test_helper/common_setup'
	_common_setup
	DAEMON_STARTED=""
	REPLACEMENT_PID=""
	TARGET_PID=""
	WAIT_STATUS=""
	unset BLOCK_RESOLUTION COMMAND_MARKER PID_FILE RESOLUTION_MARKER SIGNAL_MARKER
}

# Install a fake Bitwarden CLI so tests can observe exactly when provider
# resolution starts. BLOCK_RESOLUTION keeps the resolver active for signal tests.
create_fake_bw() {
	cat >"$TEST_TEMP_DIR/bw" <<'SCRIPT'
#!/usr/bin/env bash
set -eu

touch "$RESOLUTION_MARKER"
if [ -n "${BLOCK_RESOLUTION:-}" ]; then
	# Exit when fnox exits so the fake provider does not remain orphaned.
	parent=$PPID
	while kill -0 "$parent" 2>/dev/null; do
		sleep 0.05
	done
	exit 0
fi
echo "resolved-value"
SCRIPT
	chmod +x "$TEST_TEMP_DIR/bw"
	export PATH="$TEST_TEMP_DIR:$PATH"
	export BW_SESSION="test-session"
}

# A completed child remains visible as a zombie until its parent calls wait.
wait_for_process_exit() {
	local pid="$1"
	local state
	for _ in $(seq 1 50); do
		state=$(ps -p "$pid" -o stat= 2>/dev/null || true)
		if [ -z "$state" ] || [[ "$state" == *Z* ]]; then
			WAIT_STATUS=0
			wait "$pid" 2>/dev/null || WAIT_STATUS=$?
			return 0
		fi
		sleep 0.1
	done
	return 1
}

# `kill -0` also succeeds for zombies, so inspect process state after each signal.
assert_process_survives_signal() {
	local pid="$1"
	local signal="$2"
	local state

	kill -"$signal" "$pid"
	for _ in $(seq 1 5); do
		sleep 0.1
		state=$(ps -p "$pid" -o stat= 2>/dev/null || true)
		if [ -z "$state" ] || [[ "$state" == *Z* ]]; then
			return 1
		fi
	done
}

teardown() {
	# Stop resources that may survive if an assertion fails before normal cleanup.
	if [ -n "$DAEMON_STARTED" ]; then
		"$FNOX_BIN" daemon stop >/dev/null 2>&1 || true
	fi
	# TARGET_PID differs from REPLACEMENT_PID only if process replacement regresses.
	if [ -n "$TARGET_PID" ] && [ "$TARGET_PID" != "$REPLACEMENT_PID" ]; then
		kill -KILL "$TARGET_PID" 2>/dev/null || true
	fi
	if [ -n "$REPLACEMENT_PID" ]; then
		kill -KILL "$REPLACEMENT_PID" 2>/dev/null || true
		wait "$REPLACEMENT_PID" 2>/dev/null || true
	fi
	_common_teardown
}

@test "exec --replace preserves pid, injects secrets, omits ambient age identities, and returns target status" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets.INJECTED_SECRET]
provider = "plain"
value = "injected-value"
TOML

	cat >check-replacement.sh <<'SCRIPT'
#!/usr/bin/env bash
set -eu

test "$$" = "$EXPECTED_PID"
test "$INJECTED_SECRET" = "injected-value"
test -z "${FNOX_AGE_KEY+x}"
test -z "${FNOX_AGE_KEY_FILE+x}"
echo "replacement-ok"
exit 42
SCRIPT
	chmod +x check-replacement.sh

	# These ambient values may resolve fnox secrets but must not reach the target.
	export FNOX_AGE_KEY="AGE-SECRET-KEY-TEST"
	export FNOX_AGE_KEY_FILE="$TEST_TEMP_DIR/age-key.txt"

	# Record the wrapper PID before it execs fnox; the final script must see it unchanged.
	run sh -c 'EXPECTED_PID=$$; export EXPECTED_PID; exec "$1" --no-daemon exec --replace -- "$2"' \
		_ "$FNOX_BIN" "$TEST_TEMP_DIR/check-replacement.sh"

	[ "$status" -eq 42 ]
	assert_output "replacement-ok"
}

@test "exec omits ambient age identities when spawning a child" {
	cat >fnox.toml <<'TOML'
root = true
TOML

	export FNOX_AGE_KEY="AGE-SECRET-KEY-TEST"
	export FNOX_AGE_KEY_FILE="$TEST_TEMP_DIR/age-key.txt"

	run "$FNOX_BIN" --no-daemon exec -- \
		bash -c 'test -z "${FNOX_AGE_KEY+x}" && test -z "${FNOX_AGE_KEY_FILE+x}"'
	assert_success
}

@test "exec --replace delivers signals directly to the replacement process" {
	cat >fnox.toml <<'TOML'
root = true
TOML

	cat >wait-for-term.sh <<'SCRIPT'
#!/usr/bin/env bash
set -eu

trap 'echo terminated >"$SIGNAL_MARKER"; exit 0' TERM
echo "$$" >"$PID_FILE"
while :; do
	sleep 1
done
SCRIPT
	chmod +x wait-for-term.sh

	export PID_FILE="$TEST_TEMP_DIR/replacement.pid"
	export SIGNAL_MARKER="$TEST_TEMP_DIR/terminated"

	# The target writes its PID only after installing the TERM handler.
	sh -c 'exec "$1" --no-daemon exec --replace -- "$2"' \
		_ "$FNOX_BIN" "$TEST_TEMP_DIR/wait-for-term.sh" &
	REPLACEMENT_PID=$!

	for _ in $(seq 1 50); do
		if [ -f "$PID_FILE" ]; then
			break
		fi
		sleep 0.1
	done

	assert_file_exists "$PID_FILE"
	TARGET_PID=$(cat "$PID_FILE")
	# A spawned child would have a different PID and would fail this assertion.
	[ "$TARGET_PID" -eq "$REPLACEMENT_PID" ]
	kill -TERM "$REPLACEMENT_PID"
	for _ in $(seq 1 50); do
		if [ -f "$SIGNAL_MARKER" ]; then
			break
		fi
		sleep 0.1
	done
	assert_file_exists "$SIGNAL_MARKER"
	wait_for_process_exit "$REPLACEMENT_PID"
	exit_status="$WAIT_STATUS"
	REPLACEMENT_PID=""
	TARGET_PID=""
	[ "$exit_status" -eq 0 ]
	assert_file_contains "$SIGNAL_MARKER" "terminated"
}

@test "exec --replace preserves inherited ignored termination signals" {
	cat >fnox.toml <<'TOML'
root = true
TOML

	cat >wait-with-ignored-signals.sh <<'SCRIPT'
#!/usr/bin/env bash
set -eu

echo "$$" >"$PID_FILE"
exec sleep 30
SCRIPT
	chmod +x wait-with-ignored-signals.sh
	export PID_FILE="$TEST_TEMP_DIR/replacement.pid"

	# POSIX preserves ignored dispositions across exec; fnox must not replace them.
	sh -c 'trap "" INT TERM; exec "$1" --no-daemon exec --replace -- "$2"' \
		_ "$FNOX_BIN" "$TEST_TEMP_DIR/wait-with-ignored-signals.sh" &
	REPLACEMENT_PID=$!

	for _ in $(seq 1 50); do
		if [ -f "$PID_FILE" ]; then
			break
		fi
		sleep 0.1
	done

	assert_file_exists "$PID_FILE"
	TARGET_PID=$(cat "$PID_FILE")
	[ "$TARGET_PID" -eq "$REPLACEMENT_PID" ]
	# Confirm replacement completed before checking the inherited dispositions.
	for _ in $(seq 1 50); do
		if [ "$(ps -p "$REPLACEMENT_PID" -o comm= 2>/dev/null)" = "sleep" ]; then
			break
		fi
		sleep 0.1
	done
	[ "$(ps -p "$REPLACEMENT_PID" -o comm= 2>/dev/null)" = "sleep" ]
	assert_process_survives_signal "$REPLACEMENT_PID" INT
	assert_process_survives_signal "$REPLACEMENT_PID" TERM
	kill -KILL "$REPLACEMENT_PID"
	wait "$REPLACEMENT_PID" || true
	REPLACEMENT_PID=""
	TARGET_PID=""
}

@test "exec allows explicit secrets to restore scrubbed variables" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets.FNOX_AGE_KEY]
provider = "plain"
value = "selected-value"

[secrets.FNOX_AGE_KEY_FILE]
provider = "plain"
value = "selected-file"
TOML

	export FNOX_AGE_KEY="ambient-value"
	export FNOX_AGE_KEY_FILE="ambient-file"

	# Selected secrets are applied after ambient resolver credentials are removed.
	run "$FNOX_BIN" --no-daemon exec -- \
		bash -c 'test "$FNOX_AGE_KEY" = "selected-value" && test "$FNOX_AGE_KEY_FILE" = "selected-file"'
	assert_success

	run "$FNOX_BIN" --no-daemon exec --replace -- \
		bash -c 'test "$FNOX_AGE_KEY" = "selected-value" && test "$FNOX_AGE_KEY_FILE" = "selected-file"'
	assert_success
}

@test "exec --replace rejects file-based secrets" {
	create_fake_bw
	export RESOLUTION_MARKER="$TEST_TEMP_DIR/resolution-started"

	cat >fnox.toml <<'TOML'
root = true

[providers.bitwarden]
type = "bitwarden"

[secrets.FILE_SECRET]
provider = "bitwarden"
value = "file-secret"
as_file = true
TOML

	# The absent marker proves rejection happened before provider resolution.
	run "$FNOX_BIN" --no-daemon exec --replace -- true
	assert_failure
	assert_output --partial "--replace"
	assert_output --partial "file-based secrets"
	assert_output --partial "FILE_SECRET"
	assert_file_not_exists "$RESOLUTION_MARKER"
}

@test "exec --replace handles signals received during secret resolution" {
	create_fake_bw
	export BLOCK_RESOLUTION=1
	export COMMAND_MARKER="$TEST_TEMP_DIR/command-started"

	cat >fnox.toml <<'TOML'
root = true

[providers.bitwarden]
type = "bitwarden"

[secrets.REMOTE_SECRET]
provider = "bitwarden"
value = "remote-secret"
TOML

	# Shell wait statuses cannot distinguish `_exit(143)` from default SIGTERM
	# termination. Python exposes 143 for the installed handler and -15 for
	# default signal death, proving the pre-exec handlers are active.
	cat >signal-during-resolution.py <<'PYTHON'
import os
import signal
import subprocess
import sys
import time

fnox, marker_prefix = sys.argv[1:]


def reset_termination_signals():
    # GNU Parallel workers may inherit ignored signals from their parent shell.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


for sig in (signal.SIGINT, signal.SIGTERM):
    marker = f"{marker_prefix}-{sig.name}"
    env = os.environ.copy()
    env["RESOLUTION_MARKER"] = marker
    # Own the process group so timeout cleanup also terminates the fake provider.
    process = subprocess.Popen(
        [fnox, "--no-daemon", "exec", "--replace", "--", "bash", "-c", 'touch "$COMMAND_MARKER"'],
        env=env,
        preexec_fn=reset_termination_signals,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not os.path.exists(marker):
            if process.poll() is not None:
                raise RuntimeError(f"fnox exited before resolving secrets: {process.returncode}")
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for secret resolution")
            time.sleep(0.1)

        os.kill(process.pid, sig)
        returncode = process.wait(timeout=5)
        print(f"{sig.name}={returncode}")
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
PYTHON

	run python3 signal-during-resolution.py "$FNOX_BIN" "$TEST_TEMP_DIR/resolution-started"
	assert_success
	assert_line "SIGINT=130"
	assert_line "SIGTERM=143"
	assert_file_not_exists "$COMMAND_MARKER"
}

@test "exec --replace does not start the command when a required secret is missing" {
	cat >fnox.toml <<'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.REQUIRED_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
if_missing = "error"
TOML

	export FNOX_AGE_KEY="$TEST_TEMP_DIR/missing-age-key.txt"
	export COMMAND_MARKER="$TEST_TEMP_DIR/command-started"

	# The marker distinguishes a resolution error from accidentally starting the target.
	run "$FNOX_BIN" --no-daemon exec --replace -- \
		bash -c 'touch "$COMMAND_MARKER"'
	assert_failure
	assert_output --partial "REQUIRED_SECRET"
	assert_file_not_exists "$COMMAND_MARKER"
}

@test "exec --replace supports daemon-backed resolution" {
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR"
	DAEMON_STARTED=1

	cat >fnox.toml <<'TOML'
root = true

[daemon]
enabled = true

[providers.plain]
type = "plain"

[secrets.DAEMON_SECRET]
provider = "plain"
value = "daemon-value"
TOML

	# Omit --no-daemon so this invocation exercises daemon-backed resolution.
	run "$FNOX_BIN" exec --replace -- \
		bash -c 'test "$DAEMON_SECRET" = "daemon-value"'
	assert_success

	run "$FNOX_BIN" daemon status
	assert_success
	# A populated cache proves the daemon resolved DAEMON_SECRET.
	assert_output --partial "fnox daemon running"
	assert_output --partial "cached_entries: 1"
}

@test "exec --replace rejects leases before creating credentials" {
	cat >create-credentials.sh <<SCRIPT
#!/usr/bin/env bash
touch "$TEST_TEMP_DIR/lease-created"
echo '{"credentials":{"LEASE_TOKEN":"value"},"lease_id":"test"}'
SCRIPT
	chmod +x create-credentials.sh

	cat >fnox.toml <<TOML
root = true

[leases.test]
type = "command"
create_command = "$TEST_TEMP_DIR/create-credentials.sh"
TOML

	# The absent marker proves rejection happened before lease creation.
	run "$FNOX_BIN" --no-daemon exec --replace -- true
	assert_failure
	assert_output --partial "--replace"
	assert_output --partial "credential leases"
	assert_file_not_exists "$TEST_TEMP_DIR/lease-created"
}
