#!/usr/bin/env bats

# Create isolated mock providers and configuration for hook recovery tests.
setup() {
	load 'test_helper/common_setup'
	_common_setup
	export FNOX_DAEMON=off FNOX_PROMPT_AUTH=false
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR"
	unset OP_SERVICE_ACCOUNT_TOKEN FNOX_OP_SERVICE_ACCOUNT_TOKEN PROXMOX_URL
	mkdir -p bin
	export PATH="$PWD/bin:$PATH"
	cat >bin/pass <<'MOCK'
#!/bin/sh
printf 'test-token\n'
MOCK
	cat >bin/op <<'MOCK'
#!/bin/sh
printf 'called\n' >> op-calls
[ "$OP_SERVICE_ACCOUNT_TOKEN" = test-token ] || exit 2
[ -f provider-ready ] || exit 1
printf 'mock-url\n'
MOCK
	chmod +x bin/pass bin/op
	cat >fnox.toml <<'CONFIG'
root = true
[providers.pass]
type = "password-store"
[providers.op]
type = "1password"
vault = "test"
[secrets]
OP_SERVICE_ACCOUNT_TOKEN = { provider = "pass", value = "token" }
PROXMOX_URL = { provider = "op", value = "proxmox/url" }
CONFIG
}

# Stop the test daemon before removing its temporary directory.
teardown() {
	"$FNOX_BIN" daemon stop >/dev/null 2>&1 || true
	_common_teardown
}

@test "hook retries a partial load and resumes early exit after recovery" {
	eval "$("$FNOX_BIN" hook-env -s bash)"
	[ "$OP_SERVICE_ACCOUNT_TOKEN" = test-token ]
	[ -z "${PROXMOX_URL:-}" ]
	[ -n "$__FNOX_SESSION" ]

	# Provider readiness changes without touching config or FNOX_* variables.
	touch provider-ready
	eval "$("$FNOX_BIN" hook-env -s bash)"
	[ "$PROXMOX_URL" = mock-url ]
	local calls
	calls=$(wc -l <op-calls)
	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output ""
	[ "$(wc -l <op-calls)" = "$calls" ]
}

@test "hook retries after a fail-fast resolution error" {
	cat >>fnox.toml <<'CONFIG'
[secrets.PROXMOX_URL]
provider = "op"
value = "proxmox/url"
if_missing = "error"
CONFIG
	# Replace the inline entry to avoid defining the same key twice.
	sed -i.bak '/^PROXMOX_URL = /d' fnox.toml
	eval "$("$FNOX_BIN" hook-env -s bash)"
	[ -z "${PROXMOX_URL:-}" ]
	[ -n "$__FNOX_SESSION" ]
	touch provider-ready
	eval "$("$FNOX_BIN" hook-env -s bash)"
	[ "$PROXMOX_URL" = mock-url ]
}

@test "hook does not retry an unresolved secret excluded from the shell" {
	sed -i.bak 's/value = "proxmox\/url" }/value = "proxmox\/url", env = false }/' fnox.toml
	eval "$("$FNOX_BIN" hook-env -s bash)"
	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output ""
}

# Exercise recovery and a subsequent reload against the same daemon cache.
daemon_retry() {
	# Keep credential-dependent cache fingerprints identical across attempts.
	export OP_SERVICE_ACCOUNT_TOKEN=test-token
	export FNOX_DAEMON=auto
	cat >>fnox.toml <<'CONFIG'
[daemon]
enabled = true
CONFIG
	eval "$("$FNOX_BIN" hook-env -s bash)"
	[ -z "${PROXMOX_URL:-}" ]
	run "$FNOX_BIN" daemon status
	assert_success
	assert_output --partial "cached_entries: 1"
	touch provider-ready
	eval "$("$FNOX_BIN" hook-env -s bash)"
	[ "$PROXMOX_URL" = mock-url ]
	run "$FNOX_BIN" daemon status
	assert_success
	assert_output --partial "cached_entries: 2"

	# Force a later reload with the same daemon cache key. The recovered
	# value must remain available even if the provider goes offline again.
	rm provider-ready
	unset __FNOX_SESSION
	eval "$("$FNOX_BIN" hook-env -s bash)"
	[ "$PROXMOX_URL" = mock-url ]
}

@test "hook retry fills the daemon cache and survives a later reload" {
	daemon_retry
}

@test "non-interactive hook retry fills the daemon cache and survives a later reload" {
	export FNOX_NON_INTERACTIVE=true
	daemon_retry
}
