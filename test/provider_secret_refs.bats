#!/usr/bin/env bats

# Tests for provider config secret references
# This feature allows provider configs to reference secrets using { secret = "SECRET_NAME" } syntax

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "plain token value in vault provider config works" {
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers]
plain = { type = "plain" }

[providers.vault]
type = "vault"
address = "https://vault.example.com"
token = "hvs.test-token"

[secrets]
TEST = { provider = "plain", value = "test-value" }
EOF

	run "$FNOX_BIN" get TEST
	assert_success
	assert_output "test-value"
}

@test "secret ref in vault provider config with env var fallback" {
	# Set up config with secret ref but no secret defined
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers]
plain = { type = "plain" }

[providers.vault]
type = "vault"
address = "https://vault.example.com"
token = { secret = "VAULT_TOKEN" }

[secrets]
TEST = { provider = "plain", value = "test-value" }
EOF

	# Set the env var that the secret ref should fall back to
	export VAULT_TOKEN="hvs.from-env"

	run "$FNOX_BIN" get TEST
	assert_success
	assert_output "test-value"
}

@test "secret ref in vault provider config resolved from config" {
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers]
plain = { type = "plain" }

[providers.vault]
type = "vault"
address = "https://vault.example.com"
token = { secret = "VAULT_TOKEN" }

[secrets]
# This is a secret that can bootstrap - using plain provider
VAULT_TOKEN = { provider = "plain", value = "hvs.from-config" }
TEST = { provider = "plain", value = "test-value" }
EOF

	run "$FNOX_BIN" get TEST
	assert_success
	assert_output "test-value"
}

@test "missing secret ref with no env var errors" {
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.vault]
type = "vault"
address = "https://vault.example.com"
token = { secret = "NONEXISTENT_SECRET" }

[secrets]
TEST = { provider = "vault", value = "secret/data/test" }
EOF

	# Ensure the env var is not set
	unset NONEXISTENT_SECRET 2>/dev/null || true

	run "$FNOX_BIN" get TEST
	assert_failure
	assert_output --partial "not found"
}

@test "keepass provider with plain password works" {
	skip "keepass tests require KEEPASS_PASSWORD env var"

	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.keepass]
type = "keepass"
database = "/tmp/test.kdbx"
password = "test-password"

[secrets]
TEST = { provider = "keepass", value = "test-entry" }
EOF

	# This would require a real KeePass database to test fully
	run "$FNOX_BIN" get TEST
	# Just verify the config parses without error
}

@test "keepass provider with secret ref password works" {
	skip "keepass tests require actual database"

	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers]
plain = { type = "plain" }

[providers.keepass]
type = "keepass"
database = "/tmp/test.kdbx"
password = { secret = "KEEPASS_PASSWORD" }

[secrets]
KEEPASS_PASSWORD = { provider = "plain", value = "test-password" }
TEST = { provider = "keepass", value = "test-entry" }
EOF

	# This would require a real KeePass database to test fully
	run "$FNOX_BIN" get TEST
	# Just verify the config parses without error
}

@test "fnox edit preserves secret refs in provider config" {
	# Set up config with secret ref in vault provider
	cat >"${FNOX_CONFIG_FILE}" <<EOF
root = true

[providers]
plain = { type = "plain" }

[providers.vault]
type = "vault"
address = "https://vault.example.com"
token = { secret = "VAULT_TOKEN" }

[secrets]
VAULT_TOKEN = { provider = "plain", value = "hvs.from-config" }
TEST = { provider = "plain", value = "test-value" }
EOF

	# Verify initial state
	run "$FNOX_BIN" get TEST
	assert_success
	assert_output "test-value"

	# Create an editor script that modifies the TEST secret value
	cat >"${BATS_TEST_TMPDIR}/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys
import re

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Change TEST value (flexible pattern to handle spacing variations)
content = re.sub(
    r'TEST\s*=\s*\{\s*provider\s*=\s*"plain",\s*value\s*=\s*"[^"]*"\s*\}',
    r'TEST= { provider = "plain", value = "modified-value" }',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "${BATS_TEST_TMPDIR}/test-editor.py"

	export EDITOR="${BATS_TEST_TMPDIR}/test-editor.py"

	# Run edit command
	run "$FNOX_BIN" edit
	assert_success

	# Verify the secret was modified
	run "$FNOX_BIN" get TEST
	assert_success
	assert_output "modified-value"

	# Verify the secret ref in vault provider config was preserved
	run grep 'token = { secret = "VAULT_TOKEN" }' "${FNOX_CONFIG_FILE}"
	assert_success
}

@test "fnox edit can add secret ref to provider config" {
	# Set up config with plain token in vault provider
	cat >"${FNOX_CONFIG_FILE}" <<EOF
root = true

[providers]
plain = { type = "plain" }

[providers.vault]
type = "vault"
address = "https://vault.example.com"
token = "hvs.plain-token"

[secrets]
TEST = { provider = "plain", value = "test-value" }
EOF

	# Create an editor script that converts plain token to secret ref
	cat >"${BATS_TEST_TMPDIR}/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys
import re

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Add VAULT_TOKEN secret
content = re.sub(
    r'(\[secrets\]\n)',
    r'\1VAULT_TOKEN= { provider = "plain", value = "hvs.secret-token" }\n',
    content
)

# Change vault token from plain to secret ref
content = re.sub(
    r'token = "hvs\.plain-token"',
    r'token = { secret = "VAULT_TOKEN" }',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "${BATS_TEST_TMPDIR}/test-editor.py"

	export EDITOR="${BATS_TEST_TMPDIR}/test-editor.py"

	# Run edit command
	run "$FNOX_BIN" edit
	assert_success

	# Verify the VAULT_TOKEN secret was added
	run "$FNOX_BIN" get VAULT_TOKEN
	assert_success
	assert_output "hvs.secret-token"

	# Verify the secret ref in vault provider config was persisted
	run grep 'token = { secret = "VAULT_TOKEN" }' "${FNOX_CONFIG_FILE}"
	assert_success
}
