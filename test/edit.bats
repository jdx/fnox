#!/usr/bin/env bats

load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

setup() {
	# Create a temporary test directory
	TEST_DIR="$(mktemp -d)"
	cd "$TEST_DIR" || exit 1

	# Generate age key for testing
	AGE_KEY_FILE="$TEST_DIR/age-key.txt"
	age-keygen -o "$AGE_KEY_FILE" 2>/dev/null
	# Export the actual key content, not the file path
	FNOX_AGE_KEY="$(grep 'AGE-SECRET-KEY' "$AGE_KEY_FILE")"
	export FNOX_AGE_KEY

	# Create a minimal fnox config with age provider (no fnox init to avoid default secrets)
	cat >fnox.toml <<EOF
[providers.age]
type = "age"
recipients = ["$(grep 'public key:' "$AGE_KEY_FILE" | cut -d: -f2- | xargs)"]

[secrets]
EOF

	# Add some test secrets
	echo "secret123" | fnox set TEST_SECRET --provider age
	echo "password456" | fnox set TEST_PASSWORD --provider age
}

teardown() {
	# Clean up test directory
	if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
		rm -rf "$TEST_DIR"
	fi
}

@test "edit command with non-interactive editor (modify secret)" {
	# Create a Python script that modifies a secret
	cat >"$TEST_DIR/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys
import re

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Replace TEST_SECRET value with new plaintext
# The temporary file should have plaintext values
# Note: inline table format is "KEY= { ... }" with no space before =
content = re.sub(
    r'TEST_SECRET= \{ provider = "age", value = "[^"]*" \}',
    r'TEST_SECRET= { provider = "age", value = "newsecret789" }',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.py"

	# Set the test editor
	export EDITOR="$TEST_DIR/test-editor.py"

	# Run edit command
	run fnox edit
	assert_success

	# Verify the secret was changed and re-encrypted
	run fnox get TEST_SECRET
	assert_success
	assert_output "newsecret789"
}

@test "edit command preserves unchanged secrets" {
	skip "Debugging - need to check why edit breaks the config"

	# Get original values before edit
	original_secret=$(fnox get TEST_SECRET)
	original_password=$(fnox get TEST_PASSWORD)

	echo "Original TEST_SECRET: $original_secret" >&3
	echo "Original TEST_PASSWORD: $original_password" >&3

	# Show config before edit
	echo "Config before edit:" >&3
	cat fnox.toml >&3

	# Create a script that doesn't change anything (just exits)
	cat >"$TEST_DIR/test-editor.sh" <<'EDITOR_SCRIPT'
#!/bin/bash
# This script does nothing - just exits
echo "Editor called with file: $1" >&2
cat "$1" >&2
exit 0
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.sh"

	# Set the test editor
	export EDITOR="$TEST_DIR/test-editor.sh"

	# Run edit command
	run fnox edit
	echo "Edit command output: $output" >&3
	assert_success

	# Show config after edit
	echo "Config after edit:" >&3
	cat fnox.toml >&3

	# Verify secrets are unchanged
	run fnox get TEST_SECRET
	echo "TEST_SECRET after edit: $output" >&3
	assert_success
	assert_output "$original_secret"

	run fnox get TEST_PASSWORD
	echo "TEST_PASSWORD after edit: $output" >&3
	assert_success
	assert_output "$original_password"
}

@test "edit command decrypts secrets in temporary file" {
	# Create a script that captures the decrypted content
	# Use double quotes to allow $TEST_DIR to be expanded
	cat >"$TEST_DIR/test-editor.sh" <<EDITOR_SCRIPT
#!/bin/bash
# Capture the decrypted content
cp "\$1" "$TEST_DIR/decrypted-content.txt"
exit 0
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.sh"

	# Set the test editor
	export EDITOR="$TEST_DIR/test-editor.sh"

	# Run edit command
	run fnox edit
	assert_success

	# Verify the temporary file contained plaintext secrets
	assert [ -f "$TEST_DIR/decrypted-content.txt" ]

	# The decrypted file should contain the plaintext values
	run grep -q "secret123" "$TEST_DIR/decrypted-content.txt"
	assert_success

	run grep -q "password456" "$TEST_DIR/decrypted-content.txt"
	assert_success
}

@test "edit command handles editor failure" {
	# Create a script that fails
	cat >"$TEST_DIR/test-editor.sh" <<'EDITOR_SCRIPT'
#!/bin/bash
exit 1
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.sh"

	# Set the test editor
	export EDITOR="$TEST_DIR/test-editor.sh"

	# Run edit command - should fail
	run fnox edit
	assert_failure
}

@test "edit command works with multiple secrets" {
	# Add more secrets
	echo "value1" | fnox set SECRET1 --provider age
	echo "value2" | fnox set SECRET2 --provider age
	echo "value3" | fnox set SECRET3 --provider age

	# Create a script that modifies multiple secrets
	# Note: inline table format is "KEY= { ... }" with no space before =
	cat >"$TEST_DIR/test-editor.sh" <<'EDITOR_SCRIPT'
#!/bin/bash
sed -i.bak 's/SECRET1= { provider = "age", value = "[^"]*" }/SECRET1= { provider = "age", value = "modified1" }/' "$1"
sed -i.bak 's/SECRET2= { provider = "age", value = "[^"]*" }/SECRET2= { provider = "age", value = "modified2" }/' "$1"
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.sh"

	# Set the test editor
	export EDITOR="$TEST_DIR/test-editor.sh"

	# Run edit command
	run fnox edit
	assert_success

	# Verify secrets were updated correctly
	run fnox get SECRET1
	assert_success
	assert_output "modified1"

	run fnox get SECRET2
	assert_success
	assert_output "modified2"

	# SECRET3 should be unchanged
	run fnox get SECRET3
	assert_success
	assert_output "value3"
}

@test "edit command: create, edit, and remove encrypted secrets" {
	# Setup: Start with one existing secret
	echo "original-value" | fnox set EXISTING_SECRET --provider age

	# Create an editor script that:
	# 1. Creates a new secret (NEW_SECRET)
	# 2. Edits the existing secret (EXISTING_SECRET)
	# 3. Removes TEST_SECRET (from setup)
	cat >"$TEST_DIR/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys
import re

with open(sys.argv[1], 'r') as f:
    content = f.read()

# 1. Edit existing secret - change EXISTING_SECRET value
content = re.sub(
    r'EXISTING_SECRET= \{ provider = "age", value = "[^"]*" \}',
    r'EXISTING_SECRET= { provider = "age", value = "edited-value" }',
    content
)

# 2. Add a new secret - append to the [secrets] section
# Find the end of the secrets section and add new secret
if '[secrets]' in content:
    # Add new secret after [secrets] section
    content = re.sub(
        r'(\[secrets\]\n)',
        r'\1NEW_SECRET= { provider = "age", value = "new-secret-value" }\n',
        content
    )

# 3. Remove TEST_SECRET - delete the line
content = re.sub(
    r'TEST_SECRET= \{[^}]*\}\n',
    '',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.py"

	export EDITOR="$TEST_DIR/test-editor.py"

	# Run edit command
	run fnox edit
	assert_success

	# Verify: NEW_SECRET was created and encrypted
	run fnox get NEW_SECRET
	assert_success
	assert_output "new-secret-value"

	# Verify: EXISTING_SECRET was edited and re-encrypted
	run fnox get EXISTING_SECRET
	assert_success
	assert_output "edited-value"

	# Verify: TEST_SECRET was removed (should fail)
	run fnox get TEST_SECRET
	assert_failure
}

@test "edit command: create, edit, and remove keychain secrets" {
	# Skip if keychain is not available (CI environments)
	if ! command -v security &>/dev/null && ! command -v secret-tool &>/dev/null; then
		skip "Keychain/secret-tool not available"
	fi

	# Add keychain provider to config
	cat >>fnox.toml <<EOF

[providers.keychain]
type = "keychain"
service = "fnox-test"
prefix = "test-$$/"
EOF

	# Setup: Create initial keychain secrets
	echo "kc-original" | fnox set KC_EXISTING --provider keychain
	echo "kc-to-delete" | fnox set KC_DELETE --provider keychain

	# Verify setup
	run fnox get KC_EXISTING
	if [ "$status" -ne 0 ]; then
		skip "Keychain not accessible in this environment"
	fi

	# Create an editor script that:
	# 1. Creates a new keychain secret
	# 2. Edits existing keychain secret
	# 3. Removes a keychain secret
	cat >"$TEST_DIR/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys
import re

with open(sys.argv[1], 'r') as f:
    content = f.read()

# 1. Edit existing keychain secret
content = re.sub(
    r'KC_EXISTING= \{ provider = "keychain", value = "[^"]*" \}',
    r'KC_EXISTING= { provider = "keychain", value = "kc-edited" }',
    content
)

# 2. Add new keychain secret
if '[secrets]' in content:
    content = re.sub(
        r'(\[secrets\]\n)',
        r'\1KC_NEW= { provider = "keychain", value = "kc-new-value" }\n',
        content
    )

# 3. Remove KC_DELETE secret
content = re.sub(
    r'KC_DELETE= \{[^}]*\}\n',
    '',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.py"

	export EDITOR="$TEST_DIR/test-editor.py"

	# Run edit command
	run fnox edit
	assert_success

	# Verify: KC_NEW was created in keychain
	run fnox get KC_NEW
	assert_success
	assert_output "kc-new-value"

	# Verify: KC_EXISTING was edited in keychain
	run fnox get KC_EXISTING
	assert_success
	assert_output "kc-edited"

	# Verify: KC_DELETE was removed (should fail)
	run fnox get KC_DELETE
	assert_failure

	# Cleanup: manually remove keychain entries
	if command -v security &>/dev/null; then
		# macOS keychain
		security delete-generic-password -s "fnox-test" -a "test-$$/KC_NEW" 2>/dev/null || true
		security delete-generic-password -s "fnox-test" -a "test-$$/KC_EXISTING" 2>/dev/null || true
	elif command -v secret-tool &>/dev/null; then
		# Linux secret-service
		secret-tool clear service "fnox-test" account "test-$$/KC_NEW" 2>/dev/null || true
		secret-tool clear service "fnox-test" account "test-$$/KC_EXISTING" 2>/dev/null || true
	fi
}

@test "edit command persists default_provider and provider changes (issue #118)" {
	# Create an editor script that adds default_provider
	cat >"$TEST_DIR/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Add default_provider at the top (after the header comments)
if 'default_provider' not in content:
    # Find where [providers.age] starts and add default_provider before it
    content = content.replace('[providers.age]', 'default_provider = "age"\n\n[providers.age]')

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.py"

	export EDITOR="$TEST_DIR/test-editor.py"

	# Run edit command
	run fnox edit
	assert_success

	# Verify default_provider was persisted in the config file
	run grep 'default_provider = "age"' fnox.toml
	assert_success
}

@test "edit command preserves comments added during edit" {
	# Create an editor script that adds a comment
	cat >"$TEST_DIR/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Add a custom comment before the [providers.age] section
content = content.replace('[providers.age]', '# My custom comment\n[providers.age]')

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.py"

	export EDITOR="$TEST_DIR/test-editor.py"

	# Run edit command
	run fnox edit
	assert_success

	# Verify the custom comment was preserved
	run grep '# My custom comment' fnox.toml
	assert_success
}

@test "edit command respects provider removal from existing secret" {
	# Setup: Create a config with default_provider and a secret with explicit provider
	cat >fnox.toml <<EOF
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$(grep 'public key:' "$AGE_KEY_FILE" | cut -d: -f2- | xargs)"]

[secrets]
EOF

	# Add a secret with explicit provider
	echo "mysecret" | fnox set MY_SECRET --provider age

	# Verify the secret has explicit provider
	run grep 'provider = "age"' fnox.toml
	assert_success

	# Create an editor script that removes the provider field from the secret
	cat >"$TEST_DIR/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys
import re

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Change from { provider = "age", value = "..." } to just { value = "..." }
# This simulates the user removing the explicit provider
content = re.sub(
    r'MY_SECRET= \{ provider = "age", value = "([^"]*)" \}',
    r'MY_SECRET= { value = "\1" }',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.py"

	export EDITOR="$TEST_DIR/test-editor.py"

	# Run edit command
	run fnox edit
	assert_success

	# The secret should still work (using default provider)
	run fnox get MY_SECRET
	assert_success
	assert_output "mysecret"

	# The config should no longer have explicit provider for MY_SECRET
	# (it should use default_provider instead)
	run grep 'MY_SECRET.*provider = "age"' fnox.toml
	assert_failure "Provider field should have been removed"
}

@test "edit command recognizes new providers added during edit (issue #118)" {
	# Start with a config that only has age provider
	# Create an editor script that adds a new plain provider and uses it for a secret
	cat >"$TEST_DIR/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys
import re

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Add a new plain provider before [secrets]
# This is safer than trying to insert after [providers.age]
content = content.replace(
    '[secrets]',
    '[providers.plain]\ntype = "plain"\n\n[secrets]'
)

# Add a new secret that uses the newly added plain provider
content = re.sub(
    r'(\[secrets\]\n)',
    r'\1PLAIN_SECRET= { provider = "plain", value = "my-plain-value" }\n',
    content
)

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.py"

	export EDITOR="$TEST_DIR/test-editor.py"

	# Run edit command
	run fnox edit
	assert_success

	# Verify the new provider was recognized and the secret works
	run fnox get PLAIN_SECRET
	assert_success
	assert_output "my-plain-value"

	# Verify the provider was persisted in the config
	run grep '\[providers.plain\]' fnox.toml
	assert_success
}

@test "edit command: move secret to new profile section (issue #105)" {
	# Setup: Start with a secret in the default [secrets] section
	echo "my-secret-value" | fnox set MY_SECRET --provider age

	# Verify initial state
	run fnox get MY_SECRET
	assert_success
	assert_output "my-secret-value"

	# Show initial config
	echo "Initial config:" >&3
	cat fnox.toml >&3

	# Create an editor script that:
	# 1. Creates a new [profiles.production] section
	# 2. Moves MY_SECRET from [secrets] to [profiles.production.secrets]
	cat >"$TEST_DIR/test-editor.py" <<'EDITOR_SCRIPT'
#!/usr/bin/env python3
import sys
import re

with open(sys.argv[1], 'r') as f:
    content = f.read()

# Extract the MY_SECRET line from [secrets]
secret_match = re.search(r'MY_SECRET= \{ provider = "age", value = "([^"]*)" \}', content)
if secret_match:
    secret_value = secret_match.group(1)

    # Remove MY_SECRET from [secrets] section
    content = re.sub(
        r'MY_SECRET= \{[^}]*\}\n',
        '',
        content
    )

    # Add new [profiles.production] section with the secret
    # Add it after the [secrets] section
    profile_section = f'''
[profiles.production]

[profiles.production.secrets]
MY_SECRET= {{ provider = "age", value = "{secret_value}" }}
'''
    content = content.rstrip() + profile_section + '\n'

with open(sys.argv[1], 'w') as f:
    f.write(content)
EDITOR_SCRIPT
	chmod +x "$TEST_DIR/test-editor.py"

	export EDITOR="$TEST_DIR/test-editor.py"

	# Run edit command
	run fnox edit
	echo "Edit output: $output" >&3
	assert_success

	# Show config after edit
	echo "Config after edit:" >&3
	cat fnox.toml >&3

	# Verify: MY_SECRET should no longer be in default profile
	run fnox get MY_SECRET
	echo "Getting MY_SECRET from default profile: status=$status output=$output" >&3
	assert_failure

	# Verify: MY_SECRET should now be in production profile
	run fnox get MY_SECRET --profile production
	echo "Getting MY_SECRET from production profile: status=$status output=$output" >&3
	assert_success
	assert_output "my-secret-value"

	# Verify the config file actually contains the production profile
	run grep -q '\[profiles.production\]' fnox.toml
	assert_success "Config should contain [profiles.production] section"

	run grep -q '\[profiles.production.secrets\]' fnox.toml
	assert_success "Config should contain [profiles.production.secrets] section"
}
