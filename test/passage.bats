#!/usr/bin/env bats
#
# Passage Provider Tests
#
# These tests verify the passage provider integration with fnox. They use a small
# stand-in `passage` script on PATH that stores entries as plain files under
# $PASSAGE_DIR, so they need neither the real passage nor age.
#
#   Run tests: mise run test:bats -- test/passage.bats
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	unset FNOX_PASSAGE_DIR FNOX_PASSAGE_IDENTITIES_FILE PASSAGE_IDENTITIES_FILE
	export PASSAGE_DIR="$BATS_TEST_TMPDIR/passage-store"
	mkdir -p "$PASSAGE_DIR" "$BATS_TEST_TMPDIR/bin"

	cat >"$BATS_TEST_TMPDIR/bin/passage" <<'SCRIPT'
#!/usr/bin/env bash
# Minimal passage stand-in: show, insert -m -f, ls
cmd="$1"
shift
case "$cmd" in
show)
	f="$PASSAGE_DIR/$1.age"
	if [ ! -f "$f" ]; then
		echo "Error: $1 is not in the password store." >&2
		exit 1
	fi
	cat "$f"
	;;
insert)
	while [ "${1#-}" != "$1" ]; do shift; done
	mkdir -p "$(dirname "$PASSAGE_DIR/$1.age")"
	cat >"$PASSAGE_DIR/$1.age"
	;;
ls)
	echo "Password Store"
	;;
*)
	echo "unsupported: $cmd" >&2
	exit 1
	;;
esac
SCRIPT
	chmod +x "$BATS_TEST_TMPDIR/bin/passage"
	export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

teardown() {
	_common_teardown
}

create_passage_config() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.passage]
type = "passage"
prefix = "${1:-}"

[secrets]
EOF
}

@test "fnox set writes to passage and keeps only a reference in config" {
	create_passage_config "fnox/"

	run "$FNOX_BIN" set MY_SECRET "my-secret-value" --provider passage
	assert_success

	run cat "${FNOX_CONFIG_FILE}"
	assert_output --partial 'provider = "passage"'
	assert_output --partial 'value = "MY_SECRET"'
	refute_output --partial "my-secret-value"

	run cat "$PASSAGE_DIR/fnox/MY_SECRET.age"
	assert_output "my-secret-value"
}

@test "fnox get reads a secret from passage" {
	create_passage_config "fnox/"

	run "$FNOX_BIN" set TEST_GET "test-value-123" --provider passage
	assert_success

	run "$FNOX_BIN" get TEST_GET
	assert_success
	assert_output "test-value-123"
}

@test "fnox get returns a passage value exactly as stored" {
	create_passage_config "fnox/"

	run "$FNOX_BIN" set SPACED "  padded value  " --provider passage
	assert_success

	run cat "$PASSAGE_DIR/fnox/SPACED.age"
	assert_output "  padded value  "

	run "$FNOX_BIN" get SPACED
	assert_success
	assert_output "  padded value  "
}

@test "fnox get keeps a trailing newline and carriage return in a passage value" {
	create_passage_config
	printf 'tok' >"$PASSAGE_DIR/plain.age"
	printf 'tok\n' >"$PASSAGE_DIR/newline.age"
	printf 'tok\r' >"$PASSAGE_DIR/cr.age"
	cat >>"${FNOX_CONFIG_FILE}" <<EOF
PLAIN = { provider = "passage", value = "plain" }
NEWLINE = { provider = "passage", value = "newline" }
CR = { provider = "passage", value = "cr" }
EOF

	"$FNOX_BIN" get PLAIN >"$BATS_TEST_TMPDIR/plain.out"
	"$FNOX_BIN" get NEWLINE >"$BATS_TEST_TMPDIR/newline.out"
	"$FNOX_BIN" get CR >"$BATS_TEST_TMPDIR/cr.out"

	# bats `run` drops trailing newlines, so compare byte counts: each extra character
	# stored in the entry must reach the output
	plain=$(wc -c <"$BATS_TEST_TMPDIR/plain.out")
	newline=$(wc -c <"$BATS_TEST_TMPDIR/newline.out")
	cr=$(wc -c <"$BATS_TEST_TMPDIR/cr.out")
	[ "$newline" -eq $((plain + 1)) ]
	[ "$cr" -eq $((plain + 1)) ]
}

@test "fnox get selects a line of a multi-line passage entry" {
	create_passage_config
	printf 'hunter2\nalice\n' >"$PASSAGE_DIR/database.age"
	cat >>"${FNOX_CONFIG_FILE}" <<EOF
DB_PASSWORD = { provider = "passage", value = "database", line = 1 }
DB_USERNAME = { provider = "passage", value = "database", line = 2 }
EOF

	run "$FNOX_BIN" get DB_PASSWORD
	assert_success
	assert_output "hunter2"

	run "$FNOX_BIN" get DB_USERNAME
	assert_success
	assert_output "alice"
}

@test "passage store_dir overrides PASSAGE_DIR" {
	other="$BATS_TEST_TMPDIR/other-store"
	mkdir -p "$other"
	echo "from-other" >"$other/TOKEN.age"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.passage]
type = "passage"
store_dir = "$other"

[secrets]
TOKEN = { provider = "passage", value = "TOKEN" }
EOF

	run "$FNOX_BIN" get TOKEN
	assert_success
	assert_output "from-other"
}

@test "fnox get reports a missing passage entry" {
	create_passage_config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF
MISSING = { provider = "passage", value = "nope", if_missing = "error" }
EOF

	run "$FNOX_BIN" get MISSING
	assert_failure
	assert_output --partial "nope"
}

@test "a missing passage entry with if_missing ignore prints no error" {
	create_passage_config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF
MISSING = { provider = "passage", value = "nope", if_missing = "ignore" }
EOF

	run "$FNOX_BIN" get MISSING
	refute_output --partial "not in the password store"
}

@test "fnox provider test succeeds for passage" {
	create_passage_config

	run "$FNOX_BIN" provider test passage
	assert_success
}

@test "fnox reports when the passage CLI is not installed" {
	create_passage_config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF
TOKEN = { provider = "passage", value = "TOKEN", if_missing = "error" }
EOF
	rm "$BATS_TEST_TMPDIR/bin/passage"

	run env PATH="$BATS_TEST_TMPDIR/bin:/usr/bin:/bin" "$FNOX_BIN" get TOKEN
	assert_failure
	assert_output --partial "passage"
}
