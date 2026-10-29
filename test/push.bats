#!/usr/bin/env bats
#
# fnox push tests for CLI-based targets
#
# Stub `gh`, `glab`, `vercel`, `wrangler` and `fly` executables record their
# arguments and stdin, so no accounts are required.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	STUB_DIR="$BATS_TEST_TMPDIR/stub"
	export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
	mkdir -p "$STUB_DIR"
	# STUB_FAIL makes any call whose "<program> <args>" starts with it fail
	cat >"$STUB_DIR/stub" <<'STUB'
#!/usr/bin/env bash
prog=$(basename "$0")
if [ -n "$STUB_FAIL" ] && [[ "$prog $*" == "$STUB_FAIL"* ]]; then
	echo "HTTP 403: refused $prog $*" >&2
	exit 1
fi
printf '%s %s|%s\n' "$prog" "$*" "$(cat)" >>"$STUB_LOG"
STUB
	chmod +x "$STUB_DIR/stub"
	for prog in gh glab vercel wrangler fly; do
		ln -s stub "$STUB_DIR/$prog"
	done
	export PATH="$STUB_DIR:$PATH"

	cat >fnox.toml <<'TOML'
[providers.plain]
type = "plain"

[targets.gh]
type = "github-actions"
repo = "jdx/fnox"

[targets.gh-prod]
type = "github-actions"
repo = "jdx/fnox"
environment = "production"

[secrets]
API_KEY = { provider = "plain", value = "key-123", push = ["gh", "gh-prod"] }
DB_URL = { provider = "plain", value = "postgres://db", push = ["gh-prod"] }
LOCAL_ONLY = { provider = "plain", value = "not-pushed" }
TOML
}

teardown() {
	_common_teardown
}

# Replace fnox.toml with one target and one secret pushed to it
single_target() {
	cat >fnox.toml <<TOML
[providers.plain]
type = "plain"

[targets.t]
$1

[secrets]
KEY = { provider = "plain", value = "s3cret", push = ["t"] }
TOML
}

@test "push sends each value to its targets on stdin" {
	run "$FNOX_BIN" push --force
	assert_success
	assert_output --partial "Pushed 3 of 3"

	run cat "$STUB_LOG"
	assert_line "gh secret set API_KEY --repo jdx/fnox|key-123"
	assert_line "gh secret set API_KEY --repo jdx/fnox --env production|key-123"
	assert_line "gh secret set DB_URL --repo jdx/fnox --env production|postgres://db"
	refute_output --partial "LOCAL_ONLY"
}

@test "push never puts the value in the CLI's arguments" {
	run "$FNOX_BIN" push --force API_KEY
	assert_success
	run cut -d'|' -f1 "$STUB_LOG"
	refute_output --partial "key-123"
}

@test "push filters by key and target" {
	run "$FNOX_BIN" push --force --target gh-prod DB_URL
	assert_success
	run cat "$STUB_LOG"
	assert_output "gh secret set DB_URL --repo jdx/fnox --env production|postgres://db"
}

@test "push --dry-run describes destinations without pushing" {
	run "$FNOX_BIN" push --dry-run
	assert_success
	assert_output --partial "Would push 2 secrets (3 writes)"
	assert_output --partial "GitHub Actions secret in jdx/fnox, environment production"
	assert_output --partial "GitHub Actions secret in jdx/fnox)"
	refute_output --partial "key-123"
	assert_file_not_exists "$STUB_LOG"
}

@test "push asks for confirmation and cancels on no" {
	run bash -c "echo n | '$FNOX_BIN' push"
	assert_success
	assert_output --partial "Push cancelled"
	assert_file_not_exists "$STUB_LOG"
}

@test "push fails before pushing when a secret names an unknown target" {
	cat >>fnox.toml <<'TOML'
TYPO = { provider = "plain", value = "x", push = ["gh-prdo"] }
TOML
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "secret 'TYPO' pushes to unknown target 'gh-prdo'"
	assert_output --partial "configured targets: gh, gh-prod"
	assert_file_not_exists "$STUB_LOG"
}

@test "push --dry-run rejects an invalid target config" {
	single_target 'type = "github-actions"
repo = "jdx/fnox"
org = "jdx"'
	run "$FNOX_BIN" push --dry-run
	assert_failure
	assert_output --partial "push target 't': set either org"
}

@test "push rejects a key without push targets" {
	run "$FNOX_BIN" push --force LOCAL_ONLY
	assert_failure
	assert_output --partial "secret 'LOCAL_ONLY' has no push targets"
}

@test "push reports a failed target and keeps going" {
	export STUB_FAIL="gh secret set API_KEY"
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "refused gh secret set API_KEY"
	assert_output --partial "pushed 1 of 3"
	run cat "$STUB_LOG"
	assert_output "gh secret set DB_URL --repo jdx/fnox --env production|postgres://db"
}

@test "push uses the active profile's targets" {
	cat >>fnox.toml <<'TOML'

[profiles.staging.targets.gh-prod]
type = "github-actions"
repo = "jdx/fnox"
environment = "staging"
TOML
	run "$FNOX_BIN" -P staging push --force DB_URL
	assert_success
	run cat "$STUB_LOG"
	assert_output "gh secret set DB_URL --repo jdx/fnox --env staging|postgres://db"
}

@test "push requires --force when non-interactive" {
	run "$FNOX_BIN" --non-interactive push
	assert_failure
	assert_output --partial "pass --force"
}

@test "fnox set keeps an existing secret's push targets" {
	run "$FNOX_BIN" set API_KEY new-value --provider plain
	assert_success
	run "$FNOX_BIN" push --force API_KEY --target gh
	assert_success
	run cat "$STUB_LOG"
	assert_output "gh secret set API_KEY --repo jdx/fnox|new-value"
}

@test "gitlab-ci creates a variable with glab variable set" {
	single_target 'type = "gitlab-ci"
repo = "acme/api"
environment = "production"
masked = true'
	run "$FNOX_BIN" push --force
	assert_success
	run cat "$STUB_LOG"
	assert_output "glab variable set KEY --repo acme/api --scope production --masked=true|s3cret"
}

@test "gitlab-ci falls back to glab variable update for an existing variable" {
	single_target 'type = "gitlab-ci"
repo = "acme/api"'
	export STUB_FAIL="glab variable set"
	run "$FNOX_BIN" push --force
	assert_success
	run cat "$STUB_LOG"
	assert_output "glab variable update KEY --repo acme/api|s3cret"
}

@test "gitlab-ci reports both errors when set and update fail" {
	single_target 'type = "gitlab-ci"'
	export STUB_FAIL="glab variable"
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "glab variable set failed"
	assert_output --partial "glab variable update failed"
}

@test "vercel adds the variable to each environment with --force" {
	single_target 'type = "vercel"
environments = ["production", "preview"]
sensitive = true'
	run "$FNOX_BIN" push --force
	assert_success
	run cat "$STUB_LOG"
	assert_line "vercel env add KEY production --force --yes --sensitive|s3cret"
	assert_line "vercel env add KEY preview --force --yes --sensitive|s3cret"
}

@test "vercel tries every environment when one fails" {
	single_target 'type = "vercel"
environments = ["production", "preview"]'
	export STUB_FAIL="vercel env add KEY production"
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "vercel env add failed for production"
	run cat "$STUB_LOG"
	assert_output "vercel env add KEY preview --force --yes|s3cret"
}

@test "push resolves the secrets a pushed value depends on" {
	cat >fnox.toml <<'TOML'
[providers.plain]
type = "plain"

[targets.t]
type = "cloudflare-workers"

[secrets]
DB_HOST = { provider = "plain", value = "db.internal" }
DATABASE_URL = { default = "postgres://${DB_HOST}/app", push = ["t"] }
TOML
	run "$FNOX_BIN" push --force
	assert_success
	run cat "$STUB_LOG"
	assert_output "wrangler secret put DATABASE_URL|postgres://db.internal/app"
}

@test "cloudflare-workers puts the secret with wrangler" {
	single_target 'type = "cloudflare-workers"
worker = "api"
environment = "staging"'
	run "$FNOX_BIN" push --force
	assert_success
	run cat "$STUB_LOG"
	assert_output "wrangler secret put KEY --name api --env staging|s3cret"
}

@test "fly imports the secret as a triple-quoted line" {
	single_target 'type = "fly"
app = "api"
stage = true'
	run "$FNOX_BIN" push --force
	assert_success
	run cat "$STUB_LOG"
	assert_output 'fly secrets import --app api --stage|KEY="""s3cret"""'
}

@test "fly refuses a value its import parser would change" {
	cat >fnox.toml <<'TOML'
[providers.plain]
type = "plain"

[targets.t]
type = "fly"

[secrets]
KEY = { provider = "plain", value = 'a"b#c', push = ["t"] }
TOML
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "cannot push KEY to Fly.io"
	assert_file_not_exists "$STUB_LOG"
}

@test "a missing CLI is reported with an install hint" {
	rm "$STUB_DIR/wrangler"
	export PATH="$STUB_DIR:/usr/bin:/bin"
	single_target 'type = "cloudflare-workers"'
	run "$FNOX_BIN" push --force
	assert_failure
	assert_output --partial "CLI tool 'wrangler' not found"
}
