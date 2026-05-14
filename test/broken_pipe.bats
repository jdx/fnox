#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# Regression: `fnox get` used to panic with "failed printing to stdout:
# Broken pipe (os error 32)" when its stdout was closed early — e.g.
# `fnox get FOO | head -c 0` or any pipeline where the reader exits before
# fnox writes. Rust inherits SIG_IGN for SIGPIPE from libc, so writes to a
# closed pipe return EPIPE and `println!` panics. The fix resets SIGPIPE to
# SIG_DFL in main() so fnox dies from the signal like a normal Unix tool.
@test "fnox get does not panic when stdout pipe is closed" {
	cat >fnox.toml <<'EOF'
root = true

[providers.age]
type = "age"
recipients = ["age1exampleexampleexampleexampleexampleexampleexampleexampleexampleexample"]

[secrets]
PIPE_TEST = { default = "hello" }
EOF

	# `false` exits immediately, closing the read end of the pipe before
	# fnox writes. Without the SIGPIPE reset, fnox panics on the write.
	run bash -c '"$FNOX_BIN" get PIPE_TEST | false; echo "fnox_exit=${PIPESTATUS[0]}"'

	refute_output --partial "Main thread panicked"
	refute_output --partial "failed printing to stdout"
	# Buggy behavior exited 1 via the miette panic handler. Fixed behavior
	# exits 0 (write fit in the pipe buffer before the reader closed) or
	# 141 (128 + SIGPIPE). Use refute_line so "1" doesn't substring-match
	# "141".
	refute_line "fnox_exit=1"
}
