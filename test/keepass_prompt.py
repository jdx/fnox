"""Exercise KeePass prompting through a real terminal."""

import os
import pty
import select
import signal
import sys
import termios
import time


mode = sys.argv[2] if len(sys.argv) > 2 else "exec"
hook_mode = mode == "hook-env"
if not hook_mode:
    read_end, write_end = os.pipe()
pid, terminal = pty.fork()
if pid == 0:
    if hook_mode:
        os.execv(sys.argv[1], [sys.argv[1], "--no-daemon", "hook-env", "-s", "bash"])
    os.close(write_end)
    os.dup2(read_end, 0)
    os.close(read_end)
    if mode == "exec-redirected":
        error_output = os.open(os.devnull, os.O_WRONLY)
        os.dup2(error_output, 2)
        os.close(error_output)
    os.execv(
        sys.argv[1],
        [
            sys.argv[1],
            "--no-daemon",
            "exec",
            "--",
            "sh",
            "-c",
            'read -r input && test "$input" = piped-value && '
            'test "$FIRST" = first-value && test "$SECOND" = second-value',
        ],
    )

if not hook_mode:
    os.close(read_end)
    os.write(write_end, b"piped-value\n")
    os.close(write_end)
output = b""
deadline = time.monotonic() + 30
prompt = b"KeePass password for "
sent_password = False
done = 0
status = 0
try:
    while time.monotonic() < deadline:
        ready, _, _ = select.select([terminal], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(terminal, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
        if (
            prompt in output
            and not sent_password
            and not hook_mode
            and not (termios.tcgetattr(terminal)[3] & termios.ECHO)
        ):
            os.write(terminal, b"fnox-test-password\n")
            sent_password = True
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
    else:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise AssertionError("fnox exec timed out")
    if not done:
        _, status = os.waitpid(pid, 0)
finally:
    os.close(terminal)

if hook_mode:
    assert prompt not in output, output.decode(errors="replace")
else:
    assert sent_password, output.decode(errors="replace")
    assert output.count(prompt) == 1, output.decode(errors="replace")
    assert b"fnox-test-password" not in output, "password was echoed"
assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors="replace")
