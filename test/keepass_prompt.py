"""Exercise KeePass prompting through a real terminal during fnox exec."""

import os
import pty
import select
import signal
import sys
import time


read_end, write_end = os.pipe()
pid, terminal = pty.fork()
if pid == 0:
    os.close(write_end)
    os.dup2(read_end, 0)
    os.close(read_end)
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
            if prompt in output and not sent_password:
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

assert sent_password, output.decode(errors="replace")
assert output.count(prompt) == 1, output.decode(errors="replace")
assert b"fnox-test-password" not in output, "password was echoed"
assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors="replace")
