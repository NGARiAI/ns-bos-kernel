"""One `python -m core.kernel` per data directory. A second one stops with
exit status 2 and names the first; the lock goes with the process that
held it, however that process ends."""

import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import core.kernel as kernel_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
STARTED = f"{kernel_mod.KERNEL_FULL_NAME} v{kernel_mod.VERSION} started"


class Kernel:
    """A kernel process on data_dir, started and waited for."""

    def __init__(self, data_dir):
        env = {**os.environ, "NGARI_DATA_DIR": str(data_dir), "PYTHONUNBUFFERED": "1"}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "core.kernel"], cwd=REPO_ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )  # fmt: skip
        self.lines = queue.Queue()
        threading.Thread(
            target=lambda: [self.lines.put(ln) for ln in self.proc.stdout], daemon=True
        ).start()
        deadline = time.monotonic() + 60
        seen = []
        while True:
            try:
                line = self.lines.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                self.proc.kill()
                pytest.fail("kernel did not start:\n" + "".join(seen))
            seen.append(line)
            if line.rstrip().endswith(STARTED):
                return

    def stop(self, sig=signal.SIGTERM):
        self.proc.send_signal(sig)
        return self.proc.wait(timeout=60)


def _second(data_dir):
    env = {**os.environ, "NGARI_DATA_DIR": str(data_dir)}
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel"], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    return run.returncode, run.stdout + run.stderr


def test_a_second_kernel_on_the_same_data_is_refused(tmp_path):
    first = Kernel(tmp_path)
    try:
        code, output = _second(tmp_path)
        assert code == 2, output
        assert (
            f"Cannot start: another kernel is running on {tmp_path} "
            f"(pid {first.proc.pid}); stop it first" in output
        )
        assert "Traceback" not in output
        assert (tmp_path / "kernel.lock").stat().st_mode & 0o777 == 0o600
    finally:
        assert first.stop() == 0
    # Once the first one is stopped, a new one starts.
    again = Kernel(tmp_path)
    assert again.stop() == 0


def test_a_killed_kernel_leaves_no_stale_lock(tmp_path):
    first = Kernel(tmp_path)
    first.stop(signal.SIGKILL)
    assert (tmp_path / "kernel.lock").read_text().strip() == str(first.proc.pid)
    again = Kernel(tmp_path)
    assert again.stop() == 0


def test_key_commands_still_run_beside_a_kernel(tmp_path):
    first = Kernel(tmp_path)
    try:
        run = subprocess.run(
            [sys.executable, "-m", "core.kernel", "keys", "status"], cwd=REPO_ROOT,
            env={**os.environ, "NGARI_DATA_DIR": str(tmp_path)},
            capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
        assert run.returncode == 0, run.stderr
    finally:
        first.stop()


def test_the_lock_is_exclusive_and_its_holder_readable(tmp_path):
    held = kernel_mod._hold_instance_lock(tmp_path)
    try:
        assert held is not None
        assert kernel_mod._hold_instance_lock(tmp_path) is None
        assert kernel_mod._lock_holder(tmp_path) == str(os.getpid())
    finally:
        held.close()
    reopened = kernel_mod._hold_instance_lock(tmp_path)
    assert reopened is not None
    reopened.close()


@pytest.mark.parametrize("content", ["", "not a pid\n", "12ab\n"])
def test_an_unreadable_holder_is_not_named(tmp_path, content):
    (tmp_path / "kernel.lock").write_text(content)
    assert kernel_mod._lock_holder(tmp_path) is None
    assert kernel_mod._lock_holder(tmp_path / "missing") is None
