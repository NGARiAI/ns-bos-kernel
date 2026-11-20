"""The sandbox's boundary is bubblewrap plus seccomp. The Python import
blocklist is a guard against accidents that code can walk round, so these
tests walk round it and check that the boundary still holds."""

import os
import platform
import shutil
from pathlib import Path

import pytest

from core.kernel.sandbox import bwrap

BYPASS = "import importlib\nsp = importlib.import_module('subprocess')\n"
ON_X86 = pytest.mark.skipif(platform.machine() != "x86_64", reason="x86_64 numbers")
HAS_BWRAP = pytest.mark.skipif(shutil.which("bwrap") is None, reason="needs bubblewrap")


@pytest.fixture(scope="module")
def sandbox():
    box = bwrap.BwrapSandbox(require_bwrap=True)
    if not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    return box


def test_the_import_blocklist_is_not_a_boundary(sandbox):
    """Documents the limit: importlib reaches a blocked module."""
    r = sandbox.execute_python(BYPASS + "print(sp.__name__)")
    assert r.stdout.strip() == "subprocess"


@HAS_BWRAP
def test_code_past_the_blocklist_still_runs_as_nobody_without_a_network(sandbox):
    r = sandbox.execute_python(
        BYPASS
        + "print(sp.run(['id', '-u'], capture_output=True, text=True).stdout.strip())\n"
        + "import socket\n"
        + "s = socket.socket()\n"
        + "s.settimeout(2)\n"
        + "try:\n    s.connect(('1.1.1.1', 53)); print('connected')\n"
        + "except OSError as e:\n    print('no network', e.errno)\n"
    )
    lines = r.stdout.split("\n")
    assert lines[0] == "65534"
    assert lines[1].startswith("no network")


@ON_X86
def test_the_restricted_profile_applies_by_default(sandbox):
    probe = (
        "import importlib\nc = importlib.import_module('ctypes')\n"
        "l = c.CDLL(None, use_errno=True)\n"
        "l.syscall(101, 0xFFFF, 0, 0, 0)\nprint(c.get_errno())\n"
    )
    assert sandbox.execute_python(probe).stdout.strip() == "1"  # ptrace: EPERM
    assert sandbox.execute_python(probe, seccomp_level="").stdout.strip() != "1"


def test_a_working_filter_adds_nothing_to_stderr(sandbox):
    r = sandbox.execute_python("print('hi')")
    assert (r.exit_code, r.stdout.strip(), r.stderr) == (0, "hi", "")


def test_the_default_is_the_documented_profile():
    assert bwrap.DEFAULT_SECCOMP_LEVEL == "restricted"


@pytest.mark.parametrize("level", ["Strict", "STRICT", " strict", "strict\n", "none"])
def test_a_profile_name_the_sandbox_does_not_know_is_refused(level):
    # An unknown name is an error; it never means running with no filter.
    with pytest.raises(ValueError, match="is not one of"):
        bwrap.BwrapSandbox(require_bwrap=False).execute_python(
            "print(1)", seccomp_level=level
        )


@pytest.mark.parametrize("level", [None, "", "restricted", "strict"])
def test_the_known_profile_names_run(level, monkeypatch):
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    result = bwrap.BwrapSandbox(require_bwrap=False).execute_python(
        "print(1)", seccomp_level=level
    )
    assert result.stdout.strip() == "1", result.to_dict()


UNDECODABLE = (
    "import sys\nprint('kept')\nsys.stdout.flush()\nsys.stdout.buffer.write(b'\\xff')\n"
)


def test_output_that_is_not_utf8_keeps_the_result(sandbox):
    # A byte that is not UTF-8 is replaced: the rest of the output and the
    # exit code are kept.
    result = sandbox.execute_python(UNDECODABLE)
    assert (result.error, result.exit_code) == ("", 0), result.to_dict()
    assert result.stdout == "kept\n\ufffd"


def test_the_fallback_keeps_output_that_is_not_utf8(monkeypatch):
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    result = bwrap.BwrapSandbox(require_bwrap=False).execute_python(UNDECODABLE)
    assert (result.error, result.exit_code, result.stdout) == ("", 0, "kept\n\ufffd")


# -- the caller's terminal and input ---------------------------------------------------

TOUCH_THE_TERMINAL = """
import os, importlib
termios = importlib.import_module("termios")
for path in ("/dev/tty", None):
    try:
        fd = os.open(path, os.O_RDWR) if path else 0
        if not os.isatty(fd):
            continue
        os.write(fd, b"AGENT-WROTE-" + b"TO-TTY\\r\\n")
        mode = termios.tcgetattr(fd)
        mode[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, mode)
    except OSError:
        pass
"""


@pytest.mark.parametrize("path", ["bubblewrap", "fallback"])
def test_agent_code_cannot_reach_the_callers_terminal(path):
    import os
    import pty
    import select
    import time

    if path == "bubblewrap" and not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    pid, master = pty.fork()  # the child's controlling terminal is this pty
    if pid == 0:
        try:
            if path == "fallback":
                os.environ["NGARI_AIR_GAP"] = "0"
                bwrap._BWRAP_PATH = None
            bwrap.BwrapSandbox(require_bwrap=path == "bubblewrap").execute_python(
                TOUCH_THE_TERMINAL
            )
            import termios

            if not termios.tcgetattr(0)[3] & termios.ECHO:
                os.write(1, b"ECHO-WAS-TURNED-OFF\r\n")
        finally:
            os._exit(0)
    seen, deadline = b"", time.monotonic() + 60
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.5)[0]:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
        elif os.waitpid(pid, os.WNOHANG) != (0, 0):
            pid = 0
            break
    if pid:
        os.waitpid(pid, 0)
    os.close(master)
    assert b"AGENT-WROTE-TO-TTY" not in seen and b"ECHO-WAS-TURNED-OFF" not in seen, (
        seen
    )


@pytest.mark.parametrize("path", ["bubblewrap", "fallback"])
def test_agent_code_does_not_read_the_callers_input(path, monkeypatch):
    import os

    if path == "bubblewrap" and not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    if path == "fallback":
        monkeypatch.setenv("NGARI_AIR_GAP", "0")
        monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    box = bwrap.BwrapSandbox(require_bwrap=path == "bubblewrap")
    read_end, write_end = os.pipe()
    os.write(write_end, b"operator-typed-pin-1234\n")
    os.close(write_end)
    saved = os.dup(0)
    try:
        os.dup2(read_end, 0)
        result = box.execute_python("import sys\nprint(repr(sys.stdin.read()))")
    finally:
        os.dup2(saved, 0)
        os.close(saved)
        os.close(read_end)
    assert result.stdout.strip() == "''", result.to_dict()


# -- the fallback's import path --------------------------------------------------------


@pytest.fixture
def fallback(monkeypatch):
    """The plain-subprocess fallback, as a caller gets it with the gap off."""
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    return bwrap.BwrapSandbox(require_bwrap=False)


def test_the_fallback_imports_from_no_directory_others_can_write(fallback):
    code = (
        "import os, stat, sys\n"
        "for p in sys.path:\n"
        "    d = os.path.abspath(p or os.getcwd())\n"
        "    if os.path.isdir(d) and os.stat(d).st_mode & stat.S_IWOTH:\n"
        "        print('WORLD-WRITABLE', repr(p), d)\n"
        "print('cwd', os.getcwd())\n"
    )
    result = fallback.execute_python(code)
    assert result.exit_code == 0, result.stderr
    assert "WORLD-WRITABLE" not in result.stdout, result.stdout
    cwd = result.stdout.split("cwd ", 1)[1].strip()
    assert cwd != "/tmp" and not __import__("os").path.exists(cwd)  # removed after


def test_a_module_planted_in_the_working_directory_is_not_imported(
    fallback, monkeypatch
):
    import tempfile

    planted = tempfile.mkdtemp(prefix="ngari-planted-")
    try:
        with open(f"{planted}/ctypes.py", "w") as f:
            f.write("print('PLANTED RAN')\n")
        # Whatever directory the fallback is given, its own files are not on
        # the path the bootstrap imports ctypes from.
        monkeypatch.setattr(bwrap.tempfile, "mkdtemp", lambda prefix: planted)
        result = fallback.execute_python("print('agent')")
        assert "PLANTED RAN" not in result.stdout, result.to_dict()
        assert result.stdout.strip() == "agent"
    finally:
        import shutil

        shutil.rmtree(planted, ignore_errors=True)


# -- output is capped as it is read ----------------------------------------------------

FLOOD = (
    "import sys\n"
    "chunk = 'A' * (1 << 20)\n"
    "for _ in range(32):\n"
    "    sys.stdout.write(chunk)\n"
    "sys.stdout.write('END')\n"
)


@pytest.mark.parametrize("path", ["bubblewrap", "fallback"])
def test_output_is_capped_while_it_is_read_not_after(path, monkeypatch):
    import tracemalloc

    if path == "bubblewrap" and not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    if path == "fallback":
        monkeypatch.setenv("NGARI_AIR_GAP", "0")
        monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    box = bwrap.BwrapSandbox(require_bwrap=path == "bubblewrap")
    tracemalloc.start()
    try:
        result = box.execute_python(FLOOD, timeout=60)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.truncated and result.exit_code == 0
    assert result.stdout == "A" * (bwrap.MAX_OUTPUT - 3) + "END"
    # 32 MiB of output: the kernel holds about the cap, not three times it.
    assert peak < 4 << 20, f"kernel peaked at {peak >> 20} MiB for 32 MiB of output"


def test_the_tail_kept_is_whole_characters(sandbox):
    # 4-byte characters and a 1-byte one at the end: the bytes kept start
    # three bytes into a character, which must not show.
    result = sandbox.execute_python("print('\\U0001F600' * 30001 + 'z', end='')")
    assert result.truncated
    assert result.stdout == "\U0001f600" * (bwrap.MAX_OUTPUT - 1) + "z"
    # More characters than the cap, but few enough bytes to keep them all.
    result = sandbox.execute_python("print('x' * 20000, end='')")
    assert (result.truncated, result.stdout) == (True, "x" * bwrap.MAX_OUTPUT)


def test_stderr_is_capped_and_short_output_is_whole(sandbox):
    result = sandbox.execute_python(
        "import sys\nprint('short')\nsys.stderr.write('E' * 50000)\n"
    )
    assert result.stdout == "short\n" and result.stderr == "E" * bwrap.MAX_OUTPUT
    assert result.truncated
    assert not sandbox.execute_python("print('x' * 9999)").truncated


def test_a_run_that_keeps_printing_still_times_out(sandbox):
    result = sandbox.execute_python(
        "import sys\nwhile True:\n    sys.stdout.write('A' * 65536)\n", timeout=2
    )
    assert (result.exit_code, result.error) == (-1, "timeout:2s")


def _running(marker: str, within: float = 2.0) -> list[str]:
    """Processes whose command line holds marker, once those killed have had
    up to `within` seconds to go: SIGKILL is delivered, not awaited."""
    import os
    import time

    deadline = time.monotonic() + within
    while True:
        found = []
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    if marker.encode() in f.read():
                        found.append(pid)
            except OSError:
                continue
        if not found or time.monotonic() > deadline:
            return found
        time.sleep(0.1)


@pytest.mark.parametrize("path", ["bubblewrap", "fallback"])
def test_a_timed_out_run_is_not_left_running(path, monkeypatch):
    if path == "bubblewrap" and not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    if path == "fallback":
        monkeypatch.setenv("NGARI_AIR_GAP", "0")
        monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    marker = f"ngari-left-{__import__('uuid').uuid4().hex}"  # in no other command line
    result = bwrap.BwrapSandbox(require_bwrap=path == "bubblewrap").execute_python(
        f"import time  # {marker}\ntime.sleep(30)\n", timeout=1
    )
    assert result.error == "timeout:1s"
    assert _running(marker) == []


def test_the_fallback_timeout_kills_what_the_agent_started(fallback, tmp_path):
    import time

    # A child and a grandchild that each leave the process group, then write
    # after the timeout.
    marker = f"ngari-tree-{__import__('uuid').uuid4().hex}"
    code = (
        f"import os, time  # {marker}\n"
        "def later(name):\n"
        "    os.setsid()\n"
        "    time.sleep(2)\n"
        f"    os.close(os.open(os.path.join({str(tmp_path)!r}, name), os.O_CREAT | os.O_WRONLY, 0o600))\n"
        "    os._exit(0)\n"
        "if os.fork() == 0:\n"
        "    if os.fork() == 0:\n"
        "        later('grandchild')\n"
        "    later('child')\n"
        "time.sleep(30)\n"
    )
    result = fallback.execute_python(code, timeout=1)
    assert result.error == "timeout:1s"
    assert _running(marker) == []
    time.sleep(2.5)
    assert sorted(p.name for p in tmp_path.iterdir()) == [], (
        "kept running after the timeout"
    )


def test_a_process_name_with_a_parenthesis_does_not_hide_it(tmp_path):
    # /proc/<pid>/stat puts the name in parentheses; the fields start after
    # the last one.
    import os
    import subprocess

    link = tmp_path / "odd) name"
    link.symlink_to(shutil.which("sleep"))
    child = subprocess.Popen([str(link), "5"])
    try:
        assert child.pid in bwrap._descendants(os.getpid())
    finally:
        child.kill()
        child.wait()


# -- memory and process limits ---------------------------------------------------------

MOUNTS_AND_LIMITS = """
import os, resource
total, seen = 0, set()
for p in ("/tmp", "/home", "/mnt", "/root", "/var", "/run", "/dev", "/dev/shm"):
    s = os.statvfs(p)
    if os.stat(p).st_dev in seen or s.f_flag & os.ST_RDONLY:
        continue
    seen.add(os.stat(p).st_dev)
    total += s.f_blocks * s.f_frsize
limits = [resource.getrlimit(getattr(resource, n))[0]
          for n in ("RLIMIT_AS", "RLIMIT_FSIZE", "RLIMIT_NPROC")]
print(total, os.access("/dev", os.W_OK), *limits)
"""


def test_agent_code_cannot_fill_the_hosts_memory(sandbox):
    # Unsized, each of the seven tmpfs mounts could take half the host's memory.
    out = sandbox.execute_python(MOUNTS_AND_LIMITS).stdout.split()
    writable, dev_writable = int(out[0]), out[1]
    assert writable <= bwrap.TMPFS_SIZE + 6 * bwrap.SMALL_TMPFS_SIZE
    assert dev_writable == "False"
    assert [int(x) for x in out[2:]] == [
        bwrap.MEMORY_LIMIT, bwrap.TMPFS_SIZE, bwrap.MAX_PROCESSES
    ]  # fmt: skip


def test_the_limits_can_be_set_per_sandbox_and_hold():
    if not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    box = bwrap.BwrapSandbox(
        require_bwrap=True, memory_limit=256 << 20, tmpfs_size=1 << 20, max_processes=8
    )
    out = box.execute_python(MOUNTS_AND_LIMITS).stdout.split()
    assert int(out[0]) <= (1 << 20) + 6 * bwrap.SMALL_TMPFS_SIZE  # /tmp follows too
    assert [int(x) for x in out[2:]] == [256 << 20, 1 << 20, 8]
    result = box.execute_python(
        "try:\n"
        "    b = bytearray(512 << 20)\n"
        "    print('allocated')\n"
        "except MemoryError:\n"
        "    print('refused')\n"
        "import os\n"
        "try:\n"
        "    with os.fdopen(os.open('/tmp/big', os.O_CREAT | os.O_WRONLY), 'wb') as f:\n"
        "        f.write(b'x' * (2 << 20))\n"
        "    print('wrote')\n"
        "except OSError as e:\n"
        "    print('refused', e.errno in (27, 28))\n"  # EFBIG, ENOSPC
    )
    assert result.stdout.split("\n")[:2] == ["refused", "refused True"], (
        result.to_dict()
    )


def test_the_fallback_gets_the_same_limits(fallback):
    out = fallback.execute_python(
        "import resource\n"
        "print(*[resource.getrlimit(getattr(resource, n))[0]"
        " for n in ('RLIMIT_AS', 'RLIMIT_FSIZE', 'RLIMIT_NPROC')])\n"
    ).stdout.split()
    assert [int(x) for x in out] == [
        bwrap.MEMORY_LIMIT, bwrap.TMPFS_SIZE, bwrap.MAX_PROCESSES
    ]  # fmt: skip


def test_a_lower_hard_limit_already_in_force_is_kept():
    # Inside the sandbox a hard limit cannot be raised: asking for more than
    # is allowed would stop the run instead of bounding it.
    import subprocess
    import sys

    if not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    driver = (
        "import resource\n"
        "resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))\n"
        "from core.kernel.sandbox.bwrap import BwrapSandbox\n"
        "r = BwrapSandbox(require_bwrap=True).execute_python(\n"
        "    'import resource; print(resource.getrlimit(resource.RLIMIT_NPROC))')\n"
        "print(r.stdout.strip(), r.exit_code)\n"
    )
    run = subprocess.run([sys.executable, "-c", driver], cwd=Path(__file__).parent.parent,
                         capture_output=True, text=True, timeout=60, check=False)  # fmt: skip
    assert run.stdout.strip() == "(32, 32) 0", run.stdout + run.stderr


# -- the root bwrap makes --------------------------------------------------------------


def test_the_sandbox_root_is_read_only_and_the_sized_mounts_are_not(sandbox):
    # bwrap's root tmpfs and its /etc are unsized, so they are read-only.
    code = (
        "import os\n"
        "for d in ('/', '/etc', '/tmp', '/home', '/dev/shm'):\n"
        "    try:\n"
        "        os.close(os.open(os.path.join(d, 'probe'), os.O_CREAT | os.O_WRONLY, 0o600))\n"
        "        print(d, 'writable')\n"
        "    except OSError as e:\n"
        "        print(d, 'refused', e.errno)\n"
    )
    result = sandbox.execute_python(code)
    assert result.stdout.splitlines() == [
        "/ refused 30", "/etc refused 30", "/tmp writable", "/home writable",
        "/dev/shm writable",
    ], result.to_dict()  # fmt: skip


# -- memory outside the address space limit --------------------------------------------


def test_memory_cannot_be_held_through_a_memfd(sandbox):
    # A memfd's pages are not in the address space until mapped and not on
    # a sized tmpfs, so no limit here counts them: memfd_create is refused.
    code = (
        "import os, resource\n"
        "try:\n"
        "    os.memfd_create('m')\n"
        "except OSError as e:\n"
        "    print('memfd', e.errno)\n"
        "print('nofile', resource.getrlimit(resource.RLIMIT_NOFILE)[0])\n"
    )
    result = sandbox.execute_python(code)
    assert result.stdout.splitlines() == [
        "memfd 1", f"nofile {bwrap.MAX_OPEN_FILES}"
    ], result.to_dict()  # fmt: skip


def test_open_files_are_bounded(sandbox):
    # Each pipe holds kernel memory outside every limit above.
    code = (
        "import os\n"
        "n = 0\n"
        "try:\n"
        "    while True:\n"
        "        os.pipe()\n"
        "        n += 1\n"
        "except OSError as e:\n"
        "    print(e.errno, n < 128)\n"
    )
    result = sandbox.execute_python(code)
    assert result.stdout.strip() == "24 True", result.to_dict()


def test_a_double_fork_does_not_outlive_a_fallback_timeout(fallback, tmp_path):
    # A grandchild whose parent exits belongs to init at once, so the tree
    # read from /proc does not reach it; its session still leads back.
    import time

    code = (
        "import os, time\n"
        "if os.fork() == 0:\n"
        "    if os.fork() == 0:\n"
        "        os.setpgid(0, 0)\n"  # its own group, still the session's
        "        time.sleep(2)\n"
        f"        os.close(os.open(os.path.join({str(tmp_path)!r}, 'orphan'), os.O_CREAT | os.O_WRONLY, 0o600))\n"
        "        os._exit(0)\n"
        "    os._exit(0)\n"
        "time.sleep(30)\n"
    )  # fmt: skip
    result = fallback.execute_python(code, timeout=1)
    assert result.error == "timeout:1s"
    time.sleep(3)
    assert list(tmp_path.iterdir()) == [], "the orphan kept running after the timeout"


# -- a failure before the run ----------------------------------------------------------


def _open_fds():
    return set(os.listdir("/proc/self/fd"))


def test_a_fallback_that_cannot_make_its_directory_leaks_nothing(fallback, monkeypatch):
    def refuse(prefix=None):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(bwrap.tempfile, "mkdtemp", refuse)
    before = _open_fds()
    result = fallback.execute_python("print('x')")
    assert _open_fds() - before == set()
    assert result.exit_code == -1 and "No space left" in result.error


@pytest.mark.parametrize("path", ["fallback", "bwrap"])
def test_a_run_that_fails_before_it_starts_closes_the_status_pipe(
    path, request, monkeypatch
):
    if path == "bwrap":
        if not bwrap.probe_bwrap()["ok"]:
            pytest.skip("bubblewrap cannot run here")
        box = bwrap.BwrapSandbox(require_bwrap=True)
    else:
        box = request.getfixturevalue("fallback")

    def fail(*args, **kwargs):
        raise RuntimeError("could not build the bootstrap")

    monkeypatch.setattr(bwrap, "_wrap_python", fail)
    before = _open_fds()
    result = box.execute_python("print('x')")
    assert _open_fds() - before == set()
    assert result.exit_code == -1 and "could not build" in result.error
    assert list(Path(bwrap.tempfile.gettempdir()).glob("ngari-sandbox-*")) == []


def test_a_bubblewrap_failure_is_not_reported_as_a_refused_filter(tmp_path):
    # A missing status byte means bwrap did not start, not that the filter
    # was refused: a setup failure (here a bind whose source is gone) is
    # SANDBOX_NOT_STARTED, not seccomp_not_installed.
    if not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    box = bwrap.BwrapSandbox(
        require_bwrap=True, extra_ro_binds=[(str(tmp_path / "gone"), "/data")]
    )
    result = box.execute_python("print('x')")
    assert result.stdout == "" and result.exit_code != 0
    assert result.error == bwrap.SANDBOX_NOT_STARTED, result.to_dict()
    assert "gone" in result.stderr
    assert box.probe_seccomp() == {"ok": False, "error": bwrap.SANDBOX_NOT_STARTED}


# -- a pid reused before the timeout kill ----------------------------------------------


@pytest.mark.parametrize("pidfd", ["pidfd", "no pidfd_open", "pidfd_open fails"])
def test_a_timeout_kill_spares_a_process_that_took_a_reused_pid(monkeypatch, pidfd):
    # The kernel can run as root: a pid read from /proc that exits and is
    # given to another process before the kill must not get that one killed.
    import errno
    import subprocess

    if pidfd == "no pidfd_open":
        monkeypatch.delattr(bwrap.os, "pidfd_open", raising=False)
    elif pidfd == "pidfd_open fails":

        def unsupported(pid):
            raise OSError(errno.ENOSYS, "Function not implemented")

        monkeypatch.setattr(bwrap.os, "pidfd_open", unsupported)
    other = subprocess.Popen(["sleep", "30"])
    try:
        started = int(bwrap._stat_fields(other.pid)[19])
        bwrap._kill(other.pid, started + 1)  # the pid as the scan saw it, earlier
        with pytest.raises(subprocess.TimeoutExpired):  # still alive a second on
            other.wait(timeout=1)
        bwrap._kill(other.pid, started)
        assert other.wait(timeout=10) == -9
    finally:
        other.kill()
        other.wait()
    bwrap._kill(other.pid, started)  # reaped since: nothing to kill, no error


def test_the_scan_records_each_process_with_its_start_time():
    import os
    import subprocess

    child = subprocess.Popen(["sleep", "5"])
    try:
        found = bwrap._descendants(os.getpid())
        assert found[child.pid] == int(bwrap._stat_fields(child.pid)[19])
    finally:
        child.kill()
        child.wait()


# -- a refused pidfd signal ------------------------------------------------------------


def _alive(pid):
    try:
        state = bwrap._stat_fields(pid)[0]
    except OSError:
        return False
    return state not in (b"Z", b"X")


def test_a_refused_pidfd_signal_still_kills_the_tree(tmp_path, monkeypatch):
    import errno
    import signal
    import subprocess
    import sys
    import time

    # pidfd_open allowed and pidfd_send_signal refused (a container's seccomp
    # profile): _kill falls back to os.kill, so the tree ends with its timeout.

    def refused(fd, sig, *args):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(signal, "pidfd_send_signal", refused)
    pids = tmp_path / "pids"
    code = (
        "import os, subprocess, sys, time\n"
        "c = subprocess.Popen(['sleep', '60'])\n"
        f"open({str(pids)!r}, 'w').write(f'{{os.getpid()}} {{c.pid}}')\n"
        "time.sleep(60)\n"
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            bwrap._run_capped(
                [sys.executable, "-c", code], timeout=2, env={}, cwd=str(tmp_path),
                max_output=1000, new_session=True,
            )  # fmt: skip
        _, child = map(int, pids.read_text().split())
        time.sleep(0.5)
        assert not _alive(child), "the run's child outlived its timeout"
    finally:
        if pids.exists() and pids.read_text().strip():
            for pid in map(int, pids.read_text().split()):
                try:
                    os.kill(pid, signal.SIGKILL)  # started by this test
                except ProcessLookupError:
                    pass


def test_one_pid_that_cannot_be_killed_does_not_spare_the_rest(tmp_path, monkeypatch):
    import errno
    import signal
    import subprocess
    import sys

    real_kill, calls = bwrap._kill, []

    def refused_once(pid, started):
        calls.append(pid)
        if len(calls) == 1:
            raise PermissionError(errno.EPERM, "Operation not permitted")
        real_kill(pid, started)

    monkeypatch.setattr(bwrap, "_kill", refused_once)
    pids = tmp_path / "pids"
    code = (
        "import os, subprocess, time\n"
        "c = subprocess.Popen(['sleep', '60'])\n"
        f"open({str(pids)!r}, 'w').write(str(c.pid))\n"
        "time.sleep(60)\n"
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):  # not the PermissionError
            bwrap._run_capped(
                [sys.executable, "-c", code], timeout=2, env={}, cwd=str(tmp_path),
                max_output=1000, new_session=True,
            )  # fmt: skip
        assert len(calls) >= 2  # the second round reached it
    finally:
        if pids.exists() and pids.read_text().strip():
            try:
                os.kill(int(pids.read_text()), signal.SIGKILL)  # started by this test
            except ProcessLookupError:
                pass
