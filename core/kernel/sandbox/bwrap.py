"""
Bubblewrap sandbox: Linux namespace isolation for agent code execution.

Uses bubblewrap (bwrap) to create a sandboxed process with:
- User namespace (UID/GID mapping, runs as nobody)
- Mount namespace (read-only system paths, tmpfs for /tmp)
- Network namespace (no network access)
- PID namespace (process isolation)
- UTS namespace (hidden hostname)
- IPC namespace (no shared memory/semaphores)
- Seccomp-bpf syscall filtering (configurable levels)

Architecture:
    BwrapSandbox
    ├── execute_python(code, timeout, seccomp_level) -> Result
    └── get_capabilities() -> dict

Seccomp levels:
    None / ""    No seccomp filter
    "restricted" Blocks dangerous syscalls (ptrace, bpf, module loading, etc.)
    "strict"     Also blocks networking and process creation

Dependencies: bubblewrap (bwrap) >= 0.4.0; the tmpfs mounts are sized from
0.7.0, which added --size, and unsized before it (tmpfs_sized in
get_capabilities()).
"""

import io
import logging
import os
import platform
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tokenize
from typing import Any

logger = logging.getLogger(__name__)

_BWRAP_PATH = shutil.which("bwrap")
# Set to 1 to refuse agent code when bubblewrap is missing, rather than run it
# in a plain subprocess with no namespace isolation.
REQUIRE_BWRAP_ENV = "NGARI_SANDBOX_REQUIRE_BWRAP"

AIR_GAP_ENV = "NGARI_AIR_GAP"
_AIR_GAP_OFF = frozenset({"0", "false", "no", "off"})
_AIR_GAP_ON = frozenset({"", "1", "true", "yes", "on"})


def air_gap_enabled(environ=None) -> bool:
    """On unless NGARI_AIR_GAP is 0, false, no or off (case and whitespace
    ignored). Any other value keeps it on and logs one warning naming the
    accepted values."""
    env = os.environ if environ is None else environ
    raw = (env.get(AIR_GAP_ENV) or "").strip().lower()
    if raw in _AIR_GAP_OFF:
        return False
    if raw not in _AIR_GAP_ON:
        logger.warning(
            "%s=%r is not a known value; air gap stays on (0, false, no or off turn it off)",
            AIR_GAP_ENV,
            raw[:32],
        )
    return True


DEFAULT_TIMEOUT = 30
# Seccomp profile for agent code unless the caller names one; "" runs without
# a filter. The import blocklist is a guard against accidents, not a
# boundary: Python offers too many ways round it (importlib, for one).
DEFAULT_SECCOMP_LEVEL = "restricted"
# The levels there are; any other name is refused rather than run unfiltered.
SECCOMP_LEVELS = ("", "restricted", "strict")
MAX_OUTPUT = 10000
# What one run may take. The memory limit is per process:
# without a cgroup, several processes together are not bounded.
MEMORY_LIMIT = 1 << 30  # RLIMIT_AS, bytes of address space
TMPFS_SIZE = 64 << 20  # /tmp, and the largest file written (RLIMIT_FSIZE)
SMALL_TMPFS_SIZE = 1 << 20  # /home, /mnt, /root, /var, /run, /dev/shm
MAX_PROCESSES = 64  # RLIMIT_NPROC; Linux does not apply it to root's processes
MAX_OPEN_FILES = 256  # RLIMIT_NOFILE; pipes hold kernel memory too

BLOCKED_MODULES = {
    "subprocess",
    "multiprocessing",
    "ctypes",
    "fcntl",
    "pickle",
    "shelve",
    "crypt",
    "cffi",
}

BLOCKED_KEYWORDS = [
    "eval(",
    "exec(",
    "open(",
    "compile(",
    "__import__",
    "__builtins__",
]


class SandboxResult:
    __slots__ = (
        "elapsed_seconds",
        "error",
        "exit_code",
        "stderr",
        "stdout",
        "truncated",
    )

    def __init__(
        self,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        elapsed_seconds: float = 0.0,
        truncated: bool = False,
        error: str = "",
    ):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.elapsed_seconds = elapsed_seconds
        self.truncated = truncated
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "truncated": self.truncated,
            "error": self.error,
        }


def _has_bwrap() -> bool:
    return _BWRAP_PATH is not None


PROBE_TIMEOUT = 10


def probe_bwrap(extra_ro_binds: list | None = None) -> dict:
    """Run `true` under the same bwrap arguments agent code gets. Isolation
    is reported from this result, never from configuration alone: bwrap can
    be installed and still fail, for example when unprivileged user
    namespaces are blocked."""
    if not _has_bwrap():
        return {"ok": False, "error": "bwrap not found"}
    try:
        result = subprocess.run(
            [*_build_bwrap_args(extra_ro_binds=extra_ro_binds), "true"],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT,
            env={"PATH": "/usr/bin:/bin"},
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {PROBE_TIMEOUT}s"}
    except OSError as exc:
        return {"ok": False, "error": exc.strerror or str(exc)}
    if result.returncode != 0:
        lines = [ln.strip() for ln in result.stderr.splitlines() if ln.strip()]
        detail = lines[-1][:200] if lines else "no error output"
        return {"ok": False, "error": f"exit {result.returncode}: {detail}"}
    return {"ok": True, "error": ""}


# Builtins agent code may not use, and the name each is renamed to.
_RENAMED = {
    "eval": "_sanitized_eval_",
    "exec": "_sanitized_exec_",
    "open": "_sanitized_open_",
    "compile": "_sanitized_compile_",
    "__import__": "_sanitized___import__",
    "__builtins__": "_sanitized___builtins__",
}


def _sanitize_code(code: str) -> str:
    """Rename the blocked builtins where they are names in the code. Strings
    and comments are left alone, and so is attribute access such as
    re.compile or gzip.open. Code that does not tokenize is returned as is,
    so Python reports the error itself."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
    except (tokenize.TokenError, SyntaxError):
        return code
    edits = []
    previous = None
    for tok in tokens:
        if (
            tok.type == tokenize.NAME
            and tok.string in _RENAMED
            and not (previous is not None and previous.string == ".")
        ):
            edits.append((tok.start, tok.end, _RENAMED[tok.string]))
        if tok.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT):
            previous = tok
    lines = code.splitlines(keepends=True)
    for (row, col), (_, end), name in reversed(edits):
        line = lines[row - 1]
        lines[row - 1] = line[:col] + name + line[end:]
    return "".join(lines)


def _descendants(pid: int) -> dict[int, int]:
    """pid's children, theirs and so on, and every process in the session
    pid leads, read from /proc, each with its start time. A child that left
    the session with setsid is still found through its parent, and one
    whose parent exited (it then belongs to init) through its session."""
    children: dict[int, list[int]] = {}
    started: dict[int, int] = {}
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            fields = _stat_fields(int(entry))
            parent, session = int(fields[1]), int(fields[3])
            started[int(entry)] = int(fields[19])
        except (OSError, IndexError, ValueError):
            continue  # gone meanwhile
        children.setdefault(parent, []).append(int(entry))
        if session == pid and int(entry) != pid:
            found.append(int(entry))
    todo = list(children.get(pid, []))
    while todo:
        child = todo.pop()
        found.append(child)
        todo.extend(children.get(child, []))
    return {child: started[child] for child in found}


def _stat_fields(pid: int) -> list[bytes]:
    """The fields of /proc/<pid>/stat after the name, which is in
    parentheses and may hold any character: [0] is the state, [1] the
    parent, [3] the session and [19] the start time, in clock ticks."""
    with open(f"/proc/{pid}/stat", "rb") as f:
        return f.read().rsplit(b")", 1)[1].split()


def _kill(pid: int, started: int) -> None:
    """SIGKILL pid if it is still the process that started at started. The
    kernel can run as root, and a pid read from /proc may since have exited
    and been given to another process. A pidfd holds the process itself, so
    the start time is checked once it is open and the signal goes to that
    process; without pidfd_open, os.kill follows the same check."""
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    except (OSError, AttributeError):  # Linux before 5.3, or no os.pidfd_open
        fd = None
    try:
        if int(_stat_fields(pid)[19]) != started:
            return  # another process has this pid now
        if fd is not None:
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
                return
            except ProcessLookupError:
                return
            except OSError:
                pass  # refused (a seccomp profile can allow pidfd_open alone)
        # While the pidfd is open its pid is not given to another process.
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, FileNotFoundError, IndexError, ValueError):
        pass  # gone meanwhile
    finally:
        if fd is not None:
            os.close(fd)


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the process and everything it started. Twice, for a child that
    forked while the tree was read. proc itself is not reaped until it is
    waited for, so its pid cannot be reused before then."""
    for _ in range(2):
        for pid, started in _descendants(proc.pid).items():
            try:
                _kill(pid, started)
            except OSError as exc:  # one refusal must not spare the rest
                logger.error("Cannot kill pid %d of a timed-out run: %s", pid, exc)
        try:
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            logger.error("Cannot kill a timed-out run (pid %d): %s", proc.pid, exc)


def _run_capped(cmd: list, *, timeout: float, env: dict, cwd: str, max_output: int,
                new_session: bool = False, pass_fds=()) -> tuple[int, str, str, bool]:  # fmt: skip
    """Run cmd and read its output while it runs, keeping only the last
    max_output characters of each stream, so a run that prints gigabytes
    costs the kernel no more memory than that. (returncode, stdout, stderr,
    truncated); after the timeout the process is killed and
    subprocess.TimeoutExpired raised. Output is decoded with replacement
    characters: agent output need not be UTF-8."""
    keep = 4 * max_output  # bytes: a UTF-8 character is at most four
    proc = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=cwd, start_new_session=new_session, pass_fds=pass_fds,
    )  # fmt: skip
    streams = (proc.stdout.fileno(), proc.stderr.fileno())
    tails = {fd: bytearray() for fd in streams}
    dropped = dict.fromkeys(streams, False)
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in (proc.stdout, proc.stderr):
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired(cmd, timeout)
                for key, _ in selector.select(left):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    tail = tails[key.fd]
                    tail += chunk
                    if len(tail) > keep:
                        del tail[: len(tail) - keep]
                        dropped[key.fd] = True
        returncode = proc.wait(timeout=max(deadline - time.monotonic(), 0))
    except BaseException:
        # bubblewrap's PID namespace ends with it; the fallback has none, so
        # its whole tree is killed (new_session is only asked for there).
        _kill_tree(proc) if new_session else proc.kill()
        proc.wait()
        raise
    finally:
        proc.stdout.close()
        proc.stderr.close()
    texts = []
    for fd in streams:
        text = tails[fd].decode("utf-8", "replace")
        dropped[fd] = dropped[fd] or len(text) > max_output
        texts.append(text[-max_output:] if len(text) > max_output else text)
    return returncode, texts[0], texts[1], any(dropped.values())


def _build_bwrap_args(
    uid: int = 65534,
    gid: int = 65534,
    hostname: str = "sandbox",
    extra_ro_binds: list | None = None,
    extra_tmpfs: list | None = None,
    tmpfs_size: int = TMPFS_SIZE,
) -> list:
    """The bwrap argument list. Every writable mount is a sized tmpfs, so
    agent code cannot fill the machine's memory with files: /tmp holds
    tmpfs_size, the rest a little; /dev is read-only but for a small /dev/shm."""
    small = str(SMALL_TMPFS_SIZE)
    args = [
        _BWRAP_PATH,
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--uid",
        str(uid),
        "--gid",
        str(gid),
        "--hostname",
        hostname,
        "--die-with-parent",
        # No controlling terminal: agent code cannot write to the caller's
        # terminal, change its modes or push keystrokes into it (TIOCSTI).
        "--new-session",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--remount-ro",
        "/dev",
        "--size",
        small,
        "--tmpfs",
        "/dev/shm",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        # x86_64 keeps the ELF interpreter (ld-linux-x86-64.so.2) in /lib64;
        # bind-try so aarch64 targets (no /lib64) are unaffected.
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind",
        "/bin",
        "/bin",
        "--ro-bind",
        "/sbin",
        "/sbin",
        # Two files from /etc, not the tree: the interpreter runs without
        # any of it, ld.so.cache speeds library lookup and localtime gives
        # local time instead of UTC. /opt is not bound: it can hold the
        # kernel itself and other software's data.
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--ro-bind-try",
        "/etc/localtime",
        "/etc/localtime",
        "--size",
        str(tmpfs_size),
        "--tmpfs",
        "/tmp",  # nosec B108 - namespace-internal tmpfs, not host /tmp
    ]
    for path in ("/home", "/mnt", "/root", "/var", "/run"):
        args.extend(["--size", small, "--tmpfs", path])
    if extra_ro_binds:
        for src, dst in extra_ro_binds:
            args.extend(["--ro-bind", src, dst])
    if extra_tmpfs:
        for path in extra_tmpfs:
            args.extend(["--size", str(tmpfs_size), "--tmpfs", path])
    # Last: bwrap's own root is a tmpfs as large as half the host's memory,
    # holding the /etc it made for the two files above, and writable by uid
    # nobody. It is remounted read-only; the sized mounts on it stay writable.
    args.extend(["--remount-ro", "/"])
    if not _sizes_tmpfs(_BWRAP_PATH):
        args = _without_sizes(args)
    return args


def _without_sizes(args: list) -> list:
    """args without each "--size N" pair."""
    kept, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg == "--size":
            skip = True
        else:
            kept.append(arg)
    return kept


_SIZES_TMPFS: dict[str, bool] = {}


def _sizes_tmpfs(bwrap: str | None) -> bool:
    """Whether this bwrap takes --size, read once from its --help. 0.7.0
    added it; an older bwrap refuses every run that passes it, so the
    mounts go unsized there, with a warning. If --help cannot be read the
    sizes stay, and a bwrap without them fails loudly, not unsized."""
    if bwrap is None:
        return True
    if bwrap not in _SIZES_TMPFS:
        try:
            out = subprocess.run(
                [bwrap, "--help"], capture_output=True, text=True,
                timeout=PROBE_TIMEOUT, env={"PATH": "/usr/bin:/bin"}, check=False,
            )  # fmt: skip
            sized = out.returncode != 0 or "--size" in out.stdout + out.stderr
        except (OSError, subprocess.TimeoutExpired):
            sized = True
        if not sized:
            logger.warning(
                "%s does not take --size (bubblewrap 0.7.0 or later does): the "
                "sandbox's /tmp, /dev/shm and other tmpfs mounts are unsized, and "
                "a run can fill them up to the host's memory; RLIMIT_FSIZE still "
                "caps each file",
                bwrap,
            )
        _SIZES_TMPFS[bwrap] = sized
    return _SIZES_TMPFS[bwrap]


def _refusal(status_fd: int | None) -> str:
    """Bootstrap code defining _refused(), which reports a refused filter
    through status_fd before the run stops."""
    if status_fd is None:
        return "def _refused():\n    pass\n"
    return (
        "def _refused():\n"
        "    try:\n"
        f"        _os.write({status_fd}, b'0')\n"
        "    except OSError:\n"
        "        pass\n"
    )


def _wrap_python(
    code: str,
    blocked: set,
    seccomp_level: str = "",
    status_fd: int | None = None,
    limits: dict[str, int] | None = None,
) -> str:
    """The program the sandbox runs: the seccomp bootstrap, the import guard,
    then code. With status_fd, the bootstrap writes one byte to it once the
    filter is in place and closes it before any agent code runs, so the
    caller can tell a refused filter from agent code that prints the same
    words and exits 1."""
    from .seccomp import (
        PR_SET_NO_NEW_PRIVS,
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER,
        current_arch,
        filter_program,
        level_rules,
    )

    _NR_LIST = _resolve_seccomp_nrs(seccomp_level)
    here = current_arch()
    seccomp_bootstrap = ""
    if _NR_LIST and here is not None:
        # The same program apply_seccomp() installs: ABI check, x32 refusal on
        # x86_64, then the blocklist.
        program = filter_program(
            _NR_LIST, here[1], **level_rules(seccomp_level, here[2])
        )
        # Fail closed: if the filter asked for is not in place, the agent code
        # after this block never runs.
        seccomp_bootstrap = f"""
import ctypes, os as _os
_seccomp_error = None
{_refusal(status_fd)}
try:
    _libc = ctypes.CDLL(None, use_errno=True)
    _libc.prctl({PR_SET_NO_NEW_PRIVS}, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS

    _SF = type('SF', (ctypes.Structure,), {{
        '_fields_': [('c', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                     ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    }})
    _FP = type('FP', (ctypes.Structure,), {{
        '_fields_': [('len', ctypes.c_ushort), ('f', ctypes.POINTER(_SF))]
    }})

    _prog = {program!r}
    _a = (_SF * len(_prog))()
    for _i, (_c, _jt, _jf, _k) in enumerate(_prog):
        _a[_i].c, _a[_i].jt, _a[_i].jf, _a[_i].k = _c, _jt, _jf, _k
    _p = _FP(len(_prog), _a)
    if _libc.prctl({PR_SET_SECCOMP}, {SECCOMP_MODE_FILTER}, ctypes.byref(_p), 0, 0) != 0:
        _seccomp_error = _os.strerror(ctypes.get_errno())
except Exception as _e:
    _seccomp_error = f'{{type(_e).__name__}}: {{_e}}'
if _seccomp_error is not None:
    _refused()
    raise SystemExit(
        f'seccomp: the filter was not installed ({{_seccomp_error}}); the code was not run'
    )
"""
        if status_fd is not None:
            seccomp_bootstrap += (
                f"_os.write({status_fd}, b'1')\n_os.close({status_fd})\n"
            )

    if limits:
        # Before anything else; a hard limit already lower is kept.
        seccomp_bootstrap = (
            "import resource as _resource\n"
            f"for _name, _value in {sorted(limits.items())!r}:\n"
            "    _hard = _resource.getrlimit(getattr(_resource, _name))[1]\n"
            "    if _hard != _resource.RLIM_INFINITY:\n"
            "        _value = min(_value, _hard)\n"
            "    _resource.setrlimit(getattr(_resource, _name), (_value, _value))\n"
        ) + seccomp_bootstrap

    noops = """
def _sanitized_blocked_(*a, **kw):
    raise PermissionError("eval, exec, open, compile and __import__ are not available in the sandbox")
_sanitized_eval_ = _sanitized_exec_ = _sanitized_open_ = _sanitized_blocked_
_sanitized_compile_ = _sanitized___import__ = _sanitized_blocked_
_sanitized___builtins__ = None
"""
    return f"""{seccomp_bootstrap}
import builtins as __b
_old_import = __b.__import__
_blocked = {sorted(blocked)!r}
def _restricted_import(name, *args, **kw):
    base = name.split('.')[0]
    if base in _blocked:
        raise ImportError(f"Module '{{name}}' is blocked")
    return _old_import(name, *args, **kw)
__b.__import__ = _restricted_import
{noops}
{code}
"""


def _resolve_seccomp_nrs(level: str) -> list:
    from .seccomp import (
        DANGEROUS_SYSCALLS,
        NETWORK_SYSCALLS,
        PROCESS_SYSCALLS,
        SYSCALL_NUMBERS,
    )

    if level == "restricted":
        blocked_names = DANGEROUS_SYSCALLS
    elif level == "strict":
        blocked_names = DANGEROUS_SYSCALLS + NETWORK_SYSCALLS + PROCESS_SYSCALLS
    else:
        return []

    nrs = []
    for name in blocked_names:
        if name in SYSCALL_NUMBERS:
            nrs.append(SYSCALL_NUMBERS[name])
    return sorted(set(nrs))


# The error a result carries when a filter was asked for and not installed.
SECCOMP_NOT_INSTALLED = "seccomp_not_installed"
# The error when the run never reached the bootstrap that installs it:
# bubblewrap or Python could not start.
SANDBOX_NOT_STARTED = "sandbox_not_started"


def _filter_pipe(seccomp_level: str) -> tuple[int, int] | None:
    """A pipe for the bootstrap to report through, when a filter will be built."""
    from .seccomp import current_arch

    if not _resolve_seccomp_nrs(seccomp_level) or current_arch() is None:
        return None
    return os.pipe()


def _filter_error(pipe: tuple[int, int] | None) -> str:
    """The result's error from what the bootstrap reported: "" when the
    filter is in place or none was asked for, SECCOMP_NOT_INSTALLED when it
    said the filter was refused, SANDBOX_NOT_STARTED when it never reported.
    Read once the run is over, with the write end closed here."""
    if pipe is None:
        return ""
    read_end, write_end = pipe
    os.close(write_end)
    try:
        status = os.read(read_end, 1)
    finally:
        os.close(read_end)
    if status == b"1":
        return ""
    return SECCOMP_NOT_INSTALLED if status == b"0" else SANDBOX_NOT_STARTED


class BwrapSandbox:
    """Linux namespace sandbox using bubblewrap for agent code execution."""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        max_output: int = MAX_OUTPUT,
        require_bwrap: bool | None = None,
        extra_ro_binds: list[tuple[str, str]] | None = None,
        memory_limit: int = MEMORY_LIMIT,
        tmpfs_size: int = TMPFS_SIZE,
        max_processes: int = MAX_PROCESSES,
    ):
        """extra_ro_binds: (host path, sandbox path) pairs bound read-only,
        for agent code that needs a host directory such as a dataset. nobody
        in the sandbox is the kernel's own user outside, so agent code reads
        any file there the kernel's user can, whatever its mode says.
        memory_limit (bytes of address space per process), tmpfs_size (bytes
        of /tmp, and of the largest file) and max_processes bound one run."""
        self.timeout = timeout
        self.max_output = max_output
        self.tmpfs_size = tmpfs_size
        self.limits = {
            "RLIMIT_AS": memory_limit,
            "RLIMIT_FSIZE": tmpfs_size,
            "RLIMIT_NPROC": max_processes,
            "RLIMIT_NOFILE": MAX_OPEN_FILES,
        }
        self.extra_ro_binds = list(extra_ro_binds or [])
        self.air_gap = air_gap_enabled()
        # The fallback runs agent code in a plain subprocess with the host's
        # network, the one kernel path with egress. Under the air gap it needs
        # an explicit require_bwrap=False.
        self.require_bwrap = (
            os.environ.get(REQUIRE_BWRAP_ENV) == "1" or self.air_gap
            if require_bwrap is None
            else require_bwrap
        )
        if not _has_bwrap():
            if self.require_bwrap:
                logger.error(
                    "bubblewrap (bwrap) not found and %s=1 or air-gap mode is on: "
                    "agent code will not run (install bubblewrap, or set %s=0)",
                    REQUIRE_BWRAP_ENV,
                    AIR_GAP_ENV,
                )
            else:
                logger.warning(
                    "bubblewrap (bwrap) not found; agent code will run in a plain subprocess"
                )
                if self.air_gap:
                    logger.warning(
                        "air gap is on and bubblewrap is not available; agent code "
                        "runs with the host's network because require_bwrap=False "
                        "was passed"
                    )

    def _refuse(self, start: float) -> SandboxResult:
        return SandboxResult(
            stderr="bubblewrap is not available and "
            f"{REQUIRE_BWRAP_ENV}=1 or air-gap mode is on; the code was not run",
            exit_code=-1,
            elapsed_seconds=time.monotonic() - start,
            error="sandbox_unavailable",
        )

    def execute_python(
        self, code: str, timeout: int | None = None, seccomp_level: str | None = None
    ) -> SandboxResult:
        start = time.monotonic()
        if seccomp_level is None:
            seccomp_level = DEFAULT_SECCOMP_LEVEL
        if seccomp_level not in SECCOMP_LEVELS:
            # "Strict" or " strict" would otherwise run with no filter at all.
            raise ValueError(
                f"seccomp_level {seccomp_level!r} is not one of {SECCOMP_LEVELS}"
            )
        if not _has_bwrap():
            if self.require_bwrap:
                return self._refuse(start)
            return self._fallback_subprocess(
                code, timeout or self.timeout, start, seccomp_level=seccomp_level
            )

        sanitized = _sanitize_code(code)
        effective_timeout = timeout or self.timeout
        bwrap_args = _build_bwrap_args(
            extra_ro_binds=self.extra_ro_binds, tmpfs_size=self.tmpfs_size
        )

        try:
            # Made inside the try, so every way out closes it.
            pipe = _filter_pipe(seccomp_level)
            try:
                wrapped = _wrap_python(
                    sanitized, BLOCKED_MODULES, seccomp_level=seccomp_level,
                    status_fd=pipe[1] if pipe else None, limits=self.limits,
                )  # fmt: skip
                cmd = bwrap_args + ["python3", "-c", wrapped]
                code_, stdout, stderr, truncated = _run_capped(
                    cmd,
                    timeout=effective_timeout,
                    env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},  # nosec B108 - sandboxed HOME on namespace tmpfs
                    cwd="/tmp",  # nosec B108 - sandboxed process cwd on its own tmpfs
                    max_output=self.max_output,
                    pass_fds=pipe[1:] if pipe else (),
                )
            finally:
                error = _filter_error(pipe)
            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=code_,
                elapsed_seconds=time.monotonic() - start,
                truncated=truncated,
                error=error,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                stderr=f"Execution timed out after {effective_timeout}s",
                exit_code=-1,
                elapsed_seconds=effective_timeout,
                error=f"timeout:{effective_timeout}s",
            )
        except FileNotFoundError:
            if self.require_bwrap:
                return self._refuse(start)
            return self._fallback_subprocess(
                code, effective_timeout, start, seccomp_level=seccomp_level
            )
        except Exception as e:  # noqa: BLE001 - sandbox boundary: the result carries it
            elapsed = time.monotonic() - start
            return SandboxResult(
                stderr=f"Sandbox error: {e}",
                exit_code=-1,
                elapsed_seconds=elapsed,
                error=str(e),
            )

    def _fallback_subprocess(
        self, code: str, timeout: int, start: float, seccomp_level: str = ""
    ) -> SandboxResult:
        sanitized = _sanitize_code(code)
        workdir = None
        try:
            # A private working directory and -I (no current directory on
            # sys.path): from host /tmp, a ctypes.py anyone planted there
            # would run as the kernel's user before the filter is in place.
            workdir = tempfile.mkdtemp(prefix="ngari-sandbox-")
            # Made inside the try, so every way out closes it.
            pipe = _filter_pipe(seccomp_level)
            try:
                wrapped = _wrap_python(
                    sanitized, BLOCKED_MODULES, seccomp_level=seccomp_level,
                    status_fd=pipe[1] if pipe else None, limits=self.limits,
                )  # fmt: skip
                code_, stdout, stderr, truncated = _run_capped(
                    [sys.executable, "-I", "-c", wrapped],
                    timeout=timeout,
                    env={},
                    cwd=workdir,
                    max_output=self.max_output,
                    new_session=True,  # no controlling terminal
                    pass_fds=pipe[1:] if pipe else (),
                )
            finally:
                error = _filter_error(pipe)
            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=code_,
                elapsed_seconds=time.monotonic() - start,
                truncated=truncated,
                error=error,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                stderr=f"Execution timed out after {timeout}s",
                exit_code=-1,
                elapsed_seconds=timeout,
                error=f"timeout:{timeout}s",
            )
        except Exception as e:  # noqa: BLE001 - sandbox boundary: the result carries it
            elapsed = time.monotonic() - start
            return SandboxResult(
                stderr=str(e),
                exit_code=-1,
                elapsed_seconds=elapsed,
                error=str(e),
            )
        finally:
            if workdir is not None:
                shutil.rmtree(workdir, ignore_errors=True)

    _SECCOMP_PROBE = (
        "import socket\n"
        "try:\n"
        "    socket.socket().close()\n"
        "    print('open')\n"
        "except PermissionError:\n"
        "    print('blocked')\n"
    )

    def probe_seccomp(self) -> dict:
        """Run a socket() call under the strict profile, the way agent code
        runs. EPERM means a filter was installed; a filter that cannot be
        installed stops the run, and its reason is reported here."""
        from .seccomp import current_arch

        here = current_arch()
        if here is None:
            return {"ok": False, "error": f"no syscall table for {platform.machine()}"}
        result = self.execute_python(
            self._SECCOMP_PROBE, timeout=10, seccomp_level="strict"
        )
        if result.error and result.error != SECCOMP_NOT_INSTALLED:
            return {"ok": False, "error": result.error}
        if result.stdout.strip() == "blocked":
            return {"ok": True, "error": "", "arch": here[0]}
        detail = result.stdout.strip() or result.stderr.strip()[-200:] or "no output"
        return {"ok": False, "error": f"filter not in effect ({detail})"}

    def batch_execute(self, code_snippets: list, timeout: int | None = None) -> list:
        return [self.execute_python(code, timeout) for code in code_snippets]

    def get_capabilities(self) -> dict:
        from .seccomp import DANGEROUS_SYSCALLS, NETWORK_SYSCALLS, PROCESS_SYSCALLS

        probe = probe_bwrap(self.extra_ro_binds)
        works = probe["ok"]
        seccomp_probe = self.probe_seccomp()
        if works:
            kind = "bubblewrap"
        elif _has_bwrap():
            kind = "bubblewrap-not-working"
        else:
            kind = "unavailable" if self.require_bwrap else "subprocess-fallback"
        caps = {
            "sandbox": kind,
            "require_bwrap": self.require_bwrap,
            "air_gap": self.air_gap,
            "bwrap_probe": probe,
            "namespace_isolation": works,
            "network_isolation": works,
            "filesystem_isolation": works,
            "process_isolation": works,
            "user_isolation": works,
            # The writable mounts have sizes: bubblewrap 0.7.0 or later.
            "tmpfs_sized": works and _sizes_tmpfs(_BWRAP_PATH),
            "seccomp_enabled": seccomp_probe["ok"],
            "seccomp_probe": seccomp_probe,
            "seccomp_profiles": {
                "restricted": {
                    "syscalls_blocked": DANGEROUS_SYSCALLS,
                    "count": len(DANGEROUS_SYSCALLS),
                },
                "strict": {
                    "syscalls_blocked": DANGEROUS_SYSCALLS
                    + NETWORK_SYSCALLS
                    + PROCESS_SYSCALLS,
                    "count": len(
                        DANGEROUS_SYSCALLS + NETWORK_SYSCALLS + PROCESS_SYSCALLS
                    ),
                },
            },
        }
        if works:
            caps["uid"] = 65534
            caps["gid"] = 65534
        return caps


_sandboxes: dict[int, BwrapSandbox] = {}


def get_sandbox(timeout: int = DEFAULT_TIMEOUT) -> BwrapSandbox:
    """A shared sandbox with this timeout. Callers asking for the same
    timeout share one; a different timeout gets its own, so one caller's
    choice never changes another's."""
    if timeout not in _sandboxes:
        _sandboxes[timeout] = BwrapSandbox(timeout=timeout)
    return _sandboxes[timeout]
