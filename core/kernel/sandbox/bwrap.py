"""
Bubblewrap Sandbox — Linux namespace isolation for agent code execution.

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
    None / ""  — No seccomp
    "restricted" — Blocks dangerous syscalls (ptrace, bpf, module loading, etc.)
    "strict"     — Also blocks networking and process creation

Dependencies: bubblewrap (bwrap) >= 0.4.0
"""

import logging
import shutil
import subprocess
import sys
import time
from typing import Any

logger = logging.getLogger(__name__)

_BWRAP_PATH = shutil.which("bwrap")

DEFAULT_TIMEOUT = 30
MAX_OUTPUT = 10000

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


def _sanitize_code(code: str) -> str:
    for keyword in BLOCKED_KEYWORDS:
        code = code.replace(keyword, f"_sanitized_{keyword.replace('(', '_')}(")
    return code


def _build_bwrap_args(
    uid: int = 65534,
    gid: int = 65534,
    hostname: str = "sandbox",
    extra_ro_binds: list | None = None,
    extra_tmpfs: list | None = None,
) -> list:
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
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/bin",
        "/bin",
        "--ro-bind",
        "/sbin",
        "/sbin",
        "--ro-bind-try",
        "/etc",
        "/etc",
        "--ro-bind-try",
        "/opt",
        "/opt",
        "--tmpfs",
        "/tmp",  # nosec B108 — namespace-internal tmpfs, not host /tmp
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/mnt",
        "--tmpfs",
        "/root",
        "--tmpfs",
        "/var",
        "--tmpfs",
        "/run",
    ]
    if extra_ro_binds:
        for src, dst in extra_ro_binds:
            args.extend(["--ro-bind", src, dst])
    if extra_tmpfs:
        for path in extra_tmpfs:
            args.extend(["--tmpfs", path])
    return args


def _wrap_python(code: str, blocked: set, seccomp_level: str = "") -> str:
    _NR_LIST = _resolve_seccomp_nrs(seccomp_level)
    seccomp_bootstrap = ""
    if _NR_LIST:
        seccomp_bootstrap = f"""
import ctypes, logging as _log
_log.basicConfig(level=_log.WARN)
try:
    _libc = ctypes.CDLL(None, use_errno=True)
    _libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS

    _SF = type('SF', (ctypes.Structure,), {{
        '_fields_': [('c', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                     ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    }})
    _FP = type('FP', (ctypes.Structure,), {{
        '_fields_': [('len', ctypes.c_ushort), ('f', ctypes.POINTER(_SF))]
    }})

    _nrs = {_NR_LIST}
    _nf = len(_nrs) * 2 + 2
    _a = (_SF * _nf)()
    _i = 0
    _a[_i].c = 0x20; _a[_i].k = 0; _i += 1  # LD nr
    for _nr in _nrs:
        _a[_i].c = 0x15; _a[_i].jt = 0; _a[_i].jf = 1; _a[_i].k = _nr; _i += 1  # JEQ nr
        _a[_i].c = 0x06; _a[_i].k = 0x00050001; _i += 1  # RET EPERM
    _a[_i].c = 0x06; _a[_i].k = 0x7fff0000; _i += 1  # RET ALLOW
    _p = _FP(_nf, _a)
    _ok = _libc.prctl(22, 2, ctypes.byref(_p), 0, 0) == 0
    _log.warning(f'seccomp: {{"OK" if _ok else "FAIL"}} ({{len(_nrs)}} syscalls)')
except Exception as _e:
    _log.warning(f'seccomp: {{_e}}')
"""

    noops = """
_sanitized_eval_ = lambda *a, **kw: None
_sanitized_exec_ = lambda *a, **kw: None
_sanitized_open_ = lambda *a, **kw: None
_sanitized_compile_ = lambda *a, **kw: None
_sanitized___import__ = lambda *a, **kw: None
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


class BwrapSandbox:
    """Linux namespace sandbox using bubblewrap for agent code execution."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, max_output: int = MAX_OUTPUT):
        self.timeout = timeout
        self.max_output = max_output
        if not _has_bwrap():
            logger.warning(
                "bubblewrap (bwrap) not found — sandbox will fall back to subprocess"
            )

    def execute_python(
        self, code: str, timeout: int | None = None, seccomp_level: str = ""
    ) -> SandboxResult:
        start = time.time()
        if not _has_bwrap():
            return self._fallback_subprocess(
                code, timeout or self.timeout, start, seccomp_level=seccomp_level
            )

        sanitized = _sanitize_code(code)
        wrapped = _wrap_python(sanitized, BLOCKED_MODULES, seccomp_level=seccomp_level)
        effective_timeout = timeout or self.timeout

        bwrap_args = _build_bwrap_args()
        cmd = bwrap_args + ["python3", "-c", wrapped]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},  # nosec B108 — sandboxed HOME on namespace tmpfs
                cwd="/tmp",  # nosec B108 — sandboxed process cwd on its own tmpfs
                check=False,
            )
            elapsed = time.time() - start
            stdout = (
                result.stdout[-self.max_output :]
                if len(result.stdout) > self.max_output
                else result.stdout
            )
            stderr = (
                result.stderr[-self.max_output :]
                if len(result.stderr) > self.max_output
                else result.stderr
            )
            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=result.returncode,
                elapsed_seconds=elapsed,
                truncated=len(result.stdout) > self.max_output
                or len(result.stderr) > self.max_output,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                stderr=f"Execution timed out after {effective_timeout}s",
                exit_code=-1,
                elapsed_seconds=effective_timeout,
                error=f"timeout:{effective_timeout}s",
            )
        except FileNotFoundError:
            return self._fallback_subprocess(
                code, effective_timeout, start, seccomp_level=seccomp_level
            )
        except Exception as e:  # noqa: BLE001 - sandbox boundary, surface error in result
            elapsed = time.time() - start
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
        wrapped = _wrap_python(sanitized, BLOCKED_MODULES, seccomp_level=seccomp_level)
        try:
            result = subprocess.run(
                [sys.executable, "-c", wrapped],
                capture_output=True,
                text=True,
                timeout=timeout,
                env={},
                cwd="/tmp",  # nosec B108 — fallback subprocess working dir
                check=False,
            )
            elapsed = time.time() - start
            stdout = (
                result.stdout[-self.max_output :]
                if len(result.stdout) > self.max_output
                else result.stdout
            )
            stderr = (
                result.stderr[-self.max_output :]
                if len(result.stderr) > self.max_output
                else result.stderr
            )
            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=result.returncode,
                elapsed_seconds=elapsed,
                truncated=len(result.stdout) > self.max_output
                or len(result.stderr) > self.max_output,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                stderr=f"Execution timed out after {timeout}s",
                exit_code=-1,
                elapsed_seconds=timeout,
                error=f"timeout:{timeout}s",
            )
        except Exception as e:  # noqa: BLE001 - sandbox boundary, surface error in result
            elapsed = time.time() - start
            return SandboxResult(
                stderr=str(e),
                exit_code=-1,
                elapsed_seconds=elapsed,
                error=str(e),
            )

    def batch_execute(self, code_snippets: list, timeout: int | None = None) -> list:
        return [self.execute_python(code, timeout) for code in code_snippets]

    def get_capabilities(self) -> dict:
        from .seccomp import DANGEROUS_SYSCALLS, NETWORK_SYSCALLS, PROCESS_SYSCALLS

        caps = {
            "sandbox": "bubblewrap" if _has_bwrap() else "subprocess-fallback",
            "namespace_isolation": _has_bwrap(),
            "network_isolation": _has_bwrap(),
            "filesystem_isolation": _has_bwrap(),
            "process_isolation": _has_bwrap(),
            "user_isolation": _has_bwrap(),
            "seccomp_enabled": True,
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
        if _has_bwrap():
            caps["uid"] = 65534
            caps["gid"] = 65534
        return caps


_sandbox = None


def get_sandbox(timeout: int = DEFAULT_TIMEOUT) -> BwrapSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = BwrapSandbox(timeout=timeout)
    return _sandbox
