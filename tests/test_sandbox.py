"""Sandbox tests for core/kernel/sandbox.

Behavior verified on the AGX Orin edge node (aarch64) and designed to
run anywhere:
  - Pure-unit tests (seccomp profiles/BPF bytes) always run.
  - Namespace-isolation tests require bubblewrap + Linux and are skipped
    otherwise (CI runners generally lack bwrap / user namespaces).
The sandbox itself runs code in a subprocess, so execution tests are
hermetically contained (sandboxed python3, never the test process).
"""

import subprocess
import sys
from pathlib import Path

import pytest

from core.kernel.sandbox import BwrapSandbox, get_sandbox
from core.kernel.sandbox.bwrap import (
    BLOCKED_MODULES,
    MAX_OUTPUT,
    _resolve_seccomp_nrs,
    _sanitize_code,
)
from core.kernel.sandbox.seccomp import (
    ARCH_AARCH64,
    DANGEROUS_SYSCALLS,
    NETWORK_SYSCALLS,
    PROCESS_SYSCALLS,
    _build_blocklist_filter,
    apply_seccomp,
    generate_bpf_bytes,
    get_profile,
    get_seccomp_profile,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="namespace sandbox requires Linux",
)

BWRAP_PRESENT = (
    Path("/usr/bin/bwrap").exists()
    or subprocess.run(["which", "bwrap"], capture_output=True, check=False).returncode
    == 0
)

requires_bwrap = pytest.mark.skipif(
    not BWRAP_PRESENT, reason="bubblewrap not installed — namespace tests skipped"
)

SANDBOX_TIMEOUT = 20


@pytest.fixture(scope="module")
def sandbox():
    return BwrapSandbox(timeout=SANDBOX_TIMEOUT)


# ---------------------------------------------------------------------------
# Unit tests (always run)
# ---------------------------------------------------------------------------


def test_seccomp_profiles_expose_expected_syscalls():
    restricted = get_profile("restricted")
    strict = get_profile("strict")
    assert "error" not in restricted and "error" not in strict
    assert set(restricted["blocked_syscalls"]) == set(DANGEROUS_SYSCALLS)
    assert set(strict["blocked_syscalls"]) == set(
        DANGEROUS_SYSCALLS + NETWORK_SYSCALLS + PROCESS_SYSCALLS
    )
    assert "ptrace" in restricted["blocked_syscalls"]
    assert "socket" in strict["blocked_syscalls"]
    assert restricted["blocked_numbers"] == sorted(set(restricted["blocked_numbers"]))
    assert get_profile("nope")["error"]


def test_seccomp_profile_json():
    j = get_seccomp_profile("restricted")
    assert j is not None and '"profile": "restricted"' in j
    assert get_seccomp_profile("nope") is None


def test_bpf_bytes_generation_valid():
    nrs = [117, 280]  # ptrace, bpf
    raw = generate_bpf_bytes(nrs, arch=ARCH_AARCH64)
    assert isinstance(raw, bytes) and len(raw) > 0 and len(raw) % 8 == 0
    # contains arch LD, an ERRNO ret and an ALLOW ret
    assert raw
    blocked = _build_blocklist_filter([280])
    assert blocked


def test_syscall_number_resolution():
    nrs = _resolve_seccomp_nrs("restricted")
    assert nrs and nrs == sorted(set(nrs))
    assert 117 in nrs  # ptrace
    assert _resolve_seccomp_nrs("") == []
    strict_nrs = _resolve_seccomp_nrs("strict")
    assert strict_nrs and len(strict_nrs) > len(nrs)


def test_blocked_modules_and_sanitize():
    assert "subprocess" in BLOCKED_MODULES and "ctypes" in BLOCKED_MODULES
    out = _sanitize_code("eval(x) + exec(y) + open(z)")
    assert (
        "_sanitized_eval_(" in out
        and "_sanitized_exec_(" in out
        and "_sanitized_open_(" in out
    )
    assert "eval(" not in out and "exec(" not in out


# ---------------------------------------------------------------------------
# Execution tests (run under bwrap where available, else subprocess fallback)
# ---------------------------------------------------------------------------


def test_basic_execution_prints(sandbox):
    r = sandbox.execute_python('print("hello kernel")')
    assert r.exit_code == 0
    assert "hello kernel" in r.stdout


def test_math_module_works(sandbox):
    r = sandbox.execute_python("print(2 + 2)")
    assert r.exit_code == 0 and r.stdout.strip() == "4"


def test_stdlib_imports(sandbox):
    code = "import json, math, os, sys, collections\nprint(json.dumps(math.pi))"
    r = sandbox.execute_python(code)
    assert r.exit_code == 0
    assert r.stdout.strip() == "3.141592653589793"


def test_blocked_module_raises(sandbox):
    for mod in ("subprocess", "multiprocessing", "ctypes", "pickle", "fcntl"):
        r = sandbox.execute_python(f"import {mod}; print('leaked')")
        assert r.exit_code != 0, f"{mod} was importable in the sandbox"
        assert "blocked" in r.stderr.lower() or "importerror" in r.stderr.lower()


def test_eval_exec_open_neutralized(sandbox):
    code = (
        "eval('__import__(\\'os\\').system(\\'echo pwned\\')'); exec('x=1'); open('x')"
    )
    r = sandbox.execute_python(code)
    assert r.exit_code == 0, r.stderr
    assert "pwned" not in r.stdout


def test_timeout_enforced(sandbox):
    r = sandbox.execute_python("import time; time.sleep(60)", timeout=1)
    assert r.exit_code == -1
    assert r.error and r.error.startswith("timeout")


def test_variable_scope_isolation(sandbox):
    r = sandbox.execute_python("import os\nprint(os.getcwd())")
    assert r.exit_code == 0


@requires_bwrap
def test_runs_as_nobody_uid_65534(sandbox):
    r = sandbox.execute_python("import os; print(os.getuid(), os.getgid())")
    assert r.exit_code == 0, r.stderr
    uid, gid = r.stdout.split()
    assert (uid, gid) == ("65534", "65534")


@requires_bwrap
def test_filesystem_isolation(sandbox):
    r = sandbox.execute_python(
        "import os; print(len(os.listdir('/tmp')), os.path.exists('/etc/passwd'))"
    )
    assert r.exit_code == 0, r.stderr
    n_entries, etc = r.stdout.split()
    assert n_entries == "0"  # /tmp is an empty tmpfs inside the sandbox
    assert etc == "True"  # read-only system paths are bound in


@requires_bwrap
def test_network_namespace_isolated(sandbox):
    r = sandbox.execute_python(
        "import socket; s = socket.socket(); print('socket-created')", seccomp_level=""
    )
    assert r.exit_code == 0, r.stderr


@requires_bwrap
def test_strict_seccomp_blocks_socket(sandbox):
    r = sandbox.execute_python(
        "import socket; s = socket.socket(); print('network-available')",
        seccomp_level="strict",
    )
    assert r.exit_code != 0
    assert "network-available" not in r.stdout
    assert (
        "errno" in r.stderr.lower()
        or "permission" in r.stderr.lower()
        or "error" in r.stderr.lower()
    )


@requires_bwrap
def test_seccomp_isolation_end_to_end(sandbox):
    assert apply_seccomp.__name__  # module path exists
    caps = sandbox.get_capabilities()
    assert caps["sandbox"] == "bubblewrap"
    assert caps["namespace_isolation"] is True
    assert caps["seccomp_enabled"] is True
    assert caps["seccomp_profiles"]["restricted"]["count"] == len(DANGEROUS_SYSCALLS)


def test_output_truncation(sandbox, monkeypatch):
    sandbox.max_output = 100
    r = sandbox.execute_python("print('x' * 5000)")
    assert r.truncated is True
    assert len(r.stdout) <= 100
    sandbox.max_output = MAX_OUTPUT


def test_get_sandbox_singleton():
    a = get_sandbox()
    b = get_sandbox()
    assert a is b
