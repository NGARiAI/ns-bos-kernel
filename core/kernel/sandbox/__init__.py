"""
NS-BOS Kernel Sandbox — Secure code execution environment for AI agents.

BwrapSandbox (primary) — Linux namespace isolation via bubblewrap:
- User, PID, net, mount, IPC, UTS namespace isolation
- Runs as nobody (uid 65534)
- Read-only system filesystem, writable /tmp
- No network access
- Optional seccomp-bpf syscall filtering (restricted / strict profiles)

Falls back to a subprocess execution with Python import/function gates
when bubblewrap is unavailable.

Usage:
    from core.kernel.sandbox import BwrapSandbox, get_sandbox
    sandbox = get_sandbox()
    result = sandbox.execute_python("print(2+2)")
"""

from .bwrap import BwrapSandbox, SandboxResult, get_sandbox
from .seccomp import (
    DANGEROUS_SYSCALLS,
    NETWORK_SYSCALLS,
    PROCESS_SYSCALLS,
    get_profile,
    get_seccomp_profile,
)

__all__ = [
    "DANGEROUS_SYSCALLS",
    "NETWORK_SYSCALLS",
    "PROCESS_SYSCALLS",
    "BwrapSandbox",
    "SandboxResult",
    "get_profile",
    "get_sandbox",
    "get_seccomp_profile",
]
