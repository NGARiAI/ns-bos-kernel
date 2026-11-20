"""
Seccomp-bpf profile generator for agent code execution sandbox.

Generates Berkeley Packet Filter (BPF) bytecode for seccomp(2) syscall filtering.
Compatible with Linux kernel seccomp() and bubblewrap --seccomp FD.

Architecture:
    generate_bpf_bytes(blocked_nrs, arch) -> bytes  (raw sock_filter instructions)
    filter_program(blocked_nrs, arch) -> list       (the same, as (code, jt, jf, k))
    apply_seccomp(blocked_nrs, level=) -> bool      (install on the calling process)
    get_profile(name) -> dict                       (JSON documentation)

The sandbox installs filter_program()'s output in front of agent code, so
there is one filter builder.
"""

import ctypes
import json
import logging
import platform
import struct

logger = logging.getLogger(__name__)

# Seccomp return values
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_TRACE = 0x7FF00000
SECCOMP_RET_LOG = 0x7FFC0000
SECCOMP_RET_ALLOW = 0x7FFF0000

# BPF opcodes
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_JMP = 0x05
BPF_RET = 0x06

BPF_W = 0x00
BPF_ABS = 0x20

BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40

# prctl(2) options
PR_SET_SECCOMP = 22
PR_SET_NO_NEW_PRIVS = 38
SECCOMP_MODE_FILTER = 2

# seccomp_data offsets (the same on every architecture)
OFFSET_NR = 0  # offsetof(struct seccomp_data, nr) = 0
OFFSET_ARCH = 4  # offsetof(struct seccomp_data, arch) = 4
OFFSET_ARG0 = 16  # offsetof(struct seccomp_data, args[0]); low 32 bits, little-endian
ENOSYS = 38
# CLONE_NEWTIME, NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID and NEWNET:
# all in the low 32 bits of clone's flags.
CLONE_NAMESPACE_FLAGS = 0x7E020080

ARCH_AARCH64 = 0xC00000B7  # AUDIT_ARCH_AARCH64 (little-endian)

# sock_filter struct: struct.pack('HBBI', code, jt, jf, k)
_FILTER_FMT = "HBBI"


def _bpf_stmt(code: int, k: int) -> bytes:
    """BPF statement: no jump."""
    return struct.pack(_FILTER_FMT, code & 0xFFFF, 0, 0, k & 0xFFFFFFFF)


def _bpf_jump(code: int, k: int, jt: int, jf: int) -> bytes:
    """BPF jump instruction."""
    return struct.pack(_FILTER_FMT, code & 0xFFFF, jt & 0xFF, jf & 0xFF, k & 0xFFFFFFFF)


def _validate_arch(arch_val: int) -> bytes:
    """BPF that kills a process making a syscall through another ABI. Three
    instructions; a match jumps over the one KILL, to the next block."""
    insns = b""
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH)
    insns += _bpf_jump(BPF_JMP | BPF_JEQ, arch_val, 1, 0)
    insns += _bpf_stmt(BPF_RET, SECCOMP_RET_KILL_PROCESS)
    if arch_val == ARCH_X86_64:
        # x32 syscalls share AUDIT_ARCH_X86_64 and set bit 30 in nr.
        insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR)
        insns += _bpf_jump(BPF_JMP | BPF_JGE, X32_SYSCALL_BIT, 0, 1)
        insns += _bpf_stmt(BPF_RET, SECCOMP_RET_ERRNO | 1)
    return insns


def _build_blocklist_filter(
    blocked_nrs: list[int], enosys_nrs=(), clone_nr: int | None = None
) -> bytes:
    """BPF that answers each blocked syscall with EPERM and each enosys one
    with ENOSYS, by linear comparison:

        JEQ nr, jt=0, jf=1   (a match falls through to the RET; else skip it)
        RET ERRNO|EPERM

    With clone_nr, clone itself is let through unless its flags ask for a new
    namespace (CLONE_NAMESPACE_FLAGS), which gets EPERM. Everything else is
    allowed."""
    insns = _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR)
    for nr in sorted(set(blocked_nrs)):
        insns += _bpf_jump(BPF_JMP | BPF_JEQ, nr, 0, 1)
        insns += _bpf_stmt(BPF_RET, SECCOMP_RET_ERRNO | 1)  # EPERM = 1
    for nr in sorted(set(enosys_nrs) - set(blocked_nrs)):
        insns += _bpf_jump(BPF_JMP | BPF_JEQ, nr, 0, 1)
        insns += _bpf_stmt(BPF_RET, SECCOMP_RET_ERRNO | ENOSYS)
    if clone_nr is not None and clone_nr not in blocked_nrs:
        # Not clone: jump over the next three to ALLOW. clone: load its flags
        # and refuse any namespace bit.
        insns += _bpf_jump(BPF_JMP | BPF_JEQ, clone_nr, 0, 3)
        insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARG0)
        insns += _bpf_jump(BPF_JMP | BPF_JSET, CLONE_NAMESPACE_FLAGS, 0, 1)
        insns += _bpf_stmt(BPF_RET, SECCOMP_RET_ERRNO | 1)
    insns += _bpf_stmt(BPF_RET, SECCOMP_RET_ALLOW)
    return insns


def generate_bpf_bytes(
    blocked_nrs: list[int],
    arch: int | None = None,
    *,
    enosys_nrs=(),
    clone_nr: int | None = None,
) -> bytes:
    """Generate the complete seccomp-bpf filter as raw bytes for prctl(PR_SET_SECCOMP).
    arch defaults to this machine's; numbers must be from the same table."""
    if arch is None:
        here = current_arch()
        if here is None:
            raise ValueError(f"no syscall table for {platform.machine()!r}")
        arch = here[1]
    insns = b""
    insns += _validate_arch(arch)
    insns += _build_blocklist_filter(blocked_nrs, enosys_nrs, clone_nr)
    return insns


def filter_program(
    blocked_nrs: list[int],
    arch: int | None = None,
    *,
    enosys_nrs=(),
    clone_nr: int | None = None,
) -> list[tuple[int, int, int, int]]:
    """generate_bpf_bytes() as (code, jt, jf, k) tuples, the form ctypes takes."""
    raw = generate_bpf_bytes(
        blocked_nrs, arch, enosys_nrs=enosys_nrs, clone_nr=clone_nr
    )
    return [struct.unpack(_FILTER_FMT, raw[o : o + 8]) for o in range(0, len(raw), 8)]


def level_rules(level: str, numbers: dict[str, int] | None = None) -> dict:
    """What a level does besides its blocklist, by number: restricted keeps
    threads and fork but no new namespace, so clone with a namespace flag is
    refused and clone3, whose flags sit in memory a filter cannot read, gets
    ENOSYS (the C library then falls back to clone). strict blocks both."""
    numbers = SYSCALL_NUMBERS if numbers is None else numbers
    if level != "restricted" or "clone" not in numbers:
        return {}
    rules = {"clone_nr": numbers["clone"]}
    if "clone3" in numbers:
        rules["enosys_nrs"] = [numbers["clone3"]]
    return rules


# x86_64 numbers from <asm/unistd_64.h> (Linux uapi), for the syscalls the
# profiles block. A name missing here does not exist on that architecture.
_X86_64_NUMBERS: dict[str, int] = {
    "accept": 43,
    "accept4": 288,
    "acct": 163,
    "add_key": 248,
    "bind": 49,
    "bpf": 321,
    "clone": 56,
    "clone3": 435,
    "connect": 42,
    "delete_module": 176,
    "fork": 57,
    "fsconfig": 431,
    "fsmount": 432,
    "fsopen": 430,
    "fspick": 433,
    "init_module": 175,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    "io_uring_setup": 425,
    "kcmp": 312,
    "kexec_file_load": 320,
    "kexec_load": 246,
    "keyctl": 250,
    "listen": 50,
    "memfd_create": 319,
    "mount": 165,
    "mount_setattr": 442,
    "move_mount": 429,
    "open_tree": 428,
    "perf_event_open": 298,
    "pivot_root": 155,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "ptrace": 101,
    "reboot": 169,
    "recvfrom": 45,
    "recvmmsg": 299,
    "recvmsg": 47,
    "request_key": 249,
    "sendmmsg": 307,
    "sendmsg": 46,
    "sendto": 44,
    "setns": 308,
    "shutdown": 48,
    "socket": 41,
    "socketpair": 53,
    "swapoff": 168,
    "swapon": 167,
    "sysfs": 139,
    "umount2": 166,
    "unshare": 272,
    "userfaultfd": 323,
    "vfork": 58,
    "vhangup": 153,
}

# aarch64 numbers from <asm-generic/unistd.h> (Linux uapi), for the syscalls the
# profiles block. A name missing here does not exist on that architecture.
_AARCH64_NUMBERS: dict[str, int] = {
    "accept": 202,
    "accept4": 242,
    "acct": 89,
    "add_key": 217,
    "bind": 200,
    "bpf": 280,
    "clone": 220,
    "clone3": 435,
    "connect": 203,
    "delete_module": 106,
    "fsconfig": 431,
    "fsmount": 432,
    "fsopen": 430,
    "fspick": 433,
    "init_module": 105,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    "io_uring_setup": 425,
    "kcmp": 272,
    "kexec_file_load": 294,
    "kexec_load": 104,
    "keyctl": 219,
    "listen": 201,
    "memfd_create": 279,
    "mount": 40,
    "mount_setattr": 442,
    "move_mount": 429,
    "open_tree": 428,
    "perf_event_open": 241,
    "pivot_root": 41,
    "process_vm_readv": 270,
    "process_vm_writev": 271,
    "ptrace": 117,
    "reboot": 142,
    "recvfrom": 207,
    "recvmmsg": 243,
    "recvmsg": 212,
    "request_key": 218,
    "sendmmsg": 269,
    "sendmsg": 211,
    "sendto": 206,
    "setns": 268,
    "shutdown": 210,
    "socket": 198,
    "socketpair": 199,
    "swapoff": 225,
    "swapon": 224,
    "umount2": 39,
    "unshare": 97,
    "userfaultfd": 282,
    "vhangup": 58,
}

ARCH_X86_64 = 0xC000003E  # AUDIT_ARCH_X86_64
X32_SYSCALL_BIT = 0x40000000  # x32 ABI syscalls on x86_64 set this bit

# platform.machine() -> (audit arch, syscall numbers). Seccomp filters compare
# raw numbers, which differ per architecture; using one architecture's table
# on another blocks unrelated syscalls and lets the intended ones through.
_ARCHES: dict[str, tuple[int, dict[str, int]]] = {
    "x86_64": (ARCH_X86_64, _X86_64_NUMBERS),
    "amd64": (ARCH_X86_64, _X86_64_NUMBERS),
    "aarch64": (ARCH_AARCH64, _AARCH64_NUMBERS),
    "arm64": (ARCH_AARCH64, _AARCH64_NUMBERS),
}


def current_arch() -> tuple[str, int, dict[str, int]] | None:
    """(machine, audit arch, syscall numbers) for this machine, or None when
    no table exists for it, in which case no filter can be built."""
    machine = platform.machine().lower()
    if machine not in _ARCHES:
        return None
    audit, numbers = _ARCHES[machine]
    return machine, audit, numbers


_here = current_arch()
SYSCALL_NUMBERS: dict[str, int] = dict(_here[2]) if _here else {}


def _resolve_blocked(names: list[str]) -> tuple[list[int], list[str]]:
    nums = []
    unresolved = []
    for name in names:
        if name in SYSCALL_NUMBERS:
            nums.append(SYSCALL_NUMBERS[name])
        else:
            unresolved.append(name)
    return nums, unresolved


def apply_seccomp(blocked_nrs: list[int], *, level: str = "") -> bool:
    """Apply a seccomp-bpf filter using ctypes and prctl(PR_SET_SECCOMP).

    level adds what that profile does besides its list (level_rules):
    apply_seccomp(get_profile("restricted")["blocked_numbers"],
    level="restricted") installs the program the sandbox installs, clone
    with a namespace flag refused and clone3 answered ENOSYS. Without it
    the list alone is installed. Returns True on success, False on failure.
    """
    if level not in ("", "restricted", "strict"):
        # A misspelt level would otherwise install the list alone.
        raise ValueError(f"level {level!r} is not '', 'restricted' or 'strict'")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

        class _SF(ctypes.Structure):
            _fields_ = [
                ("code", ctypes.c_ushort),
                ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte),
                ("k", ctypes.c_uint),
            ]

        class _FP(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("f", ctypes.POINTER(_SF))]

        # The same builder as the sandbox: ABI check, x32 refusal, then the list.
        insns = filter_program(blocked_nrs, **level_rules(level))
        nf = len(insns)
        a = (_SF * nf)()
        for i, (code, jt, jf, k) in enumerate(insns):
            a[i].code, a[i].jt, a[i].jf, a[i].k = code, jt, jf, k

        p = _FP(nf, a)
        result = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(p), 0, 0)
        return result == 0
    except Exception as e:  # noqa: BLE001 - any failure is reported as False
        logger.warning(f"seccomp apply failed: {e}")
        return False


# --- High-level profiles ---

DANGEROUS_SYSCALLS = [
    "acct",
    # The kernel keyrings: the sandbox shares its caller's session keyring,
    # which can hold Kerberos tickets and disk encryption keys.
    "add_key",
    "keyctl",
    "request_key",
    "bpf",
    "delete_module",
    "init_module",
    "kcmp",
    "kexec_file_load",
    "kexec_load",
    "perf_event_open",
    "pivot_root",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
    "reboot",
    "setns",
    "swapoff",
    "swapon",
    "sysfs",
    "userfaultfd",
    "vhangup",
    # A memfd's pages are outside the address space limit until mapped and
    # outside every sized tmpfs, so one process could hold memory without
    # bound. Python and the C library fall back to a file without it.
    "memfd_create",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    # No new namespace, where agent code would hold every capability again,
    # and no mounts (with clone and clone3 handled in level_rules).
    "unshare",
    "mount",
    "umount2",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "move_mount",
    "open_tree",
    "mount_setattr",
]

NETWORK_SYSCALLS = [
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "recvmmsg",
    "sendmmsg",
    "socketpair",
    "shutdown",
]

PROCESS_SYSCALLS = [
    "clone",
    "fork",
    "vfork",
    "clone3",
]


def get_profile(name: str = "restricted") -> dict:
    """Get a seccomp profile as a dict with syscall list + BPF info."""
    if name == "restricted":
        blocked = DANGEROUS_SYSCALLS
    elif name == "strict":
        blocked = DANGEROUS_SYSCALLS + NETWORK_SYSCALLS + PROCESS_SYSCALLS
    else:
        return {"error": f"Unknown profile: {name}"}

    nums, unresolved = _resolve_blocked(blocked)
    return {
        "profile": name,
        "arch": _here[0] if _here else platform.machine(),
        "arch_id": _here[1] if _here else None,
        "blocked_syscalls": blocked,
        "blocked_numbers": sorted(nums),
        "unresolved": unresolved,
        "clone_namespace_flags_refused": name == "restricted",
        "bpf_instruction_count": (
            len(filter_program(nums, **level_rules(name))) if _here else None
        ),
    }


def get_seccomp_profile(name: str = "restricted") -> str | None:
    """Get seccomp profile as JSON string for documentation."""
    p = get_profile(name)
    if "error" in p:
        return None
    return json.dumps(p, indent=2)
