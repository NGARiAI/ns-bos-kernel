"""
Seccomp-bpf profile generator for agent code execution sandbox.

Generates Berkeley Packet Filter (BPF) bytecode for seccomp(2) syscall filtering.
Compatible with Linux kernel seccomp() and bubblewrap --seccomp FD.

Architecture:
    generate_bpf(arch, blocked_syscalls) -> bytes  (raw sock_fprog)
    get_profile(name) -> dict                      (JSON documentation)
"""

import ctypes
import json
import logging
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

# seccomp_data offsets (aarch64)
OFFSET_NR = 0  # offsetof(struct seccomp_data, nr) = 0
OFFSET_ARCH = 4  # offsetof(struct seccomp_data, arch) = 4
OFFSET_ARG0 = 16  # offsetof(struct seccomp_data, args[0]) = 16

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
    """Generate BPF to validate architecture, returning 6 instructions."""
    insns = b""
    # LD arch offset
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH)
    # JEQ arch_val -> skip next 2 (continue to nr check), else KILL
    insns += _bpf_jump(BPF_JMP | BPF_JEQ, arch_val, 2, 0)
    insns += _bpf_stmt(BPF_RET, SECCOMP_RET_KILL_PROCESS)
    return insns


def _build_blocklist_filter(blocked_nrs: list[int]) -> bytes:
    """Generate BPF to block specific syscall numbers using linear comparison.

    For each blocked syscall:
        JEQ nr, jt=0, jf=1   (if match, execute next ERRNO; if no match, skip ERRNO)
        RET ERRNO|EPERM

    Returns raw BPF instructions.
    """
    insns = b""
    # LD syscall number (nr)
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR)

    blocked_sorted = sorted(set(blocked_nrs))

    for nr in blocked_sorted:
        # JEQ nr, jt=0, jf=1  (if match: fall through to ERRNO; if no match: skip ERRNO)
        insns += _bpf_jump(BPF_JMP | BPF_JEQ, nr, 0, 1)
        insns += _bpf_stmt(BPF_RET, SECCOMP_RET_ERRNO | 1)  # EPERM = 1

    # ALLOW
    insns += _bpf_stmt(BPF_RET, SECCOMP_RET_ALLOW)
    return insns


def generate_bpf_bytes(blocked_nrs: list[int], arch: int = ARCH_AARCH64) -> bytes:
    """Generate complete seccomp-bpf filter as raw bytes ready for prctl(PR_SET_SECCOMP)."""
    insns = b""
    insns += _validate_arch(arch)
    insns += _build_blocklist_filter(blocked_nrs)
    return insns


SYSCALL_NUMBERS: dict[str, int] = {
    # aarch64 syscall numbers from /usr/include/asm-generic/unistd.h
    "accept": 202,
    "accept4": 242,
    "acct": 89,
    "add_key": 217,
    "bind": 200,
    "bpf": 280,
    "brk": 214,
    "chdir": 49,
    "chmod": 52,
    "chown": 55,
    "clock_gettime": 113,
    "clone": 220,
    "clone3": 435,
    "close": 57,
    "connect": 203,
    "creat": 51,
    "delete_module": 106,
    "dup": 23,
    "dup2": 24,
    "dup3": 24,
    "epoll_create1": 20,
    "epoll_ctl": 21,
    "epoll_pwait": 22,
    "eventfd2": 19,
    "execve": 221,
    "execveat": 281,
    "exit": 93,
    "exit_group": 94,
    "faccessat": 48,
    "fchdir": 50,
    "fchmod": 53,
    "fchmodat": 54,
    "fchown": 55,
    "fchownat": 56,
    "fcntl": 25,
    "flock": 32,
    "fstat": 80,
    "fstatfs": 44,
    "fsync": 82,
    "ftruncate": 46,
    "fork": 220,  # glibc fork uses clone on aarch64
    "futex": 98,
    "getdents64": 61,
    "getegid": 177,
    "geteuid": 175,
    "getgid": 176,
    "getpeername": 52,
    "getpid": 172,
    "getppid": 173,
    "getrandom": 278,
    "getresgid": 148,
    "getresuid": 147,
    "getrlimit": 163,
    "getrusage": 165,
    "getsockname": 51,
    "getsockopt": 209,
    "gettid": 178,
    "getuid": 174,
    "init_module": 105,
    "ioctl": 29,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    "io_uring_setup": 425,
    "kcmp": 272,
    "kexec_file_load": 294,
    "kexec_load": 104,
    "kill": 129,
    "link": 45,
    "linkat": 37,
    "listen": 201,
    "lseek": 62,
    "madvise": 233,
    "mkdir": 48,
    "mkdirat": 34,
    "mlock": 228,
    "mlockall": 229,
    "mmap": 222,
    "mount": 40,
    "mprotect": 226,
    "mremap": 239,
    "munmap": 215,
    "nanosleep": 101,
    "newfstatat": 79,
    "openat": 56,
    "pause": 137,
    "perf_event_open": 241,
    "personality": 135,
    "pidfd_open": 434,
    "pipe2": 59,
    "pivot_root": 41,
    "poll": 7,
    "ppoll": 73,
    "prctl": 167,
    "prlimit64": 261,
    "process_vm_readv": 270,
    "process_vm_writev": 271,
    "ptrace": 117,
    "read": 63,
    "readlink": 78,
    "readlinkat": 78,
    "readv": 65,
    "reboot": 142,
    "recvfrom": 207,
    "recvmmsg": 243,
    "recvmsg": 212,
    "rename": 38,
    "renameat": 38,
    "rmdir": 49,
    "rt_sigaction": 13,
    "rt_sigprocmask": 14,
    "rt_sigreturn": 15,
    "rt_sigsuspend": 133,
    "sched_getaffinity": 123,
    "sched_setaffinity": 122,
    "sched_yield": 124,
    "seccomp": 277,
    "sendfile": 71,
    "sendmmsg": 269,
    "sendmsg": 211,
    "sendto": 206,
    "set_robust_list": 11,
    "set_tid_address": 96,
    "setgid": 144,
    "setgroups": 145,
    "sethostname": 161,
    "setitimer": 104,
    "setns": 268,
    "setpgid": 109,
    "setpriority": 141,
    "setregid": 146,
    "setresgid": 149,
    "setresuid": 148,
    "setreuid": 147,
    "setrlimit": 164,
    "setsid": 112,
    "setsockopt": 208,
    "setuid": 143,
    "shmat": 265,
    "shmctl": 266,
    "shmdt": 267,
    "shmget": 264,
    "shutdown": 210,
    "sigaltstack": 132,
    "signalfd4": 17,
    "socket": 198,
    "socketpair": 199,
    "splice": 76,
    "stat": 4,
    "statfs": 43,
    "statx": 291,
    "symlink": 44,
    "symlinkat": 36,
    "sync": 81,
    "syncfs": 85,
    "sysfs": 100,
    "syslog": 116,
    "swapoff": 225,
    "swapon": 224,
    "tgkill": 131,
    "timer_create": 107,
    "timer_delete": 111,
    "timer_getoverrun": 109,
    "timer_gettime": 108,
    "timer_settime": 110,
    "timerfd_create": 161,
    "timerfd_gettime": 156,
    "timerfd_settime": 153,
    "times": 102,
    "tkill": 130,
    "truncate": 46,
    "umask": 95,
    "umount2": 39,
    "uname": 160,
    "unlink": 35,
    "unlinkat": 35,
    "unshare": 97,
    "userfaultfd": 282,
    "utimensat": 88,
    "vfork": 220,  # glibc vfork uses clone on aarch64
    "vhangup": 58,
    "wait4": 260,
    "waitid": 261,
    "write": 64,
    "writev": 66,
}


def _resolve_blocked(names: list[str]) -> tuple[list[int], list[str]]:
    nums = []
    unresolved = []
    for name in names:
        if name in SYSCALL_NUMBERS:
            nums.append(SYSCALL_NUMBERS[name])
        elif name == "clone3":
            # clone3 nr differs by kernel; skip if unknown
            unresolved.append(name)
        else:
            unresolved.append(name)
    return nums, unresolved


def _build_sock_fprog(insns: bytes) -> bytes:
    """Build sock_fprog struct: len (2 bytes) + pointer (8 bytes on aarch64).
    Returns just the raw instructions for direct prctl use.
    """
    return insns


def apply_seccomp(blocked_nrs: list[int]) -> bool:
    """Apply a seccomp-bpf filter using ctypes and prctl(PR_SET_SECCOMP).

    Builds proper sock_fprog with ctypes structs and calls prctl.
    Returns True on success, False on failure.
    """
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(38, 1, 0, 0, 0)

        class _SF(ctypes.Structure):
            _fields_ = [
                ("code", ctypes.c_ushort),
                ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte),
                ("k", ctypes.c_uint),
            ]

        class _FP(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("f", ctypes.POINTER(_SF))]

        nrs = sorted(set(blocked_nrs))
        nf = len(nrs) * 2 + 2
        a = (_SF * nf)()
        i = 0
        a[i].code = 0x20
        a[i].k = 0
        i += 1
        for nr in nrs:
            a[i].code = 0x15
            a[i].jt = 0
            a[i].jf = 1
            a[i].k = nr
            i += 1
            a[i].code = 0x06
            a[i].k = 0x00050001
            i += 1
        a[i].code = 0x06
        a[i].k = 0x7FFF0000
        i += 1

        p = _FP(nf, a)
        result = libc.prctl(22, 2, ctypes.byref(p), 0, 0)
        return result == 0
    except Exception as e:  # noqa: BLE001 - best-effort kernel filter, fall back to namespaces only
        logger.warning(f"seccomp apply failed: {e}")
        return False


# --- High-level profiles ---

DANGEROUS_SYSCALLS = [
    "acct",
    "add_key",
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
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
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
        "arch": "aarch64",
        "arch_id": ARCH_AARCH64,
        "blocked_syscalls": blocked,
        "blocked_numbers": sorted(nums),
        "unresolved": unresolved,
        "bpf_instruction_count": len(nums) * 2 + 4,  # approx
    }


def get_seccomp_profile(name: str = "restricted") -> str | None:
    """Get seccomp profile as JSON string for documentation."""
    p = get_profile(name)
    if "error" in p:
        return None
    return json.dumps(p, indent=2)
