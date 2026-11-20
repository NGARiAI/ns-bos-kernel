"""Seccomp filters compare raw syscall numbers, which differ per
architecture. The tables must match the kernel's own headers, the filter
must use the running machine's table, and other ABIs must be refused."""

import platform
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from core.kernel.sandbox import bwrap, seccomp

HEADERS = {
    "x86_64": Path("/usr/include/x86_64-linux-gnu/asm/unistd_64.h"),
    "aarch64": Path("/usr/include/asm-generic/unistd.h"),
}
TABLES = {"x86_64": seccomp._X86_64_NUMBERS, "aarch64": seccomp._AARCH64_NUMBERS}
BLOCKED = set(
    seccomp.DANGEROUS_SYSCALLS + seccomp.NETWORK_SYSCALLS + seccomp.PROCESS_SYSCALLS
)


def _parse(header: Path) -> dict:
    numbers = {}
    for m in re.finditer(
        r"^#define __NR(?:3264)?_(\w+)\s+(\d+)\s*$", header.read_text(), re.MULTILINE
    ):
        numbers.setdefault(m.group(1), int(m.group(2)))
    return numbers


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_tables_match_the_kernel_headers(arch):
    if not HEADERS[arch].exists():
        pytest.skip(f"{HEADERS[arch]} not installed")
    header = _parse(HEADERS[arch])
    expected = {name: header[name] for name in BLOCKED if name in header}
    assert TABLES[arch] == expected


@pytest.mark.parametrize(
    ("arch", "name", "number"),
    [
        ("x86_64", "ptrace", 101), ("x86_64", "bpf", 321), ("x86_64", "socket", 41),
        ("x86_64", "kexec_load", 246), ("aarch64", "ptrace", 117),
        ("aarch64", "bpf", 280), ("aarch64", "socket", 198),
    ],
)  # fmt: skip
def test_known_numbers(arch, name, number):
    assert TABLES[arch][name] == number


def test_syscalls_aarch64_does_not_have_are_not_in_its_table():
    for name in ("fork", "vfork", "sysfs"):
        assert name not in seccomp._AARCH64_NUMBERS


@pytest.mark.parametrize(
    ("machine", "audit"),
    [("x86_64", 0xC000003E), ("AMD64", 0xC000003E), ("aarch64", 0xC00000B7),
     ("arm64", 0xC00000B7)],
)  # fmt: skip
def test_the_table_follows_the_machine(monkeypatch, machine, audit):
    monkeypatch.setattr(seccomp.platform, "machine", lambda: machine)
    _, arch, numbers = seccomp.current_arch()
    assert arch == audit
    assert numbers is TABLES["x86_64" if audit == 0xC000003E else "aarch64"]


def test_an_unknown_machine_gets_no_filter(monkeypatch):
    monkeypatch.setattr(seccomp.platform, "machine", lambda: "riscv64")
    assert seccomp.current_arch() is None
    assert "ctypes" not in bwrap._wrap_python("print(1)", set(), seccomp_level="strict")
    with pytest.raises(ValueError, match="no syscall table"):
        seccomp.generate_bpf_bytes([1])


def _insns(raw: bytes):
    return [struct.unpack("HBBI", raw[i : i + 8]) for i in range(0, len(raw), 8)]


def test_the_arch_check_lands_on_the_syscall_number():
    prog = _insns(seccomp.generate_bpf_bytes([101], arch=seccomp.ARCH_X86_64))
    code, jt, _, k = prog[1]
    assert (code, k) == (seccomp.BPF_JMP | seccomp.BPF_JEQ, seccomp.ARCH_X86_64)
    assert prog[1 + 1 + jt][0] == seccomp.BPF_LD | seccomp.BPF_W | seccomp.BPF_ABS
    assert prog[1 + 1 + jt][3] == seccomp.OFFSET_NR
    assert prog[2][3] == seccomp.SECCOMP_RET_KILL_PROCESS
    # x32 numbers are refused before the blocklist.
    assert (prog[4][0], prog[4][3]) == (seccomp.BPF_JMP | seccomp.BPF_JGE, 0x40000000)


def test_the_aarch64_filter_has_no_x32_check():
    prog = _insns(seccomp.generate_bpf_bytes([117], arch=seccomp.ARCH_AARCH64))
    assert all(k != 0x40000000 for _, _, _, k in prog)


def test_the_sandbox_installs_the_program_apply_seccomp_does():
    nrs = bwrap._resolve_seccomp_nrs("strict")
    arch = seccomp.ARCH_X86_64
    program = seccomp.filter_program(nrs, arch)
    assert program == _insns(seccomp.generate_bpf_bytes(nrs, arch))
    with pytest.MonkeyPatch.context() as m:
        m.setattr(seccomp, "current_arch", lambda: ("x86_64", arch, {}))
        wrapped = bwrap._wrap_python("", set(), seccomp_level="strict")
    assert f"_prog = {program!r}" in wrapped
    # A syscall through another ABI kills the process, in the sandbox as well.
    assert program[2] == (seccomp.BPF_RET, 0, 0, seccomp.SECCOMP_RET_KILL_PROCESS)


def test_the_profile_counts_the_instructions_it_installs():
    for name, level in (("restricted", "restricted"), ("strict", "strict")):
        profile = seccomp.get_profile(name)
        if seccomp.current_arch() is None:
            assert profile["bpf_instruction_count"] is None
        else:
            program = seccomp.filter_program(
                bwrap._resolve_seccomp_nrs(level), **seccomp.level_rules(level)
            )
            assert profile["bpf_instruction_count"] == len(program)


def _probe(level: str, checks: str) -> str:
    code = bwrap._wrap_python("", bwrap.BLOCKED_MODULES, seccomp_level=level) + (
        "\n_c = _old_import('ctypes')\n_l = _c.CDLL(None, use_errno=True)\n" + checks
    )
    run = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         timeout=60, check=False)  # fmt: skip
    return run.stdout.strip()


ON_X86 = pytest.mark.skipif(platform.machine() != "x86_64", reason="x86_64 numbers")


@ON_X86
@pytest.mark.parametrize("level", ["restricted", "strict"])
def test_dangerous_syscalls_are_refused_and_ordinary_ones_are_not(level):
    out = _probe(level, (
        "res = []\n"
        "for nr, args in ((101, (0xFFFF, 0, 0, 0)), (321, (0xFFFF, 0, 0)), (246, (0, 0, 0, 0))):\n"
        "    _l.syscall(nr, *args); res.append(_c.get_errno())\n"
        "import os\n"
        "res.append(os.readlink('/proc/self/exe') != '')\n"
        "_l.syscall(0x40000000 | 39); res.append(_c.get_errno())\n"
        "print(res)\n"
    ))  # fmt: skip
    # ptrace, bpf and kexec_load: EPERM. readlink works. An x32 getpid: EPERM.
    assert out == "[1, 1, 1, True, 1]"


@ON_X86
def test_restricted_leaves_sockets_alone_and_strict_does_not():
    check = (
        "import socket\n"
        "try:\n    socket.socket().close(); print('open')\n"
        "except PermissionError:\n    print('blocked')\n"
    )
    assert _probe("restricted", check) == "open"
    assert _probe("strict", check) == "blocked"


# -- a filter that cannot be installed stops the agent code ------------------------

HAS_TABLE = pytest.mark.skipif(
    seccomp.current_arch() is None, reason="no syscall table here"
)
REFUSED = "seccomp: the filter was not installed ({}); the code was not run"


NNP = "print([l for l in _old_open('/proc/self/status') if l.startswith('NoNewPrivs')])"


def _run_wrapped(monkeypatch, nrs, code="print('ran')"):
    monkeypatch.setattr(bwrap, "_resolve_seccomp_nrs", lambda level: nrs)
    wrapped = bwrap._wrap_python("", bwrap.BLOCKED_MODULES, "restricted")
    wrapped = "_old_open = open\n" + wrapped + "\n" + code
    return subprocess.run([sys.executable, "-c", wrapped], capture_output=True,
                          text=True, timeout=60, check=False)  # fmt: skip


@HAS_TABLE
def test_agent_code_does_not_run_when_the_kernel_refuses_the_filter(monkeypatch):
    # 3000 entries make about 6000 instructions; the kernel's limit is 4096.
    run = _run_wrapped(monkeypatch, list(range(3000)))
    assert (run.returncode, run.stdout) == (1, "")
    assert run.stderr.strip() == REFUSED.format("Invalid argument")


@HAS_TABLE
def test_agent_code_does_not_run_when_the_filter_cannot_be_built(monkeypatch):
    monkeypatch.setattr(
        seccomp, "filter_program", lambda nrs, arch, **rules: [(6, 0, 0, "x")]
    )
    run = _run_wrapped(monkeypatch, [1])
    assert (run.returncode, run.stdout) == (1, "")
    assert run.stderr.startswith("seccomp: the filter was not installed (TypeError")


@HAS_TABLE
def test_a_working_filter_still_runs_the_code(monkeypatch):
    run = _run_wrapped(monkeypatch, [seccomp.SYSCALL_NUMBERS["ptrace"]], NNP)
    assert (run.returncode, run.stdout, run.stderr) == (
        0,
        "['NoNewPrivs:\\t1\\n']\n",
        "",
    )


@HAS_TABLE
def test_the_probe_reports_a_refused_filter(monkeypatch):
    monkeypatch.setattr(bwrap, "_resolve_seccomp_nrs", lambda level: list(range(3000)))
    probe = bwrap.BwrapSandbox().probe_seccomp()
    assert probe == {
        "ok": False,
        "error": f"filter not in effect ({REFUSED.format('Invalid argument')})",
    }


# -- get_capabilities() measures seccomp ----------------------------------------


@pytest.mark.skipif(seccomp.current_arch() is None, reason="no syscall table here")
def test_capabilities_report_seccomp_from_a_real_run():
    caps = bwrap.BwrapSandbox().get_capabilities()
    assert caps["seccomp_probe"]["ok"] is True, caps["seccomp_probe"]
    assert caps["seccomp_enabled"] is True


def test_a_filter_that_is_not_installed_is_reported(monkeypatch):
    monkeypatch.setattr(bwrap, "_resolve_seccomp_nrs", lambda level: [])
    caps = bwrap.BwrapSandbox().get_capabilities()
    assert caps["seccomp_enabled"] is False
    assert caps["seccomp_probe"] == {
        "ok": False,
        "error": "filter not in effect (open)",
    }


def test_an_unknown_architecture_reports_no_seccomp(monkeypatch):
    monkeypatch.setattr(seccomp.platform, "machine", lambda: "riscv64")
    monkeypatch.setattr(bwrap.platform, "machine", lambda: "riscv64")
    caps = bwrap.BwrapSandbox().get_capabilities()
    assert caps["seccomp_enabled"] is False
    assert caps["seccomp_probe"]["error"] == "no syscall table for riscv64"


def test_a_refused_sandbox_reports_no_seccomp(monkeypatch):
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    caps = bwrap.BwrapSandbox(require_bwrap=True).get_capabilities()
    assert caps["seccomp_probe"] == {"ok": False, "error": "sandbox_unavailable"}


# -- apply_seccomp() on the calling process (run in a child) ---------------------


def _child(code: str) -> str:
    run = subprocess.run(
        [sys.executable, "-c", "import ctypes, os\nfrom core.kernel.sandbox import seccomp\n" + code],
        capture_output=True, text=True, timeout=60, check=False,
        cwd=Path(__file__).resolve().parent.parent,
    )  # fmt: skip
    return (run.stdout + run.stderr).strip()


@ON_X86
def test_apply_seccomp_blocks_what_it_is_given_and_nothing_else():
    out = _child(
        "ok = seccomp.apply_seccomp([seccomp.SYSCALL_NUMBERS['ptrace']])\n"
        "l = ctypes.CDLL(None, use_errno=True)\n"
        "l.syscall(101, 0xFFFF, 0, 0, 0); ptrace = ctypes.get_errno()\n"
        "l.syscall(0x40000000 | 39); x32 = ctypes.get_errno()\n"
        "nnp = 'NoNewPrivs:\\t1\\n' in open('/proc/self/status').readlines()\n"
        "print(ok, ptrace, x32, os.readlink('/proc/self/exe') != '', os.getpid() > 0, nnp)\n"
    )
    assert out == "True 1 1 True True True"


def test_apply_seccomp_reports_failure_on_an_unknown_architecture():
    out = _child(
        "seccomp.platform.machine = lambda: 'riscv64'\n"
        "print(seccomp.apply_seccomp([1]))\n"
    )
    assert out.splitlines()[0] == "False"
    assert "no syscall table for 'riscv64'" in out


# -- no new namespaces -----------------------------------------------------------------


SCHED_H = Path("/usr/include/linux/sched.h")
# From <linux/sched.h>, for the agent code below: Python has these in os only
# from 3.12, and not all of them even there.
CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWNET = 0x00020000, 0x10000000, 0x40000000


def test_the_namespace_mask_is_every_clone_new_flag():
    if not SCHED_H.exists():
        pytest.skip(f"{SCHED_H} not installed")
    flags = {
        m.group(1): int(m.group(2), 16)
        for m in re.finditer(r"^#define (CLONE_NEW\w+)\s+(0x[0-9a-fA-F]+)", SCHED_H.read_text(),
                             re.MULTILINE)
    }  # fmt: skip
    assert len(flags) == 8, flags  # mount, cgroup, UTS, IPC, user, PID, network, time
    mask = 0
    for flag in flags.values():
        mask |= flag
    assert mask == seccomp.CLONE_NAMESPACE_FLAGS
    assert (flags["CLONE_NEWNS"], flags["CLONE_NEWUSER"], flags["CLONE_NEWNET"]) == (
        CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWNET
    )  # fmt: skip


def test_restricted_refuses_clone_into_a_namespace_and_answers_clone3_enosys():
    numbers = {"clone": 56, "clone3": 435}
    assert seccomp.level_rules("restricted", numbers) == {
        "clone_nr": 56, "enosys_nrs": [435]
    }  # fmt: skip
    assert seccomp.level_rules("strict", numbers) == {}  # it blocks both outright
    program = seccomp.filter_program(
        [101], seccomp.ARCH_X86_64, **seccomp.level_rules("restricted", numbers)
    )
    jeq, ret = seccomp.BPF_JMP | seccomp.BPF_JEQ, seccomp.BPF_RET
    assert program[-7:] == [
        (jeq, 0, 1, 435),  # clone3: ENOSYS
        (ret, 0, 0, seccomp.SECCOMP_RET_ERRNO | seccomp.ENOSYS),
        (jeq, 0, 3, 56),  # clone: not it, jump to ALLOW
        (seccomp.BPF_LD | seccomp.BPF_W | seccomp.BPF_ABS, 0, 0, seccomp.OFFSET_ARG0),
        (seccomp.BPF_JMP | seccomp.BPF_JSET, 0, 1, seccomp.CLONE_NAMESPACE_FLAGS),
        (ret, 0, 0, seccomp.SECCOMP_RET_ERRNO | 1),  # a namespace flag: EPERM
        (ret, 0, 0, seccomp.SECCOMP_RET_ALLOW),
    ]


@pytest.fixture(scope="module")
def box():
    if not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    return bwrap.BwrapSandbox(require_bwrap=True)


@HAS_TABLE
@pytest.mark.parametrize("level", ["restricted", "strict"])
def test_agent_code_cannot_make_a_namespace_and_regain_capabilities(box, level):
    # Inside a new user namespace agent code holds every capability: mounts,
    # nf_tables through CAP_NET_ADMIN, and the kernel bugs those reach.
    nrs = seccomp.SYSCALL_NUMBERS
    code = (
        "import os, builtins, importlib, signal\n"
        "ct = importlib.import_module('ctypes')\n"
        "libc = ct.CDLL(None, use_errno=True)\n"
        f"NEWNS, NEWUSER, NEWNET = {CLONE_NEWNS}, {CLONE_NEWUSER}, {CLONE_NEWNET}\n"
        "def report(how, rc):\n"
        "    if rc == 0:\n"
        "        os._exit(0)\n"
        "    if rc > 0:\n"
        "        os.waitpid(rc, 0)\n"
        "    print(how, 'created' if rc >= 0 else 'refused')\n"
        f"report('clone', libc.syscall({nrs['clone']}, NEWUSER | signal.SIGCHLD, 0, 0, 0, 0))\n"
        "args = (ct.c_uint64 * 8)(NEWUSER, 0, 0, 0, signal.SIGCHLD, 0, 0, 0)\n"
        f"report('clone3', libc.syscall({nrs['clone3']}, ct.byref(args), 64))\n"
        "for how, flags in (('mount ns', NEWNS), ('user ns', NEWUSER | NEWNS | NEWNET)):\n"
        "    print(how, 'created' if libc.unshare(flags) == 0 else 'refused')\n"
        "print('mount', 'created' if libc.mount(b'none', b'/tmp', b'tmpfs', 0, None) == 0 else 'refused')\n"
    )
    result = box.execute_python(code, seccomp_level=level)
    assert result.exit_code == 0, result.stderr
    assert result.stdout.split("\n")[:-1] == [
        "clone refused", "clone3 refused", "mount ns refused", "user ns refused",
        "mount refused",
    ]  # fmt: skip


@HAS_TABLE
def test_threads_fork_and_subprocesses_still_work_under_restricted(box):
    # clone3 answers ENOSYS, so the C library falls back to plain clone.
    code = (
        "import os, threading, importlib\n"
        "from concurrent.futures import ThreadPoolExecutor\n"
        "out = []\n"
        "t = threading.Thread(target=lambda: out.append('thread')); t.start(); t.join()\n"
        "with ThreadPoolExecutor(4) as pool:\n"
        "    out.append(sum(pool.map(lambda n: n * n, range(10))))\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    os._exit(7)\n"
        "out.append(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))\n"
        "sp = importlib.import_module('subprocess')\n"
        "out.append(sp.run(['true']).returncode)\n"
        "print(out)\n"
    )
    result = box.execute_python(code)
    assert result.stdout.strip() == "['thread', 285, 7, 0]", result.to_dict()


# -- the kernel keyrings ---------------------------------------------------------------


@HAS_TABLE
def test_agent_code_cannot_read_or_clear_the_callers_session_keyring(box):
    # A child with its own anonymous session keyring holds the secret, so the
    # test never touches the runner's keyrings.
    keyctl, add_key = (seccomp.SYSCALL_NUMBERS[n] for n in ("keyctl", "add_key"))
    agent = (
        "import importlib\n"
        "ct = importlib.import_module('ctypes')\n"
        "libc = ct.CDLL(None, use_errno=True)\n"
        f"kid = libc.syscall({keyctl}, 10, -3, b'user', b'ngari-test', 0)\n"  # SEARCH
        "buf = ct.create_string_buffer(64)\n"
        f"n = libc.syscall({keyctl}, 11, kid, buf, 64)\n"  # READ
        "print('payload', buf.raw[:max(n, 0)])\n"
        f"print('clear', libc.syscall({keyctl}, 7, -3))\n"  # CLEAR the session keyring
    )
    driver = (
        "import ctypes, sys\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        f"assert libc.syscall({keyctl}, 1, None) > 0\n"  # JOIN_SESSION_KEYRING(NULL)
        f"assert libc.syscall({add_key}, b'user', b'ngari-test', b'pin=123456', 10, -3) > 0\n"
        "from core.kernel.sandbox.bwrap import BwrapSandbox\n"
        f"print(BwrapSandbox(require_bwrap=True).execute_python({agent!r}).stdout)\n"
        f"kid = libc.syscall({keyctl}, 10, -3, b'user', b'ngari-test', 0)\n"
        "print('still there' if kid > 0 else 'gone')\n"
    )
    run = subprocess.run([sys.executable, "-c", driver], cwd=Path(__file__).parent.parent, capture_output=True,
                         text=True, timeout=60, stdin=subprocess.DEVNULL, check=False)  # fmt: skip
    assert run.returncode == 0, run.stderr
    lines = [line for line in run.stdout.splitlines() if line]
    assert lines == ["payload b''", "clear -1", "still there"]


# -- a refused filter is told apart from agent code ------------------------------------

LOOKS_REFUSED = (
    "import sys\n"
    "sys.stderr.write('seccomp: the filter was not installed (Invalid argument); "
    "the code was not run\\n')\n"
    "sys.exit(1)\n"
)


@HAS_TABLE
@pytest.mark.parametrize("path", ["bubblewrap", "fallback"])
def test_a_refused_filter_is_flagged_and_agent_code_cannot_fake_one(path, monkeypatch):
    import os

    if path == "bubblewrap" and not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    if path == "fallback":
        monkeypatch.setenv("NGARI_AIR_GAP", "0")
        monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    box = bwrap.BwrapSandbox(require_bwrap=path == "bubblewrap")
    before = len(os.listdir("/proc/self/fd"))
    faked = box.execute_python(LOOKS_REFUSED)
    assert (faked.exit_code, faked.error) == (1, "")  # its own exit, not a refusal
    with monkeypatch.context() as m:
        m.setattr(bwrap, "_resolve_seccomp_nrs", lambda level: list(range(3000)))
        refused = box.execute_python("print('ran')")
    assert (refused.stdout, refused.exit_code) == ("", 1)
    assert refused.error == bwrap.SECCOMP_NOT_INSTALLED
    assert (
        box.execute_python("print(1)", seccomp_level="").error == ""
    )  # no filter asked
    assert len(os.listdir("/proc/self/fd")) == before  # no pipe left open here


@HAS_TABLE
def test_agent_code_cannot_write_the_status_byte(box):
    # The bootstrap closes its end before the agent's code: nothing is left
    # to write to.
    result = box.execute_python(
        "import os\n"
        "wrote = []\n"
        "for fd in range(3, 64):\n"
        "    try:\n"
        "        os.write(fd, b'1'); wrote.append(fd)\n"
        "    except OSError:\n"
        "        pass\n"
        "print(wrote)\n"
    )
    assert (result.stdout.strip(), result.error) == ("[]", "")


# -- apply_seccomp installs what the sandbox installs ----------------------------------


def test_apply_seccomp_with_a_level_builds_the_sandbox_program(monkeypatch):
    # A list alone cannot refuse clone(CLONE_NEWUSER) or clone3; a level adds
    # the rules get_profile reports for restricted.
    from core.kernel.sandbox import bwrap, seccomp

    here = seccomp.current_arch()
    if here is None:
        pytest.skip("no syscall table here")
    built = []
    real = seccomp.filter_program
    monkeypatch.setattr(
        seccomp,
        "filter_program",
        lambda *a, **kw: built.append(real(*a, **kw)) or built[-1],
    )

    class FakeLibc:  # nothing is installed on the test process
        def prctl(self, *args):
            return 0

    monkeypatch.setattr(seccomp.ctypes, "CDLL", lambda *a, **kw: FakeLibc())
    nums = seccomp.get_profile("restricted")["blocked_numbers"]
    built.clear()  # get_profile builds one to count its instructions
    assert seccomp.apply_seccomp(nums, level="restricted")
    assert seccomp.apply_seccomp(nums)
    assert built == [
        real(bwrap._resolve_seccomp_nrs("restricted"), here[1],
             **seccomp.level_rules("restricted", here[2])),
        real(nums),
    ]  # fmt: skip
    with pytest.raises(ValueError, match="is not ''"):
        seccomp.apply_seccomp(nums, level="Restricted")


@pytest.mark.parametrize("level", ["restricted", ""])
def test_apply_seccomp_restricted_answers_clone3_with_enosys(level):
    import subprocess
    import sys

    from core.kernel.sandbox import seccomp

    if seccomp.current_arch() is None or "clone3" not in seccomp.SYSCALL_NUMBERS:
        pytest.skip("no syscall table here")
    code = (
        "import ctypes, errno\n"
        "from core.kernel.sandbox import seccomp\n"
        "nums = seccomp.get_profile('restricted')['blocked_numbers']\n"
        f"assert seccomp.apply_seccomp(nums, level={level!r})\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "libc.syscall(seccomp.SYSCALL_NUMBERS['clone3'], None, 0)\n"
        "print(errno.errorcode[ctypes.get_errno()])\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == ("ENOSYS" if level else "EINVAL")
