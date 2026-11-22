"""KNOWN_LIMITATIONS.md against the code: each limit the page states is
checked to still hold, so a limit that is lifted fails here until the page
is updated."""

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "core" / "kernel"
PAGE = (ROOT / "KNOWN_LIMITATIONS.md").read_text()
TEXT = " ".join(PAGE.split())


def _source(*parts: str) -> str:
    base = KERNEL.joinpath(*parts)
    files = [base] if base.is_file() else sorted(base.rglob("*.py"))
    return "\n".join(p.read_text() for p in files if "build" not in p.parts)


def _names(source: str) -> set[str]:
    tree = ast.parse(source)
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }


def test_every_page_it_names_exists():
    named = set(re.findall(r"`((?:docs/)?[A-Z_]+\.md)`", PAGE))
    assert len(named) >= 8
    assert [name for name in named if not (ROOT / name).is_file()] == []


def test_the_readme_lists_the_page():
    assert "| `KNOWN_LIMITATIONS.md` |" in (ROOT / "README.md").read_text()


def test_the_default_key_is_a_plaintext_file(tmp_path):
    from core.kernel.data_plane import keys

    assert "The default key is a plaintext file." in TEXT
    assert keys.DEFAULT_PROVIDER == "file"
    provider = keys.provider_from_env(tmp_path, {})
    key = provider.load_or_create()
    assert (tmp_path / "master.key").read_bytes().strip() == key


def test_there_is_one_key_and_no_rotation():
    assert "One key, no rotation." in TEXT
    names = _names(_source("data_plane"))
    assert not names & {"MultiFernet", "rotate", "Argon2id", "AESGCM"}


def test_scrypt_protects_the_recovery_bundle():
    assert "scrypt, which protects the recovery bundle" in TEXT
    assert "scrypt" in _names(_source("data_plane", "recovery.py"))


def test_anchors_are_unsigned_and_some_entries_carry_no_mac():
    from core.kernel import data_plane

    assert "Anchors are taken by hand with `audit anchor` and are not signed" in TEXT
    assert "Some entries carry no MAC." in TEXT
    assert {
        "operator_auth",
        "esignature",
        "agent_sponsored",
    } <= data_plane.KEYLESS_ACTIONS
    assert not _names(_source("data_plane", "audit_cli.py")) & {
        "sign",
        "Ed25519PrivateKey",
    }


def test_the_kernel_registers_an_agent_without_a_manifest(tmp_path, monkeypatch):
    from core.kernel import NSBOSKernel

    assert "The kernel registers an agent that has no manifest" in TEXT
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    assert kernel.register_agent("unsponsored", "core")
    assert not (tmp_path / "sovereign" / "agents").exists()


def test_the_filter_is_a_denylist_of_the_documented_size():
    from core.kernel.sandbox import seccomp

    restricted = len(seccomp.DANGEROUS_SYSCALLS)
    strict = restricted + len(seccomp.NETWORK_SYSCALLS + seccomp.PROCESS_SYSCALLS)
    assert (
        f"refuses {restricted} system calls (`restricted`) or {strict} (`strict`)"
        in TEXT
    )
    # The filter's last instruction allows what the list did not name.
    assert "insns += _bpf_stmt(BPF_RET, SECCOMP_RET_ALLOW)" in _source(
        "sandbox", "seccomp.py"
    )


def test_limits_are_per_process_with_no_cgroup_or_cpu_limit():
    assert "There is no cgroup and no CPU-time limit" in TEXT
    source = _source("sandbox")
    assert "RLIMIT_AS" in source and "RLIMIT_NPROC" in source
    assert "RLIMIT_CPU" not in source
    assert not re.search(r"cgroup\.procs|memory\.max\"|pids\.max\"", _source("sandbox"))


def test_filters_exist_for_two_architectures_only():
    from core.kernel.sandbox import seccomp

    assert "No filter on architectures other than x86_64 and aarch64." in TEXT
    arches = {name for name in vars(seccomp) if name.startswith("ARCH_")}
    assert arches == {"ARCH_X86_64", "ARCH_AARCH64"}


def test_agent_state_is_plaintext_by_default(tmp_path, monkeypatch):
    from core.kernel import NSBOSKernel

    assert "Agent state is plaintext by default." in TEXT
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("NGARI_ENCRYPT_STATE", raising=False)
    kernel = NSBOSKernel()
    kernel.register_agent("reader", "core")
    registry = tmp_path / "agents" / "registry" / "registry.json"
    assert '"reader"' in registry.read_text()


def test_key_material_is_not_locked_in_memory():
    assert "Key material is not locked in memory." in TEXT
    assert not re.search(r"\bmlock(all)?\b", _source())


def test_nothing_is_sent_between_machines():
    assert "No sync between machines." in TEXT
    imports = re.findall(
        r"^(?:import|from) (\w+)", _source("network_sync"), re.MULTILINE
    )
    assert not {"socket", "ssl", "http", "requests", "urllib"} & set(imports)


def test_models_are_not_signed_or_verified():
    assert "Models are not signed or verified" in TEXT
    import dataclasses

    from core.kernel.inference import ModelInfo

    fields = {field.name for field in dataclasses.fields(ModelInfo)}
    assert not fields & {"sha256", "digest", "checksum", "signature", "manifest"}
    assert not re.search(r"sha256|hashlib|\.verify\(", _source("inference"))


def test_nothing_in_the_kernel_runs_the_task_queue():
    assert "The kernel stores tasks and does not run them." in TEXT
    callers = [
        path.name
        for path in KERNEL.rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "process_queue"
    ]
    assert callers == []


@pytest.mark.parametrize("word", ["RBAC at kernel level", "mesh,", "zero-knowledge"])
def test_the_code_makes_no_claim_the_page_contradicts(word):
    assert word not in _source()
