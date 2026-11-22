"""core/kernel/README.md, the module reference, against the code.

Its code blocks are parsed: every import must work, and every
`name.method(...)` call must name a method of the class `name` was built
from. Return values and fields it describes are checked where the code
can say."""

import ast
import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "core" / "kernel"
DOC = (KERNEL / "README.md").read_text()

QUOTED = [
    "# SandboxResult: exit_code, stdout, stderr, elapsed_seconds, truncated, error",
    "mgr.get_status()  # → {available_engines: [...], registered_models: n, ...}",
    "(`restricted` 36 syscalls / `strict` 54)",
    "| Jetson AGX Orin | `JetsonHAL` | Ollama (native) | Active | Local only |",
    "| Cloud VM | `X86HAL`* | vLLM | Active | Local only |",
    "**States:** INITIALIZING → RUNNING → IDLE → PAUSED → ERROR → TERMINATED",
    "**Modes:** LOCAL_ONLY | PEER_TO_PEER | CLOUD_SYNC | HYBRID",
    "dp.export_compliance_report()  # → {encryption, audit_entries, ...}",
    "hal.get_temperature()  # → dict {zone: celsius}",
]

# Functions in the reference that return an instance of one of these.
FACTORIES = {
    "create_hal": ("core.kernel.hal", ["JetsonHAL", "X86HAL"]),
    "get_sandbox": ("core.kernel.sandbox", ["BwrapSandbox"]),
}


def _blocks() -> list[ast.Module]:
    return [ast.parse(b) for b in re.findall(r"```python\n(.*?)```", DOC, re.DOTALL)]


def _method_calls() -> list[tuple[str, str, list[tuple[str, str]]]]:
    """(variable, method, [(module, class), ...]) for each call in the code."""
    found = []
    for tree in _blocks():
        imported = {
            alias.name: node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        bound = {}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                continue
            func = node.value.func
            if not isinstance(func, ast.Name):
                continue
            if func.id in FACTORIES:
                module, classes = FACTORIES[func.id]
                kinds = [(module, c) for c in classes]
            elif func.id in imported:
                kinds = [(imported[func.id], func.id)]
            else:
                continue
            for target in node.targets:
                bound[target.id] = kinds
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in bound
            ):
                var = node.func.value.id
                found.append((var, node.func.attr, bound[var]))
    return found


def test_every_quoted_reference_is_still_in_the_document():
    assert [q for q in QUOTED if q not in DOC] == []


def test_every_import_in_the_reference_works():
    names = [
        (node.module, alias.name)
        for tree in _blocks()
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    ]
    assert len(names) >= 13
    missing = [(m, n) for m, n in names if not hasattr(importlib.import_module(m), n)]
    assert missing == []


def test_every_method_the_reference_calls_exists():
    calls = _method_calls()
    assert len(calls) >= 25, calls
    missing = [
        f"{cls}.{method}"
        for _, method, kinds in calls
        for module, cls in kinds
        if not hasattr(getattr(importlib.import_module(module), cls), method)
    ]
    assert missing == []


def test_the_documented_values_hold(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    from core.kernel.agent_runtime import AgentStateEnum
    from core.kernel.data_plane import SovereignDataPlane
    from core.kernel.hal import PlatformType, create_hal, detect_platform
    from core.kernel.inference import InferenceEngineManager
    from core.kernel.network_sync import NetworkSynchronization, SyncMode

    assert isinstance(detect_platform(), PlatformType)
    hal = create_hal()
    assert isinstance(hal.get_temperature(), dict)
    assert all(
        isinstance(v, float) and 0 <= v <= 100
        for v in (hal.get_gpu_utilization(), hal.get_memory_utilization())
    )
    report = SovereignDataPlane(str(tmp_path / "dp")).export_compliance_report()
    assert {"encryption", "audit_entries"} <= set(report)
    assert "models" in InferenceEngineManager().get_status()
    assert hasattr(NetworkSynchronization, "import_twin")
    states = re.search(r"\*\*States:\*\* (.*)", DOC).group(1).split(" → ")
    assert states == [m.name for m in AgentStateEnum]
    modes = re.search(r"\*\*Modes:\*\* (.*)", DOC).group(1).split(" | ")
    assert modes == [m.name for m in SyncMode]


@pytest.mark.parametrize(
    ("platform", "hal_class"),
    [("JETSON_AGX_ORIN", "JetsonHAL"), ("JETSON_NANO", "JetsonHAL"),
     ("X86_64", "X86HAL"), ("RASPBERRY_PI", "X86HAL"), ("CLOUD_VM", "X86HAL")],
)  # fmt: skip
def test_the_platform_table_names_the_hal_each_platform_gets(
    monkeypatch, platform, hal_class
):
    from core.kernel import hal

    monkeypatch.setattr(hal, "detect_platform", lambda: hal.PlatformType[platform])
    assert type(hal.create_hal()).__name__ == hal_class
    assert re.search(rf"^\| [^|]+ \| `{hal_class}`\*? \|", DOC, re.MULTILINE)


def test_the_deployment_one_liner_runs(tmp_path):
    line = re.search(r'^python -c "(.*)"$', DOC, re.MULTILINE).group(1)
    run = subprocess.run(
        [sys.executable, "-c", line], cwd=ROOT, capture_output=True, text=True,
        timeout=120, check=False, env={"NGARI_DATA_DIR": str(tmp_path), "PATH": "/usr/bin:/bin"},
    )  # fmt: skip
    assert run.returncode == 0, run.stderr[-300:]
    assert "registered_models" in run.stdout


# -- details the reference states --------------------------------------------------


def test_sandbox_result_has_the_documented_fields():
    from core.kernel.sandbox import SandboxResult

    listed = re.search(r"# SandboxResult: (.*)", DOC).group(1).split(", ")
    assert listed == [
        "exit_code",
        "stdout",
        "stderr",
        "elapsed_seconds",
        "truncated",
        "error",
    ]
    result = SandboxResult()
    for name in listed:
        getattr(result, name)


def test_manager_status_has_the_documented_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    from core.kernel.inference import InferenceEngineManager

    status = InferenceEngineManager().get_status()
    assert "{available_engines: [...], registered_models: n, ...}" in DOC
    assert {"available_engines", "registered_models"} <= set(status)


def test_the_profiles_block_the_documented_number_of_syscalls():
    from core.kernel.sandbox.seccomp import (
        DANGEROUS_SYSCALLS,
        NETWORK_SYSCALLS,
        PROCESS_SYSCALLS,
    )

    strict = len(DANGEROUS_SYSCALLS + NETWORK_SYSCALLS + PROCESS_SYSCALLS)
    assert f"`restricted` {len(DANGEROUS_SYSCALLS)} syscalls / `strict` {strict}" in DOC


def test_no_platform_is_said_to_sync_with_other_nodes():
    source = (KERNEL / "network_sync" / "__init__.py").read_text()
    assert not re.search(
        r"^(import|from) (socket|ssl|http|requests|urllib)", source, re.MULTILINE
    )
    table = DOC.split("## Platform Status", 1)[1]
    assert "P2P" not in table and "Cloud Sync" not in table
    assert table.count("| Local only |") == 5
