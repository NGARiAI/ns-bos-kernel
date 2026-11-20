"""ARCHITECTURE.md against the code: the names, paths, settings and limits
it states are checked here, so the page cannot drift from the kernel."""

import ast
import json
import re
from pathlib import Path

import pytest

from core.kernel import NSBOSKernel
from core.kernel.agent_runtime import AgentStateEnum, TaskPriority
from core.kernel.hal import PlatformType
from core.kernel.network_sync import SyncMode

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "ARCHITECTURE.md").read_text()
KERNEL = ROOT / "core" / "kernel"


def _listed(enum_name):
    m = re.search(rf"{enum_name}(?: enum)? \(([^)]*)\)", DOC.replace("\n │", " "))
    return [n.strip() for n in re.split(r"[,\s]+", m.group(1)) if n.strip()]


@pytest.mark.parametrize(
    ("name", "enum"), [("PlatformType", PlatformType), ("SyncMode", SyncMode)]
)
def test_enum_members_are_the_documented_ones(name, enum):
    assert _listed(name) == [m.name for m in enum]


def test_the_task_flow_names_real_methods():
    from core.kernel.agent_runtime import TaskScheduler

    for method in re.findall(r"TaskScheduler\.(\w+)\(\)", DOC):
        assert hasattr(TaskScheduler, method), method


@pytest.fixture
def booted(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    agent_id = kernel.register_agent("CEO", "core", "x")
    kernel.agent_runtime.registry.get_agent(agent_id).memory["note"] = "plain"
    kernel.agent_runtime.registry.save_registry()
    kernel.create_task(agent_id, "x", {"secret": "task-payload"})
    return tmp_path


def _readable_json(path: Path) -> bool:
    try:
        json.loads(path.read_text())
    except (ValueError, UnicodeDecodeError):
        return False
    return True


def test_agent_and_task_state_are_plaintext_unless_state_encryption_is_on(booted):
    assert "plaintext by default; encrypted with `NGARI_ENCRYPT_STATE=1`" in " ".join(
        DOC.replace("Plaintext", "plaintext").split()
    )
    assert _readable_json(booted / "agents" / "registry" / "registry.json")
    assert "task-payload" in (booted / "agents" / "tasks" / "tasks.json").read_text()


def test_the_audit_log_is_where_the_data_layout_says(booted):
    assert "`sovereign/audit/sovereign_audit.log`" in DOC
    assert (booted / "sovereign" / "audit" / "sovereign_audit.log").exists()


@pytest.mark.parametrize(
    "path",
    ["sovereign/keys", "sovereign/encrypted", "agents/registry", "agents/tasks",
     "agents/comm", "sync"],
)  # fmt: skip
def test_the_data_layout_names_directories_the_kernel_makes(booted, path):
    assert f"`{path}/`" in DOC
    assert (booted / path).is_dir()


def _source():
    return "\n".join(
        p.read_text() for p in KERNEL.rglob("*.py") if "build" not in p.parts
    )


def test_no_feature_the_kernel_lacks_is_described():
    # Peer discovery, a transport between nodes and payments are not in the
    # kernel, and the page says so or does not mention them.
    assert "no peer discovery and no transport between nodes" in " ".join(DOC.split())
    assert not re.search(r"mdns|zeroconf|5353", _source(), re.IGNORECASE)
    assert "Wallet" not in DOC and "class Wallet" not in _source()


def test_the_application_runs_the_task_queue():
    assert "The kernel stores tasks and does not run them." in " ".join(DOC.split())
    callers = []
    for path in KERNEL.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "process_queue"):  # fmt: skip
                callers.append(path.name)
    assert callers == []


def test_documented_states_and_priorities_exist():
    assert {m.name for m in AgentStateEnum} >= {"RUNNING", "IDLE", "ERROR"}
    assert [m.value for m in TaskPriority] == [0, 1, 2, 3]


# -- Configuration -----------------------------------------------------------------

CONFIG = DOC.split("## Configuration", 1)[1].split("\n## ", 1)[0]
DOCUMENTED = dict(
    re.findall(r"^\| `(NGARI_[A-Z0-9_]+)` \| ([^|]*?) \|", CONFIG, re.MULTILINE)
)


def _read_by_the_code():
    return set(re.findall(r"\"(NGARI_[A-Z0-9_]+)\"", _source()))


def test_every_variable_the_code_reads_is_documented():
    elsewhere = "\n".join(p.read_text() for p in (ROOT / "docs").glob("*.md"))
    missing = [
        v for v in _read_by_the_code() if v not in DOCUMENTED and v not in elsewhere
    ]
    assert missing == []


def test_the_documented_defaults_hold(monkeypatch, tmp_path):
    from core.kernel.data_plane import keys, tpm
    from core.kernel.data_plane.keys_cli import sovereign_dir

    monkeypatch.setenv("HOME", str(tmp_path))
    assert DOCUMENTED["NGARI_DATA_DIR"] == "`~/.ngari/kernel/`"
    assert sovereign_dir({}).parent == tmp_path / ".ngari" / "kernel"
    assert DOCUMENTED["NGARI_KEY_PROVIDER"] == f"`{keys.DEFAULT_PROVIDER}`"
    assert type(keys.provider_from_env(tmp_path, {})).__name__ == "FileKeyProvider"
    from core.kernel import inference

    assert DOCUMENTED["NGARI_AIR_GAP"] == "`true`"
    assert inference.air_gap_enabled({}) is True
    assert DOCUMENTED["NGARI_TPM_TCTI"] == f"`{tpm.DEFAULT_TCTI}`"
    assert DOCUMENTED["NGARI_TPM_TIMEOUT"] == f"`{int(tpm.DEFAULT_TIMEOUT)}`"
    provider = tpm.TPMKeyProvider.from_env(tmp_path / "keys", {})
    assert (provider.tcti, provider.timeout) == (tpm.DEFAULT_TCTI, tpm.DEFAULT_TIMEOUT)


def test_every_documented_variable_is_read_by_the_code():
    documented = set(re.findall(r"`(NGARI_[A-Z0-9_]+)`", CONFIG))
    assert len(documented) >= 12
    assert documented - _read_by_the_code() == set()


def test_configuration_is_the_environment_alone():
    assert "takes no options" in " ".join(CONFIG.split())
    assert not re.search(r"dotenv|[\"']\.env[\"']", _source())
    assert "argparse" not in (KERNEL / "__init__.py").read_text()


# -- Where each component keeps its files when built without a directory -------------


def _components():
    from core.kernel.agent_runtime import AgentRuntime
    from core.kernel.data_plane import SovereignDataPlane
    from core.kernel.generative_ui import GenerativeUIEngine
    from core.kernel.inference import ModelRegistry
    from core.kernel.network_sync import NetworkSynchronization

    return {
        "data_plane": (lambda: SovereignDataPlane().data_dir, "sovereign"),
        "agent_runtime": (
            lambda: AgentRuntime().registry.registry_dir,
            "agents/registry",
        ),
        "network_sync": (lambda: NetworkSynchronization().sync_dir, "sync"),
        "model_registry": (lambda: ModelRegistry().registry_dir, "models"),
        "generative_ui": (lambda: GenerativeUIEngine().ui_dir, "ui"),
    }


@pytest.mark.parametrize(
    ("component", "env_set"),
    [(c, e) for c in ("data_plane", "agent_runtime", "network_sync", "model_registry",
                      "generative_ui") for e in (True, False)],
)  # fmt: skip
def test_a_component_built_alone_uses_its_own_default_directory(
    monkeypatch, tmp_path, component, env_set
):
    # The page says a component built outside NSBOSKernel has its own default,
    # not always the kernel's path for it. These are those defaults.
    root = tmp_path / ("data" if env_set else "home/.ngari/kernel")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    if env_set:
        monkeypatch.setenv("NGARI_DATA_DIR", str(root))
    else:
        monkeypatch.delenv("NGARI_DATA_DIR", raising=False)
    assert "pass the directory explicitly to share the kernel's files" in " ".join(
        DOC.split()
    )
    where, _ = _components()[component]
    own = {
        ("data_plane", True): root, ("data_plane", False): root,
        ("agent_runtime", True): root / "registry",
        ("agent_runtime", False): root / "registry",
        ("network_sync", True): root, ("network_sync", False): root / "sync",
        ("model_registry", True): root, ("model_registry", False): root / "models",
        ("generative_ui", True): root / "ui", ("generative_ui", False): root / "ui",
    }  # fmt: skip
    assert where() == own[(component, env_set)]
