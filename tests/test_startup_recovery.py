"""Every JSON file the kernel loads at start must survive a crash mid-write,
and an unreadable one must not stop the kernel from starting."""

import os

import pytest

from core.kernel import NSBOSKernel
from core.kernel.agent_runtime import AgentConfig, AgentRegistry
from core.kernel.network_sync import NetworkSynchronization

STARTUP_FILES = [
    "agents/registry/registry.json",
    "agents/tasks/tasks.json",
    "sync/digital_twin.json",
    "sync/fleet.json",
]


@pytest.fixture
def booted(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    kernel.register_agent("CEO", "core")
    kernel.create_task(next(iter(kernel.agent_runtime.registry.agents)), "x", {})
    import sys

    # The kernel imports its modules flat; use its own copy of FleetNode.
    FleetNode = sys.modules[type(kernel.network_sync).__module__].FleetNode
    kernel.network_sync.register_node(FleetNode("n1", "h", "p", "127.0.0.1"))
    return tmp_path


@pytest.mark.parametrize("rel", STARTUP_FILES)
def test_a_truncated_startup_file_does_not_stop_the_kernel(booted, rel, caplog):
    path = booted / rel
    assert path.exists(), rel
    original = path.read_text()
    path.write_text(original[: len(original) // 2])
    NSBOSKernel()
    kept = list(path.parent.glob(f"{path.name}.corrupt-*"))
    assert len(kept) == 1, rel
    assert kept[0].read_text() == original[: len(original) // 2]
    assert "unreadable" in caplog.text


def _crash_on_write(monkeypatch):
    """The new contents are written, then syncing them fails, as on a full
    disk: the rename that would replace the old file never happens."""

    def full_disk(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full_disk)


def test_a_crash_while_saving_the_registry_keeps_the_old_one(tmp_path, monkeypatch):
    registry = AgentRegistry(str(tmp_path))
    agent_id = registry.register_agent(AgentConfig("CEO", "core"))
    before = (tmp_path / "registry.json").read_bytes()
    _crash_on_write(monkeypatch)
    with pytest.raises(OSError):
        registry.register_agent(AgentConfig("CRO", "core"))
    monkeypatch.undo()
    assert (tmp_path / "registry.json").read_bytes() == before
    assert list(AgentRegistry(str(tmp_path)).agents) == [agent_id]


def test_a_crash_while_saving_the_twin_keeps_the_old_one(tmp_path, monkeypatch):
    sync = NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.a", 1)
    before = (tmp_path / "digital_twin.json").read_bytes()
    _crash_on_write(monkeypatch)
    with pytest.raises(OSError):
        sync.update_twin("pref.a", 2)
    monkeypatch.undo()
    assert (tmp_path / "digital_twin.json").read_bytes() == before
    assert NetworkSynchronization(str(tmp_path)).get_twin_value("pref.a") == 1


def test_a_registry_with_a_bad_entry_is_set_aside_whole(tmp_path):
    (tmp_path / "registry.json").write_text('{"a1": {"state": "running"}}')
    registry = AgentRegistry(str(tmp_path))
    assert registry.agents == {}
    assert len(list(tmp_path.glob("registry.json.corrupt-*"))) == 1
