"""The kernel imports its modules flat (agent_runtime, network_sync) while
callers import core.kernel.agent_runtime and core.kernel.network_sync: two
copies, two enum classes. Values from either copy must work with the kernel."""

import sys

import pytest

from core.kernel import NSBOSKernel
from core.kernel.agent_runtime import TaskPriority
from core.kernel.network_sync import FleetNode, SyncMode


@pytest.fixture
def kernel(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    return NSBOSKernel()


def test_the_kernel_really_uses_another_copy(kernel):
    flat = sys.modules[type(kernel.network_sync).__module__]
    assert flat.SyncMode is not SyncMode  # otherwise these tests prove nothing


def test_a_package_priority_works_with_the_kernel(kernel, tmp_path):
    agent_id = kernel.register_agent("CEO", "core")
    task_id = kernel.create_task(agent_id, "x", {}, TaskPriority.HIGH)
    again = NSBOSKernel()
    assert again.agent_runtime.scheduler.tasks[task_id].priority.value == 2
    assert again.agent_runtime.scheduler.get_pending_tasks()[0].task_id == task_id


def test_a_package_sync_mode_works_with_the_kernel(kernel, monkeypatch):
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    kernel.network_sync.register_node(
        FleetNode("n1", "h", "p", "127.0.0.1", sync_mode=SyncMode.PEER_TO_PEER)
    )
    kernel.network_sync.set_sync_mode(SyncMode.HYBRID)
    flat = sys.modules[type(kernel.network_sync).__module__].SyncMode
    assert kernel.network_sync.sync_mode is flat.HYBRID
    assert kernel.network_sync.fleet_nodes["n1"].sync_mode is flat.PEER_TO_PEER
    again = NSBOSKernel()
    assert again.network_sync.fleet_nodes["n1"].sync_mode.value == "peer_to_peer"


def test_plain_values_are_accepted_too(kernel):
    agent_id = kernel.register_agent("CEO", "core")
    task_id = kernel.create_task(agent_id, "x", {}, 3)
    assert kernel.agent_runtime.scheduler.tasks[task_id].priority.name == "CRITICAL"
    with pytest.raises(ValueError):
        kernel.create_task(agent_id, "x", {}, 9)


def test_an_agent_state_from_the_other_module_copy_is_stored_as_ours(kernel):
    import core.kernel.agent_runtime as dotted

    registry = kernel.agent_runtime.registry
    flat = type(registry.get_agent(kernel.register_agent("A", "t")).state)
    agent_id = kernel.register_agent("B", "t")
    assert flat is not dotted.AgentStateEnum
    registry.update_agent_state(agent_id, dotted.AgentStateEnum.PAUSED)
    state = registry.get_agent(agent_id).state
    assert type(state) is flat and state.value == "paused"
    registry.update_agent_state(agent_id, "idle")  # a plain value too
    assert registry.get_agent(agent_id).state.value == "idle"


def test_start_finds_agents_set_initializing_through_the_other_copy(kernel):
    import core.kernel.agent_runtime as dotted

    registry = kernel.agent_runtime.registry
    agent_id = kernel.register_agent("A", "t")
    registry.update_agent_state(agent_id, dotted.AgentStateEnum.RUNNING)
    registry.update_agent_state(agent_id, dotted.AgentStateEnum.INITIALIZING)
    kernel.start()
    assert registry.get_agent(agent_id).state.value == "running"
    status = kernel.agent_runtime.get_status()
    assert status["agents_by_state"]["running"] == 1
    assert status["agents_by_state"]["initializing"] == 0


def test_an_unchanged_registration_through_the_other_class_copy_changes_nothing(
    kernel, monkeypatch
):
    import core.kernel.agent_runtime as dotted

    registry = kernel.agent_runtime.registry
    agent_id = kernel.register_agent("CEO", "strategic")
    saves = []
    monkeypatch.setattr(registry, "save_registry", lambda: saves.append(1))
    again = registry.register_agent(dotted.AgentConfig("CEO", "strategic"))
    assert again == agent_id and saves == []
    changed = registry.register_agent(
        dotted.AgentConfig("CEO", "strategic", max_restarts=9)
    )
    assert changed == agent_id and saves == [1]
