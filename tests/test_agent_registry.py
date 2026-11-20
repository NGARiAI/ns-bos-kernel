"""Agent registration is idempotent by name: rebooting must not grow the
registry, and an agent keeps its id and what it has accumulated."""

import json

import pytest

from core.kernel.agent_runtime import AgentConfig, AgentRegistry, AgentStateEnum

CORE = ["CEO", "CRO", "Engineer", "Worker", "Email", "Communications"]


def _boot(path):
    registry = AgentRegistry(str(path))
    return registry, {n: registry.register_agent(AgentConfig(n, "core")) for n in CORE}


def test_four_boots_leave_six_agents(tmp_path):
    first = None
    for _ in range(4):
        registry, ids = _boot(tmp_path)
        first = first or ids
        assert ids == first
    assert len(registry.list_agents()) == 6
    on_disk = json.loads((tmp_path / "registry.json").read_text())
    assert sorted(a["config"]["name"] for a in on_disk.values()) == sorted(CORE)


def test_a_reregistered_agent_keeps_its_state(tmp_path):
    registry, ids = _boot(tmp_path)
    agent = registry.get_agent(ids["CEO"])
    agent.memory["goal"] = "revenue"
    agent.tasks_completed = 7
    registry.update_agent_state(ids["CEO"], AgentStateEnum.RUNNING)

    again, ids2 = _boot(tmp_path)
    kept = again.get_agent(ids2["CEO"])
    assert ids2["CEO"] == ids["CEO"]
    assert kept.memory == {"goal": "revenue"}
    assert kept.tasks_completed == 7
    assert kept.state == AgentStateEnum.RUNNING


def test_a_changed_config_is_taken_and_saved(tmp_path):
    registry = AgentRegistry(str(tmp_path))
    agent_id = registry.register_agent(AgentConfig("CEO", "strategic", description="a"))
    assert (
        registry.register_agent(AgentConfig("CEO", "strategic", description="b"))
        == agent_id
    )
    reloaded = AgentRegistry(str(tmp_path))
    assert reloaded.get_agent(agent_id).config.description == "b"


def test_an_unchanged_reregistration_does_not_rewrite_the_file(tmp_path, monkeypatch):
    registry = AgentRegistry(str(tmp_path))
    registry.register_agent(AgentConfig("CEO", "core"))
    saves = []
    monkeypatch.setattr(registry, "save_registry", lambda: saves.append(1))
    registry.register_agent(AgentConfig("CEO", "core"))
    assert saves == []


def test_names_are_exact(tmp_path):
    registry = AgentRegistry(str(tmp_path))
    a = registry.register_agent(AgentConfig("ceo", "core"))
    b = registry.register_agent(AgentConfig("CEO", "core"))
    assert a != b


@pytest.mark.parametrize("order", [("old", "new"), ("new", "old")])
def test_old_duplicates_resolve_to_the_oldest_and_are_kept(tmp_path, order):
    entries = {
        "old": {"config": {"name": "CEO", "agent_type": "core"},
                "started_at": "2026-01-01T00:00:00+00:00"},
        "new": {"config": {"name": "CEO", "agent_type": "core"},
                "started_at": "2026-06-01T00:00:00+00:00"},
    }  # fmt: skip
    data = {f"id-{k}": entries[k] for k in order}
    (tmp_path / "registry.json").write_text(json.dumps(data))
    registry = AgentRegistry(str(tmp_path))
    assert registry.register_agent(AgentConfig("CEO", "core")) == "id-old"
    assert len(registry.list_agents()) == 2


def test_kernel_boots_do_not_grow_the_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    from core.kernel import NSBOSKernel

    ids = None
    for _ in range(4):
        kernel = NSBOSKernel()
        now = {n: kernel.register_agent(n, "core") for n in CORE}
        ids = ids or now
        assert now == ids
        assert len(kernel.agent_runtime.registry.list_agents()) == 6


@pytest.mark.parametrize("bad", [0, None, ["2025"]], ids=repr)
@pytest.mark.parametrize("order", [("odd", "good"), ("good", "odd")])
def test_a_duplicate_with_an_odd_start_time_does_not_stop_registration(
    tmp_path, order, bad
):
    entries = {
        "good": {"config": {"name": "CEO", "agent_type": "core"},
                 "started_at": "2026-06-01T00:00:00+00:00"},
        "odd": {"config": {"name": "CEO", "agent_type": "core"}, "started_at": bad},
    }  # fmt: skip
    data = {f"id-{k}": entries[k] for k in order}
    (tmp_path / "registry.json").write_text(json.dumps(data))
    registry = AgentRegistry(str(tmp_path))
    assert len(registry.list_agents()) == 2
    # The entry with a real start time wins, whatever the other one holds.
    assert registry.register_agent(AgentConfig("CEO", "core")) == "id-good"


def test_odd_values_elsewhere_in_an_entry_still_load(tmp_path):
    # A v0.1.0 registry holds AgentConfig values as the application passed
    # them; it must keep loading, not be set aside with every agent in it.
    data = {"id-a": {"config": {"name": "CEO", "agent_type": "core", "version": 2,
                                "max_memory_mb": 512.5},
                     "memory": {"note": "kept"}, "tasks_completed": "3"}}  # fmt: skip
    (tmp_path / "registry.json").write_text(json.dumps(data))
    registry = AgentRegistry(str(tmp_path))
    assert registry.get_agent("id-a").memory == {"note": "kept"}
    assert registry.register_agent(AgentConfig("CEO", "core", version=2,
                                               max_memory_mb=512.5)) == "id-a"  # fmt: skip
