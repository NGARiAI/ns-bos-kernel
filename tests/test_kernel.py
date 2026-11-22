"""NSBOSKernel's public API, in process: lifecycle, status, agents, tasks
and events."""

import json

import pytest

from core.kernel import NSBOSKernel, TaskPriority


@pytest.fixture
def kernel(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    return NSBOSKernel()


def test_start_and_stop_are_recorded_in_the_twin(kernel):
    kernel.start()
    assert kernel.running
    assert kernel.network_sync.get_twin_value("kernel.status") == "running"
    assert (
        kernel.network_sync.get_twin_value("kernel.version")
        == kernel.get_status()["kernel"]["version"]
    )
    kernel.stop()
    assert not kernel.running
    assert kernel.network_sync.get_twin_value("kernel.status") == "stopped"


def test_status_reports_every_section(kernel):
    kernel.register_agent("CEO", "strategic")
    kernel.start()
    status = kernel.get_status()
    assert set(status) == {"kernel", "hardware", "agents", "fleet", "data_sovereignty"}
    assert status["kernel"]["status"] == "running"
    assert status["kernel"]["uptime_seconds"] >= 0
    assert status["agents"]["agents"] == 1
    assert status["fleet"]["total_nodes"] == 0
    assert status["data_sovereignty"]["data_sovereignty"] == "enforced"
    assert status["data_sovereignty"]["audit_integrity"] is True
    json.dumps(status)  # the status is plain data
    kernel.stop()
    assert kernel.get_status()["kernel"]["status"] == "stopped"


def test_kernel_state_is_stored_encrypted_at_every_start(kernel, tmp_path):
    state = kernel.data_plane.retrieve_decrypted("kernel_state")
    assert state["version"] == kernel.get_status()["kernel"]["version"]
    raw = (tmp_path / "sovereign" / "encrypted" / "kernel_state.enc").read_bytes()
    assert b"version" not in raw


def test_registering_an_agent_updates_the_twin(kernel):
    agent_id = kernel.register_agent("CEO", "strategic", "oversight")
    assert kernel.network_sync.get_twin_value("agent.CEO") == {
        "agent_id": agent_id, "type": "strategic", "status": "registered"
    }  # fmt: skip


def test_tasks_through_the_kernel(kernel):
    agent_id = kernel.register_agent("Worker", "execution")
    task_id = kernel.create_task(agent_id, "ship", {"order": 7}, TaskPriority.HIGH)
    pending = kernel.agent_runtime.scheduler.get_pending_tasks()
    assert [t.task_id for t in pending] == [task_id]
    assert kernel.get_status()["agents"]["pending_tasks"] == 1


def test_events_through_the_kernel(kernel):
    got = []
    kernel.subscribe_event("orders", got.append)
    kernel.publish_event("orders", {"id": 7})
    assert got == [{"id": 7}]
    assert kernel.agent_runtime.comm.get_messages("orders")[0]["message"] == {"id": 7}


def _uptime(kernel):
    return kernel.get_status()["kernel"]["uptime_seconds"]


def test_uptime_counts_from_start_and_is_zero_when_stopped(kernel, monkeypatch):
    import core.kernel as kernel_mod

    clock = [1000.0]
    monkeypatch.setattr(kernel_mod.time, "monotonic", lambda: clock[0])
    clock[0] = 5000.0  # time since construction must not count
    assert _uptime(kernel) == 0.0
    kernel.start()
    clock[0] += 42.5
    assert _uptime(kernel) == 42.5
    kernel.stop()
    clock[0] += 100
    assert _uptime(kernel) == 0.0
    kernel.start()
    clock[0] += 3
    assert _uptime(kernel) == 3.0


def test_uptime_ignores_the_wall_clock(kernel, monkeypatch):
    # A board without a real-time clock can have its time set backwards or
    # forwards while running; uptime must not jump with it.
    import datetime as real_datetime

    import core.kernel as kernel_mod

    kernel.start()
    before = _uptime(kernel)

    class Jumped(real_datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.datetime(1970, 1, 2, tzinfo=tz)

    monkeypatch.setattr(kernel_mod, "datetime", Jumped)
    after = _uptime(kernel)
    assert 0 <= before <= after < before + 5


# -- a state file nested too deep is set aside -----------------------------------------

_DEEP = "[" * 100_000 + "]" * 100_000


def _agents(d):
    from core.kernel.agent_runtime import AgentRegistry

    (d / "registry.json").write_text(_DEEP)
    return d / "registry.json", AgentRegistry(str(d)).agents


def _tasks(d):
    from core.kernel.agent_runtime import TaskScheduler

    (d / "tasks.json").write_text(_DEEP)
    return d / "tasks.json", TaskScheduler(str(d)).tasks


def _layout(d):
    from core.kernel.generative_ui import GenerativeUIEngine

    (d / "ui" / "layouts").mkdir(parents=True)
    (d / "ui" / "layouts" / "x_web.json").write_text(_DEEP)
    return d / "ui" / "layouts" / "x_web.json", GenerativeUIEngine(str(d)).layouts


def _behavior(d):
    from core.kernel.generative_ui import GenerativeUIEngine

    (d / "ui" / "behavior").mkdir(parents=True)
    (d / "ui" / "behavior" / "u.json").write_text(_DEEP)
    return d / "ui" / "behavior" / "u.json", GenerativeUIEngine(str(d)).user_behaviors


def _models(d):
    from core.kernel.inference import ModelRegistry

    (d / "registry.json").write_text(_DEEP)
    return d / "registry.json", ModelRegistry(str(d)).models


@pytest.mark.parametrize("make", [_agents, _tasks, _layout, _behavior, _models])
def test_a_state_file_nested_too_deep_is_set_aside(tmp_path, monkeypatch, make):
    # RecursionError from the decoder counts as unreadable, so the component,
    # and with the agent files the kernel, still starts.
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path / "unused"))
    path, loaded = make(tmp_path)
    assert loaded == {}
    assert not path.exists()
    assert len(list(path.parent.glob(f"{path.name}.corrupt-*"))) == 1


def test_the_kernel_starts_over_agent_files_nested_too_deep(tmp_path, monkeypatch):
    monkeypatch.delenv("NGARI_KEY_PROVIDER", raising=False)
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    for name in ("registry", "tasks"):
        (tmp_path / "agents" / name).mkdir(parents=True)
        (tmp_path / "agents" / name / f"{name}.json").write_text(_DEEP)
    kernel = NSBOSKernel()
    kernel.start()
    try:
        assert kernel.register_agent("CEO", "strategic", "x")
    finally:
        kernel.stop()


# -- a state file the decoder reads and asdict cannot save -----------------------------


def _below_the_decoder_limit(depth=3000):
    """An object nested depth deep that json.loads still reads (3.12 and later
    read about 10,000 levels) and dataclasses.asdict, which gives up near
    500, cannot write back."""
    text = '{"a":' * depth + "1" + "}" * depth
    try:
        json.loads(text)
    except RecursionError:
        pytest.skip(
            "this Python's decoder refuses it; the nested-too-deep tests cover that"
        )
    return text


def test_an_agent_registry_that_cannot_be_saved_again_is_set_aside(
    tmp_path, monkeypatch
):
    # A registry that cannot be written back is set aside at load, so the
    # first save, in AgentRuntime.start(), succeeds.
    monkeypatch.delenv("NGARI_KEY_PROVIDER", raising=False)
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    registry = tmp_path / "agents" / "registry"
    registry.mkdir(parents=True)
    config = '{"config": {"name": "CEO", "agent_type": "strategic", "environment": '
    (registry / "registry.json").write_text(
        '{"x": ' + config + _below_the_decoder_limit() + "}}}"
    )
    kernel = NSBOSKernel()
    kernel.start()
    try:
        assert kernel.register_agent("CEO", "strategic", "x")
    finally:
        kernel.stop()
    assert len(list(registry.glob("registry.json.corrupt-*"))) == 1


def test_a_task_file_that_cannot_be_saved_again_is_set_aside(tmp_path):
    from core.kernel.agent_runtime import TaskScheduler

    task = '{"task_id": "t", "agent_id": "a", "action": "echo", "payload": '
    (tmp_path / "tasks.json").write_text(
        '{"t": ' + task + _below_the_decoder_limit() + "}}"
    )
    scheduler = TaskScheduler(str(tmp_path))
    assert scheduler.tasks == {}
    assert len(list(tmp_path.glob("tasks.json.corrupt-*"))) == 1
    scheduler.create_task("agent", "echo", {})  # saves


def test_a_deep_registry_that_can_be_saved_is_kept(tmp_path):
    # Deeper than new payloads and configs may be, but it saves: kept unchanged.
    from core.kernel.agent_runtime import AgentRegistry

    deep = '{"a":' * 100 + "1" + "}" * 100
    (tmp_path / "registry.json").write_text(
        '{"x": {"config": {"name": "CEO", "agent_type": "s", "environment": '
        + deep + "}}}"
    )  # fmt: skip
    registry = AgentRegistry(str(tmp_path))
    assert list(registry.agents) == ["x"]
    registry.save_registry()


def test_a_model_registry_that_cannot_be_saved_again_is_set_aside(tmp_path):
    # Set aside at load, so a later register_model or remove_model can save.
    from core.kernel.inference import InferenceEngine, ModelInfo, ModelRegistry

    model = {
        "name": "m", "engine": "ollama", "size_gb": 1.0, "parameters": "7B",
        "context_length": 1, "quantization": "q4", "status": "available",
    }  # fmt: skip
    text = json.dumps({"m": model})[:-2] + ', "last_used": '
    (tmp_path / "registry.json").write_text(text + _below_the_decoder_limit() + "}}")
    registry = ModelRegistry(str(tmp_path))
    assert registry.models == {}
    assert len(list(tmp_path.glob("registry.json.corrupt-*"))) == 1
    registry.register_model(
        ModelInfo("n", InferenceEngine.OLLAMA, 1.0, "7B", 1, "q4", "available")
    )


def test_ui_files_that_cannot_be_saved_again_are_set_aside(tmp_path):
    # Set aside at load, so export_layout and saves of a layout, and the
    # next interaction on a behaviour record, do not raise.
    from core.kernel.generative_ui import GenerativeUIEngine

    deep = _below_the_decoder_limit()
    layouts, behavior = tmp_path / "ui" / "layouts", tmp_path / "ui" / "behavior"
    layouts.mkdir(parents=True)
    behavior.mkdir(parents=True)
    component = (
        '{"component_type": "card", "id": "a", "label": "l", "data_source": "s", '
        '"properties": ' + deep + "}"
    )
    (layouts / "x_web.json").write_text(
        '{"layout_id": "x_web", "context": "x", "platform": "web", "components": ['
        + component + "]}"
    )  # fmt: skip
    (behavior / "u.json").write_text(
        '{"user_id": "u", "most_used_components": {}, "least_used_components": '
        + deep + "}"
    )  # fmt: skip
    engine = GenerativeUIEngine(str(tmp_path))
    assert engine.layouts == {} and engine.user_behaviors == {}
    assert len(list(layouts.glob("x_web.json.corrupt-*"))) == 1
    assert len(list(behavior.glob("u.json.corrupt-*"))) == 1
    engine.track_interaction("u", "a")
    assert engine.export_layout(engine.generate_layout("x", "web").layout_id)
