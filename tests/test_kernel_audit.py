"""The kernel's own actions are in the audit chain: one keyed entry per
state change, written after the state is on disk, with ids, names, topics,
sizes and state names only. A runtime built alone records nothing."""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from core.kernel import KERNEL_ACTOR, VERSION, NSBOSKernel, TaskPriority
from core.kernel.agent_runtime import AgentConfig, AgentRuntime
from core.kernel.data_plane import audit_anchor, check_audit_chain

REPO_ROOT = Path(__file__).resolve().parent.parent
SENTINELS = {
    "description": "SENTINEL-DESCRIPTION",
    "environment": "SENTINEL-ENV",
    "payload": "SENTINEL-PAYLOAD",
    "message": "SENTINEL-MESSAGE",
    "error": "SENTINEL-ERROR",
    "result": "SENTINEL-RESULT",
}


@pytest.fixture
def kernel(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    return NSBOSKernel()


def _log(kernel):
    return [
        e for e in kernel.data_plane.get_audit_log(10**6) if e["actor"] == KERNEL_ACTOR
    ]


def _actions(kernel):
    return [e["action"] for e in _log(kernel)]


def test_each_api_call_writes_one_keyed_entry(kernel):
    agent_id = kernel.register_agent("CEO", "strategic", SENTINELS["description"])
    task_id = kernel.create_task(
        agent_id, "report", {"p": SENTINELS["payload"]}, TaskPriority.HIGH
    )
    kernel.subscribe_event("orders", lambda m: None)
    kernel.publish_event("orders", {"m": SENTINELS["message"]})
    by_action = {e["action"]: e for e in _log(kernel)}
    assert set(by_action) == {
        "agent_registered",
        "twin_updated",
        "task_created",
        "event_published",
    }
    registered = by_action["agent_registered"]
    assert (registered["resource"], registered["details"]) == (
        agent_id, {"name": "CEO", "type": "strategic", "outcome": "created"}
    )  # fmt: skip
    assert by_action["twin_updated"]["resource"] == "agent.CEO"
    assert (by_action["task_created"]["resource"], by_action["task_created"]["details"]) == (
        task_id, {"agent_id": agent_id, "action": "report", "priority": "HIGH"}
    )  # fmt: skip
    published = by_action["event_published"]
    assert published["resource"] == "orders"
    assert set(published["details"]) == {"file", "bytes", "subscribers"}
    assert published["details"]["subscribers"] == 1
    assert all("mac" in e for e in _log(kernel))
    assert kernel.data_plane.verify_audit_integrity()


def test_no_payload_description_or_error_reaches_the_log(kernel):
    agent_id = kernel.register_agent("CEO", "strategic", SENTINELS["description"])
    runtime = kernel.agent_runtime
    runtime.registry.get_agent(agent_id).config.environment["K"] = SENTINELS[
        "environment"
    ]
    runtime.registry.get_agent(agent_id).memory["m"] = SENTINELS["result"]
    runtime.scheduler.register_handler("ok", lambda p: SENTINELS["result"])

    def boom(payload):
        raise RuntimeError(SENTINELS["error"])

    runtime.scheduler.register_handler("boom", boom)
    kernel.create_task(agent_id, "ok", {"p": SENTINELS["payload"]})
    kernel.create_task(agent_id, "boom", {"p": SENTINELS["payload"]})
    kernel.publish_event("t", {"m": SENTINELS["message"]})
    asyncio.run(runtime.scheduler.process_queue())
    raw = kernel.data_plane.audit_log.read_text()
    assert [name for name, value in SENTINELS.items() if value in raw] == []


def test_start_and_stop_are_recorded_in_order(kernel):
    kernel.register_agent("CEO", "strategic")
    kernel.start()
    assert _actions(kernel)[-4:] == [
        "kernel_started", "agent_state_changed", "twin_updated", "twin_updated"
    ]  # fmt: skip
    kernel.stop()
    log = _log(kernel)
    actions = [e["action"] for e in log]
    assert actions.index("kernel_started") < actions.index("agent_state_changed")
    started = log[actions.index("kernel_started")]
    assert started["details"]["agents"] == 1 and started["resource"] == VERSION
    changed = log[actions.index("agent_state_changed")]
    assert changed["details"] == {"from": "initializing", "to": "running"}
    stopped = log[-1]
    assert (
        stopped["action"] == "kernel_stopped"
        and stopped["details"]["uptime_seconds"] >= 0
    )
    assert kernel.data_plane.verify_audit_integrity()


def test_nothing_is_written_when_nothing_changed(kernel):
    agent_id = kernel.register_agent("CEO", "strategic")
    before = len(_log(kernel))
    kernel.agent_runtime.register_agent(AgentConfig("CEO", "strategic"))  # unchanged
    kernel.agent_runtime.registry.update_agent_state(
        agent_id, "initializing"
    )  # same state
    assert len(_log(kernel)) == before
    kernel.agent_runtime.register_agent(AgentConfig("CEO", "strategic", max_restarts=9))
    assert _log(kernel)[-1]["details"]["outcome"] == "updated"


def test_task_states_follow_the_task(kernel):
    runtime = kernel.agent_runtime
    agent_id = kernel.register_agent("CEO", "strategic")
    runtime.scheduler.register_handler("ok", lambda p: 1)
    runtime.scheduler.register_handler("boom", lambda p: 1 / 0)
    ok = kernel.create_task(agent_id, "ok", {})
    bad = kernel.create_task(agent_id, "boom", {})
    missing = kernel.create_task(agent_id, "nobody", {})
    asyncio.run(runtime.scheduler.process_queue())
    moves = {}
    for e in _log(kernel):
        if e["action"] == "task_state_changed":
            moves.setdefault(e["resource"], []).append(
                (e["details"]["from"], e["details"]["to"])
            )
    assert moves[ok] == [("pending", "running"), ("running", "completed")]
    assert moves[bad] == [("pending", "running"), ("running", "error")]
    assert moves[missing] == [("pending", "error")]


def test_a_failing_append_is_not_a_task_error(kernel, monkeypatch):
    runtime = kernel.agent_runtime
    agent_id = kernel.register_agent("CEO", "strategic")
    runtime.scheduler.register_handler("ok", lambda p: 1)
    task_id = kernel.create_task(agent_id, "ok", {})

    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(kernel.data_plane, "record", full)
    with pytest.raises(OSError):
        asyncio.run(runtime.scheduler.process_queue())
    # The handler ran and the state it reached is on disk; only the record failed.
    assert runtime.scheduler.tasks[task_id].error is None


def test_a_failed_sync_leaves_no_entry(kernel, monkeypatch):
    before = len(_log(kernel))

    def full(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full)
    with pytest.raises(OSError):
        kernel.register_agent("CEO", "strategic")
    monkeypatch.undo()
    assert len(_log(kernel)) == before and kernel.data_plane.verify_audit_integrity()


def test_a_failed_append_reaches_the_caller_but_not_the_chain(kernel, monkeypatch):
    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    flat = sys.modules[type(kernel.data_plane).__module__]  # the kernel's own copy
    monkeypatch.setattr(flat, "append_audit", full)
    with pytest.raises(OSError):
        kernel.register_agent("CEO", "strategic")
    monkeypatch.undo()
    assert (
        kernel.agent_runtime.registry.find_by_name("CEO") is not None
    )  # the agent is saved
    assert kernel.data_plane.verify_audit_integrity()


def test_stop_logs_a_failed_record_and_returns(kernel, monkeypatch, caplog):
    kernel.start()

    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(kernel.data_plane, "record", full)
    kernel.stop()
    assert kernel.running is False
    assert "Cannot record the shutdown in the audit log" in caplog.text


def test_a_runtime_built_alone_writes_no_audit_log(tmp_path):
    runtime = AgentRuntime(str(tmp_path))
    agent_id = runtime.register_agent(AgentConfig("CEO", "strategic"))
    runtime.create_task(agent_id, "x", {})
    runtime.publish_event("t", {})
    runtime.start()
    assert not list(tmp_path.rglob("*audit*"))


def test_counts_and_the_tail_come_from_the_log(kernel):
    kernel.register_agent("CEO", "strategic")
    kernel.publish_event("t", {})
    counts = kernel.get_status()["kernel"]["audited_actions"]
    assert counts == {"agent_registered": 1, "twin_updated": 1, "event_published": 1}
    report = kernel.get_status()["data_sovereignty"]
    assert report["audit_tail"] == audit_anchor(kernel.data_plane.audit_log)["tail"]


def test_the_tail_survives_a_torn_log(tmp_path):
    from core.kernel.data_plane import GENESIS_HASH, SovereignDataPlane

    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    tail = plane.audit_tail()
    plane.audit_log.write_bytes(plane.audit_log.read_bytes() + b'{"torn')
    assert plane.audit_tail() == tail
    plane.audit_log.unlink()
    assert plane.audit_tail() == GENESIS_HASH


def test_record_checks_before_it_writes(tmp_path):
    from core.kernel.data_plane import SovereignDataPlane

    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    before = plane.audit_log.read_bytes()
    for bad in (("", "kernel", "r", {}), ("a", "", "r", {}), ("a", "k", 7, {}),
                ("a", "k", "r", []), ("a", "k", "r", {"x": object()})):  # fmt: skip
        with pytest.raises(TypeError):
            plane.record(*bad)
    assert plane.audit_log.read_bytes() == before


def test_two_real_boots_show_the_sequence_and_the_log_verifies(tmp_path):
    from core.kernel import KERNEL_FULL_NAME, VERSION

    started = f"{KERNEL_FULL_NAME} v{VERSION} started"
    env = {**os.environ, "NGARI_DATA_DIR": str(tmp_path), "PYTHONUNBUFFERED": "1"}
    for _ in range(2):
        proc = subprocess.Popen(
            [sys.executable, "-m", "core.kernel"], cwd=REPO_ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )  # fmt: skip
        seen = []
        for line in proc.stdout:
            seen.append(line)
            if line.rstrip().endswith(started):
                proc.terminate()
                break
        proc.wait(timeout=60)
        assert "Traceback" not in "".join(seen) + (proc.stdout.read() or "")
    log = tmp_path / "sovereign" / "audit" / "sovereign_audit.log"
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    kinds = [e["action"] for e in entries if e["actor"] == KERNEL_ACTOR]
    assert kinds.count("kernel_started") == 2 and kinds.count("kernel_stopped") == 2
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel", "audit", "verify"], cwd=REPO_ROOT,
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert run.returncode == 0, run.stderr
    assert check_audit_chain(log, None) is None


def test_a_bad_record_fails_before_it_waits_for_the_log(tmp_path):
    import fcntl
    import threading

    from core.kernel.data_plane import SovereignDataPlane

    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    raised = []

    def call():
        try:
            plane.record("a", "kernel", "r", {"x": object()})
        except TypeError as exc:
            raised.append(exc)

    with open(plane.audit_log, "ab") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX)  # a writer is busy
        thread = threading.Thread(target=call, daemon=True)
        thread.start()
        thread.join(2)
        assert not thread.is_alive(), "record waited for the lock before checking"
    assert len(raised) == 1


@pytest.mark.parametrize(
    "details",
    [{9: "a", 10: "b"}, {"nested": {9: "a", 10: "b"}}, {True: 1, 2: 2}],
    ids=["int keys", "nested int keys", "bool and int keys"],
)
def test_details_with_keys_that_are_not_strings_still_verify(tmp_path, details):
    from core.kernel.data_plane import SovereignDataPlane

    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    plane.record("probe", "kernel", "r", details)
    assert plane.verify_audit_integrity()
    stored = plane.get_audit_log(1)[-1]["details"]
    assert stored == json.loads(json.dumps(details, sort_keys=True))


def test_an_odd_agent_id_in_create_task_does_not_break_the_chain(kernel):
    with pytest.raises(TypeError, match="agent_id must be a non-empty string"):
        kernel.create_task({10: "a", 9: "b"}, "x", {})
    assert kernel.data_plane.verify_audit_integrity()
    assert kernel.agent_runtime.scheduler.tasks == {}  # refused before any save


def _entries_of(kernel, action):
    from core.kernel import KERNEL_ACTOR

    return [e for e in kernel.data_plane.get_audit_log(10**6)
            if e["actor"] == KERNEL_ACTOR and e["action"] == action]  # fmt: skip


@pytest.mark.parametrize(
    ("agent_id", "action"),
    [(__import__("uuid").uuid4(), "report"), ("agent", ["report"]), ("", "report"),
     ("agent", None)],
    ids=["uuid-object", "list-action", "empty-id", "no-action"],
)  # fmt: skip
def test_every_task_on_disk_has_an_audit_entry(kernel, agent_id, action):
    # The task file writes default=str and would store a UUID object the
    # audit refuses, so the check runs before the save: no task without an entry.
    for _ in range(2):
        with pytest.raises(TypeError):
            kernel.create_task(agent_id, action, {})
    from core.kernel.agent_runtime import TaskScheduler

    tasks = TaskScheduler(str(kernel.data_dir / "agents" / "tasks")).tasks
    assert tasks == {} and _entries_of(kernel, "task_created") == []


@pytest.mark.parametrize(
    ("name", "agent_type"),
    [({1: "a", "b": 2}, "strategic"), ("ops", ["strategic"]), ("", "strategic")],
    ids=["mixed-key-name", "list-type", "empty-name"],
)
def test_every_registered_agent_has_an_audit_entry(kernel, name, agent_type):
    for _ in range(2):
        with pytest.raises(TypeError):
            kernel.register_agent(name, agent_type)
    assert kernel.agent_runtime.registry.list_agents() == []
    assert _entries_of(kernel, "agent_registered") == []


@pytest.mark.parametrize(
    "action",
    ["legacy_history", "key_provider", "operator_auth", "audit_tail_set_aside"],
)
def test_actions_the_data_plane_writes_itself_are_refused(tmp_path, action):
    from core.kernel.data_plane import SovereignDataPlane

    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    before = plane.audit_log.read_bytes()
    with pytest.raises(ValueError, match="written by the data plane only"):
        plane.record(action, "kernel", "r", {})
    assert plane.audit_log.read_bytes() == before and plane.verify_audit_integrity()


# -- a save or an append that fails once ----------------------------------------------


def _fail_next_save(kernel, monkeypatch):
    module = sys.modules[
        type(kernel.agent_runtime.registry).__module__
    ]  # the kernel's copy
    real = module._write_state
    state = {"armed": True}

    def flaky(*args, **kwargs):
        if state["armed"]:
            state["armed"] = False
            raise OSError(28, "No space left on device")
        return real(*args, **kwargs)

    monkeypatch.setattr(module, "_write_state", flaky)


def test_a_state_change_whose_save_failed_is_recorded_when_it_is_saved(
    kernel, monkeypatch
):
    agent_id = kernel.register_agent("CEO", "strategic")
    registry = kernel.agent_runtime.registry
    _fail_next_save(kernel, monkeypatch)
    with pytest.raises(OSError):
        registry.update_agent_state(agent_id, "paused")
    assert registry.get_agent(agent_id).state.value == "initializing"  # not changed
    registry.update_agent_state(agent_id, "paused")
    assert _log(kernel)[-1]["details"] == {"from": "initializing", "to": "paused"}


def test_a_registration_whose_save_failed_is_recorded_on_the_retry(kernel, monkeypatch):
    kernel.register_agent("CEO", "strategic")
    runtime = kernel.agent_runtime
    _fail_next_save(kernel, monkeypatch)
    with pytest.raises(OSError):
        runtime.register_agent(AgentConfig("CEO", "strategic", max_restarts=9))
    assert runtime.registry.find_by_name("CEO").config.max_restarts == 5
    runtime.register_agent(AgentConfig("CEO", "strategic", max_restarts=9))
    assert _log(kernel)[-1]["details"]["outcome"] == "updated"
    _fail_next_save(kernel, monkeypatch)
    with pytest.raises(OSError):
        runtime.register_agent(AgentConfig("CFO", "finance"))
    assert runtime.registry.find_by_name("CFO") is None  # not half-registered
    runtime.register_agent(AgentConfig("CFO", "finance"))
    assert _log(kernel)[-1]["details"]["outcome"] == "created"


def test_a_task_whose_save_failed_is_not_kept(kernel, monkeypatch):
    agent_id = kernel.register_agent("CEO", "strategic")
    _fail_next_save(kernel, monkeypatch)
    with pytest.raises(OSError):
        kernel.create_task(agent_id, "x", {})
    assert kernel.agent_runtime.scheduler.tasks == {}


def test_a_task_whose_start_could_not_be_recorded_runs_next_time(kernel, monkeypatch):
    runtime = kernel.agent_runtime
    agent_id = kernel.register_agent("CEO", "strategic")
    ran = []
    runtime.scheduler.register_handler("ok", lambda p: ran.append(1))
    task_id = kernel.create_task(agent_id, "ok", {})
    real = kernel.data_plane.record
    state = {"armed": True}

    def flaky(*args, **kwargs):
        if state["armed"]:
            state["armed"] = False
            raise OSError(28, "No space left on device")
        return real(*args, **kwargs)

    monkeypatch.setattr(kernel.data_plane, "record", flaky)
    with pytest.raises(OSError):
        asyncio.run(runtime.scheduler.process_queue())
    assert runtime.scheduler.tasks[task_id].status == "pending" and ran == []
    asyncio.run(runtime.scheduler.process_queue())
    assert runtime.scheduler.tasks[task_id].status == "completed" and ran == [1]


@pytest.mark.parametrize("bad_id", ["", 7, None])
def test_a_hand_edited_task_id_does_not_stop_the_queue(tmp_path, monkeypatch, bad_id):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    agent_id = kernel.register_agent("CEO", "strategic")
    first = kernel.create_task(agent_id, "ok", {})
    second = kernel.create_task(agent_id, "ok", {})
    tasks_file = tmp_path / "agents" / "tasks" / "tasks.json"
    data = json.loads(tasks_file.read_text())
    data[first]["task_id"] = bad_id
    tasks_file.write_text(json.dumps(data))
    again = NSBOSKernel()
    again.agent_runtime.scheduler.register_handler("ok", lambda p: 1)
    asyncio.run(again.agent_runtime.scheduler.process_queue())
    statuses = {k: t.status for k, t in again.agent_runtime.scheduler.tasks.items()}
    assert statuses == {first: "completed", second: "completed"}
    assert again.data_plane.verify_audit_integrity()
    moved = {e["resource"] for e in _log(again) if e["action"] == "task_state_changed"}
    assert moved == {first, second}  # the edited task is recorded under its real id


def test_running_an_errored_task_again_writes_nothing(kernel):
    runtime = kernel.agent_runtime
    agent_id = kernel.register_agent("CEO", "strategic")
    task_id = kernel.create_task(agent_id, "nobody", {})
    asyncio.run(runtime.scheduler.process_queue())
    before = len(_log(kernel))
    asyncio.run(runtime.scheduler.execute_task(runtime.scheduler.tasks[task_id]))
    assert len(_log(kernel)) == before


def test_an_unchanged_registration_writes_no_twin_entry(kernel):
    kernel.register_agent("CEO", "strategic")
    before = (len(_log(kernel)), kernel.network_sync.local_state.version)
    kernel.register_agent("CEO", "strategic")
    assert (len(_log(kernel)), kernel.network_sync.local_state.version) == before


def test_stop_without_a_start_and_a_second_stop_write_nothing(kernel):
    before = len(_log(kernel))
    kernel.stop()
    assert len(_log(kernel)) == before
    kernel.start()
    kernel.stop()
    after = len(_log(kernel))
    kernel.stop()
    assert len(_log(kernel)) == after
    assert [e["action"] for e in _log(kernel)].count("kernel_stopped") == 1


@pytest.mark.parametrize(
    "error", [OSError(28, "No space left on device"), TypeError("odd twin")]
)
def test_a_twin_that_fails_at_shutdown_still_lets_the_stop_be_recorded(
    kernel, monkeypatch, caplog, error
):
    kernel.start()

    def broken(*args, **kwargs):
        raise error

    monkeypatch.setattr(kernel.network_sync, "update_twin", broken)
    kernel.stop()  # returns, whatever the twin raised
    assert kernel.running is False
    assert _log(kernel)[-1]["action"] == "kernel_stopped"
    assert "Cannot record the stopped state in the digital twin" in caplog.text
    assert "Cannot record the shutdown in the audit log" not in caplog.text
