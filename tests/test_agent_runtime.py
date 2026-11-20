"""Agent runtime lifecycle, the task scheduler and the message bus."""

import asyncio
import json
import os
from pathlib import Path

import pytest

from core.kernel.agent_runtime import (
    AgentConfig,
    AgentRuntime,
    AgentStateEnum,
    InterAgentCommunication,
    TaskPriority,
    TaskScheduler,
)


@pytest.fixture
def runtime(tmp_path):
    return AgentRuntime(str(tmp_path))


def test_start_moves_initializing_agents_to_running(runtime):
    agent_id = runtime.register_agent(AgentConfig("CEO", "strategic"))
    paused = runtime.register_agent(AgentConfig("Worker", "execution"))
    runtime.registry.update_agent_state(paused, AgentStateEnum.PAUSED)
    runtime.start()
    assert runtime.running
    assert runtime.registry.get_agent(agent_id).state == AgentStateEnum.RUNNING
    assert runtime.registry.get_agent(paused).state == AgentStateEnum.PAUSED
    runtime.stop()
    assert not runtime.running


def test_status_counts_agents_by_state(runtime):
    runtime.register_agent(AgentConfig("A", "t"))
    runtime.register_agent(AgentConfig("B", "t"))
    runtime.start()
    status = runtime.get_status()
    assert status["running"] is True
    assert status["agents"] == 2
    assert status["agents_by_state"]["running"] == 2
    assert set(status["agents_by_state"]) == {s.value for s in AgentStateEnum}
    assert (status["pending_tasks"], status["total_tasks"]) == (0, 0)


def test_agent_states_survive_a_restart(tmp_path, runtime):
    agent_id = runtime.register_agent(AgentConfig("CEO", "strategic"))
    runtime.start()
    again = AgentRuntime(str(tmp_path))
    assert again.registry.get_agent(agent_id).state == AgentStateEnum.RUNNING


def test_subscribers_get_messages_and_a_failing_one_is_isolated(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    got = []

    def broken(message):
        raise RuntimeError("subscriber bug")

    bus.subscribe("orders", broken)
    bus.subscribe("orders", got.append)
    bus.subscribe("other", lambda m: got.append(("other", m)))
    bus.publish("orders", {"id": 1})
    assert got == [{"id": 1}]


def test_runtime_events_reach_subscribers(runtime):
    got = []
    runtime.subscribe_event("alerts", got.append)
    runtime.publish_event("alerts", {"level": "high"})
    assert got == [{"level": "high"}]
    assert runtime.comm.get_messages("alerts")[0]["message"] == {"level": "high"}


# -- task scheduler -------------------------------------------------------------


@pytest.fixture
def scheduler(tmp_path):
    return TaskScheduler(str(tmp_path))


def test_tasks_are_created_saved_and_reloaded(scheduler, tmp_path):
    task_id = scheduler.create_task("agent", "report", {"n": 1}, TaskPriority.HIGH)
    saved = json.loads((tmp_path / "tasks.json").read_text())
    assert saved[task_id]["priority"] == 2
    again = TaskScheduler(str(tmp_path))
    task = again.tasks[task_id]
    assert task.priority is TaskPriority.HIGH
    assert (task.status, task.payload) == ("pending", {"n": 1})


def test_pending_tasks_come_highest_priority_first(scheduler, tmp_path):
    for priority in (TaskPriority.LOW, TaskPriority.CRITICAL, TaskPriority.NORMAL):
        scheduler.create_task("a", "x", {}, priority)
    order = [t.priority for t in TaskScheduler(str(tmp_path)).get_pending_tasks()]
    assert order == [TaskPriority.CRITICAL, TaskPriority.NORMAL, TaskPriority.LOW]


def test_the_queue_runs_handlers_and_records_results(scheduler, tmp_path):
    async def double(payload):
        return payload["n"] * 2

    def boom(payload):
        raise ValueError("bad payload")

    scheduler.register_handler("double", double)
    scheduler.register_handler("boom", boom)
    ok = scheduler.create_task("a", "double", {"n": 21}, TaskPriority.HIGH)
    bad = scheduler.create_task("a", "boom", {}, TaskPriority.NORMAL)
    missing = scheduler.create_task("a", "nobody", {}, TaskPriority.LOW)

    assert asyncio.run(scheduler.process_queue()) == [42, None, None]
    tasks = TaskScheduler(str(tmp_path)).tasks
    assert (tasks[ok].status, tasks[ok].result) == ("completed", 42)
    assert tasks[ok].started_at and tasks[ok].completed_at
    assert (tasks[bad].status, tasks[bad].error) == ("error", "bad payload")
    assert tasks[missing].status == "error"
    assert "No handler registered" in tasks[missing].error
    assert scheduler.get_pending_tasks() == []


@pytest.mark.parametrize("action", [["x"], {"x": 1}, 5, None], ids=repr)
def test_a_task_with_an_odd_action_fails_alone_and_the_queue_goes_on(tmp_path, action):
    data = {
        "odd": {"task_id": "odd", "agent_id": "a", "action": action, "payload": {},
                "priority": TaskPriority.CRITICAL.value},
        "ok": {"task_id": "ok", "agent_id": "a", "action": "x", "payload": {"n": 1},
               "priority": TaskPriority.LOW.value},
    }  # fmt: skip
    (tmp_path / "tasks.json").write_text(json.dumps(data))
    scheduler = TaskScheduler(str(tmp_path))
    scheduler.register_handler("x", lambda payload: payload["n"])
    assert asyncio.run(scheduler.process_queue()) == [None, 1]
    tasks = TaskScheduler(str(tmp_path)).tasks
    assert tasks["odd"].status == "error"
    assert tasks["odd"].error == f"No handler registered for action: {action}"
    assert (tasks["ok"].status, tasks["ok"].result) == ("completed", 1)


def test_a_result_that_is_not_json_is_saved_as_text(scheduler, tmp_path):
    scheduler.register_handler("obj", lambda payload: object())
    task_id = scheduler.create_task("a", "obj", {})
    asyncio.run(scheduler.process_queue())
    stored = TaskScheduler(str(tmp_path)).tasks[task_id]
    assert stored.status == "completed"
    assert stored.result.startswith("<object object at")


def test_a_crash_while_saving_keeps_the_old_task_file(scheduler, tmp_path, monkeypatch):
    scheduler.create_task("a", "x", {})
    before = (tmp_path / "tasks.json").read_bytes()

    def full_disk(fd):  # the data is written, then the sync fails
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full_disk)
    with pytest.raises(OSError):
        scheduler.create_task("a", "y", {})
    monkeypatch.undo()
    assert (tmp_path / "tasks.json").read_bytes() == before
    assert [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_a_truncated_task_file_does_not_stop_startup(tmp_path, caplog):
    truncated = '{\n  "t1": {\n    "task_id": "t1",\n    "priority":'
    (tmp_path / "tasks.json").write_text(truncated)
    scheduler = TaskScheduler(str(tmp_path))
    assert scheduler.tasks == {}
    kept = [p for p in tmp_path.iterdir() if p.name.startswith("tasks.json.corrupt-")]
    assert len(kept) == 1 and kept[0].read_text() == truncated
    assert "Task file unreadable" in caplog.text


def test_runtime_status_counts_tasks(runtime):
    runtime.create_task("a", "x", {})
    assert runtime.get_status()["pending_tasks"] == 1


# -- stored messages --------------------------------------------------------------


@pytest.fixture
def bus(tmp_path):
    return InterAgentCommunication(str(tmp_path / "comm"))


def test_messages_in_the_same_second_are_all_kept(bus):
    for n in range(5):
        bus.publish("alerts", {"n": n})
    assert [m["message"]["n"] for m in bus.get_messages("alerts")] == [4, 3, 2, 1, 0]
    assert [m["message"]["n"] for m in bus.get_messages("alerts", limit=2)] == [4, 3]


def test_a_topic_only_returns_its_own_messages(bus):
    bus.publish("alerts", {"n": 1})
    bus.publish("alerts_low", {"n": 2})
    bus.publish("alerts_low_x", {"n": 3})
    assert [m["topic"] for m in bus.get_messages("alerts")] == ["alerts"]
    assert [m["topic"] for m in bus.get_messages("alerts_low")] == ["alerts_low"]


def test_glob_characters_in_a_topic_are_literal(bus):
    bus.publish("a", {"n": 1})
    bus.publish("[ab]", {"n": 2})
    assert [m["topic"] for m in bus.get_messages("[ab]")] == ["[ab]"]
    assert bus.get_messages("*") == []


@pytest.mark.parametrize("topic", ["../escaped", "a/b", "", "nul\0"])
def test_topics_that_leave_the_directory_are_refused(bus, tmp_path, topic):
    got = []
    bus.subscribe(topic, got.append)
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    with pytest.raises(ValueError, match="invalid topic"):
        bus.publish(topic, {"n": 1})
    with pytest.raises(ValueError, match="invalid topic"):
        bus.get_messages(topic)
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before
    assert got == []


def test_old_message_files_are_still_read(bus):
    old = {
        "topic": "alerts",
        "message": {"n": 0},
        "timestamp": "2026-01-01T00:00:00+00:00",
    }
    (bus.comm_dir / "alerts_20260101_000000.json").write_text(json.dumps(old))
    bus.publish("alerts", {"n": 1})
    assert [m["message"]["n"] for m in bus.get_messages("alerts")] == [1, 0]


def test_an_unreadable_message_file_is_skipped(bus, caplog):
    bus.publish("alerts", {"n": 1})
    bus.publish("alerts", {"n": 2})
    (bus.comm_dir / "alerts_20990101_000000.json").write_text("{not json")
    assert [m["message"]["n"] for m in bus.get_messages("alerts", limit=2)] == [2, 1]
    assert "Skipping unreadable message file" in caplog.text


def test_no_temporary_files_are_left(bus):
    bus.publish("alerts", {"n": 1})
    assert [p.name for p in bus.comm_dir.iterdir() if p.name.startswith(".")] == []


def _stored(bus, file_name, topic="t", **message):
    data = {"topic": topic, "message": message, "timestamp": file_name}
    (bus.comm_dir / file_name).write_text(json.dumps(data))


def test_messages_are_newest_first_across_both_name_formats(bus):
    # t_<date>_<time>.json is the v0.1.0 name; current names add microseconds
    # and random bytes. An old file sorts before a new one from the same second.
    for name in [
        "t_20260301_000000.json",
        "t_20260101_000000_000005_0a0b0c0d.json",
        "t_20260201_120000.json",
        "t_20260201_120000_000001_01020304.json",
    ]:
        _stored(bus, name, name=name)  # fmt: skip
    assert [m["message"]["name"] for m in bus.get_messages("t")] == [
        "t_20260301_000000.json",
        "t_20260201_120000_000001_01020304.json",
        "t_20260201_120000.json",
        "t_20260101_000000_000005_0a0b0c0d.json",
    ]


def _count_reads(monkeypatch, bus):
    reads = []

    def spy(name):
        real = getattr(Path, name)

        def counting(self, *args, **kwargs):
            if self.parent == bus.comm_dir:
                reads.append(self.name)
            return real(self, *args, **kwargs)

        monkeypatch.setattr(Path, name, counting)

    spy("read_text")
    spy("read_bytes")
    return reads


def test_get_messages_reads_only_what_it_returns(bus, monkeypatch):
    for n in range(30):
        bus.publish("alerts", {"n": n})
    reads = _count_reads(monkeypatch, bus)
    assert [m["message"]["n"] for m in bus.get_messages("alerts", limit=5)] == [
        29, 28, 27, 26, 25
    ]  # fmt: skip
    assert len(reads) == 5


def test_other_topics_are_not_read(bus, monkeypatch):
    for n in range(20):
        bus.publish("alerts_low", {"n": n})
        bus.publish("zzzzzz", {"n": n})
    bus.publish("alerts", {"n": "mine"})
    reads = _count_reads(monkeypatch, bus)
    assert [m["message"]["n"] for m in bus.get_messages("alerts")] == ["mine"]
    assert len(reads) == 1


def test_a_file_whose_stored_topic_differs_is_skipped(bus):
    bus.publish("alerts", {"n": 1})
    _stored(bus, "alerts_20990101_000000.json", topic="other", n=2)
    assert [m["message"]["n"] for m in bus.get_messages("alerts")] == [1]


def test_files_the_kernel_did_not_name_are_not_messages(bus):
    bus.publish("alerts", {"n": 1})
    _stored(bus, "alerts_copy.json", topic="alerts", n=2)
    _stored(bus, "alerts_20990101_000000.json.bak", topic="alerts", n=3)
    assert [m["message"]["n"] for m in bus.get_messages("alerts")] == [1]


@pytest.mark.parametrize("limit", [0, -1])
def test_no_limit_means_no_messages(bus, limit):
    bus.publish("alerts", {"n": 1})
    bus.publish("alerts", {"n": 2})
    assert bus.get_messages("alerts", limit=limit) == []


# -- a result the task file cannot hold ------------------------------------------------


def _nested(depth):
    """Lists inside each other, depth deep, built without parsing: Python
    3.10 and 3.11's JSON decoder stops near a thousand levels."""
    value = []
    for _ in range(depth - 1):
        value = [value]
    return value


@pytest.mark.parametrize(
    "result",
    [_nested(1500), 10**5000, {(1, 2): "pair"}],
    ids=["deep", "long-number", "tuple-key"],
)
def test_one_unstorable_result_does_not_stop_every_other_task(tmp_path, result):
    # A result the task file cannot hold is replaced before the save, so later
    # saves succeed and the task is stored as completed.
    scheduler = TaskScheduler(str(tmp_path))
    scheduler.register_handler("ask", lambda payload: result)
    first = scheduler.create_task("agent-a", "ask", {})
    asyncio.run(scheduler.process_queue())
    scheduler.create_task("agent-b", "other", {})  # a later save succeeds
    reloaded = TaskScheduler(str(tmp_path)).tasks[first]
    assert reloaded.status == "completed"
    assert reloaded.result == {"error": "the result could not be stored"}


def test_an_ordinary_result_is_kept_as_the_file_holds_it(tmp_path):
    scheduler = TaskScheduler(str(tmp_path))
    scheduler.register_handler("ask", lambda payload: {"n": 1, "items": ("a", "b")})
    task_id = scheduler.create_task("agent-a", "ask", {})
    asyncio.run(scheduler.process_queue())
    expected = {"n": 1, "items": ["a", "b"]}
    assert scheduler.tasks[task_id].result == expected
    assert TaskScheduler(str(tmp_path)).tasks[task_id].result == expected


def test_a_result_as_deep_as_allowed_is_kept(tmp_path):
    from core.kernel.agent_runtime import MAX_RESULT_DEPTH

    at_limit = json.loads("[" * MAX_RESULT_DEPTH + "]" * MAX_RESULT_DEPTH)
    one_more = json.loads("[" * (MAX_RESULT_DEPTH + 1) + "]" * (MAX_RESULT_DEPTH + 1))
    scheduler = TaskScheduler(str(tmp_path))
    scheduler.register_handler("at", lambda payload: at_limit)
    scheduler.register_handler("over", lambda payload: one_more)
    kept, replaced = (scheduler.create_task("a", n, {}) for n in ("at", "over"))
    asyncio.run(scheduler.process_queue())
    assert scheduler.tasks[kept].result == at_limit
    assert scheduler.tasks[replaced].result == {
        "error": "the result could not be stored"
    }


# -- what agents put in the kernel's log -----------------------------------------------

FORGED = "\n2026-11-01 09:00:00,000 [NSBOS] Audit chain verified"


def test_agent_supplied_text_cannot_forge_a_log_line(tmp_path, caplog):
    import logging

    caplog.set_level(logging.INFO)
    runtime = AgentRuntime(str(tmp_path))
    agent_id = runtime.register_agent(AgentConfig(name="Ops" + FORGED, agent_type="x"))
    runtime.register_agent(AgentConfig(name="Ops" + FORGED, agent_type="y"))  # updated
    runtime.scheduler.register_handler(
        "fail" + FORGED,
        lambda payload: (_ for _ in ()).throw(RuntimeError("bad" + FORGED)),
    )
    runtime.create_task(agent_id, "fail" + FORGED, {})
    asyncio.run(runtime.scheduler.process_queue())
    runtime.comm.subscribe(
        "t", lambda m: (_ for _ in ()).throw(RuntimeError("cb" + FORGED))
    )
    runtime.comm.publish("t", {"m": 1})
    messages = [r.getMessage() for r in caplog.records]
    assert sum("Ops" in m for m in messages) == 2 and any("fail" in m for m in messages)
    assert not [m for m in messages if "\n" in m], messages


def test_a_long_agent_name_is_logged_cut_short(tmp_path, caplog):
    import logging

    caplog.set_level(logging.INFO)
    AgentRuntime(str(tmp_path)).register_agent(
        AgentConfig(name="n" * 256, agent_type="x")
    )
    [line] = [
        r.getMessage() for r in caplog.records if "Agent registered" in r.getMessage()
    ]
    assert len(line) < 300 and "..." in line


def test_a_topic_cannot_forge_a_log_line_through_its_file_name(tmp_path, caplog):
    import logging

    caplog.set_level(logging.INFO)
    bus = InterAgentCommunication(str(tmp_path))
    topic = "t" + FORGED
    bus.publish(topic, {"m": 1})
    [stored] = [p for p in Path(tmp_path).iterdir() if p.name.startswith("t\n")]
    stored.write_text("not json")
    assert bus.get_messages(topic) == []
    skipped = [r.getMessage() for r in caplog.records if "Skipping" in r.getMessage()]
    assert skipped and not [m for m in skipped if "\n" in m]


# -- subscribers -----------------------------------------------------------------------


def test_a_subscriber_cannot_change_what_the_next_one_receives(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    got = []
    bus.subscribe("payments", lambda m: m.update(amount=0))
    bus.subscribe("payments", lambda m: got.append(m["amount"]))
    sent = {"amount": 100, "items": [1]}
    bus.publish("payments", sent)
    assert got == [100]
    assert sent == {"amount": 100, "items": [1]}  # nor what the publisher holds
    assert bus.get_messages("payments")[0]["message"] == {"amount": 100, "items": [1]}


def test_a_callback_that_subscribes_waits_for_the_next_message(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    calls = []

    def again(message):
        calls.append(message["n"])
        if len(calls) < 1000:
            bus.subscribe("t", again)

    bus.subscribe("t", again)
    bus.publish("t", {"n": 1})
    assert calls == [1]
    bus.publish("t", {"n": 2})
    assert calls == [1, 2, 2]  # the two subscriptions held by then


# -- how much one agent may hand the kernel --------------------------------------------


def test_a_payload_over_the_limit_is_refused_and_costs_nobody_else(
    tmp_path, monkeypatch
):
    from core.kernel import agent_runtime
    from core.kernel.agent_runtime import MAX_PAYLOAD_BYTES

    scheduler = TaskScheduler(str(tmp_path))
    room = MAX_PAYLOAD_BYTES - len(json.dumps({"blob": ""}))
    scheduler.create_task("agent-a", "x", {"blob": "x" * room})  # exactly at the limit
    with pytest.raises(ValueError, match="over the 262144-byte limit"):
        scheduler.create_task("agent-a", "x", {"blob": "x" * (room + 1)})
    with pytest.raises(ValueError):
        scheduler.create_task("agent-a", "x", {"blob": "x" * (8 << 20)})
    assert len(scheduler.tasks) == 1
    written = []
    real = agent_runtime._write_durably
    monkeypatch.setattr(agent_runtime, "_write_durably",
                        lambda path, data: written.append(len(data)) or real(path, data))  # fmt: skip
    scheduler.create_task("agent-b", "y", {})
    assert sum(written) < 2 * MAX_PAYLOAD_BYTES  # not the 8 MB one


def test_a_message_over_the_limit_is_refused_before_it_is_written(tmp_path):
    from core.kernel.agent_runtime import MAX_PAYLOAD_BYTES

    recorded = []
    bus = InterAgentCommunication(str(tmp_path), audit=lambda *a: recorded.append(a))
    with pytest.raises(ValueError, match="the message is"):
        bus.publish("t", {"blob": "x" * MAX_PAYLOAD_BYTES})
    assert list(Path(tmp_path).glob("t_*")) == [] and recorded == []


def test_a_description_over_the_limit_is_refused(tmp_path):
    from core.kernel.agent_runtime import MAX_DESCRIPTION_BYTES

    runtime = AgentRuntime(str(tmp_path))
    with pytest.raises(ValueError, match="the version, description and environment"):
        runtime.register_agent(
            AgentConfig(
                name="a", agent_type="x", description="d" * MAX_DESCRIPTION_BYTES
            )
        )
    with pytest.raises(ValueError):
        runtime.register_agent(
            AgentConfig(
                name="a", agent_type="x", environment={"k": "v" * MAX_DESCRIPTION_BYTES}
            )
        )
    assert runtime.registry.list_agents() == []


def test_a_result_over_the_limit_is_replaced(tmp_path):
    from core.kernel.agent_runtime import MAX_PAYLOAD_BYTES

    scheduler = TaskScheduler(str(tmp_path))
    scheduler.register_handler("big", lambda payload: "r" * MAX_PAYLOAD_BYTES)
    task_id = scheduler.create_task("a", "big", {})
    asyncio.run(scheduler.process_queue())
    assert scheduler.tasks[task_id].result == {
        "error": "the result could not be stored"
    }


# -- names that must fit a file name ---------------------------------------------------


@pytest.mark.parametrize("encrypt", [False, True])
def test_the_longest_topic_allowed_publishes_and_one_more_byte_is_refused(
    tmp_path, encrypt
):
    from cryptography.fernet import Fernet

    from core.kernel.agent_runtime import MAX_TOPIC_BYTES
    from core.kernel.data_plane.state import StateCipher

    cipher = StateCipher(Fernet.generate_key()) if encrypt else None
    bus = InterAgentCommunication(str(tmp_path), cipher=cipher, encrypt=encrypt)
    # Three bytes a character: the limit counts bytes, so the temporary name
    # stays within 255 bytes as the message file does.
    topic = "話" * (MAX_TOPIC_BYTES // 3) + "x" * (MAX_TOPIC_BYTES % 3)
    assert len(topic.encode()) == MAX_TOPIC_BYTES
    bus.publish(topic, {"m": 1})
    assert [m["message"] for m in bus.get_messages(topic)] == [{"m": 1}]
    with pytest.raises(ValueError, match="255-byte file name limit"):
        bus.publish(topic + "y", {"m": 2})


# -- a payload nested too deep ---------------------------------------------------------


def test_a_payload_nested_too_deep_is_refused_before_it_is_saved(tmp_path):
    # Saving a payload nested that deep from the queue's deeper stack would
    # pass the recursion limit, so it is refused when the task is created.
    from core.kernel.agent_runtime import MAX_RESULT_DEPTH

    sched = TaskScheduler(str(tmp_path))
    sched.register_handler("echo", lambda payload: "ok")
    sched.create_task("agent", "echo", {"x": _nested(MAX_RESULT_DEPTH - 1)})
    for deep in ({"x": _nested(MAX_RESULT_DEPTH)}, {"x": _nested(900)}):
        with pytest.raises(ValueError, match="nests more than 64 deep"):
            sched.create_task("agent", "echo", deep)
    tupled = ((),)
    for _ in range(MAX_RESULT_DEPTH):
        tupled = (tupled,)
    with pytest.raises(ValueError, match="nests more than"):
        sched.create_task("agent", "echo", {"x": tupled})
    plain = sched.create_task("agent", "echo", {})
    asyncio.run(sched.process_queue())
    assert [t.status for t in sched.tasks.values()] == ["completed", "completed"]
    assert sched.tasks[plain].result == "ok"


def test_a_value_that_contains_itself_is_refused_and_does_not_hang(tmp_path):
    payload = {"x": []}
    payload["x"].append(payload)
    with pytest.raises(ValueError, match="nests more than"):
        TaskScheduler(str(tmp_path)).create_task("agent", "echo", payload)


def test_a_message_or_agent_nested_too_deep_is_refused(tmp_path):
    from core.kernel.agent_runtime import AgentRegistry

    with pytest.raises(ValueError, match="nests more than"):
        InterAgentCommunication(str(tmp_path / "c")).publish("t", {"x": _nested(70)})
    assert list((tmp_path / "c").glob("t_*")) == []
    registry = AgentRegistry(str(tmp_path / "r"))
    with pytest.raises(ValueError, match="nests more than"):
        registry.register_agent(AgentConfig("a", "t", environment={"x": _nested(70)}))
    assert registry.agents == {}


def test_the_payload_bound_bounds_what_is_written(tmp_path):
    # Written compact, as it is measured: indented, a 120 KiB payload nested
    # 60 deep would make tasks.json about 5 MB on every save.
    payload = {"x": _nested(60)}
    leaf = payload["x"]
    while leaf:
        leaf = leaf[0]
    leaf.extend([1] * 40000)
    size = len(json.dumps(payload).encode())
    sched = TaskScheduler(str(tmp_path / "t"))
    sched.create_task("agent", "echo", payload)
    assert (tmp_path / "t" / "tasks.json").stat().st_size < size + 1024
    bus = InterAgentCommunication(str(tmp_path / "c"))
    bus.publish("t", payload)
    (written,) = (tmp_path / "c").glob("t_*.json")
    assert written.stat().st_size < size + 1024
    assert bus.get_messages("t")[0]["message"] == payload


def test_the_registry_is_written_as_the_description_bound_measures_it(tmp_path):
    from core.kernel.agent_runtime import AgentRegistry

    environment = {"x": _nested(60)}
    leaf = environment["x"]
    while leaf:
        leaf = leaf[0]
    leaf.extend([1] * 1000)
    AgentRegistry(str(tmp_path)).register_agent(
        AgentConfig("a", "t", environment=environment)
    )
    assert (tmp_path / "registry.json").stat().st_size < 4 * 1024 + 1024


def test_a_result_is_measured_as_a_payload_is():
    # Measured compact, as a payload is: a 151 KiB result of 6000 small
    # records is kept, as a payload of the same value is accepted.
    from core.kernel.agent_runtime import MAX_PAYLOAD_BYTES, _require_size, _storable

    result = {"rows": [{"id": i, "ok": True} for i in range(6000)]}
    _require_size("the payload", result, MAX_PAYLOAD_BYTES)
    assert _storable(result) == result
    over = {"rows": "r" * MAX_PAYLOAD_BYTES}
    assert _storable(over) == {"error": "the result could not be stored"}


# -- names and actions have a length ---------------------------------------------------


@pytest.mark.parametrize("field", ["agent_id", "action"])
def test_a_task_cannot_carry_a_megabyte_in_its_action_or_agent_id(tmp_path, field):
    # Kept in tasks.json for good and copied whole into the audit chain.
    audited = []
    sched = TaskScheduler(str(tmp_path), audit=lambda *a: audited.append(a))
    args = {"agent_id": "agent", "action": "echo"}
    args[field] = "a" * 257
    with pytest.raises(ValueError, match=f"{field} is 257 bytes, over the 256-byte"):
        sched.create_task(args["agent_id"], args["action"], {})
    assert sched.tasks == {} and audited == []
    args[field] = "é" * 129  # 129 characters, 258 bytes
    with pytest.raises(ValueError, match="258 bytes"):
        sched.create_task(args["agent_id"], args["action"], {})
    args[field] = "é" * 128  # 256 bytes
    sched.create_task(args["agent_id"], args["action"], {})


@pytest.mark.parametrize("field", ["name", "agent_type"])
def test_an_agent_name_or_type_cannot_be_a_megabyte(tmp_path, field):
    from core.kernel.agent_runtime import AgentRegistry

    registry = AgentRegistry(str(tmp_path))
    config = {"name": "n", "agent_type": "t", field: "n" * (1 << 20)}
    with pytest.raises(ValueError, match="over the 256-byte limit"):
        registry.register_agent(AgentConfig(**config))
    with pytest.raises(ValueError, match="the version, description and environment"):
        registry.register_agent(AgentConfig("n", "t", version="v" * 5000))
    assert registry.agents == {}
    config[field] = "\udcff" * 85  # a lone surrogate is three bytes, not an error
    registry.register_agent(AgentConfig(**config))


def test_messages_on_a_topic_an_earlier_version_wrote_can_still_be_read(tmp_path):
    # Topics up to 218 bytes written by earlier versions are still read
    # (<topic>_<stamp>_<hex>.json fits 255); publishing on one is refused.
    from core.kernel.agent_runtime import MAX_TOPIC_BYTES

    topic = "t" * 218
    name = f"{topic}_20261031_120000_000000_0123abcd.json"
    assert len(name.encode()) == 255
    message = {
        "topic": topic,
        "message": {"n": 1},
        "timestamp": "2026-10-31T12:00:00+00:00",
    }
    (tmp_path / name).write_text(json.dumps(message))
    bus = InterAgentCommunication(str(tmp_path))
    assert bus.get_messages(topic) == [message]
    with pytest.raises(ValueError, match="255-byte file name limit"):
        bus.publish(topic, {"n": 2})
    assert len(topic) > MAX_TOPIC_BYTES


@pytest.mark.parametrize("days", [999_999_999, 10**19])
def test_a_retention_longer_than_the_calendar_keeps_every_message(tmp_path, days):
    # Any whole number of days from the floor up is taken; one that goes
    # past year 1 removes nothing and does not raise.
    from core.kernel.agent_runtime import retention_days

    assert retention_days({"NGARI_RETENTION_DAYS": str(days)}) == days
    bus = InterAgentCommunication(str(tmp_path))
    bus.publish("t", {"m": 1})
    bus.expire(days)
    assert [m["message"] for m in bus.get_messages("t")] == [{"m": 1}]
