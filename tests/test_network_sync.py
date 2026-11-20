"""Network synchronization: the digital twin, its checksum, history, fleet
status and import/export."""

import json
import os

import pytest

from core.kernel.network_sync import (
    DigitalTwinState,
    FleetNode,
    NetworkSynchronization,
    SyncMode,
)


@pytest.fixture
def sync(tmp_path):
    return NetworkSynchronization(str(tmp_path))


@pytest.mark.parametrize(
    ("key", "section", "name"),
    [
        ("agent.ceo", "agent_states", "ceo"),
        ("pref.theme", "preferences", "theme"),
        ("memory.idx", "memory_index", "idx"),
        ("plain", "preferences", "plain"),
        ("agent.a.b", "agent_states", "a.b"),
    ],
)
def test_keys_route_to_their_section(sync, key, section, name):
    sync.update_twin(key, {"v": 1})
    assert getattr(sync.local_state, section)[name] == {"v": 1}
    assert sync.get_twin_value(key) == {"v": 1}


def test_a_missing_key_reads_as_none(sync):
    for key in ("agent.x", "pref.x", "memory.x", "x"):
        assert sync.get_twin_value(key) is None


def test_each_update_bumps_the_version_and_keeps_a_valid_checksum(sync, tmp_path):
    for i in range(3):
        sync.update_twin("pref.n", i)
    state = sync.get_full_twin()
    assert state.version == 3
    assert state.validate()
    saved = json.loads((tmp_path / "digital_twin.json").read_text())
    assert saved["version"] == 3
    assert NetworkSynchronization(str(tmp_path)).get_twin_value("pref.n") == 2


def test_the_checksum_covers_the_content():
    state = DigitalTwinState("u", {}, {"a": 1}, {})
    state.checksum = state.compute_checksum()
    assert state.validate()
    state.preferences["a"] = 2
    assert not state.validate()


def test_history_records_updates_newest_last(sync):
    for key in ("pref.a", "agent.b", "memory.c"):
        sync.update_twin(key, 1)
    history = sync.get_sync_history()
    assert [h["key"] for h in history] == ["pref.a", "agent.b", "memory.c"]
    assert [h["version"] for h in history] == [1, 2, 3]
    assert [h["key"] for h in sync.get_sync_history(limit=1)] == ["memory.c"]


def test_no_history_before_the_first_update(sync):
    assert sync.get_sync_history() == []


def test_export_and_import_between_installs(sync, tmp_path):
    sync.update_twin("pref.theme", "dark")
    exported = sync.export_twin()
    other = NetworkSynchronization(str(tmp_path / "other"))
    assert other.import_twin(exported) is True
    assert other.get_twin_value("pref.theme") == "dark"
    assert other.get_full_twin().version == exported["version"] + 1


def test_an_edited_export_is_refused(sync, tmp_path):
    sync.update_twin("pref.theme", "dark")
    exported = sync.export_twin()
    exported["preferences"]["theme"] = "light"
    other = NetworkSynchronization(str(tmp_path / "other"))
    assert other.import_twin(exported) is False
    assert other.get_twin_value("pref.theme") is None


@pytest.mark.parametrize("data", [{"user_id": "u"}, {"bogus": 1}, "not a dict"])
def test_a_malformed_import_is_refused(sync, data):
    assert sync.import_twin(data) is False


def test_sync_mode_can_be_changed(sync, monkeypatch):
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    assert sync.sync_mode is SyncMode.LOCAL_ONLY
    sync.set_sync_mode(SyncMode.PEER_TO_PEER)
    assert sync.sync_mode is SyncMode.PEER_TO_PEER


def test_an_empty_fleet(sync):
    assert sync.get_fleet_status() == {
        "total_nodes": 0, "online_nodes": 0, "offline_nodes": 0, "nodes": {}
    }  # fmt: skip


def test_unknown_node_status_updates_are_ignored(sync):
    sync.update_node_status("nobody", "online")
    assert sync.fleet_nodes == {}
    assert FleetNode("n", "h", "p", "ip").sync_mode is SyncMode.LOCAL_ONLY


def _node(node_id="n1", **kw):
    return FleetNode(node_id, f"host-{node_id}", "x86_64", "127.0.0.1", **kw)


def test_nodes_register_and_survive_a_restart(sync, tmp_path):
    sync.register_node(_node("n1", sync_mode=SyncMode.PEER_TO_PEER))
    sync.register_node(_node("n2"))
    sync.update_node_status("n1", "online")
    again = NetworkSynchronization(str(tmp_path))
    assert again.fleet_nodes["n1"].sync_mode is SyncMode.PEER_TO_PEER
    assert again.fleet_nodes["n1"].status == "online"
    assert again.fleet_nodes["n1"].last_seen
    status = again.get_fleet_status()
    assert (status["total_nodes"], status["online_nodes"], status["offline_nodes"]) == (
        2,
        1,
        1,
    )
    saved = json.loads((tmp_path / "fleet.json").read_text())
    assert saved["n1"]["sync_mode"] == "peer_to_peer"


def test_a_failed_save_never_truncates_the_fleet_file(sync, tmp_path, monkeypatch):
    sync.register_node(_node("n1"))
    before = (tmp_path / "fleet.json").read_bytes()
    sync.fleet_nodes["bad"] = _node("bad", capabilities={"x": object()})
    with pytest.raises(TypeError):
        sync._save_fleet()
    assert (tmp_path / "fleet.json").read_bytes() == before
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".fleet")] == []


def test_a_truncated_fleet_file_does_not_stop_startup(tmp_path, caplog):
    truncated = '{\n  "n1": {\n    "node_id": "n1",\n    "sync_mode":'
    (tmp_path / "fleet.json").write_text(truncated)
    sync = NetworkSynchronization(str(tmp_path))
    assert sync.fleet_nodes == {}
    kept = [p for p in tmp_path.iterdir() if p.name.startswith("fleet.json.corrupt-")]
    assert len(kept) == 1 and kept[0].read_text() == truncated
    assert "Fleet file unreadable" in caplog.text
    sync.register_node(_node("n1"))
    assert NetworkSynchronization(str(tmp_path)).fleet_nodes["n1"].hostname == "host-n1"


def test_a_fleet_file_without_a_sync_mode_loads_as_local_only(tmp_path):
    (tmp_path / "fleet.json").write_text(json.dumps({"n1": {
        "node_id": "n1", "hostname": "h", "platform": "p", "ip_address": "i"}}))  # fmt: skip
    sync = NetworkSynchronization(str(tmp_path))
    assert sync.fleet_nodes["n1"].sync_mode is SyncMode.LOCAL_ONLY


def test_a_crash_while_writing_leaves_the_old_fleet_file(sync, tmp_path, monkeypatch):

    sync.register_node(_node("n1"))
    before = (tmp_path / "fleet.json").read_bytes()

    def full_disk(fd):  # the data is written, then the sync fails
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full_disk)
    with pytest.raises(OSError):
        sync.register_node(_node("n2"))
    monkeypatch.undo()
    assert (tmp_path / "fleet.json").read_bytes() == before
    assert list(NetworkSynchronization(str(tmp_path)).fleet_nodes) == ["n1"]
    assert [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_a_twin_with_a_bad_checksum_is_set_aside_not_loaded(tmp_path, caplog):
    sync = NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.a", 1)
    data = json.loads((tmp_path / "digital_twin.json").read_text())
    data["preferences"]["a"] = 2  # edited without updating the checksum
    edited = json.dumps(data).encode()
    (tmp_path / "digital_twin.json").write_bytes(edited)
    again = NetworkSynchronization(str(tmp_path))
    assert again.get_twin_value("pref.a") is None
    [kept] = tmp_path.glob("digital_twin.json.rejected-*")
    assert kept.read_bytes() == edited  # the edited file, untouched
    assert "checksum mismatch in digital_twin.json; kept as" in caplog.text


def test_history_reads_only_what_it_returns(sync, tmp_path):
    import tracemalloc

    with open(tmp_path / "sync.log", "w") as f:
        f.writelines(
            json.dumps({"action": "update", "key": f"k{i}", "version": i}) + "\n"
            for i in range(20_000)
        )
    tracemalloc.start()
    last = sync.get_sync_history(limit=3)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert [e["key"] for e in last] == ["k19997", "k19998", "k19999"]
    assert peak < 1_000_000


def test_history_skips_blank_and_cut_off_lines(sync, tmp_path, caplog):
    sync.update_twin("pref.a", 1)
    with open(tmp_path / "sync.log", "a") as f:
        f.write('\n{"action": "upd')
    assert [e["key"] for e in sync.get_sync_history()] == ["pref.a"]
    assert "unreadable line" in caplog.text
    assert sync.get_sync_history(limit=0) == []


# -- a twin of the wrong shape is refused or set aside --------------------------

WRONG_SHAPES = [
    {"agent_states": []},
    {"preferences": "x"},
    {"memory_index": None},
    {"version": "7"},
    {"version": None},
]


def _signed(**changes):
    fields = {"user_id": "u", "agent_states": {}, "preferences": {}, "memory_index": {},
              "version": 3}  # fmt: skip
    state = DigitalTwinState(**{**fields, **changes})
    state.checksum = state.compute_checksum()
    return {
        **fields,
        **changes,
        "checksum": state.checksum,
        "last_sync": state.last_sync,
    }


@pytest.mark.parametrize("changes", WRONG_SHAPES, ids=repr)
def test_an_import_of_the_wrong_shape_is_refused_and_changes_nothing(
    sync, tmp_path, changes
):
    sync.update_twin("pref.theme", "kemet")
    before = (tmp_path / "digital_twin.json").read_text()
    state = sync.local_state
    assert sync.import_twin(_signed(**changes)) is False
    assert sync.local_state is state and state.version == 1
    assert (tmp_path / "digital_twin.json").read_text() == before
    sync.update_twin("agent.ceo", "running")
    assert sync.get_twin_value("agent.ceo") == "running"


def test_a_failed_save_leaves_the_twin_as_it_was(sync, monkeypatch):
    state = sync.local_state

    def full_disk(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("core.kernel.network_sync._write_json", full_disk)
    with pytest.raises(OSError):
        sync.import_twin(_signed())
    assert sync.local_state is state


def test_a_good_import_still_works(sync):
    assert sync.import_twin(_signed(preferences={"theme": "kemet"})) is True
    assert sync.get_twin_value("pref.theme") == "kemet"
    assert sync.local_state.version == 4


@pytest.mark.parametrize("changes", WRONG_SHAPES, ids=repr)
def test_a_twin_file_of_the_wrong_shape_is_set_aside(tmp_path, caplog, changes):
    (tmp_path / "digital_twin.json").write_text(json.dumps(_signed(**changes)))
    sync = NetworkSynchronization(str(tmp_path))
    assert sync.local_state.user_id == "ngari-default"
    assert [
        p.name.split("-")[0] for p in tmp_path.glob("digital_twin.json.corrupt-*")
    ] == ["digital_twin.json.corrupt"]
    sync.update_twin("kernel.status", "running")
    assert "Digital twin unreadable" in caplog.text


def test_the_kernel_starts_with_a_twin_of_the_wrong_shape(tmp_path):
    from core.kernel import NSBOSKernel

    (tmp_path / "sync").mkdir()
    (tmp_path / "sync" / "digital_twin.json").write_text(
        json.dumps(_signed(preferences=[]))
    )
    kernel = NSBOSKernel(str(tmp_path))
    kernel.start()
    try:
        assert kernel.network_sync.get_twin_value("kernel.status") == "running"
    finally:
        kernel.stop()
