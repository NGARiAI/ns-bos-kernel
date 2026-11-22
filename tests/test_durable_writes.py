"""The state files (agent registry, tasks, digital twin, fleet, UI layouts,
model registry) and inter-agent messages are written durably: the new
contents are synced before the rename that puts them in place, and the
directory after it, so a power cut leaves the old file or the new one."""

import importlib
import json
import os
import stat
import threading

import pytest

MODULES = [
    "core.kernel.agent_runtime",
    "core.kernel.network_sync",
    "core.kernel.generative_ui",
    "core.kernel.inference",
]


def _record(monkeypatch):
    calls = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        calls.append(
            "fsync dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync file"
        )
        return real_fsync(fd)

    def replace(src, dst):
        calls.append("replace")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    return calls


@pytest.mark.parametrize("module", MODULES)
def test_contents_are_synced_before_the_rename_and_the_directory_after(
    tmp_path, monkeypatch, module
):
    write_json = importlib.import_module(module)._write_json
    calls = _record(monkeypatch)
    write_json(tmp_path / "state.json", {"n": 1})
    assert calls == ["fsync file", "replace", "fsync dir"]
    assert json.loads((tmp_path / "state.json").read_text()) == {"n": 1}


def test_a_published_message_is_written_the_same_way(tmp_path, monkeypatch):
    from core.kernel.agent_runtime import InterAgentCommunication

    bus = InterAgentCommunication(str(tmp_path))
    calls = _record(monkeypatch)
    bus.publish("orders", {"id": 1})
    assert calls == ["fsync file", "replace", "fsync dir"]
    assert bus.get_messages("orders")[0]["message"] == {"id": 1}


@pytest.mark.parametrize("module", MODULES)
def test_threads_saving_one_file_do_not_collide(tmp_path, module):
    write_json = importlib.import_module(module)._write_json
    path = tmp_path / "state.json"
    errors = []

    def save(n):
        try:
            for i in range(25):
                write_json(path, {"writer": n, "i": i})
        except Exception as exc:  # noqa: BLE001 - collected for the assertion
            errors.append(exc)

    threads = [threading.Thread(target=save, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert set(json.loads(path.read_text())) == {"writer", "i"}
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


@pytest.mark.parametrize("module", MODULES)
def test_stored_files_are_owner_only_whatever_the_umask(tmp_path, module):
    write_json = importlib.import_module(module)._write_json
    old = os.umask(0o000)  # the most permissive umask must not loosen the mode
    try:
        write_json(tmp_path / "state.json", {})
    finally:
        os.umask(old)
    assert (tmp_path / "state.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("module", MODULES)
def test_a_failed_sync_leaves_the_old_file_and_no_temporary(
    tmp_path, monkeypatch, module
):
    write_json = importlib.import_module(module)._write_json
    path = tmp_path / "state.json"
    write_json(path, {"old": True})

    def full(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full)
    with pytest.raises(OSError):
        write_json(path, {"new": True})
    assert json.loads(path.read_text()) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]
