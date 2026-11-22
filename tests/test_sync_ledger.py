"""sync.log is a hash chain, and a twin that fails its checksum is kept
aside, not loaded. A log written before the chain (v0.1.0) is left byte for
byte as it was."""

import hashlib
import itertools
import json
import threading
from pathlib import Path

import pytest

from core.kernel.network_sync import GENESIS_HASH, NetworkSynchronization

REPO_ROOT = Path(__file__).resolve().parent.parent

LEGACY = [
    {"timestamp": "2026-01-01T00:00:00+00:00", "action": "update", "key": "pref.a",
     "version": 1, "checksum": "c" * 64},
    {"timestamp": "2026-01-01T00:00:01+00:00", "action": "update", "key": "pref.b",
     "version": 2, "checksum": "d" * 64},
]  # fmt: skip


@pytest.fixture
def sync(tmp_path):
    return NetworkSynchronization(str(tmp_path))


def _entries(directory):
    return [json.loads(x) for x in (directory / "sync.log").read_text().splitlines()]


def _legacy(directory, newline=True):
    text = "".join(json.dumps(e) + "\n" for e in LEGACY)
    raw = (text if newline else text.rstrip("\n")).encode()
    (directory / "sync.log").write_bytes(raw)
    return raw


def test_every_entry_links_to_the_one_before(sync, tmp_path):
    for i in range(4):
        sync.update_twin("pref.a", i)
    entries = _entries(tmp_path)
    assert entries[0]["prev_hash"] == GENESIS_HASH
    for before, after in itertools.pairwise(entries):
        assert after["prev_hash"] == before["hash"]
    assert sync.verify_sync_ledger() is None
    assert (tmp_path / "sync.log").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "newline", [True, False], ids=["whole last line", "torn last line"]
)
def test_a_v010_log_is_kept_as_it_was_and_chained_after(tmp_path, newline):
    old = _legacy(tmp_path, newline)
    sync = NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.c", 3)
    raw = (tmp_path / "sync.log").read_bytes()
    assert raw.startswith(old)  # never rewritten or truncated
    chained = _entries(tmp_path)[-2:]
    marker, update = chained
    assert marker["action"] == "ledger_chained"
    assert marker["prefix_bytes"] == len(old)
    assert marker["prefix_sha256"] == hashlib.sha256(old).hexdigest()
    assert marker["prev_hash"] == GENESIS_HASH and update["prev_hash"] == marker["hash"]
    assert sync.verify_sync_ledger() is None
    history = sync.get_sync_history()
    assert [e["key"] for e in history if e["action"] == "update"] == [
        "pref.a",
        "pref.b",
        "pref.c",
    ]


def test_a_changed_v010_part_is_reported(tmp_path):
    _legacy(tmp_path)
    sync = NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.c", 3)
    raw = (tmp_path / "sync.log").read_bytes()
    (tmp_path / "sync.log").write_bytes(raw.replace(b"pref.a", b"pref.z", 1))
    assert sync.verify_sync_ledger() == "the v0.1.0 part of sync.log has changed"


@pytest.mark.parametrize("damage", ["edit", "remove", "garbage"])
def test_damage_to_the_chain_is_reported(sync, tmp_path, damage):
    for i in range(4):
        sync.update_twin("pref.a", i)
    lines = (tmp_path / "sync.log").read_text().splitlines()
    if damage == "edit":
        lines[1] = lines[1].replace('"pref.a"', '"pref.b"')
        expected = "entry 2 does not match its hash"
    elif damage == "remove":
        del lines[1]
        expected = "broken chain at entry 2"
    else:
        lines.insert(2, "not json")
        expected = "line 3 is not a ledger entry"
    (tmp_path / "sync.log").write_text("\n".join(lines) + "\n")
    assert sync.verify_sync_ledger() == expected


def test_a_torn_last_line_gets_a_newline_and_the_chain_goes_on(sync, tmp_path):
    sync.update_twin("pref.a", 1)
    good = _entries(tmp_path)[-1]
    with open(tmp_path / "sync.log", "ab") as f:
        f.write(b'{"torn')
    sync.update_twin("pref.b", 2)
    lines = (tmp_path / "sync.log").read_text().split("\n")
    assert lines[-3] == '{"torn'
    assert json.loads(lines[-2])["prev_hash"] == good["hash"]
    # The torn bytes stay in the file, and the check says where.
    assert sync.verify_sync_ledger() == f"line {len(lines) - 2} is not a ledger entry"


def test_two_writers_never_break_the_chain(tmp_path):
    first = NetworkSynchronization(str(tmp_path))
    second = NetworkSynchronization(str(tmp_path))

    def write(instance, name):
        for i in range(15):
            instance.update_twin(f"pref.{name}", i)

    threads = [
        threading.Thread(target=write, args=(s, n))
        for s, n in ((first, "a"), (second, "b"))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(_entries(tmp_path)) == 30
    assert first.verify_sync_ledger() is None


def test_get_sync_history_still_skips_what_it_cannot_read(sync, tmp_path):
    sync.update_twin("pref.a", 1)
    with open(tmp_path / "sync.log", "ab") as f:
        f.write(b'{"torn')
    assert [e["key"] for e in sync.get_sync_history()] == ["pref.a"]


# -- a twin that fails its checksum ----------------------------------------------------


def test_a_twin_that_fails_its_checksum_is_kept_and_recorded(sync, tmp_path):
    sync.update_twin("pref.a", 1)
    twin = json.loads((tmp_path / "digital_twin.json").read_text())
    twin["preferences"]["a"] = 2
    edited = json.dumps(twin).encode()
    (tmp_path / "digital_twin.json").write_bytes(edited)
    again = NetworkSynchronization(str(tmp_path))
    assert (
        again.get_twin_value("pref.a") is None
        and again.local_state.user_id == "ngari-default"
    )
    [kept] = tmp_path.glob("digital_twin.json.rejected-*")
    assert kept.read_bytes() == edited and not (tmp_path / "digital_twin.json").exists()
    last = _entries(tmp_path)[-1]
    assert last["action"] == "twin_rejected" and last["key"] == kept.name
    assert (last["reason"], last["kept_as"], last["bytes"]) == (
        "checksum",
        kept.name,
        len(edited),
    )
    assert last["sha256"] == hashlib.sha256(edited).hexdigest()
    assert again.verify_sync_ledger() is None


@pytest.mark.parametrize(
    "content", [b"{not json", b"[1]", b'{"user_id": 1}'], ids=["torn", "list", "fields"]
)
def test_a_twin_that_cannot_be_read_is_set_aside_and_recorded(tmp_path, content):
    (tmp_path / "digital_twin.json").write_bytes(content)
    again = NetworkSynchronization(str(tmp_path))
    [kept] = tmp_path.glob("digital_twin.json.corrupt-*")
    assert kept.read_bytes() == content
    last = _entries(tmp_path)[-1]
    assert (last["action"], last["key"], last["kept_as"]) == (
        "twin_set_aside",
        kept.name,
        kept.name,
    )
    assert last["reason"] in (
        "JSONDecodeError",
        "TypeError",
        "AttributeError",
        "ValueError",
    )
    assert again.local_state.user_id == "ngari-default"


def test_a_sound_twin_is_loaded_and_writes_nothing_at_load(sync, tmp_path):
    sync.update_twin("pref.a", 1)
    before = (tmp_path / "sync.log").read_bytes()
    again = NetworkSynchronization(str(tmp_path))
    assert again.get_twin_value("pref.a") == 1
    assert (tmp_path / "sync.log").read_bytes() == before
    assert not list(tmp_path.glob("digital_twin.json.*"))


def test_the_hash_does_not_depend_on_key_order(sync, tmp_path):
    sync.update_twin("pref.a", 1)
    sync.update_twin("pref.b", 2)
    lines = (tmp_path / "sync.log").read_text().splitlines()
    reordered = [json.dumps(dict(reversed(list(json.loads(x).items())))) for x in lines]
    assert reordered != lines
    (tmp_path / "sync.log").write_text("\n".join(reordered) + "\n")
    assert sync.verify_sync_ledger() is None


def test_an_append_is_synced(sync, monkeypatch):
    import os

    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: synced.append(fd) or real(fd))
    sync.update_twin("pref.a", 1)
    assert len(synced) >= 1 and synced[-1] is not None
    before = len(synced)
    sync._ledger("probe", "k")
    assert len(synced) == before + 1


def test_a_rejected_twin_comes_back_only_through_update_twin(sync, tmp_path):
    # SYNC_LEDGER.md: moving it back gets it rejected again, import_twin
    # refuses it, and update_twin is the way to keep values from it.
    import os

    sync.update_twin("pref.a", 1)
    twin = json.loads((tmp_path / "digital_twin.json").read_text())
    twin["preferences"]["a"] = 2
    (tmp_path / "digital_twin.json").write_text(json.dumps(twin))
    NetworkSynchronization(str(tmp_path))
    [kept] = tmp_path.glob("digital_twin.json.rejected-*")
    os.replace(kept, tmp_path / "digital_twin.json")
    again = NetworkSynchronization(str(tmp_path))
    assert again.get_twin_value("pref.a") is None
    [kept] = tmp_path.glob("digital_twin.json.rejected-*")
    assert again.import_twin(json.loads(kept.read_text())) is False
    again.update_twin("pref.a", 2)
    assert NetworkSynchronization(str(tmp_path)).get_twin_value("pref.a") == 2
    assert _entries(tmp_path)[-1]["key"] == "pref.a"
    doc = " ".join((REPO_ROOT / "docs" / "SYNC_LEDGER.md").read_text().split())
    assert "it is rejected again" in doc and "`update_twin`" in doc
    assert "move it back after checking it" not in doc


# -- several appends after an upgrade -------------------------------------------------


@pytest.mark.parametrize(
    "newline", [True, False], ids=["whole last line", "torn last line"]
)
def test_the_chain_starts_once_and_holds_over_many_appends(
    tmp_path, monkeypatch, newline
):
    from core.kernel import network_sync

    old = _legacy(tmp_path, newline)
    hashed = []
    real = network_sync._file_sha256
    monkeypatch.setattr(
        network_sync, "_file_sha256", lambda f, n: hashed.append(n) or real(f, n)
    )
    sync = NetworkSynchronization(str(tmp_path))
    for i in range(4):
        sync.update_twin("pref.c", i)
    assert [e["action"] for e in _entries(tmp_path)].count("ledger_chained") == 1
    assert hashed == [len(old)]  # the old bytes are hashed once, not per append
    assert sync.verify_sync_ledger() is None
    assert NetworkSynchronization(str(tmp_path)).verify_sync_ledger() is None


def test_a_first_write_cut_short_starts_the_chain_once(tmp_path):
    (tmp_path / "sync.log").write_bytes(
        b'{"timestamp": "2026-10-30T00:00:00+00:00", "act'
    )
    sync = NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.a", 1)
    sync.update_twin("pref.b", 2)
    lines = (tmp_path / "sync.log").read_text().splitlines()
    chained = [json.loads(x) for x in lines[1:]]
    assert [e["action"] for e in chained] == ["ledger_chained", "update", "update"]
    assert sync.verify_sync_ledger() is None


def test_a_v010_data_directory_verifies_after_the_kernel_starts(tmp_path, monkeypatch):
    from core.kernel import NSBOSKernel

    (tmp_path / "sync").mkdir()
    _legacy(tmp_path / "sync")
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    kernel.start()
    kernel.register_agent("CEO", "strategic")
    kernel.stop()
    assert kernel.network_sync.verify_sync_ledger() is None


FORGED = (
    json.dumps(
        {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "action": "update",
            "key": "pref.forged",
        }
    )
    + "\n"
)


def test_a_line_without_a_hash_before_a_chain_that_started_fresh_is_reported(
    sync, tmp_path
):
    sync.update_twin("pref.a", 1)
    sync.update_twin("pref.b", 2)
    log = tmp_path / "sync.log"
    log.write_text(FORGED + log.read_text())
    assert sync.verify_sync_ledger() == "line 1 is not a ledger entry"


@pytest.mark.parametrize(
    "newline", [True, False], ids=["whole last line", "torn last line"]
)
def test_a_line_slipped_in_after_the_v010_part_is_reported(tmp_path, newline):
    old = _legacy(tmp_path, newline)
    sync = NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.c", 3)
    assert sync.verify_sync_ledger() is None  # the torn case has one added newline
    log = tmp_path / "sync.log"
    raw = log.read_bytes()
    cut = len(old) + (0 if newline else 1)
    log.write_bytes(raw[:cut] + FORGED.encode() + raw[cut:])
    assert sync.verify_sync_ledger() == "the v0.1.0 part of sync.log has changed"
