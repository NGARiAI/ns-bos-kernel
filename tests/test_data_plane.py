"""Tests for the sovereign data plane: key file, audit chain, delete, report."""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from core.kernel.data_plane import GENESIS_HASH, SovereignDataPlane


@pytest.fixture
def dp(tmp_path):
    return SovereignDataPlane(data_dir=str(tmp_path))


def _lines(dp):
    return dp.audit_log.read_text().splitlines()


def _write(dp, lines):
    dp.audit_log.write_text("\n".join(lines) + "\n")


def test_round_trip(dp):
    dp.store_encrypted("k", {"a": 1})
    assert dp.retrieve_decrypted("k") == {"a": 1}


def test_key_file_is_private(dp):
    assert stat.S_IMODE(dp.key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(dp.key_file.parent.stat().st_mode) == 0o700


def test_loose_key_permissions_are_tightened(tmp_path):
    SovereignDataPlane(data_dir=str(tmp_path))
    key_file = tmp_path / "keys" / "master.key"
    os.chmod(key_file, 0o644)
    SovereignDataPlane(data_dir=str(tmp_path))
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


def test_existing_key_is_reused(tmp_path):
    first = SovereignDataPlane(data_dir=str(tmp_path))
    first.store_encrypted("k", {"v": 1})
    second = SovereignDataPlane(data_dir=str(tmp_path))
    assert second.retrieve_decrypted("k") == {"v": 1}


@pytest.mark.part11("11.10(e)")
def test_audit_entries_are_chained(dp):
    for i in range(3):
        dp.store_encrypted(f"k{i}", i)
    entries = [json.loads(line) for line in _lines(dp)]
    assert entries[0]["prev_hash"] == GENESIS_HASH
    assert entries[1]["prev_hash"] == entries[0]["hash"]
    assert entries[2]["prev_hash"] == entries[1]["hash"]
    assert dp.verify_audit_integrity()


def test_audit_log_is_private(dp):
    dp.store_encrypted("k", 1)
    assert stat.S_IMODE(dp.audit_log.stat().st_mode) == 0o600


@pytest.mark.part11("11.10(a)", "11.10(e)")
def test_edited_entry_detected(dp):
    for i in range(3):
        dp.store_encrypted(f"k{i}", i)
    lines = _lines(dp)
    entry = json.loads(lines[1])
    entry["resource"] = "forged"
    lines[1] = json.dumps(entry)
    _write(dp, lines)
    assert not dp.verify_audit_integrity()


def test_edited_entry_with_recomputed_hash_breaks_chain(dp):
    for i in range(3):
        dp.store_encrypted(f"k{i}", i)
    lines = _lines(dp)
    entry = json.loads(lines[1])
    entry["resource"] = "forged"
    body = {k: v for k, v in entry.items() if k != "hash"}
    entry["hash"] = hashlib.sha256(
        json.dumps(body, sort_keys=True).encode()
    ).hexdigest()
    lines[1] = json.dumps(entry)
    _write(dp, lines)
    assert not dp.verify_audit_integrity()


@pytest.mark.part11("11.10(a)", "11.10(e)")
def test_deleted_middle_entry_detected(dp):
    for i in range(3):
        dp.store_encrypted(f"k{i}", i)
    lines = _lines(dp)
    _write(dp, [lines[0], lines[2]])
    assert not dp.verify_audit_integrity()


def test_removed_head_detected(dp):
    for i in range(3):
        dp.store_encrypted(f"k{i}", i)
    _write(dp, _lines(dp)[1:])
    assert not dp.verify_audit_integrity()


@pytest.mark.part11("11.10(a)", "11.10(e)")
def test_reordered_entries_detected(dp):
    for i in range(3):
        dp.store_encrypted(f"k{i}", i)
    lines = _lines(dp)
    _write(dp, [lines[1], lines[0], lines[2]])
    assert not dp.verify_audit_integrity()


def test_garbage_line_is_a_failure_not_a_crash(dp):
    dp.store_encrypted("k", 1)
    with open(dp.audit_log, "a") as f:
        f.write("not json\n")
    assert not dp.verify_audit_integrity()


def _legacy_entry(n):
    entry = {
        "timestamp": f"2025-01-0{n}T00:00:00+00:00",
        "action": "store_encrypted",
        "actor": "system",
        "resource": f"old{n}",
        "details": {},
    }
    entry["hash"] = hashlib.sha256(
        json.dumps(entry, sort_keys=True).encode()
    ).hexdigest()
    return entry


def test_legacy_log_chains_forward_and_verifies_once_adopted(dp):
    from core.kernel.data_plane import LEGACY_HISTORY, append_audit, check_audit_chain

    legacy = [_legacy_entry(1), _legacy_entry(2)]
    _write(dp, [json.dumps(e) for e in legacy])
    assert check_audit_chain(dp.audit_log, dp._audit_mac_key) == (
        "2 unkeyed entries from before the key are not attested; run audit adopt-legacy"
    )
    dp.store_encrypted("new", 1)
    entries = [json.loads(line) for line in _lines(dp)]
    assert entries[2]["prev_hash"] == legacy[1]["hash"]
    assert not dp.verify_audit_integrity()
    details = {"entries": 2, "tail": legacy[1]["hash"]}
    append_audit(
        dp.audit_log, LEGACY_HISTORY, "operator", "audit", details, dp._audit_mac_key
    )
    assert dp.verify_audit_integrity()


def test_unchained_entry_after_chained_entries_rejected(dp):
    dp.store_encrypted("k", 1)
    with open(dp.audit_log, "a") as f:
        f.write(json.dumps(_legacy_entry(3)) + "\n")
    assert not dp.verify_audit_integrity()


def test_delete_overwrites_the_blocks(dp):
    path = dp.store_encrypted("k", {"secret": "x" * 200})
    alias = dp.data_dir / "alias"
    os.link(path, alias)
    original = alias.read_bytes()
    assert dp.delete("k")
    assert not os.path.exists(path)
    leftover = alias.read_bytes()
    assert len(leftover) == len(original)
    assert leftover != original


def test_delete_missing_returns_false(dp):
    assert dp.delete("nope") is False


def test_report_reflects_real_state(dp):
    dp.store_encrypted("k", 1)
    report = dp.export_compliance_report()
    assert report["data_sovereignty"] == "enforced"
    assert report["audit_integrity"] is True
    assert report["key_file_mode"] == "0o600"

    lines = _lines(dp)
    entry = json.loads(lines[0])
    entry["resource"] = "forged"
    _write(dp, [json.dumps(entry)])
    report = dp.export_compliance_report()
    assert report["audit_integrity"] is False
    assert report["data_sovereignty"] == "violations_detected"


def test_report_counts_more_than_100_entries(dp):
    for i in range(120):
        dp.store_encrypted("k", i)
    written = len(_lines(dp))
    assert written > 100
    assert dp.export_compliance_report()["audit_entries"] == written


def _append_many(data_dir, count):
    plane = SovereignDataPlane(data_dir=data_dir)
    for i in range(count):
        plane.store_encrypted("shared", i)


def test_concurrent_writers_keep_one_chain(tmp_path):
    import multiprocessing

    ctx = multiprocessing.get_context("fork")
    SovereignDataPlane(data_dir=str(tmp_path))
    procs = [
        ctx.Process(target=_append_many, args=(str(tmp_path), 25)) for _ in range(4)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    assert all(p.exitcode == 0 for p in procs)

    plane = SovereignDataPlane(data_dir=str(tmp_path))
    stores = [
        e for e in plane.get_audit_log(limit=1000) if e["action"] == "store_encrypted"
    ]
    assert len(stores) == 100
    assert plane.verify_audit_integrity()


def test_large_entry_does_not_break_tail_read(dp):
    dp.store_encrypted("first", 1)
    dp._audit("custom", "system", "r", {"blob": "x" * 20000})
    dp.store_encrypted("after", 2)
    assert dp.verify_audit_integrity()


def test_append_audit_extends_the_chain_without_a_data_plane(tmp_path):
    from core.kernel.data_plane import append_audit

    plane = SovereignDataPlane(data_dir=str(tmp_path))
    plane.store_encrypted("k", {"v": 1})
    append_audit(plane.audit_log, "operator_auth", "fp", "keys restore", {"ok": False})
    assert plane.verify_audit_integrity()
    last = plane.get_audit_log(limit=1)[0]
    assert (last["action"], last["actor"], last["details"]) == (
        "operator_auth",
        "fp",
        {"ok": False},
    )
    fresh = tmp_path / "elsewhere" / "audit" / "sovereign_audit.log"
    append_audit(fresh, "operator_auth", "fp", "keys migrate", {"ok": True})
    assert oct(fresh.stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize(
    "name",
    ["", "../escaped", "../keys/master", "a/b", "/etc/passwd", "nul\0byte", "x" * 252],
)
def test_key_names_that_leave_the_store_are_rejected(tmp_path, name):
    plane = SovereignDataPlane(data_dir=str(tmp_path / "s"))
    (tmp_path / "s" / "escaped.enc").write_bytes(b"outside")
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    log_before = plane.audit_log.read_bytes()
    for call in (
        lambda: plane.store_encrypted(name, {"x": 1}),
        lambda: plane.retrieve_decrypted(name),
        lambda: plane.delete(name),
    ):
        with pytest.raises(ValueError, match="key name"):
            call()
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before
    assert (tmp_path / "s" / "escaped.enc").read_bytes() == b"outside"
    assert plane.audit_log.read_bytes() == log_before


def test_key_names_must_be_strings(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    for bad in (b"bytes", 7, None):
        with pytest.raises(TypeError, match="key must be a str"):
            plane.store_encrypted(bad, {})


@pytest.mark.parametrize(
    "name", ["kernel_state", "agent.memory", "..", ".hidden", "ünïcode", "x" * 251]
)
def test_plain_names_still_work(tmp_path, name):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    path = Path(plane.store_encrypted(name, {"n": 1}))
    assert path.parent == plane.encrypted_dir
    assert plane.retrieve_decrypted(name) == {"n": 1}
    assert plane.delete(name) is True


def _files(plane):
    return sorted(p.name for p in plane.encrypted_dir.iterdir())


@pytest.mark.parametrize("failing", ["fdopen", "fsync", "replace"])
def test_a_failed_store_keeps_the_old_value(tmp_path, monkeypatch, failing):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    plane.store_encrypted("note", {"v": "old"})
    before = _files(plane)
    entries = len(plane.get_audit_log(limit=10**9))

    def crash(*args, **kwargs):
        raise OSError(28, "No space left on device")

    with monkeypatch.context() as patched:
        patched.setattr(os, failing, crash)
        with pytest.raises(OSError, match="No space left"):
            plane.store_encrypted("note", {"v": "new"})
    assert plane.retrieve_decrypted("note") == {"v": "old"}
    assert _files(plane) == before
    assert len(plane.get_audit_log(limit=10**9)) == entries + 1  # the retrieve


def test_an_interrupted_store_keeps_the_old_value(tmp_path, monkeypatch):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    plane.store_encrypted("note", {"v": "old"})

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(KeyboardInterrupt):
        plane.store_encrypted("note", {"v": "new"})
    monkeypatch.undo()
    assert plane.retrieve_decrypted("note") == {"v": "old"}
    assert _files(plane) == ["note.enc"]


def test_the_new_value_is_synced_before_it_replaces_the_old(tmp_path, monkeypatch):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    plane.store_encrypted("note", {"v": "old"})
    target = plane.encrypted_dir / "note.enc"
    old = target.read_bytes()
    seen = []
    real_fsync = os.fsync

    def spy(fd):
        mode = os.fstat(fd).st_mode
        what = "dir" if stat.S_ISDIR(mode) else "file"
        if what == "dir" and os.path.samestat(
            os.fstat(fd), os.stat(plane.encrypted_dir)
        ):
            what = "encrypted dir"
        seen.append((what, target.read_bytes() == old))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    plane.store_encrypted("note", {"v": "new"})
    # The new file is synced while the old value is still in place, then the
    # directory holding the rename, then the audit log.
    assert seen[:3] == [("file", True), ("encrypted dir", False), ("file", False)]


def test_a_store_in_flight_is_not_counted_as_stored_data(tmp_path, monkeypatch):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    counts = []
    real_replace = os.replace

    def spy(src, dst):
        counts.append(len(list(plane.encrypted_dir.glob("*.enc"))))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    plane.store_encrypted("note", {"v": 1})
    assert counts == [0]


def test_stored_files_are_private(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    path = plane.store_encrypted("note", {"v": 1})
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    old = plane.encrypted_dir / "legacy.enc"
    old.write_bytes(b"x")
    old.chmod(0o644)
    plane.store_encrypted("legacy", {"v": 2})
    assert stat.S_IMODE(old.stat().st_mode) == 0o600


def test_a_temporary_file_is_never_counted_as_data(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    (plane.encrypted_dir / ".tmp-0123456789abcdef").write_bytes(b"partial")
    assert plane.export_compliance_report()["encrypted_files"] == 0


def test_the_store_directories_are_owner_only(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path / "s"))
    for path in (plane.data_dir, plane.encrypted_dir, plane.audit_log.parent):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, path


def test_open_directories_from_older_versions_are_tightened(tmp_path):
    base = tmp_path / "s"
    for sub in ("", "encrypted", "audit"):
        (base / sub).mkdir(parents=True, exist_ok=True)
        (base / sub).chmod(0o755)
    plane = SovereignDataPlane(data_dir=str(base))
    plane.store_encrypted("k", 1)
    for sub in ("", "encrypted", "audit"):
        assert stat.S_IMODE((base / sub).stat().st_mode) == 0o700, sub
    assert plane.retrieve_decrypted("k") == 1


# -- a delete cut short ----------------------------------------------------------------


@pytest.fixture
def file_provider(monkeypatch):
    monkeypatch.delenv("NGARI_KEY_PROVIDER", raising=False)


def _interrupted_delete(tmp_path, monkeypatch, at_call=1):
    """A delete stopped at its at_call'th fsync, as a SIGTERM there (main
    turns it into KeyboardInterrupt) or a power loss would stop it."""
    store = tmp_path / "sovereign"
    plane = SovereignDataPlane(str(store))
    plane.store_encrypted("a-invoice", {"total": 1})
    plane.store_encrypted("b-ledger", {"total": 2})
    real, calls = os.fsync, []

    def stop_here(fd):
        calls.append(fd)
        if len(calls) == at_call:
            raise KeyboardInterrupt
        return real(fd)

    with monkeypatch.context() as m:
        m.setattr(os, "fsync", stop_here)
        with pytest.raises(KeyboardInterrupt):
            plane.delete("a-invoice")
    return store, plane


@pytest.mark.parametrize("at_call", [1, 2, 3])
def test_a_delete_cut_short_leaves_the_old_value_or_nothing(
    tmp_path, monkeypatch, file_provider, at_call
):
    # The file is renamed aside before it is overwritten: stopped at any
    # point, the key's name holds the old value or nothing, never random bytes.
    store, plane = _interrupted_delete(tmp_path, monkeypatch, at_call)
    assert not plane._path("a-invoice").exists()
    assert sorted(p.name for p in plane.encrypted_dir.glob("*.enc")) == ["b-ledger.enc"]
    # The next start finishes it: nothing of the value stays on disk.
    again = SovereignDataPlane(str(store))
    assert sorted(p.name for p in again.encrypted_dir.iterdir()) == ["b-ledger.enc"]
    assert again.retrieve_decrypted("b-ledger") == {"total": 2}


def test_a_delete_cut_short_does_not_make_the_key_commands_refuse_the_key(
    tmp_path, monkeypatch, file_provider
):
    from core.kernel.data_plane.keys_cli import current_key

    store, _ = _interrupted_delete(tmp_path, monkeypatch)
    # A file a delete has set aside is not checked against the master key.
    assert current_key(store, {"NGARI_TPM_TCTI": f"libtpms:{tmp_path}/unused.state"})


def test_a_key_another_plane_deletes_first_is_not_deleted_twice(
    tmp_path, file_provider
):
    a = SovereignDataPlane(str(tmp_path / "s"))
    b = SovereignDataPlane(str(tmp_path / "s"))
    a.store_encrypted("k", 1)
    assert b.delete("k") is True
    assert a.delete("k") is False
    deletes = [e for e in a.get_audit_log(100) if e["action"] == "delete"]
    assert len(deletes) == 1


def test_the_rename_is_synced_before_the_value_is_overwritten(
    tmp_path, monkeypatch, file_provider
):
    # A power cut after the overwrite but before an unsynced rename would put
    # the random bytes back under the key's name.
    plane = SovereignDataPlane(str(tmp_path / "s"))
    plane.store_encrypted("k", 1)
    real, synced = os.fsync, []
    monkeypatch.setattr(
        os, "fsync",
        lambda fd: synced.append(stat.S_ISDIR(os.fstat(fd).st_mode)) or real(fd),
    )  # fmt: skip
    plane.delete("k")
    # The delete's own: directory, the file, directory (then the audit append).
    assert synced[:3] == [True, False, True]


def test_delete_never_writes_outside_the_store(tmp_path, file_provider):
    plane = SovereignDataPlane(str(tmp_path / "s"))
    outside = tmp_path / "precious.db"
    outside.write_bytes(b"keep me" * 100)
    (plane.encrypted_dir / "k.enc").symlink_to(outside)
    assert plane.delete("k") is True  # the link is gone
    assert outside.read_bytes() == b"keep me" * 100
    assert not (plane.encrypted_dir / "k.enc").is_symlink()
    assert list(plane.encrypted_dir.iterdir()) == []


def test_a_key_another_plane_deletes_mid_read_reads_as_absent(
    tmp_path, monkeypatch, file_provider
):
    import builtins

    a = SovereignDataPlane(str(tmp_path / "s"))
    b = SovereignDataPlane(str(tmp_path / "s"))
    a.store_encrypted("k", 1)
    real_open = builtins.open

    def deleted_first(file, *args, **kwargs):
        if str(file).endswith("k.enc"):
            monkeypatch.setattr(builtins, "open", real_open)
            b.delete("k")  # deleted just as the read opens the file
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", deleted_first)
    assert a.retrieve_decrypted("k") is None
    assert a.retrieve_decrypted("missing") is None


def test_two_key_names_never_share_one_file(tmp_path, file_provider):
    plane = SovereignDataPlane(str(tmp_path / "s"))
    plane.store_encrypted("é", {"owner": "first"})
    for name in ("\udcc3\udca9", "a\ud800b"):
        with pytest.raises(ValueError, match="is not UTF-8 text"):
            plane.store_encrypted(name, {"owner": "second"})
        with pytest.raises(ValueError):
            plane.retrieve_decrypted(name)
    assert plane.retrieve_decrypted("é") == {"owner": "first"}


# -- a tail a crash cut short ----------------------------------------------------------


@pytest.mark.parametrize(
    "tail", [b'{"timestamp": "2026-11-01T', b"\x00\x00\x00", b'{"partial": true}\n'],
    ids=["cut-json", "zeros", "not-an-entry"],
)  # fmt: skip
def test_a_torn_last_line_does_not_stop_reading_the_log(tmp_path, file_provider, tail):
    plane = SovereignDataPlane(str(tmp_path / "s"))
    plane.store_encrypted("k", 1)
    whole = plane.get_audit_log(100)
    with open(plane.audit_log, "ab") as f:
        f.write(tail)
    # A torn tail is neither returned nor counted.
    assert plane.get_audit_log(100) == whole
    assert plane.audit_entry_count() == len(whole)
    assert plane.export_compliance_report()["audit_entries"] == len(whole)


def test_a_last_entry_missing_only_its_newline_is_still_read(tmp_path, file_provider):
    plane = SovereignDataPlane(str(tmp_path / "s"))
    plane.store_encrypted("k", 1)
    whole = plane.get_audit_log(100)
    data = plane.audit_log.read_bytes()
    plane.audit_log.write_bytes(data.rstrip(b"\n"))
    assert plane.get_audit_log(100) == whole and plane.audit_entry_count() == len(whole)


# -- what the start-time sweep erases --------------------------------------------------


def test_a_key_named_like_a_delete_leftover_survives_a_restart(tmp_path):
    # The sweep erases only what delete() set aside: a key ".deleting-x" is
    # stored as ".deleting-x.enc" and is kept.
    from core.kernel.data_plane import SovereignDataPlane

    first = SovereignDataPlane(data_dir=str(tmp_path))
    keys = [".deleting-invoice", ".deleting-0123456789abcdef"]
    for key in keys:
        first.store_encrypted(key, {"key": key})
    left = first.encrypted_dir / ".deleting-fedcba9876543210"
    left.write_bytes(b"a value a cut-short delete set aside")
    second = SovereignDataPlane(data_dir=str(tmp_path))
    assert [second.retrieve_decrypted(key) for key in keys] == [
        {"key": k} for k in keys
    ]
    assert not left.exists()


# -- a delete racing another process's start -------------------------------------------


def test_a_delete_whose_file_another_start_erased_still_succeeds(tmp_path, monkeypatch):
    # A CLI command opening the same store sweeps files set aside, and can
    # erase this one between delete's rename and its erase: the delete still
    # succeeds and is recorded once.
    from core.kernel import data_plane as dp_mod

    first = SovereignDataPlane(data_dir=str(tmp_path))
    first.store_encrypted("invoice", {"amount": 12})
    real_sync = dp_mod._sync_directory
    swept = []

    def sync_then_sweep(path):
        real_sync(path)
        if not swept:  # once, right after delete's rename
            swept.append(1)
            SovereignDataPlane(data_dir=str(tmp_path))

    monkeypatch.setattr(dp_mod, "_sync_directory", sync_then_sweep)
    assert first.delete("invoice") is True
    monkeypatch.setattr(dp_mod, "_sync_directory", real_sync)
    assert swept and first.retrieve_decrypted("invoice") is None
    assert list(first.encrypted_dir.iterdir()) == []
    assert [e["action"] for e in first.get_audit_log(100)].count("delete") == 1


@pytest.mark.parametrize("gone_at", ["open", "unlink"])
def test_a_start_whose_leftover_another_start_erased_still_starts(
    tmp_path, monkeypatch, gone_at
):
    from core.kernel import data_plane as dp_mod

    first = SovereignDataPlane(data_dir=str(tmp_path))
    left = first.encrypted_dir / ".deleting-0123456789abcdef"
    left.write_bytes(b"a value set aside")
    if gone_at == "open":
        real_open = os.open

        def erased_first(path, *args, **kwargs):
            if str(path).endswith(left.name):
                os.unlink(path)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(dp_mod.os, "open", erased_first)
    else:
        real_unlink = Path.unlink

        def erased_meanwhile(self, *args, **kwargs):
            if self.name == left.name:
                real_unlink(self)
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", erased_meanwhile)
    SovereignDataPlane(data_dir=str(tmp_path))
    assert not left.exists()


def test_an_erase_that_fails_otherwise_still_raises(tmp_path, monkeypatch):
    # Only a file already gone counts as erased.
    from core.kernel import data_plane as dp_mod

    first = SovereignDataPlane(data_dir=str(tmp_path))
    left = first.encrypted_dir / ".deleting-0123456789abcdef"
    left.write_bytes(b"x")

    def refuse(path, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(dp_mod.os, "open", refuse)
    with pytest.raises(PermissionError):
        first._erase(left)
