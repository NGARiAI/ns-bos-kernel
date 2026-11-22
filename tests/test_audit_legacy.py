"""Entries written before the audit log had a key verify only once an
operator has vouched for them with `audit adopt-legacy`; a rewrite of that
history by someone without the key fails, before and after a restart. The
resumed check keeps its saved state in step with the bytes it hashed."""

import hashlib
import json

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import (
    LEGACY_HISTORY,
    SovereignDataPlane,
    append_audit,
    audit_cli,
    check_audit_chain,
)

NOT_ATTESTED = (
    "unkeyed entries from before the key are not attested; run audit adopt-legacy"
)


@pytest.fixture
def store(tmp_path):
    return tmp_path / "sovereign"


def _env(store):
    return {"NGARI_DATA_DIR": str(store.parent)}


def _log(store):
    return store / "audit" / "sovereign_audit.log"


def _entries(store):
    return [
        json.loads(line)
        for line in _log(store).read_text().splitlines()
        if line.strip()
    ]


def _rehash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    entry["hash"] = hashlib.sha256(
        json.dumps(body, sort_keys=True).encode()
    ).hexdigest()
    return entry["hash"]


def _v010_entries(store, n):
    """Entries as v0.1.0 wrote them: a hash of the entry, no link, no MAC."""
    _log(store).parent.mkdir(parents=True, exist_ok=True)
    out = []
    for i in range(n):
        entry = {"timestamp": f"2026-01-01T00:00:0{i}+00:00", "action": "store_encrypted",
                 "actor": "system", "resource": f"old{i}", "details": {}}  # fmt: skip
        _rehash(entry)
        out.append(entry)
    _log(store).write_text("".join(json.dumps(e) + "\n" for e in out))
    return out


def _keyless_rewrite(store, keep, insert=None, chained=True):
    """What a writer without the key can do: keep some entries, add one,
    strip every MAC and rebuild the hashes and links."""
    kept = [dict(e) for e in _entries(store) if keep(e)]
    if insert is not None:
        kept.insert(1, insert(kept[0]))
    prev, out = "0" * 64, []
    for entry in kept:
        entry.pop("mac", None)
        if chained:
            entry["prev_hash"] = prev
        else:
            entry.pop("prev_hash", None)
        prev = _rehash(entry)
        out.append(json.dumps(entry))
    _log(store).write_text("\n".join(out) + "\n")


# -- history is adopted, not assumed -------------------------------------------------


def test_history_fails_until_adopted_and_then_verifies(store, capsys):
    old = _v010_entries(store, 2)
    plane = SovereignDataPlane(str(store))
    plane.store_encrypted("new", 1)
    assert check_audit_chain(_log(store), plane._audit_mac_key) == f"2 {NOT_ATTESTED}"
    assert not plane.verify_audit_integrity()
    report = plane.export_compliance_report()
    assert (report["audit_integrity"], report["data_sovereignty"]) == (
        False,
        "violations_detected",
    )
    assert audit_cli.cli(["verify"], _env(store)) == 1
    capsys.readouterr()

    assert audit_cli.cli(["adopt-legacy"], _env(store)) == 0
    out = capsys.readouterr().out
    assert out.startswith(
        f"adopted 2 entries written before the key (tail {old[1]['hash'][:16]})"
    )
    last = _entries(store)[-1]
    assert (last["action"], last["actor"], "mac" in last) == (
        LEGACY_HISTORY,
        "operator",
        True,
    )
    assert last["details"] == {"entries": 2, "tail": old[1]["hash"]}
    assert plane.verify_audit_integrity()
    assert plane.export_compliance_report()["audit_integrity"] is True
    assert audit_cli.cli(["verify"], _env(store)) == 0
    assert "5 entries verified" in capsys.readouterr().out

    assert audit_cli.cli(["adopt-legacy"], _env(store)) == 0
    assert "already attested" in capsys.readouterr().out
    assert len(_entries(store)) == 5


def test_a_log_can_be_adopted_before_the_first_keyed_start(store, capsys):
    old = _v010_entries(store, 3)
    (store / "keys").mkdir(parents=True)
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    (store / "keys" / "master.key").chmod(0o600)
    assert audit_cli.cli(["adopt-legacy"], _env(store)) == 0
    assert _entries(store)[-1]["details"] == {"entries": 3, "tail": old[2]["hash"]}
    plane = SovereignDataPlane(str(store))
    assert plane.verify_audit_integrity()
    assert [e["action"] for e in _entries(store)] == [
        "store_encrypted", "store_encrypted", "store_encrypted", LEGACY_HISTORY, "key_provider"
    ]  # fmt: skip


def test_a_fresh_log_has_nothing_to_adopt(store, capsys):
    plane = SovereignDataPlane(str(store))
    assert audit_cli.cli(["adopt-legacy"], _env(store)) == 0
    assert "nothing to adopt" in capsys.readouterr().out
    assert len(_entries(store)) == 1
    assert plane.verify_audit_integrity()


def test_adopt_refuses_history_whose_hashes_do_not_hold(store, capsys):
    _v010_entries(store, 2)
    entries = _entries(store)
    entries[0]["resource"] = "edited"
    _log(store).write_text("".join(json.dumps(e) + "\n" for e in entries))
    (store / "keys").mkdir(parents=True)
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    (store / "keys" / "master.key").chmod(0o600)
    assert audit_cli.cli(["adopt-legacy"], _env(store)) == 1
    assert "FAILED: entry 1 does not match its hash" in capsys.readouterr().err
    assert len(_entries(store)) == 2


def test_keyless_operator_entries_are_not_history(store):
    _log(store).parent.mkdir(parents=True)
    append_audit(_log(store), "operator_auth", "fp", "keys migrate", {"ok": True})
    plane = SovereignDataPlane(str(store))
    assert plane.verify_audit_integrity()


# -- a writer without the key -------------------------------------------------------


def _plane_with_history(store):
    plane = SovereignDataPlane(str(store))
    plane.store_encrypted("payroll", 1)
    plane.retrieve_decrypted("payroll")
    plane.delete("payroll")
    return plane


@pytest.mark.parametrize("chained", [True, False], ids=["linked", "v0.1.0 format"])
def test_a_keyless_rewrite_of_the_whole_log_is_caught(store, capsys, chained):
    plane = _plane_with_history(store)
    _keyless_rewrite(
        store,
        keep=lambda e: e["action"] not in ("key_provider", "retrieve_decrypted"),
        insert=lambda first: {**first, "resource": "invented"},
        chained=chained,
    )
    assert [e["resource"] for e in _entries(store)] == [
        "payroll",
        "invented",
        "payroll",
    ]
    assert check_audit_chain(_log(store), plane._audit_mac_key) == f"3 {NOT_ATTESTED}"
    assert not plane.verify_audit_integrity()
    assert plane.export_compliance_report()["audit_integrity"] is False
    # A restart appends a keyed entry after the forgery; it still fails.
    again = SovereignDataPlane(str(store))
    assert not again.verify_audit_integrity()
    assert audit_cli.cli(["verify"], _env(store)) == 1
    assert NOT_ATTESTED in capsys.readouterr().err


def test_a_rewrite_of_adopted_history_is_caught(store, capsys):
    _v010_entries(store, 2)
    plane = SovereignDataPlane(str(store))
    assert audit_cli.cli(["adopt-legacy"], _env(store)) == 0
    assert plane.verify_audit_integrity()
    for keep in (
        lambda e: e["resource"] != "old0",  # one entry removed
        lambda e: e["action"] != LEGACY_HISTORY,  # the attestation removed
    ):
        clean = _log(store).read_bytes()
        _keyless_rewrite(store, keep=keep)
        assert check_audit_chain(_log(store), plane._audit_mac_key) is not None
        assert not plane.verify_audit_integrity()
        _log(store).write_bytes(clean)
    assert plane.verify_audit_integrity()


def test_an_attestation_cannot_be_written_without_the_key(store):
    _v010_entries(store, 2)
    plane = SovereignDataPlane(str(store))
    append_audit(_log(store), LEGACY_HISTORY, "operator", "audit",
                 {"entries": 2, "tail": _entries(store)[1]["hash"]})  # fmt: skip
    assert check_audit_chain(_log(store), plane._audit_mac_key) == (
        "entry 4 (legacy_history) has no MAC"
    )


def test_an_attestation_must_name_exactly_the_history_before_it(store):
    old = _v010_entries(store, 2)
    plane = SovereignDataPlane(str(store))
    key = plane._audit_mac_key
    clean = _log(store).read_bytes()
    for details in (
        {"entries": 1, "tail": old[1]["hash"]},
        {"entries": 2, "tail": old[0]["hash"]},
        {"entries": 2},
    ):
        append_audit(_log(store), LEGACY_HISTORY, "operator", "audit", details, key)
        assert (
            check_audit_chain(_log(store), key)
            == "entry 4 attests history that is not there"
        )
        _log(store).write_bytes(clean)
    good = {"entries": 2, "tail": old[1]["hash"]}
    append_audit(_log(store), LEGACY_HISTORY, "operator", "audit", good, key)
    assert check_audit_chain(_log(store), key) is None
    append_audit(_log(store), LEGACY_HISTORY, "operator", "audit", good, key)
    assert (
        check_audit_chain(_log(store), key)
        == "entry 5 attests history that is not there"
    )
    # And on a log with no history at all.
    fresh = SovereignDataPlane(str(store.parent / "fresh"))
    append_audit(fresh.audit_log, LEGACY_HISTORY, "operator", "audit",
                 {"entries": 0, "tail": "0" * 64}, fresh._audit_mac_key)  # fmt: skip
    assert check_audit_chain(fresh.audit_log, fresh._audit_mac_key) == (
        "entry 2 attests history that is not there"
    )


# -- the resumed check and an unterminated last line --------------------------------


def test_an_unchanged_log_without_a_final_newline_verifies_every_time(store):
    plane = SovereignDataPlane(str(store))
    plane.store_encrypted("a", 1)
    _log(store).write_bytes(_log(store).read_bytes().rstrip(b"\n"))
    for _ in range(4):
        assert plane.verify_audit_integrity()
        assert check_audit_chain(_log(store), plane._audit_mac_key) is None
    plane.store_encrypted("b", 2)
    assert plane.verify_audit_integrity()
    assert plane.verify_audit_integrity()


def test_deleting_the_entry_before_a_torn_tail_is_caught_by_the_resumed_check(store):
    plane = SovereignDataPlane(str(store))
    plane.store_encrypted("a", 1)
    plane.store_encrypted("b", 2)
    log = _log(store)
    log.write_bytes(
        log.read_bytes().rstrip(b"\n")
    )  # the last entry, L, without its newline
    assert plane.verify_audit_integrity()
    plane.store_encrypted("c", 3)  # the append terminates L and adds L'
    lines = log.read_bytes().split(b"\n")
    del lines[-3]  # L goes; L' still links to it
    log.write_bytes(b"\n".join(lines))
    full = check_audit_chain(log, plane._audit_mac_key)
    assert full == "broken chain at entry 3"
    assert plane.verify_audit_integrity() is False
    assert plane.verify_audit_integrity() is False
