"""Audit log inputs that are refused or repaired without crashing a check
or an append: deeply nested JSON, crafted entries, and bytes JSON does
not count as blank."""

import json

import pytest

from core.kernel.data_plane import SovereignDataPlane, check_audit_chain


@pytest.fixture
def plane(tmp_path):
    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    plane.store_encrypted("k", {"v": 1})
    return plane


DEEP = b"[" * 100_000


# -- deeply nested JSON -------------------------------------------------------------


def test_a_deeply_nested_audit_tail_is_set_aside_like_any_damage(plane):
    plane.audit_log.write_bytes(plane.audit_log.read_bytes() + DEEP)
    plane.store_encrypted("k2", {"v": 2})
    [aside] = plane.audit_log.parent.glob("*.damaged-*")
    assert aside.read_bytes() == DEEP
    assert plane.verify_audit_integrity()
    assert check_audit_chain(plane.audit_log, plane._audit_mac_key) is None


# -- crafted entries ------------------------------------------------------------------


def _append_raw(plane, **fields):
    """A correctly linked and hashed entry with one field crafted."""
    last = json.loads(plane.audit_log.read_text().splitlines()[-1])
    entry = {"timestamp": "t", "action": "store_encrypted", "actor": "system",
             "resource": "r", "details": {}, "prev_hash": last["hash"]}  # fmt: skip
    entry.update({k: v for k, v in fields.items() if k != "hash"})
    entry["hash"] = fields.get("hash", SovereignDataPlane._entry_hash(entry))
    with open(plane.audit_log, "ab") as f:
        f.write((json.dumps(entry) + "\n").encode())


@pytest.mark.parametrize(
    ("fields", "expected"),
    [({"mac": "é"}, "has a bad MAC"), ({"action": ["x"]}, "unreadable entry"),
     ({"action": None}, "unreadable entry"), ({"hash": 7}, "unreadable entry")],
    ids=["non-ascii mac", "list action", "null action", "int hash"],
)  # fmt: skip
def test_crafted_entries_fail_the_check_instead_of_crashing_it(plane, fields, expected):
    _append_raw(plane, **fields)
    reason = check_audit_chain(plane.audit_log, plane._audit_mac_key)
    assert reason and expected in reason
    assert plane.verify_audit_integrity() is False
    assert plane.export_compliance_report()["audit_integrity"] is False


# -- what counts as blank --------------------------------------------------------------


@pytest.mark.parametrize("byte", [b"\x0b", b"\x0c"], ids=["vertical tab", "form feed"])
def test_bytes_json_does_not_treat_as_blank_are_damage(plane, byte):
    plane.audit_log.write_bytes(plane.audit_log.read_bytes() + byte)
    plane.store_encrypted("k2", {"v": 2})
    plane.store_encrypted("k3", {"v": 3})
    [aside] = plane.audit_log.parent.glob("*.damaged-*")
    assert aside.read_bytes() == byte
    assert check_audit_chain(plane.audit_log, plane._audit_mac_key) is None
    assert plane.verify_audit_integrity()
    assert plane.audit_entry_count() == len(plane.get_audit_log(100))
