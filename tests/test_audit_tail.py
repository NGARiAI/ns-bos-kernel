"""An audit log that ends in bytes that are not an entry, as a write cut
short by a crash or power loss leaves, does not stop appends or the
kernel. The bytes are kept beside the log, cut from it, and the repair
is recorded in the chain. Nothing before the last good entry changes."""

import hashlib
import json

import pytest

from core.kernel.data_plane import (
    TAIL_SET_ASIDE,
    SovereignDataPlane,
    append_audit,
    check_audit_chain,
)

TORN = b'{"timestamp": "2026-10-29T08:00:00+00:00", "act'


@pytest.fixture
def plane(tmp_path):
    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    plane.store_encrypted("k", {"v": 1})
    return plane


def _entries(log):
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def _asides(log):
    return sorted(p for p in log.parent.iterdir() if ".damaged-" in p.name)


@pytest.mark.parametrize(
    "junk",
    [
        TORN,
        b"\0" * 300,
        b"\0" * 10_000,
        b"garbage\n",
        TORN + b"\nmore garbage\n",
        b'{"not": "an entry"}\n',
        b"[1, 2]\n",
    ],
    ids=[
        "torn line",
        "zero-filled",
        "longer than the scan window",
        "garbage line",
        "several",
        "json without a hash",
        "json that is not an object",
    ],
)
def test_a_damaged_tail_is_kept_cut_and_recorded(plane, junk):
    log = plane.audit_log
    good = log.read_bytes()
    last_good = _entries(log)[-1]["hash"]
    log.write_bytes(good + junk)
    plane.store_encrypted("k2", {"v": 2})
    [aside] = _asides(log)
    assert aside.read_bytes() == junk
    assert aside.stat().st_mode & 0o777 == 0o600
    assert log.read_bytes().startswith(good)
    repair, stored = _entries(log)[-2:]
    assert repair["action"] == TAIL_SET_ASIDE
    assert repair["prev_hash"] == last_good
    assert repair["details"] == {
        "bytes": len(junk), "sha256": hashlib.sha256(junk).hexdigest(), "kept_as": aside.name
    }  # fmt: skip
    assert "mac" in repair
    assert stored["prev_hash"] == repair["hash"]
    assert plane.verify_audit_integrity()


def test_the_kernel_starts_after_a_torn_write(tmp_path):
    from core.kernel import NSBOSKernel

    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    plane.store_encrypted("k", {"v": 1})
    plane.audit_log.write_bytes(plane.audit_log.read_bytes() + TORN)
    kernel = NSBOSKernel(str(tmp_path))
    assert kernel.data_plane.retrieve_decrypted("k") == {"v": 1}
    assert kernel.data_plane.export_compliance_report()["audit_integrity"] is True


def test_before_the_next_append_the_damage_fails_the_check(plane):
    plane.audit_log.write_bytes(plane.audit_log.read_bytes() + TORN)
    assert (
        check_audit_chain(plane.audit_log, plane._audit_mac_key) == "unreadable entry"
    )


def test_a_whole_last_entry_missing_only_its_newline_is_kept(plane):
    log = plane.audit_log
    log.write_bytes(log.read_bytes().rstrip(b"\n"))
    last = _entries(log)[-1]["hash"]
    plane.store_encrypted("k2", {"v": 2})
    assert _asides(log) == []
    assert _entries(log)[-1]["prev_hash"] == last
    assert plane.verify_audit_integrity()


def test_blank_lines_at_the_end_are_not_damage(plane):
    log = plane.audit_log
    log.write_bytes(log.read_bytes() + b"\n\n  \n")
    plane.store_encrypted("k2", {"v": 2})
    assert _asides(log) == []
    assert TAIL_SET_ASIDE not in [e["action"] for e in _entries(log)]
    assert plane.verify_audit_integrity()


def test_damage_before_the_last_good_entry_is_left_for_the_check_to_report(plane):
    log = plane.audit_log
    lines = log.read_bytes().split(b"\n")
    lines.insert(1, b"garbage in the middle")
    log.write_bytes(b"\n".join(lines))
    plane.store_encrypted("k2", {"v": 2})
    assert _asides(log) == []
    assert b"garbage in the middle" in log.read_bytes()
    assert not plane.verify_audit_integrity()


def test_a_log_with_no_entry_at_all_starts_a_new_chain(plane):
    log = plane.audit_log
    log.write_bytes(b"\0" * 500)
    plane.store_encrypted("k2", {"v": 2})
    [aside] = _asides(log)
    assert aside.read_bytes() == b"\0" * 500
    repair = _entries(log)[0]
    assert repair["action"] == TAIL_SET_ASIDE
    assert repair["prev_hash"] == "0" * 64
    assert plane.verify_audit_integrity()


def test_a_repair_during_a_keyless_append_still_verifies(plane):
    # The keys commands record an operator_auth entry before they load the key.
    log = plane.audit_log
    log.write_bytes(log.read_bytes() + TORN)
    append_audit(log, "operator_auth", "fp", "keys migrate", {"ok": True})
    repair, auth = _entries(log)[-2:]
    assert repair["action"] == TAIL_SET_ASIDE and "mac" not in repair
    assert auth["prev_hash"] == repair["hash"]
    assert plane.verify_audit_integrity()


def test_if_the_damage_cannot_be_kept_the_log_is_not_changed(plane, monkeypatch):
    from core.kernel import data_plane

    log = plane.audit_log
    log.write_bytes(log.read_bytes() + TORN)
    before = log.read_bytes()
    monkeypatch.setattr(data_plane, "publish_new_file", lambda path, data: False)
    with pytest.raises(OSError, match="already exists; the audit log was not changed"):
        plane.store_encrypted("k2", {"v": 2})
    assert log.read_bytes() == before


class _Counting:
    """An open binary file that counts the bytes read through it."""

    def __init__(self, f):
        self.f, self.read_bytes = f, 0

    def seek(self, *args):
        return self.f.seek(*args)

    def read(self, n=-1):
        data = self.f.read(n)
        self.read_bytes += len(data)
        return data


def test_an_ordinary_append_reads_only_the_end_of_the_log(plane):
    from core.kernel.data_plane import _last_entry

    for i in range(200):
        plane.store_encrypted(f"k{i}", {"i": i})
    size = plane.audit_log.stat().st_size
    last = _entries(plane.audit_log)[-1]["hash"]
    with open(plane.audit_log, "rb") as f:
        counting = _Counting(f)
        assert _last_entry(counting) == (size, last, True)
    assert 0 < counting.read_bytes <= 4096 < size
