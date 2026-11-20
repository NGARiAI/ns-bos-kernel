"""verify_audit_integrity() without an anchor resumes from the last check
that passed. It must give the full check's answer, word for word, after any
change to the log, and do less work only when nothing it already checked
has changed."""

import json

import pytest

from core.kernel import data_plane as dp_module
from core.kernel.data_plane import (
    SovereignDataPlane,
    _check_appended,
    append_audit,
    check_audit_chain,
)


@pytest.fixture
def plane(tmp_path):
    plane = SovereignDataPlane(str(tmp_path / "a"))
    for i in range(5):
        plane.store_encrypted(f"k{i}", {"i": i})
    return plane


def _lines(log):
    return log.read_bytes().split(b"\n")[:-1]


def _write(log, lines, end=b"\n"):
    log.write_bytes(b"\n".join(lines) + end)


def _edit(log, index, rehash):
    lines = _lines(log)
    entry = json.loads(lines[index])
    entry["details"] = {"size": 1}
    if rehash:
        entry["hash"] = SovereignDataPlane._entry_hash(entry)
    lines[index] = json.dumps(entry).encode()
    _write(log, lines)


def _swap(log, a, b):
    lines = _lines(log)
    lines[a], lines[b] = lines[b], lines[a]
    _write(log, lines)


def _same_length_edit(log):
    raw = log.read_bytes()
    at = raw.index(b'"size": ') + len(b'"size": ')
    log.write_bytes(
        raw[:at] + (b"9" if raw[at : at + 1] != b"9" else b"8") + raw[at + 1 :]
    )


def _other_log(plane, tmp_path):
    other = SovereignDataPlane(str(tmp_path / "b"))
    for i in range(5):
        other.store_encrypted(f"k{i}", {"i": i})
    plane.audit_log.write_bytes(other.audit_log.read_bytes())


DAMAGE = {
    "same-length edit": lambda p, t: _same_length_edit(p.audit_log),
    "edited entry": lambda p, t: _edit(p.audit_log, 2, rehash=False),
    "rewritten without the key": lambda p, t: _edit(p.audit_log, 2, rehash=True),
    "first entry edited": lambda p, t: _edit(p.audit_log, 0, rehash=False),
    "middle line removed": lambda p, t: _write(p.audit_log, [l for i, l in enumerate(_lines(p.audit_log)) if i != 3]),
    "two lines swapped": lambda p, t: _swap(p.audit_log, 2, 3),
    "last entry cut off": lambda p, t: _write(p.audit_log, _lines(p.audit_log)[:-1]),
    "final newline removed": lambda p, t: _write(p.audit_log, _lines(p.audit_log), end=b""),
    "garbage appended": lambda p, t: p.audit_log.write_bytes(p.audit_log.read_bytes() + b"not json\n"),
    "torn final line": lambda p, t: p.audit_log.write_bytes(p.audit_log.read_bytes() + b'{"timestamp": "2'),
    "blank line appended": lambda p, t: p.audit_log.write_bytes(p.audit_log.read_bytes() + b"\n\n"),
    "entry appended": lambda p, t: append_audit(p.audit_log, "delete", "system", "k1", {}, p._audit_mac_key),
    "unkeyed entry appended": lambda p, t: append_audit(p.audit_log, "delete", "system", "k1", {}),
    "another store's log": _other_log,
    "log deleted": lambda p, t: p.audit_log.unlink(),
}  # fmt: skip


@pytest.mark.parametrize("damage", DAMAGE)
def test_after_any_change_the_answer_is_the_full_checks(plane, tmp_path, damage):
    assert plane.verify_audit_integrity()
    mark = plane._audit_mark
    assert mark is not None
    DAMAGE[damage](plane, tmp_path)
    full = check_audit_chain(plane.audit_log, plane._audit_mac_key)
    resumed, next_mark = _check_appended(plane.audit_log, plane._audit_mac_key, mark)
    assert resumed == full
    assert plane.verify_audit_integrity() is (full is None)
    # A failure clears the resume point; a pass sets one whenever there is a log.
    assert (next_mark is not None) is (full is None and plane.audit_log.exists())


def _count_checked(monkeypatch):
    checked = []
    real = SovereignDataPlane._entry_hash
    monkeypatch.setattr(
        SovereignDataPlane, "_entry_hash",
        staticmethod(lambda entry: checked.append(1) or real(entry)),
    )  # fmt: skip
    return checked


def test_a_later_check_reads_only_what_was_added(plane, monkeypatch):
    for i in range(40):
        plane.store_encrypted(f"more{i}", {"i": i})
    entries = len(_lines(plane.audit_log))
    checked = _count_checked(monkeypatch)
    assert plane.verify_audit_integrity()
    assert len(checked) == entries
    checked.clear()
    assert plane.verify_audit_integrity()
    assert checked == []
    for i in range(3):
        append_audit(
            plane.audit_log, "delete", "system", f"k{i}", {}, plane._audit_mac_key
        )
    checked.clear()
    assert plane.verify_audit_integrity()
    assert len(checked) == 3


def test_a_changed_prefix_or_an_anchor_means_a_full_check(plane, monkeypatch):
    assert plane.verify_audit_integrity()
    entries = len(_lines(plane.audit_log))
    clean = plane.audit_log.read_bytes()
    checked = _count_checked(monkeypatch)
    _same_length_edit(plane.audit_log)
    assert not plane.verify_audit_integrity()
    assert plane._audit_mark is None
    plane.audit_log.write_bytes(clean)
    checked.clear()
    assert plane.verify_audit_integrity()
    assert len(checked) == entries
    checked.clear()
    anchor = dp_module.audit_anchor(plane.audit_log)
    assert plane.verify_audit_integrity(anchor)
    assert len(checked) == entries


def test_an_unterminated_line_is_checked_again_next_time(plane):
    assert plane.verify_audit_integrity()
    raw = plane.audit_log.read_bytes()
    plane.audit_log.write_bytes(raw[:-1])  # the last entry, without its newline
    assert plane.verify_audit_integrity()
    length, _, _ = plane._audit_mark
    assert length == raw.rindex(b"\n", 0, len(raw) - 1) + 1
    plane.audit_log.write_bytes(raw[:-1] + b"x\n")
    assert not plane.verify_audit_integrity()


def test_a_full_check_after_a_mismatch_sets_a_clean_resume_point(plane, monkeypatch):
    assert plane.verify_audit_integrity()
    _write(plane.audit_log, _lines(plane.audit_log)[:-1])  # shorter: full check, passes
    assert plane.verify_audit_integrity()
    checked = _count_checked(monkeypatch)
    assert plane.verify_audit_integrity()
    assert checked == []
