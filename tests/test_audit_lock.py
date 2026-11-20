"""Readers of the audit log take a shared lock, so they never see a line that
an append, holding the exclusive lock, has only partly written. The test
holds that lock itself with half a real entry written, so nothing depends
on timing luck."""

import fcntl
import io
import threading
import time

import pytest

from core.kernel import data_plane as dp
from core.kernel.data_plane import SovereignDataPlane


@pytest.fixture
def plane(tmp_path):
    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    plane.store_encrypted("k", {"v": 1})
    assert plane.verify_audit_integrity()  # leave a resume point behind
    return plane


def _next_line(plane) -> bytes:
    with open(plane.audit_log, "rb") as f:
        _, prev, _ = dp._last_entry(f)
    out = io.BytesIO()
    dp._write_entry(out, prev, "delete", "system", "k", {}, plane._audit_mac_key)
    return out.getvalue()


READERS = {
    "full check": lambda p: dp.check_audit_chain(p.audit_log, p._audit_mac_key),
    "resumed check": lambda p: p.verify_audit_integrity(),
    "anchor": lambda p: dp.audit_anchor(p.audit_log)["entries"],
    "recent entries": lambda p: [e["action"] for e in p.get_audit_log(10)][-1],
    "entry count": lambda p: p.audit_entry_count(),
}
EXPECTED = {
    "full check": None,
    "resumed check": True,
    "anchor": 3,  # key_provider, store_encrypted, and the delete being written
    "recent entries": "delete",
    "entry count": 3,
}


@pytest.mark.parametrize("reader", READERS)
def test_a_reader_waits_for_an_append_in_progress(plane, reader):
    line = _next_line(plane)
    result = {}
    with open(plane.audit_log, "ab") as w:
        fcntl.flock(w, fcntl.LOCK_EX)
        w.write(line[: len(line) // 2])
        w.flush()
        thread = threading.Thread(
            target=lambda: result.update(value=READERS[reader](plane))
        )
        thread.start()
        time.sleep(0.3)
        assert thread.is_alive(), "the reader did not wait for the lock"
        w.write(line[len(line) // 2 :])
        w.flush()
    thread.join(timeout=10)
    assert result["value"] == EXPECTED[reader]


def test_without_the_lock_the_half_line_is_seen(plane, monkeypatch):
    # What the lock prevents: an unlocked reader mid-append reports damage.
    monkeypatch.setattr(dp.fcntl, "flock", lambda f, op: None)
    line = _next_line(plane)
    with open(plane.audit_log, "ab") as w:
        w.write(line[: len(line) // 2])
        w.flush()
        assert (
            dp.check_audit_chain(plane.audit_log, plane._audit_mac_key)
            == "unreadable entry"
        )
        w.write(line[len(line) // 2 :])
