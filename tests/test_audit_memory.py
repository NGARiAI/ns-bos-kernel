"""Reading the audit log must not load it all: it grows with every store and
retrieve, and the kernel reads it on every status call."""

import tracemalloc

import pytest

from core.kernel.data_plane import SovereignDataPlane, append_audit

ENTRIES = 20_000


@pytest.fixture(scope="module")
def big(tmp_path_factory):
    plane = SovereignDataPlane(data_dir=str(tmp_path_factory.mktemp("big")))
    for i in range(ENTRIES):
        append_audit(plane.audit_log, "retrieve_decrypted", "system", f"k{i}", {},
                     plane._audit_mac_key)  # fmt: skip
    return plane


def _peak_mb(fn):
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1] / 1e6
    finally:
        tracemalloc.stop()


def test_the_log_is_large_enough_to_matter(big):
    assert big.audit_log.stat().st_size > 5_000_000


def test_recent_entries_cost_memory_for_those_entries_only(big):
    assert _peak_mb(lambda: big.get_audit_log(10)) < 1.0


def test_the_compliance_report_does_not_load_the_log(big):
    assert _peak_mb(big.export_compliance_report) < 2.0


def test_recent_entries_are_the_last_ones_in_order(big):
    last = big.get_audit_log(3)
    assert [e["resource"] for e in last] == [
        f"k{ENTRIES - 3}",
        f"k{ENTRIES - 2}",
        f"k{ENTRIES - 1}",
    ]
    assert big.audit_entry_count() == ENTRIES + 1  # plus the key_provider start entry
    assert big.export_compliance_report()["audit_entries"] == ENTRIES + 1


def test_blank_lines_and_odd_limits(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    plane.store_encrypted("a", 1)
    with open(plane.audit_log, "a") as f:
        f.write("\n\n")
    assert [e["action"] for e in plane.get_audit_log(5)] == [
        "key_provider",
        "store_encrypted",
    ]
    assert plane.audit_entry_count() == 2
    assert plane.get_audit_log(0) == []
    assert plane.get_audit_log(-1) == []


def test_no_log_yet(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    plane.audit_log.unlink()
    assert plane.get_audit_log() == []
    assert plane.audit_entry_count() == 0
