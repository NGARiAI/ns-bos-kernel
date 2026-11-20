"""Keyed audit chain: an entry MAC under a key derived from the master key,
and an anchor kept off the machine for truncation."""

import base64
import hashlib
import hmac
import json

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.kernel.data_plane import (
    GENESIS_HASH,
    SovereignDataPlane,
    append_audit,
    audit_anchor,
    check_audit_chain,
)
from core.kernel.data_plane import audit_key as derive


@pytest.fixture
def plane(tmp_path):
    dp = SovereignDataPlane(data_dir=str(tmp_path))
    for i in range(3):
        dp.store_encrypted(f"k{i}", i)
    return dp


def _entries(dp):
    return [json.loads(line) for line in dp.audit_log.read_text().splitlines()]


def _rebuild(dp, entries, *, mac_key=None, strip=False):
    """What a writer of the file can do without the key: edit entries and
    recompute every hash and link, keeping or dropping the MACs."""
    prev, lines = GENESIS_HASH, []
    for entry in entries:
        entry = dict(entry)
        if strip:
            entry.pop("mac", None)
        entry["prev_hash"] = prev
        if mac_key is not None:
            body = {k: v for k, v in entry.items() if k not in ("hash", "mac")}
            entry["mac"] = hmac.new(
                mac_key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256
            ).hexdigest()
        body = {k: v for k, v in entry.items() if k != "hash"}
        entry["hash"] = hashlib.sha256(
            json.dumps(body, sort_keys=True).encode()
        ).hexdigest()
        prev = entry["hash"]
        lines.append(json.dumps(entry))
    dp.audit_log.write_text("\n".join(lines) + "\n")


@pytest.mark.part11("11.10(e)")
def test_every_entry_written_by_the_plane_carries_a_mac(plane):
    entries = _entries(plane)
    assert [e["action"] for e in entries] == ["key_provider"] + ["store_encrypted"] * 3
    assert all(len(e["mac"]) == 64 for e in entries)
    assert plane.verify_audit_integrity()


def test_the_audit_key_is_hkdf_of_the_master_key():
    key = Fernet.generate_key()
    expected = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"ngari-audit-v1"
    ).derive(base64.urlsafe_b64decode(key))
    assert derive(key) == expected
    raw = base64.urlsafe_b64decode(key)
    assert derive(key) not in (raw, raw[:16] * 2, raw[16:] * 2)


@pytest.mark.part11("11.10(a)", "11.10(e)")
def test_an_edit_with_a_rebuilt_chain_is_caught_by_the_mac(plane):
    entries = _entries(plane)
    entries[2]["resource"] = "forged"
    _rebuild(plane, entries)  # hashes and links all consistent again
    assert check_audit_chain(plane.audit_log) is None  # passes without the key
    assert not plane.verify_audit_integrity()
    assert "bad MAC" in check_audit_chain(plane.audit_log, plane._audit_mac_key)


def test_stripping_every_mac_is_caught(plane):
    _rebuild(plane, _entries(plane), strip=True)
    assert check_audit_chain(plane.audit_log) is None
    reason = check_audit_chain(plane.audit_log, plane._audit_mac_key)
    assert reason == "entry 1 (key_provider) has no MAC"


def test_an_unkeyed_entry_after_keyed_ones_is_caught(plane):
    append_audit(plane.audit_log, "store_encrypted", "system", "sneaky", {})
    assert "no MAC after keyed entries" in check_audit_chain(
        plane.audit_log, plane._audit_mac_key
    )


def test_keyless_operator_checks_are_accepted(plane):
    append_audit(plane.audit_log, "operator_auth", "fp", "keys restore", {"ok": True})
    plane.store_encrypted("after", 1)
    assert plane.verify_audit_integrity()


def test_a_log_keyed_by_another_master_key_fails(plane):
    other = derive(Fernet.generate_key())
    _rebuild(plane, _entries(plane), mac_key=other)
    assert check_audit_chain(plane.audit_log, other) is None
    assert not plane.verify_audit_integrity()


def test_unkeyed_history_verifies_once_adopted(tmp_path):
    from core.kernel.data_plane import LEGACY_HISTORY, audit_cli

    log = tmp_path / "sovereign" / "audit" / "sovereign_audit.log"
    for i in range(2):
        append_audit(log, "store_encrypted", "system", f"old{i}", {})
    plane = SovereignDataPlane(data_dir=str(tmp_path / "sovereign"))
    plane.store_encrypted("new", 1)
    entries = _entries(plane)
    assert ["mac" in e for e in entries] == [False, False, True, True]
    # Nobody has vouched for the two unkeyed entries yet.
    assert not plane.verify_audit_integrity()
    assert audit_cli.cli(["adopt-legacy"], {"NGARI_DATA_DIR": str(tmp_path)}) == 0
    assert plane.verify_audit_integrity()
    last = _entries(plane)[-1]
    assert (last["action"], "mac" in last) == (LEGACY_HISTORY, True)
    assert last["details"] == {"entries": 2, "tail": entries[1]["hash"]}


def test_a_non_string_mac_is_a_failure_not_a_crash(plane):
    entries = _entries(plane)
    entries[1]["mac"] = 7
    body = {k: v for k, v in entries[1].items() if k != "hash"}
    entries[1]["hash"] = hashlib.sha256(
        json.dumps(body, sort_keys=True).encode()
    ).hexdigest()
    entries[2]["prev_hash"] = entries[1]["hash"]
    plane.audit_log.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    assert not plane.verify_audit_integrity()


# -- anchor -------------------------------------------------------------------


def test_truncation_is_caught_by_the_anchor(plane):
    anchor = audit_anchor(plane.audit_log)
    assert anchor == {"entries": 4, "tail": _entries(plane)[-1]["hash"]}
    lines = plane.audit_log.read_text().splitlines()
    plane.audit_log.write_text("\n".join(lines[:-1]) + "\n")
    assert plane.verify_audit_integrity()  # the chain alone cannot tell
    assert not plane.verify_audit_integrity(anchor)
    assert "log has 3 entries, the anchor recorded 4" in check_audit_chain(
        plane.audit_log, plane._audit_mac_key, anchor
    )


def test_a_log_that_grew_after_the_anchor_still_verifies(plane):
    anchor = audit_anchor(plane.audit_log)
    plane.store_encrypted("later", 1)
    assert plane.verify_audit_integrity(anchor)


def test_a_replaced_tail_is_caught_by_the_anchor(plane):
    anchor = audit_anchor(plane.audit_log)
    lines = plane.audit_log.read_text().splitlines()
    plane.audit_log.write_text("\n".join(lines[:-1]) + "\n")
    plane.store_encrypted("replacement", 1)  # same count, different entry
    assert plane.verify_audit_integrity()
    assert "is not the one the anchor recorded" in check_audit_chain(
        plane.audit_log, plane._audit_mac_key, anchor
    )


def test_an_empty_log_has_a_genesis_anchor(tmp_path):
    assert audit_anchor(tmp_path / "none.log") == {"entries": 0, "tail": GENESIS_HASH}


# -- commands -----------------------------------------------------------------


def _cli_store(tmp_path):
    dp = SovereignDataPlane(data_dir=str(tmp_path / "data" / "sovereign"))
    dp.store_encrypted("k", 1)
    return dp, {"NGARI_DATA_DIR": str(tmp_path / "data")}


def test_anchor_then_verify_on_the_command_line(tmp_path, capsys):
    from core.kernel.data_plane import audit_cli

    dp, env = _cli_store(tmp_path)
    before = dp.audit_log.read_bytes()
    assert audit_cli.cli(["anchor"], env) == 0
    anchor = tmp_path / "anchor.json"
    anchor.write_text(capsys.readouterr().out)
    assert json.loads(anchor.read_text())["entries"] == 2
    assert audit_cli.cli(["verify", "--anchor", str(anchor)], env) == 0
    assert "2 entries verified and matches the anchor" in capsys.readouterr().out
    assert dp.audit_log.read_bytes() == before  # neither command appends

    lines = dp.audit_log.read_text().splitlines()
    dp.audit_log.write_text(lines[0] + "\n")
    assert audit_cli.cli(["verify", "--anchor", str(anchor)], env) == 1
    assert "anchor recorded 2" in capsys.readouterr().err
    assert audit_cli.cli(["anchor"], env) == 0  # the shorter log is itself valid


def test_anchor_refuses_a_log_that_does_not_verify(tmp_path, capsys):
    from core.kernel.data_plane import audit_cli

    dp, env = _cli_store(tmp_path)
    entries = _entries(dp)
    entries[1]["resource"] = "forged"
    _rebuild(dp, entries)
    assert audit_cli.cli(["anchor"], env) == 1
    assert "bad MAC" in capsys.readouterr().err


def test_verify_needs_the_key(tmp_path, capsys):
    from core.kernel.data_plane import audit_cli

    dp, env = _cli_store(tmp_path)
    (dp.key_file).unlink()
    assert audit_cli.cli(["verify"], env) == 1
    assert "no key file" in capsys.readouterr().err


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"entries": -1, "tail": "' + "0" * 64 + '"}',
        '{"entries": 1, "tail": "short"}',
        '{"entries": "1", "tail": "' + "0" * 64 + '"}',
    ],
)
def test_a_bad_anchor_file_is_refused(tmp_path, capsys, content):
    from core.kernel.data_plane import audit_cli

    _, env = _cli_store(tmp_path)
    anchor = tmp_path / "anchor.json"
    anchor.write_text(content)
    assert audit_cli.cli(["verify", "--anchor", str(anchor)], env) == 1


def test_an_anchor_file_nested_too_deep_is_refused(tmp_path, capsys):
    # A RecursionError in load_anchor is reported as exit 1, not a traceback.
    from core.kernel.data_plane import audit_cli

    _, env = _cli_store(tmp_path)
    anchor = tmp_path / "anchor.json"
    anchor.write_text("[" * 100_000)
    assert audit_cli.cli(["verify", "--anchor", str(anchor)], env) == 1
    assert "cannot read anchor" in capsys.readouterr().err


def test_an_empty_log_matches_its_own_anchor(tmp_path):
    log = tmp_path / "audit.log"
    assert check_audit_chain(log, None, audit_anchor(log)) is None


def test_python_dash_m_runs_the_audit_command(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    _cli_store(tmp_path)
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel", "audit", "verify"],
        cwd=Path(__file__).resolve().parent.parent,
        env={**os.environ, "NGARI_DATA_DIR": str(tmp_path / "data")},
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert run.returncode == 0, run.stderr
    assert "2 entries verified" in run.stdout
