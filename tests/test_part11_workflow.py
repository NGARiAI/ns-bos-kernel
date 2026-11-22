"""A 21 CFR Part 11 document workflow end to end, the way an operational
qualification runs it: three people with their own cards, through the real
command line (`python -m core.kernel`, one process per step), checking what
each step is refused and what the audit trail then holds.

Alice is admin and author, Bob reviewer, Carol approver. Each person's card
is a key ID on one SoftHSM token (NGARI_PKCS11_KEY_ID), as each would hold
their own PIV card.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent.parent
PEOPLE = {"alice": ("01", "Alice Author"), "bob": ("02", "Bob Reviewer"),
          "carol": ("03", "Carol Approver")}  # fmt: skip


@pytest.fixture
def site(soft_card, tmp_path, monkeypatch):
    """A fresh install: a data directory with its key, and three cards."""
    from core.kernel.data_plane import SovereignDataPlane

    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    data = tmp_path / "data"
    SovereignDataPlane(str(data / "sovereign"))  # the key, and a keyed first entry
    certs = {}
    for user, (key_id, name) in PEOPLE.items():
        cert = soft_card.issue(cn=name, key_id=key_id)
        certs[user] = tmp_path / f"{user}.pem"
        certs[user].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pin = tmp_path / "pin"
    pin.write_text("123456")

    def run(person, *args):
        env = {
            **os.environ,
            "NGARI_DATA_DIR": str(data),
            "NGARI_KEY_PROVIDER": "file",
            "NGARI_OPERATOR_AUTH": "card",
            "NGARI_PKCS11_MODULE": soft_card.module,
            "NGARI_PKCS11_TOKEN": soft_card.token,
            "NGARI_PKCS11_KEY_ID": PEOPLE[person][0] if person else "01",
        }
        argv = [*args, "--pin-file", str(pin)] if person else list(args)
        return subprocess.run(
            [sys.executable, "-m", "core.kernel", *argv], cwd=ROOT, env=env,
            capture_output=True, text=True, timeout=120, check=False,
        )  # fmt: skip

    return run, data, certs


def _ok(step):
    assert step.returncode == 0, step.stderr
    return step.stdout


def _refused(step, why):
    assert step.returncode == 1 and why in step.stderr, (step.returncode, step.stderr)


def _entries(data):
    log = data / "sovereign" / "audit" / "sovereign_audit.log"
    return [json.loads(x) for x in log.read_text().splitlines()]


@pytest.mark.part11(
    "11.10(a)", "11.10(b)", "11.10(d)", "11.10(e)", "11.10(g)", "11.50(a)(1)",
    "11.50(a)(2)", "11.50(a)(3)", "11.50(b)", "11.70", "11.100(a)", "11.200(a)(1)",
)  # fmt: skip
def test_a_document_is_written_reviewed_and_approved(site, tmp_path):
    run, data, certs = site

    # Set up: the first operator needs no card; everything after goes through it.
    _ok(run(None, "keys", "pin-operator", "--cert", str(certs["alice"]), "--user", "alice",
            "--name", "Alice Author"))  # fmt: skip
    _ok(run("alice", "keys", "set-roles", "--user", "alice", "--roles", "admin,author"))
    for user in ("bob", "carol"):
        _ok(run("alice", "keys", "pin-operator", "--cert", str(certs[user]), "--user", user,
                "--name", PEOPLE[user][1]))  # fmt: skip
    _ok(run("alice", "keys", "set-roles", "--user", "bob", "--roles", "reviewer"))
    _ok(run("alice", "keys", "set-roles", "--user", "carol", "--roles", "approver"))
    _refused(run("bob", "keys", "set-roles", "--user", "bob", "--roles", "admin"),
             "bob does not hold the admin role")  # fmt: skip
    roles = _ok(run(None, "keys", "roles"))
    assert "alice: Alice Author; admin, author" in roles
    assert (
        "bob: Bob Reviewer; reviewer" in roles
        and "carol: Carol Approver; approver" in roles
    )

    # The workflow: each signature needs its meaning's role.
    doc = tmp_path / "SOP-042 rev 3.txt"
    doc.write_text("SOP-042 Cleaning of filling line 2, revision 3\n")
    _ok(run("alice", "records", "sign", str(doc), "--meaning", "authorship"))
    _refused(run("bob", "records", "sign", str(doc), "--meaning", "approval"),
             "bob does not hold the approver role")  # fmt: skip
    _ok(run("bob", "records", "sign", str(doc), "--meaning", "review"))
    _ok(run("carol", "records", "sign", str(doc), "--meaning", "approval"))

    shown = _ok(run(None, "records", "signatures", str(doc))).splitlines()
    assert [line.split(" at ")[0] for line in shown[1:]] == [
        "authorship by Alice Author (alice)",
        "review by Bob Reviewer (bob)",
        "approval by Carol Approver (carol)",
    ]
    assert all(line.endswith(": valid") for line in shown[1:])

    # The audit trail verifies and shows who did what, refusals included.
    assert "audit log OK" in _ok(run(None, "audit", "verify"))
    signed = _ok(run(None, "audit", "show", "--action", "esignature")).splitlines()
    assert signed[0].endswith("; 3 shown")
    assert [line.split("  ")[3] for line in signed[1:]] == ["alice", "bob", "carol"]
    refused = _ok(
        run(None, "audit", "show", "--action", "esignature_refused", "--json")
    )
    [entry] = [json.loads(x) for x in refused.splitlines()]
    assert entry["details"] == {"meaning": "approval", "reason": "role"}
    actions = [e["action"] for e in _entries(data)]
    assert actions.count("operator_pinned") == 3 and actions.count("roles_changed") == 3
    gate = [
        (e["actor"], e["details"]["ok"])
        for e in _entries(data)
        if e["action"] == "operator_auth"
    ]
    assert gate == [("alice", True)] * 5 + [("bob", False)]  # Bob's own admin attempt

    # A changed document has no signatures; the original still has all three.
    anchor = tmp_path / "anchor.json"
    anchor.write_text(_ok(run(None, "audit", "anchor")))
    original = doc.read_bytes()
    doc.write_text("SOP-042 Cleaning of filling line 2, revision 3 (edited)\n")
    no_signatures = run(None, "records", "signatures", str(doc))
    assert no_signatures.returncode == 1 and "no signatures on" in no_signatures.stdout
    doc.write_bytes(original)
    _ok(run(None, "records", "signatures", str(doc)))
    assert "matches the anchor" in _ok(
        run(None, "audit", "verify", "--anchor", str(anchor))
    )

    # Bob's certificate is retired: his signature still checks, his card cannot sign.
    retired = data / "sovereign" / "operators" / "retired"
    retired.mkdir()
    shutil.move(data / "sovereign" / "operators" / "bob.pem", retired / "bob.pem")
    lines = _ok(run(None, "records", "signatures", str(doc))).splitlines()
    assert "review by Bob Reviewer (bob)" in lines[2] and lines[2].endswith(
        ": valid (certificate retired)"
    )
    _refused(
        run("bob", "records", "sign", str(doc), "--meaning", "review"), "is not pinned"
    )
    _refused(run("bob", "keys", "pin-operator", "--cert", str(certs["bob"]), "--user", "bob2"),
             "is not pinned")  # fmt: skip
