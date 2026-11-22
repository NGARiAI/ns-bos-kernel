"""Electronic signatures on records (docs/ESIGNATURES.md, 21 CFR 11.50,
11.70, 11.200(a)) against a SoftHSM token.

A signature shows the signer's printed name, the time and the meaning; it
is bound to the record's bytes, so it cannot be moved to another record or
survive a change to its own; and the card and PIN are needed every time.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

from core.kernel.data_plane import append_audit, operator_auth, records_cli
from core.kernel.data_plane.operator_auth import (
    CHALLENGE_LABEL,
    ESIGN_LABEL,
    CardAuthenticator,
    OperatorAuthError,
    challenge,
    esign_message,
    identity_bytes,
)
from core.kernel.data_plane.roles import roles_bytes


def _store(tmp_path):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    return store


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _signer(store, card, user="jdoe", name="Jane Doe"):
    cert = card.issue()
    ops = store / "operators"
    ops.mkdir(exist_ok=True)
    (ops / f"{user}.pem").write_bytes(card.pem())
    (ops / f"{user}.json").write_bytes(identity_bytes(user, name, _fp(cert)))
    return cert


def _admin(store, user):
    """A pinned, named operator whose card is not in the reader."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    ops = store / "operators"
    ops.mkdir(exist_ok=True)
    (ops / f"{user}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ops / f"{user}.json").write_bytes(identity_bytes(user, user.title(), _fp(cert)))


def _env(tmp_path, card):
    return {
        "NGARI_DATA_DIR": str(tmp_path / "data"),
        "NGARI_PKCS11_MODULE": card.module,
        "NGARI_PKCS11_TOKEN": card.token,
    }


def _record(tmp_path, text="Batch 42 deviation report, rev 3\n", name="report.txt"):
    path = tmp_path / name
    path.write_text(text)
    return path


def _sign(tmp_path, env, record, meaning="approval", pin="123456"):
    pin_file = tmp_path / "pin"
    pin_file.write_text(pin)
    args = ["sign", str(record), "--meaning", meaning, "--pin-file", str(pin_file)]
    return records_cli.cli(args, env)


def _check(env, record):
    return records_cli.cli(["signatures", str(record)], env)


def _log(store):
    return store / "audit" / "sovereign_audit.log"


def _entries(store, *actions):
    if not _log(store).exists():
        return []
    entries = [json.loads(x) for x in _log(store).read_text().splitlines()]
    return [e for e in entries if not actions or e["action"] in actions]


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rewrite(store, change):
    """Apply change to the esignature entry in place, as an editor would."""
    lines = _log(store).read_text().splitlines()
    out = []
    for line in lines:
        entry = json.loads(line)
        if entry["action"] == "esignature":
            change(entry)
        out.append(json.dumps(entry))
    _log(store).write_text("\n".join(out) + "\n")


# -- signing and checking ------------------------------------------------------------


@pytest.mark.part11("11.10(b)", "11.50(a)(1)", "11.50(a)(2)", "11.50(a)(3)", "11.50(b)")
def test_a_signature_shows_name_time_and_meaning_and_checks(
    soft_card, tmp_path, capsys
):
    store = _store(tmp_path)
    cert = _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0
    out = capsys.readouterr().out
    assert f"signed {record}: approval by Jane Doe (jdoe) at " in out
    [entry] = _entries(store)
    assert (entry["action"], entry["actor"], entry["resource"]) == (
        "esignature",
        "jdoe",
        _digest(record),
    )
    details = entry["details"]
    assert set(details) == {
        "meaning", "name", "fingerprint", "signed_at", "nonce", "signature", "file",
    }  # fmt: skip
    assert (details["meaning"], details["name"], details["fingerprint"]) == (
        "approval",
        "Jane Doe",
        _fp(cert),
    )
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", details["signed_at"])
    assert re.fullmatch(r"[0-9a-f]{32}", details["nonce"])
    assert re.fullmatch(r"[0-9a-f]+", details["signature"])
    assert details["file"] == "report.txt"
    assert "123456" not in _log(store).read_text()
    assert _check(env, record) == 0
    assert capsys.readouterr().out.splitlines() == [
        f"sha256 {_digest(record)}",
        f"approval by Jane Doe (jdoe) at {details['signed_at']}: valid",
    ]


@pytest.mark.part11("11.10(a)", "11.70")
def test_a_changed_record_has_no_signatures(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0
    record.write_text("Batch 42 deviation report, rev 4\n")
    capsys.readouterr()
    assert _check(env, record) == 1
    assert capsys.readouterr().out.startswith(f"no signatures on {record} as it is now")


@pytest.mark.part11("11.70")
def test_a_signature_moved_to_another_record_does_not_verify(
    soft_card, tmp_path, capsys
):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    other = _record(tmp_path, "Batch 43 release, unsigned\n", "other.txt")
    assert _sign(tmp_path, env, record) == 0
    [entry] = _entries(store)
    moved = {**entry, "resource": _digest(other)}
    with open(_log(store), "a") as f:
        f.write(json.dumps(moved) + "\n")
    capsys.readouterr()
    assert _check(env, other) == 1
    assert "INVALID: the signature does not verify" in capsys.readouterr().out
    assert _check(env, record) == 0  # the original still stands


@pytest.mark.parametrize(
    "change",
    [lambda e: e["details"].update(meaning="review"),
     lambda e: e["details"].update(name="John Roe"),
     lambda e: e["details"].update(signed_at="2020-01-01T00:00:00Z"),
     lambda e: e["details"].update(nonce="00" * 16),
     lambda e: e.update(actor="jroe")],
    ids=["meaning", "name", "time", "nonce", "signer"],
)  # fmt: skip
@pytest.mark.part11("11.50(a)(1)", "11.50(a)(2)", "11.50(a)(3)", "11.70")
def test_every_signed_field_is_bound(soft_card, tmp_path, capsys, change):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0
    _rewrite(store, change)
    capsys.readouterr()
    assert _check(env, record) == 1
    assert "INVALID: the signature does not verify" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    [lambda e: e["details"].update(signature="zz"),
     lambda e: e["details"].pop("nonce"),
     lambda e: e["details"].update(name=7),
     lambda e: e.update(details="approval"),
     lambda e: e.update(actor=None)],
    ids=["not-hex", "no-nonce", "name-not-text", "details-not-object", "no-signer"],
)  # fmt: skip
def test_a_malformed_entry_is_invalid(soft_card, tmp_path, capsys, change):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0
    _rewrite(store, change)
    capsys.readouterr()
    assert _check(env, record) == 1
    assert "INVALID: the entry is malformed" in capsys.readouterr().out


def test_a_bit_flipped_signature_does_not_verify(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0

    def flip(entry):
        sig = bytearray.fromhex(entry["details"]["signature"])
        sig[-1] ^= 1
        entry["details"]["signature"] = sig.hex()

    _rewrite(store, flip)
    capsys.readouterr()
    assert _check(env, record) == 1
    assert "INVALID: the signature does not verify" in capsys.readouterr().out


def test_a_gate_signature_cannot_stand_in_for_a_record_signature(soft_card, tmp_path):
    assert ESIGN_LABEL != CHALLENGE_LABEL
    store = _store(tmp_path)
    cert = _signer(store, soft_card)
    fp = _fp(cert)
    auth = CardAuthenticator(
        store / "operators", module=soft_card.module, token=soft_card.token
    )
    work = tmp_path / "work"
    work.mkdir()
    gate = challenge("keys migrate", store, fp, os.urandom(32))
    signature = auth._sign(work, cert, gate, b"123456", fp)
    message = esign_message("a" * 64, "approval", "jdoe", "Jane Doe", fp, "t", "n")
    assert message.startswith(ESIGN_LABEL + b"\0")
    with pytest.raises(OperatorAuthError, match="does not verify"):
        auth._verify(cert, signature, message, fp)


@pytest.mark.part11("11.200(a)(1)", "11.200(a)(1)(i)", "11.200(a)(1)(ii)")
def test_each_signature_needs_the_card_and_pin(
    soft_card, tmp_path, monkeypatch, capsys
):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    pins = []
    real = operator_auth.CardAuthenticator._sign

    def spy(self, work, cert, message, pin, fp):
        pins.append(pin)
        return real(self, work, cert, message, pin, fp)

    monkeypatch.setattr(operator_auth.CardAuthenticator, "_sign", spy)
    assert _sign(tmp_path, env, record, "review") == 0
    assert _sign(tmp_path, env, record, "approval") == 0
    assert pins == [b"123456", b"123456"]
    first, second = _entries(store)
    assert first["details"]["nonce"] != second["details"]["nonce"]
    capsys.readouterr()
    assert _check(env, record) == 0
    out = capsys.readouterr().out
    assert "review by Jane Doe (jdoe)" in out and "approval by Jane Doe (jdoe)" in out


def test_one_bad_signature_among_good_ones_fails_the_check(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record, "review") == 0
    assert _sign(tmp_path, env, record, "approval") == 0
    lines = _log(store).read_text().splitlines()
    first = json.loads(lines[0])
    first["details"]["name"] = "John Roe"
    _log(store).write_text("\n".join([json.dumps(first), *lines[1:]]) + "\n")
    capsys.readouterr()
    assert _check(env, record) == 1
    out = capsys.readouterr().out
    assert "INVALID" in out and "approval by Jane Doe (jdoe)" in out


def test_the_whole_file_is_hashed(tmp_path):
    big = tmp_path / "big.bin"
    data = os.urandom(3 * (1 << 20) + 5)
    big.write_bytes(data)
    assert records_cli.record_digest(big) == hashlib.sha256(data).hexdigest()


def _raw_sign(card, message):
    """What any card holder can do with their own card and PIN, no kernel."""
    (card.root / "in.bin").write_bytes(hashlib.sha256(message).digest())
    subprocess.run(
        ["pkcs11-tool", "--module", card.module, "--token-label", card.token,
         "--login", "--pin", card.pin, "--sign", "--id", "01",
         "--mechanism", "ECDSA", "--signature-format", "openssl",
         "-i", "in.bin", "-o", "sig.bin"],
        cwd=card.root, check=True, capture_output=True,
    )  # fmt: skip
    return (card.root / "sig.bin").read_bytes()


def _forge(store, card, fp, record, meaning, user, name, signed_at):
    """Sign by hand and append the entry, as anyone who can write the log can."""
    digest = _digest(record)
    nonce = "ab" * 16
    message = esign_message(digest, meaning, user, name, fp, signed_at, nonce)
    append_audit(
        _log(store), "esignature", user, digest,
        {"meaning": meaning, "name": name, "fingerprint": fp,
         "signed_at": signed_at, "nonce": nonce,
         "signature": _raw_sign(card, message).hex(), "file": record.name},
    )  # fmt: skip


@pytest.mark.parametrize("mallory_named", [True, False], ids=["named", "unnamed"])
@pytest.mark.part11("11.100(a)", "11.200(a)(3)")
def test_a_card_cannot_sign_as_another_operator(
    soft_card, tmp_path, capsys, monkeypatch, mallory_named
):
    from core.kernel.data_plane import SovereignDataPlane

    store = _store(tmp_path)
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    SovereignDataPlane(str(store))  # a keyed entry first, as on a real store
    ops = store / "operators"
    ops.mkdir()
    # Jane Doe is a named operator; her card is not involved.
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", "1" * 64))
    mallory = soft_card.issue(cn="Mallory")
    (ops / "mallory.pem").write_bytes(soft_card.pem())
    if mallory_named:
        ident = identity_bytes("mallory", "Mallory", _fp(mallory))
        (ops / "mallory.json").write_bytes(ident)
    record = _record(tmp_path)
    _forge(store, soft_card, _fp(mallory), record, "approval", "jdoe", "Jane Doe",
           "2026-10-30T09:00:00Z")  # fmt: skip
    assert SovereignDataPlane(str(store)).verify_audit_integrity()  # the chain holds
    capsys.readouterr()
    assert _check({"NGARI_DATA_DIR": str(tmp_path / "data")}, record) == 1
    out = capsys.readouterr().out
    assert (
        f"approval by Jane Doe (jdoe) at 2026-10-30T09:00:00Z: INVALID: certificate "
        f"{_fp(mallory)[:16]} is not jdoe's (Jane Doe)"
    ) in out


def test_a_name_changed_with_the_signature_still_does_not_check(
    soft_card, tmp_path, capsys
):
    # The holder's own card, signing as themselves under another printed name.
    store = _store(tmp_path)
    cert = _signer(store, soft_card)
    record = _record(tmp_path)
    _forge(store, soft_card, _fp(cert), record, "approval", "jdoe", "Jane Roe",
           "2026-10-30T09:00:00Z")  # fmt: skip
    capsys.readouterr()
    assert _check({"NGARI_DATA_DIR": str(tmp_path / "data")}, record) == 1
    assert "is not jdoe's (Jane Roe)" in capsys.readouterr().out


def test_a_holder_signing_by_hand_as_themselves_checks(soft_card, tmp_path, capsys):
    # The check proves which card signed what; the next two tests cover
    # what it cannot prove.
    store = _store(tmp_path)
    cert = _signer(store, soft_card)
    record = _record(tmp_path)
    _forge(store, soft_card, _fp(cert), record, "approval", "jdoe", "Jane Doe",
           "2026-10-30T09:00:00Z")  # fmt: skip
    assert _check({"NGARI_DATA_DIR": str(tmp_path / "data")}, record) == 0


def test_a_check_cannot_show_a_card_was_not_retired_when_it_signed(soft_card, tmp_path):
    # A stated limit (ESIGNATURES.md, What a check proves): the entry's own
    # time is the only evidence of when a retired card signed.
    store = _store(tmp_path)
    cert = _signer(store, soft_card)
    retired = store / "operators" / "retired"
    retired.mkdir()
    shutil.move(store / "operators" / "jdoe.pem", retired / "jdoe.pem")
    record = _record(tmp_path, "written after she left\n")
    _forge(store, soft_card, _fp(cert), record, "approval", "jdoe", "Jane Doe",
           "2026-01-01T00:00:00Z")  # fmt: skip
    assert _check({"NGARI_DATA_DIR": str(tmp_path / "data")}, record) == 0


def test_a_check_cannot_show_the_signer_held_the_meanings_role(soft_card, tmp_path):
    # A stated limit (ESIGNATURES.md, What a check proves): the role is
    # enforced when `records sign` runs, not by a later check.
    store = _store(tmp_path)
    cert = _signer(store, soft_card)
    (store / "roles.json").write_bytes(roles_bytes({"jdoe": ["admin", "author"]}))
    record = _record(tmp_path)
    _forge(store, soft_card, _fp(cert), record, "approval", "jdoe", "Jane Doe",
           "2026-10-30T09:00:00Z")  # fmt: skip
    assert _check({"NGARI_DATA_DIR": str(tmp_path / "data")}, record) == 0


def test_an_anchor_kept_after_signing_catches_a_rewritten_refusal(
    soft_card, tmp_path, monkeypatch
):
    # AUDIT_LOG.md, What it cannot see: keyless entries after the last keyed
    # one can be rewritten without the key; only an anchor catches it.
    from core.kernel.data_plane import SovereignDataPlane, audit_anchor

    store = _store(tmp_path)
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    SovereignDataPlane(str(store))  # the last keyed entry
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record, pin="999999") == 1
    assert _sign(tmp_path, env, record) == 0
    anchor = audit_anchor(_log(store))
    entries = [json.loads(x) for x in _log(store).read_text().splitlines()]
    assert [e["action"] for e in entries] == [
        "key_provider", "esignature_refused", "esignature",
    ]  # fmt: skip
    kept = [entries[0], entries[2]]
    kept[1]["prev_hash"] = kept[0]["hash"]
    kept[1]["hash"] = SovereignDataPlane._entry_hash(kept[1])
    _log(store).write_text("".join(json.dumps(e) + "\n" for e in kept))
    plane = SovereignDataPlane(str(store))
    assert plane.verify_audit_integrity()  # the refusal is gone without trace
    assert not plane.verify_audit_integrity(anchor)


def _cert_with(key, cn="Jane Doe", algorithm=None):
    import datetime

    from cryptography import x509
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, algorithm)
    )


def _pin_by_hand(store, cert, user="jdoe", name="Jane Doe"):
    from cryptography.hazmat.primitives import serialization

    ops = store / "operators"
    ops.mkdir(exist_ok=True)
    (ops / f"{user}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ops / f"{user}.json").write_bytes(identity_bytes(user, name, _fp(cert)))


def _entry_for(store, cert, record):
    digest = _digest(record)
    append_audit(
        _log(store), "esignature", "jdoe", digest,
        {"meaning": "approval", "name": "Jane Doe", "fingerprint": _fp(cert),
         "signed_at": "2026-10-30T09:00:00Z", "nonce": "ab" * 16,
         "signature": "00" * 64, "file": record.name},
    )  # fmt: skip


def test_a_certificate_with_another_key_type_is_invalid_not_a_crash(tmp_path, capsys):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    store = _store(tmp_path)
    cert = _cert_with(ed25519.Ed25519PrivateKey.generate())
    _pin_by_hand(store, cert)
    record = _record(tmp_path)
    _entry_for(store, cert, record)
    capsys.readouterr()
    assert _check({"NGARI_DATA_DIR": str(tmp_path / "data")}, record) == 1
    assert (
        f"INVALID: certificate {_fp(cert)[:16]} has an unsupported key type (Ed25519PublicKey)"
        in capsys.readouterr().out
    )


def test_a_broken_operator_file_stops_the_check(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0
    (store / "operators" / "jdoe.json").write_text("{")
    capsys.readouterr()
    assert _check(env, record) == 1
    assert "is not JSON" in capsys.readouterr().err


def test_an_application_gets_each_signature_checked_and_structured(soft_card, tmp_path):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record, "review") == 0
    assert _sign(tmp_path, env, record, "approval") == 0
    lines = _log(store).read_text().splitlines()
    second = json.loads(lines[1])
    second["details"]["name"] = "John Roe"  # so this one fails its check
    _log(store).write_text(lines[0] + "\n" + json.dumps(second) + "\n")
    digest, found = records_cli.checked_signatures(store, record)
    assert digest == _digest(record)
    assert [(s["meaning"], s["user"], s["name"], s["valid"]) for s in found] == [
        ("review", "jdoe", "Jane Doe", True),
        ("approval", "jdoe", "John Roe", False),
    ]
    assert found[0]["status"] == "valid"
    assert found[1]["status"] == "INVALID: the signature does not verify"
    assert all(s["signed_at"].endswith("Z") for s in found)
    record.write_text("changed\n")
    assert records_cli.checked_signatures(store, record)[1] == []


def test_signatures_can_be_checked_on_a_verified_copy(soft_card, tmp_path, monkeypatch):
    from core.kernel.data_plane import SovereignDataPlane, audit_key, checked_copy

    store = _store(tmp_path)
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    SovereignDataPlane(str(store))
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record, "review") == 0
    key = audit_key((store / "keys" / "master.key").read_bytes())
    reason, copy = checked_copy(_log(store), key)
    assert reason is None
    assert _sign(tmp_path, env, record, "approval") == 0  # after the copy was taken
    with copy:
        _, on_copy = records_cli.checked_signatures(store, record, copy)
    _, live = records_cli.checked_signatures(store, record)
    assert [s["meaning"] for s in on_copy] == ["review"]
    assert [s["meaning"] for s in live] == ["review", "approval"]
    assert records_cli.checked_signatures(store, record, [])[1] == []


def test_a_malformed_entry_is_structured_with_nones(soft_card, tmp_path):
    store = _store(tmp_path)
    _signer(store, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, _env(tmp_path, soft_card), record) == 0
    _rewrite(store, lambda e: e.update(details="approval"))
    [found] = records_cli.checked_signatures(store, record)[1]
    assert (found["meaning"], found["name"], found["signed_at"], found["valid"]) == (
        None, None, None, False,
    )  # fmt: skip
    lines, ok = records_cli.signatures(store, record)
    assert lines[1] == "? by ? (jdoe) at ?: INVALID: the entry is malformed" and not ok


# -- refusals ------------------------------------------------------------------------


def test_an_unnamed_card_cannot_sign(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    cert = soft_card.issue()
    (store / "operators").mkdir()
    (store / "operators" / "operator.pem").write_bytes(soft_card.pem())
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 1
    assert "must show the signer's name" in capsys.readouterr().err
    [refused] = _entries(store)
    assert (refused["action"], refused["actor"], refused["resource"]) == (
        "esignature_refused",
        _fp(cert),
        _digest(record),
    )
    assert refused["details"] == {"meaning": "approval", "reason": "not named"}


@pytest.mark.part11("11.200(a)(1)")
def test_a_copied_certificate_without_its_key_cannot_sign(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    cert = soft_card.issue(card_key="other")  # the real cert, someone else's key
    (store / "operators").mkdir()
    (store / "operators" / "jdoe.pem").write_bytes(soft_card.pem())
    ident = identity_bytes("jdoe", "Jane Doe", _fp(cert))
    (store / "operators" / "jdoe.json").write_bytes(ident)
    assert _sign(tmp_path, _env(tmp_path, soft_card), _record(tmp_path)) == 1
    assert "does not verify" in capsys.readouterr().err
    [refused] = _entries(store)
    assert (refused["action"], refused["details"]["reason"]) == (
        "esignature_refused",
        "signature",
    )


def test_a_card_that_is_not_pinned_cannot_sign(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _signer(store, soft_card)
    soft_card.issue()  # a new certificate on the card
    assert _sign(tmp_path, _env(tmp_path, soft_card), _record(tmp_path)) == 1
    assert "is not pinned" in capsys.readouterr().err
    assert _entries(store)[0]["details"]["reason"] == "not pinned"


def test_with_nobody_pinned_nobody_signs(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue()
    assert _sign(tmp_path, _env(tmp_path, soft_card), _record(tmp_path)) == 1
    assert _entries(store)[0]["details"]["reason"] == "no pinned certificates"


def test_an_expired_certificate_cannot_sign(soft_card, tmp_path):
    store = _store(tmp_path)
    cert = soft_card.issue(days=1, start_days_ago=10)
    (store / "operators").mkdir()
    (store / "operators" / "jdoe.pem").write_bytes(soft_card.pem())
    ident = identity_bytes("jdoe", "Jane Doe", _fp(cert))
    (store / "operators" / "jdoe.json").write_bytes(ident)
    assert _sign(tmp_path, _env(tmp_path, soft_card), _record(tmp_path)) == 1
    assert _entries(store)[0]["details"]["reason"] == "expired"


@pytest.mark.part11("11.300(d)")
def test_a_wrong_pin_signs_nothing_and_is_not_repeated(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _signer(store, soft_card)
    assert (
        _sign(tmp_path, _env(tmp_path, soft_card), _record(tmp_path), pin="999999") == 1
    )
    assert "999999" not in capsys.readouterr().err
    [refused] = _entries(store)
    assert refused["details"]["reason"] == "pin"
    assert "999999" not in _log(store).read_text()


def test_no_pin_source_fails_closed(soft_card, tmp_path, monkeypatch):
    store = _store(tmp_path)
    _signer(store, soft_card)
    monkeypatch.setattr(records_cli.sys.stdin, "isatty", lambda: False, raising=False)
    args = ["sign", str(_record(tmp_path)), "--meaning", "approval"]
    assert records_cli.cli(args, _env(tmp_path, soft_card)) == 1
    assert _entries(store)[0]["details"]["reason"] == "no pin"


def test_a_failure_the_card_check_does_not_name_is_still_recorded(
    soft_card, tmp_path, monkeypatch, capsys
):
    store = _store(tmp_path)
    _signer(store, soft_card)

    def broken(*args, **kwargs):
        raise RuntimeError("secret text from a decoder")

    monkeypatch.setattr(operator_auth.CardAuthenticator, "esign", broken)
    assert _sign(tmp_path, _env(tmp_path, soft_card), _record(tmp_path)) == 1
    err = capsys.readouterr().err
    assert "failed with RuntimeError" in err and "secret text" not in err
    assert _entries(store)[0]["details"] == {"meaning": "approval", "reason": "error"}


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_an_unreadable_record_is_refused(soft_card, tmp_path, capsys, kind):
    store = _store(tmp_path)
    _signer(store, soft_card)
    record = tmp_path / "record"
    if kind == "directory":
        record.mkdir()
    assert _sign(tmp_path, _env(tmp_path, soft_card), record) == 1
    assert "cannot read" in capsys.readouterr().err
    assert _entries(store) == []
    assert _check(_env(tmp_path, soft_card), record) == 1
    assert "cannot read" in capsys.readouterr().err


def test_a_signature_that_cannot_be_recorded_is_reported_lost(
    soft_card, tmp_path, capsys
):
    store = _store(tmp_path)
    _signer(store, soft_card)
    (store / "audit").mkdir()
    _log(store).mkdir()  # a directory, not a file
    assert _sign(tmp_path, _env(tmp_path, soft_card), _record(tmp_path)) == 1
    assert "could not be recorded" in capsys.readouterr().err


# -- roles ----------------------------------------------------------------------------


def test_each_meaning_needs_its_role():
    assert records_cli.MEANINGS == (
        "authorship",
        "review",
        "approval",
        "responsibility",
    )
    assert records_cli.MEANING_ROLES == {
        "authorship": "author",
        "review": "reviewer",
        "approval": "approver",
        "responsibility": "approver",
    }


@pytest.mark.part11("11.10(g)")
def test_with_roles_set_a_signer_needs_the_meanings_role(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _signer(store, soft_card)
    (store / "roles.json").write_bytes(roles_bytes({"jdoe": ["admin", "reviewer"]}))
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    # Refused before the card signs: with a wrong PIN the reason would be "pin".
    assert _sign(tmp_path, env, record, "approval", pin="999999") == 1
    assert "does not hold the approver role needed to sign for approval" in (
        capsys.readouterr().err
    )
    assert _entries(store)[0]["details"] == {"meaning": "approval", "reason": "role"}
    assert _sign(tmp_path, env, record, "review") == 0
    signed = _entries(store, "esignature")[0]
    assert signed["details"]["role"] == "reviewer"


@pytest.mark.part11("11.10(g)")
def test_a_role_taken_away_while_the_pin_is_typed_counts(soft_card, tmp_path, capsys):
    import threading

    from core.kernel.data_plane import keys_cli

    store = _store(tmp_path)
    _signer(store, soft_card)
    _admin(store, "boss")
    (store / "roles.json").write_bytes(
        roles_bytes({"jdoe": ["approver"], "boss": ["admin"]})
    )
    fifo = tmp_path / "pin.fifo"
    os.mkfifo(fifo)
    record = _record(tmp_path)
    args = ["sign", str(record), "--meaning", "approval", "--pin-file", str(fifo)]
    result = {}
    worker = threading.Thread(
        target=lambda: result.update(
            code=records_cli.cli(args, _env(tmp_path, soft_card))
        )
    )
    worker.start()
    with open(fifo, "w") as f:  # returns once sign opened it for its PIN
        keys_cli.set_roles(store, "jdoe", "none", actor="boss")
        f.write("123456")
    worker.join(60)
    assert result["code"] == 1
    assert "does not hold the approver role" in capsys.readouterr().err
    assert _entries(store, "esignature") == []


def test_without_roles_any_named_operator_signs(soft_card, tmp_path):
    store = _store(tmp_path)
    _signer(store, soft_card)
    assert _sign(tmp_path, _env(tmp_path, soft_card), _record(tmp_path)) == 0
    assert "role" not in _entries(store)[0]["details"]


def test_a_broken_roles_file_stops_signing_before_the_pin(
    soft_card, tmp_path, monkeypatch
):
    store = _store(tmp_path)
    _signer(store, soft_card)
    (store / "roles.json").write_text("{")
    monkeypatch.setattr(records_cli.sys.stdin, "isatty", lambda: False, raising=False)
    args = ["sign", str(_record(tmp_path)), "--meaning", "approval"]
    assert records_cli.cli(args, _env(tmp_path, soft_card)) == 1
    assert _entries(store)[0]["details"]["reason"] == "bad roles file"


# -- an operator who leaves ------------------------------------------------------------


def test_a_retired_certificate_still_checks_but_cannot_sign(
    soft_card, tmp_path, capsys
):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0
    retired = store / "operators" / "retired"
    retired.mkdir()
    shutil.move(store / "operators" / "jdoe.pem", retired / "jdoe.pem")
    capsys.readouterr()
    assert _check(env, record) == 0
    assert ": valid (certificate retired)" in capsys.readouterr().out
    assert _sign(tmp_path, env, record) == 1
    assert "no pinned operator certificates" in capsys.readouterr().err


def test_a_certificate_that_is_gone_leaves_the_signature_unchecked(
    soft_card, tmp_path, capsys
):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0
    (store / "operators" / "jdoe.pem").unlink()
    capsys.readouterr()
    assert _check(env, record) == 1
    assert "not checked: certificate" in capsys.readouterr().out


# -- the audit chain -------------------------------------------------------------------


def test_other_lines_in_the_log_are_skipped(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    record = _record(tmp_path)
    assert _sign(tmp_path, env, record) == 0
    with open(_log(store), "a") as f:
        f.write('not json\n[1, 2]\n{"action": "esignature"}\n{"action": "x"}\n')
    capsys.readouterr()
    assert _check(env, record) == 0
    assert capsys.readouterr().out.count(": valid") == 1


@pytest.mark.part11("11.50(b)")
def test_signing_keeps_the_chain_verifying(soft_card, tmp_path, monkeypatch):
    from core.kernel.data_plane import SovereignDataPlane

    store = _store(tmp_path)
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    SovereignDataPlane(str(store))  # a keyed entry first
    _signer(store, soft_card)
    env = _env(tmp_path, soft_card)
    assert _sign(tmp_path, env, _record(tmp_path)) == 0
    assert _sign(tmp_path, env, _record(tmp_path), pin="999999") == 1
    plane = SovereignDataPlane(str(store))
    assert plane.verify_audit_integrity()
    for action in ("esignature", "esignature_refused"):
        with pytest.raises(ValueError):
            plane.record(action, "kernel", "x", {})


def test_the_kernel_command_line_runs_records(tmp_path, monkeypatch, capsys):
    from core import kernel as kernel_mod

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path / "data"))
    record = _record(tmp_path)
    with pytest.raises(SystemExit) as caught:
        kernel_mod.main(["records", "signatures", str(record)])
    assert caught.value.code == 1
    assert "no signatures on" in capsys.readouterr().out
