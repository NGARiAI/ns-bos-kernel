"""Named operators (docs/PIV_CAC.md, 21 CFR 11.10(e)): `keys pin-operator`
records a user id and printed name beside a pinned certificate, and the
card gate then records that user, not the card's fingerprint, as the actor.
"""

import datetime
import json
import os
import stat

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core.kernel.data_plane import keys_cli
from core.kernel.data_plane.operator_auth import (
    OperatorAuthError,
    identity_bytes,
    load_identities,
)


def _store(tmp_path):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    (store / "keys" / "master.key").chmod(0o600)
    return store


def _cert(cn="Jane Q. Doe", days=30, start_days_ago=1):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=start_days_ago
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _write(tmp_path, cert, name="cert.pem"):
    path = tmp_path / name
    path.write_bytes(_pem(cert))
    return path


def _entries(store, *actions):
    log = store / "audit" / "sovereign_audit.log"
    if not log.exists():
        return []
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    return [e for e in entries if not actions or e["action"] in actions]


def _files(store):
    ops = store / "operators"
    return sorted(p.name for p in ops.iterdir()) if ops.exists() else []


def _cli(tmp_path, *args, **env):
    return keys_cli.cli(
        ["pin-operator", *args], {"NGARI_DATA_DIR": str(tmp_path / "data"), **env}
    )


# -- pinning -----------------------------------------------------------------------


def test_pinning_writes_the_certificate_and_the_named_operator(tmp_path, capsys):
    store = _store(tmp_path)
    cert = _cert()
    path = _write(tmp_path, cert)
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 0
    out = capsys.readouterr().out
    assert "operator jdoe: Jane Q. Doe" in out
    ops = store / "operators"
    assert _files(store) == ["jdoe.json", "jdoe.pem"]
    for name in _files(store):
        assert stat.S_IMODE((ops / name).stat().st_mode) == 0o600
    assert (ops / "jdoe.pem").read_bytes() == _pem(cert)
    assert json.loads((ops / "jdoe.json").read_text()) == {
        "version": 1,
        "user": "jdoe",
        "name": "Jane Q. Doe",
        "fingerprint": _fp(cert),
    }
    assert load_identities(ops) == {_fp(cert): {"user": "jdoe", "name": "Jane Q. Doe"}}
    [entry] = _entries(store)
    assert (entry["action"], entry["actor"], entry["resource"]) == (
        "operator_pinned",
        "local",
        "jdoe",
    )
    assert entry["details"] == {"name": "Jane Q. Doe", "fingerprint": _fp(cert)}
    assert "mac" not in entry  # recorded without reading the key


def test_the_name_given_replaces_the_common_name(tmp_path):
    store = _store(tmp_path)
    path = _write(tmp_path, _cert("DOE.JANE.Q.1234567890"))
    assert (
        _cli(tmp_path, "--cert", str(path), "--user", "jdoe", "--name", " Jane Doe ")
        == 0
    )
    [identity] = load_identities(store / "operators").values()
    assert identity["name"] == "Jane Doe"


def test_a_cac_style_common_name_comes_through_redaction_whole(tmp_path):
    # LAST.FIRST.MIDDLE.EDIPI: the ten-digit EDIPI must not be masked as a phone.
    store = _store(tmp_path)
    path = _write(tmp_path, _cert("DOE.JANE.Q.1234567890"))
    assert _cli(tmp_path, "--cert", str(path), "--user", "1234567890") == 0
    [entry] = _entries(store)
    assert entry["resource"] == "1234567890"
    assert entry["details"]["name"] == "DOE.JANE.Q.1234567890"


@pytest.mark.parametrize(
    "user",
    ["", "-jdoe", ".jdoe", "j/doe", "j doe", "jdoe\n", "j" * 65, "123-45-6789",
     "jdoe@example.com"],
)  # fmt: skip
def test_a_bad_user_id_is_refused_and_nothing_is_written(tmp_path, capsys, user):
    store = _store(tmp_path)
    path = _write(tmp_path, _cert())
    assert _cli(tmp_path, "--cert", str(path), f"--user={user}") == 1
    err = capsys.readouterr().err
    assert "user id" in err
    assert _files(store) == []
    assert _entries(store) == []


@pytest.mark.parametrize(
    ("name", "why"),
    [("", "empty"), ("   ", "empty"), ("J" * 129, "over 128"),
     ("Jane\x07Doe", "control character"), ("jane@example.com", "PII redaction"),
     ("Jane Doe 555-867-5309", "PII redaction")],
)  # fmt: skip
def test_a_bad_printed_name_is_refused_and_nothing_is_written(
    tmp_path, capsys, name, why
):
    store = _store(tmp_path)
    path = _write(tmp_path, _cert())
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe", "--name", name) == 1
    assert why in capsys.readouterr().err
    assert _files(store) == []
    assert _entries(store) == []


def test_a_common_name_redaction_would_change_needs_a_name(tmp_path, capsys):
    store = _store(tmp_path)
    path = _write(tmp_path, _cert("jane.doe@example.com"))
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 1
    err = capsys.readouterr().err
    assert "would be masked" in err and "--name" in err
    assert _files(store) == []
    assert (
        _cli(tmp_path, "--cert", str(path), "--user", "jdoe", "--name", "Jane Doe") == 0
    )


def test_a_certificate_pinned_by_copying_gets_only_its_name(tmp_path, capsys):
    store = _store(tmp_path)
    cert = _cert()
    (store / "operators").mkdir()
    (store / "operators" / "operator.pem").write_bytes(_pem(cert))
    path = _write(tmp_path, cert)
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 0
    assert "already pinned; adding its operator" in capsys.readouterr().out
    assert _files(store) == ["jdoe.json", "operator.pem"]
    assert load_identities(store / "operators")[_fp(cert)]["user"] == "jdoe"


@pytest.mark.part11("11.100(a)")
def test_a_named_certificate_cannot_be_named_again(tmp_path, capsys):
    store = _store(tmp_path)
    path = _write(tmp_path, _cert())
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 0
    before = {p: (store / "operators" / p).read_bytes() for p in _files(store)}
    assert _cli(tmp_path, "--cert", str(path), "--user", "other") == 1
    assert "already pinned for jdoe (Jane Q. Doe)" in capsys.readouterr().err
    assert {p: (store / "operators" / p).read_bytes() for p in _files(store)} == before
    assert len(_entries(store)) == 1


@pytest.mark.part11("11.100(a)")
def test_a_user_id_in_use_is_refused(tmp_path, capsys):
    store = _store(tmp_path)
    assert (
        _cli(tmp_path, "--cert", str(_write(tmp_path, _cert())), "--user", "jdoe") == 0
    )
    other = _write(tmp_path, _cert("John Roe"), "other.pem")
    assert _cli(tmp_path, "--cert", str(other), "--user", "jdoe") == 1
    assert "jdoe.json already exists" in capsys.readouterr().err
    assert _files(store) == ["jdoe.json", "jdoe.pem"]


def test_a_pem_name_in_use_by_another_certificate_is_refused(tmp_path, capsys):
    store = _store(tmp_path)
    (store / "operators").mkdir()
    (store / "operators" / "jdoe.pem").write_bytes(_pem(_cert("John Roe")))
    path = _write(tmp_path, _cert())
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 1
    assert "jdoe.pem already exists" in capsys.readouterr().err
    assert _files(store) == ["jdoe.pem"]
    assert _entries(store) == []


@pytest.mark.parametrize(
    ("make", "why"),
    [(lambda p: p.write_bytes(b"not a cert"), "is not a certificate"),
     (lambda p: p.write_bytes(_pem(_cert()) + _pem(_cert())), "holds 2 certificates"),
     (lambda p: p.write_bytes(_pem(_cert(days=1, start_days_ago=10))), "has expired"),
     (lambda p: None, "cannot read")],
)  # fmt: skip
def test_a_file_that_is_not_one_valid_certificate_is_refused(
    tmp_path, capsys, make, why
):
    store = _store(tmp_path)
    path = tmp_path / "cert.pem"
    make(path)
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 1
    assert why in capsys.readouterr().err
    assert _files(store) == []


def test_a_der_certificate_is_taken(tmp_path):
    store = _store(tmp_path)
    cert = _cert()
    path = tmp_path / "cert.der"
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 0
    assert (store / "operators" / "jdoe.pem").read_bytes() == _pem(cert)


def test_an_audit_log_that_cannot_be_written_is_reported(tmp_path, capsys):
    store = _store(tmp_path)
    (store / "audit").mkdir()
    (store / "audit" / "sovereign_audit.log").mkdir()  # a directory, not a file
    path = _write(tmp_path, _cert())
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 1
    assert "operator pinned, but the audit entry could not be written" in (
        capsys.readouterr().err
    )


def test_the_entry_is_keyless_and_the_chain_still_verifies(tmp_path, monkeypatch):
    from core.kernel.data_plane import SovereignDataPlane

    store = _store(tmp_path)
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    SovereignDataPlane(str(store))  # a keyed key_provider entry first
    path = _write(tmp_path, _cert())
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 0
    plane = SovereignDataPlane(str(store))
    assert plane.verify_audit_integrity()
    with pytest.raises(ValueError):
        plane.record("operator_pinned", "kernel", "jdoe", {})


# -- reading the named operators ---------------------------------------------------


def _identity_file(ops, user, **record):
    ops.mkdir(exist_ok=True)
    base = {"version": 1, "user": user, "name": "Jane Doe", "fingerprint": "a" * 64}
    (ops / f"{user}.json").write_text(json.dumps({**base, **record}))


@pytest.mark.parametrize(
    ("content", "why"),
    [("{", "is not JSON"), ("[]", "exactly version"),
     ('{"version": 1, "user": "jdoe", "name": "J", "fingerprint": "' + "a" * 64
      + '", "role": "admin"}', "exactly version"),
     ('{"version": 2, "user": "jdoe", "name": "J", "fingerprint": "' + "a" * 64
      + '"}', "version 2"),
     ('{"version": true, "user": "jdoe", "name": "J", "fingerprint": "' + "a" * 64
      + '"}', "version True"),
     ('{"version": 1.0, "user": "jdoe", "name": "J", "fingerprint": "' + "a" * 64
      + '"}', "version 1.0"),
     ('{"version": 1, "user": "other", "name": "J", "fingerprint": "' + "a" * 64
      + '"}', "must be other.json"),
     ('{"version": 1, "user": "jdoe", "name": "", "fingerprint": "' + "a" * 64
      + '"}', "printed name is empty"),
     ('{"version": 1, "user": "jdoe", "name": " J", "fingerprint": "' + "a" * 64
      + '"}', "spaces at an end"),
     ('{"version": 1, "user": "jdoe", "name": "J", "fingerprint": "' + "A" * 64
      + '"}', "fingerprint"),
     ('{"version": 1, "user": "jdoe", "name": "J", "fingerprint": "' + "a" * 65
      + '"}', "fingerprint"),
     ('{"version": 1, "user": "jdoe", "name": "J", "fingerprint": 7}', "fingerprint")],
)  # fmt: skip
def test_an_invalid_operator_file_fails_closed(tmp_path, content, why):
    ops = tmp_path / "operators"
    ops.mkdir()
    (ops / "jdoe.json").write_text(content)
    with pytest.raises(OperatorAuthError, match=why) as caught:
        load_identities(ops)
    assert caught.value.reason == "bad operator file"


def test_an_unreadable_operator_file_fails_closed(tmp_path):
    ops = tmp_path / "operators"
    (ops / "jdoe.json").mkdir(parents=True)  # read_bytes raises IsADirectoryError
    with pytest.raises(OperatorAuthError, match="cannot be read"):
        load_identities(ops)


@pytest.mark.part11("11.100(a)")
def test_two_files_naming_one_certificate_fail_closed(tmp_path):
    ops = tmp_path / "operators"
    _identity_file(ops, "jdoe")
    _identity_file(ops, "jroe")
    with pytest.raises(OperatorAuthError, match="name the same certificate"):
        load_identities(ops)


def test_other_files_are_not_operators(tmp_path):
    ops = tmp_path / "operators"
    _identity_file(ops, "jdoe")
    (ops / ".jdoe.json.123.ab.tmp").write_text("{")  # a write in progress
    (ops / ".hidden.json").write_text("{")
    (ops / "notes.txt").write_text("{")
    assert load_identities(ops) == {"a" * 64: {"user": "jdoe", "name": "Jane Doe"}}
    assert load_identities(tmp_path / "missing") == {}


@pytest.mark.part11("11.100(a)")
def test_only_one_file_can_name_a_user(tmp_path):
    ops = tmp_path / "operators"
    _identity_file(ops, "jdoe")
    (ops / "jdoe.JSON").write_text(
        json.dumps(
            {"version": 1, "user": "jdoe", "name": "Not Jane", "fingerprint": "b" * 64}
        )
    )
    assert load_identities(ops) == {"a" * 64: {"user": "jdoe", "name": "Jane Doe"}}


def test_the_file_written_is_the_file_read(tmp_path):
    ops = tmp_path / "operators"
    ops.mkdir()
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", "b" * 64))
    assert load_identities(ops) == {"b" * 64: {"user": "jdoe", "name": "Jane Doe"}}


# -- the gate records the named operator ------------------------------------------


def _env(tmp_path, card):
    return {
        "NGARI_DATA_DIR": str(tmp_path / "data"),
        "NGARI_OPERATOR_AUTH": "card",
        "NGARI_PKCS11_MODULE": card.module,
        "NGARI_PKCS11_TOKEN": card.token,
    }


def _export(tmp_path, env, pin_text="123456"):
    pin = tmp_path / "pin"
    pin.write_text(pin_text)
    secret = tmp_path / "pass"
    secret.write_bytes(b"correct horse battery staple")
    out = tmp_path / "bundle.json"
    args = ["export-recovery", "--out", str(out), "--passphrase-file", str(secret),
            "--pin-file", str(pin)]  # fmt: skip
    return keys_cli.cli(args, env), out


@pytest.mark.part11("11.10(e)")
def test_the_gate_records_the_named_operator_as_the_actor(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    cert = soft_card.issue(cn="DOE.JANE.Q.1234567890")
    env = _env(tmp_path, soft_card)
    path = _write(tmp_path, cert)
    # The first operator is pinned with the gate on but no card to sign for it.
    assert (
        keys_cli.cli(["pin-operator", "--cert", str(path), "--user", "jdoe"], env) == 0
    )
    code, out = _export(tmp_path, env)
    assert code == 0 and out.exists()
    assert (
        f"operator: DOE.JANE.Q.1234567890 (jdoe, certificate {_fp(cert)[:16]})"
        in capsys.readouterr().out
    )
    pinned, auth, export = _entries(store)
    assert pinned["actor"] == "local"
    assert (auth["action"], auth["actor"], auth["resource"]) == (
        "operator_auth",
        "jdoe",
        "keys export-recovery",
    )
    assert auth["details"] == {
        "ok": True,
        "subject": "DOE.JANE.Q.1234567890",
        "name": "DOE.JANE.Q.1234567890",
        "fingerprint": _fp(cert),
    }
    assert (export["action"], export["actor"]) == ("recovery_exported", "jdoe")


def test_a_card_without_a_name_is_recorded_by_fingerprint(soft_card, tmp_path):
    store = _store(tmp_path)
    cert = soft_card.issue()
    (store / "operators").mkdir()
    (store / "operators" / "operator.pem").write_bytes(soft_card.pem())
    _identity_file(store / "operators", "someone")  # names another certificate
    code, _ = _export(tmp_path, _env(tmp_path, soft_card))
    assert code == 0
    auth, export = _entries(store)
    assert auth["actor"] == _fp(cert)
    assert auth["details"] == {"ok": True, "subject": "Test Operator"}
    assert export["actor"] == _fp(cert)


def test_a_broken_operator_file_stops_the_gate_before_the_card(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue()
    (store / "operators").mkdir()
    (store / "operators" / "operator.pem").write_bytes(soft_card.pem())
    (store / "operators" / "jdoe.json").write_text("{")
    # A wrong PIN would be "pin": the card is never asked.
    code, out = _export(tmp_path, _env(tmp_path, soft_card), pin_text="999999")
    assert code == 1
    assert not out.exists()
    [auth] = _entries(store)
    assert auth["details"] == {"ok": False, "reason": "bad operator file"}


def test_pinning_a_second_operator_is_gated(soft_card, tmp_path, monkeypatch, capsys):
    store = _store(tmp_path)
    first = soft_card.issue()
    env = _env(tmp_path, soft_card)
    assert keys_cli.cli(
        ["pin-operator", "--cert", str(_write(tmp_path, first)), "--user", "jdoe"], env
    ) == 0  # fmt: skip
    second = _write(tmp_path, _cert("John Roe"), "second.pem")
    monkeypatch.setattr(keys_cli.sys.stdin, "isatty", lambda: False, raising=False)
    assert (
        keys_cli.cli(["pin-operator", "--cert", str(second), "--user", "jroe"], env)
        == 1
    )
    assert "no terminal" in capsys.readouterr().err
    assert _files(store) == ["jdoe.json", "jdoe.pem"]
    pin = tmp_path / "pin"
    pin.write_text("123456")
    assert keys_cli.cli(
        ["pin-operator", "--cert", str(second), "--user", "jroe", "--pin-file", str(pin)],
        env,
    ) == 0  # fmt: skip
    entries = _entries(store)
    assert [(e["action"], e["actor"], e["resource"]) for e in entries] == [
        ("operator_pinned", "local", "jdoe"),
        ("operator_auth", "unknown", "keys pin-operator"),  # the refusal
        ("operator_auth", "jdoe", "keys pin-operator"),
        ("operator_pinned", "jdoe", "jroe"),
    ]
    assert entries[1]["details"] == {"ok": False, "reason": "no pin"}


def test_an_application_can_see_whose_card_is_in_the_reader(
    soft_card, tmp_path, monkeypatch
):
    from core.kernel.data_plane.operator_auth import CardAuthenticator

    store = _store(tmp_path)
    cert = soft_card.issue(cn="DOE.JANE.Q.1234567890")
    ops = store / "operators"
    auth = CardAuthenticator(ops, module=soft_card.module, token=soft_card.token)
    calls = []
    real = CardAuthenticator._tool

    def watch(self, work, *args, pin=None, fingerprint="unknown"):
        calls.append(pin)
        return real(self, work, *args, pin=pin, fingerprint=fingerprint)

    monkeypatch.setattr(CardAuthenticator, "_tool", watch)
    unpinned = auth.presented()
    assert unpinned.pop("problem").startswith(
        f"certificate {_fp(cert)[:16]} is not pinned"
    )
    assert unpinned == {
        "fingerprint": _fp(cert), "subject": "DOE.JANE.Q.1234567890", "pinned": False,
    }  # fmt: skip
    path = _write(tmp_path, cert)
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 0
    assert auth.presented() == {
        "fingerprint": _fp(cert), "subject": "DOE.JANE.Q.1234567890", "pinned": True,
        "user": "jdoe", "name": "DOE.JANE.Q.1234567890", "person": "jdoe",
        "problem": None,
    }  # fmt: skip
    assert calls and all(pin is None for pin in calls)  # never asks for the PIN


@pytest.mark.parametrize(
    ("card", "why"),
    [({"days": 1, "start_days_ago": 10}, "has expired"),
     ({"kind": "rsa", "rsa_bits": 1024}, "an RSA key of 1024 bits"),
     ({}, None)],
    ids=["expired", "weak-key", "good"],
)  # fmt: skip
def test_presented_says_why_the_card_would_be_refused(soft_card, tmp_path, card, why):
    from core.kernel.data_plane.operator_auth import CardAuthenticator

    store = _store(tmp_path)
    cert = soft_card.issue(**card)
    ops = store / "operators"
    ops.mkdir()
    (ops / "jdoe.pem").write_bytes(
        soft_card.pem()
    )  # pinned by copying, the limits unchecked
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", _fp(cert)))
    facts = CardAuthenticator(
        ops, module=soft_card.module, token=soft_card.token
    ).presented()
    assert facts["user"] == "jdoe" and facts["pinned"] is True
    if why is None:
        assert facts["problem"] is None
    else:
        assert why in facts["problem"]


def test_presented_says_a_retired_card_is_not_pinned(soft_card, tmp_path):
    from core.kernel.data_plane.operator_auth import CardAuthenticator

    store = _store(tmp_path)
    cert = soft_card.issue()
    ops = store / "operators"
    (ops / "retired").mkdir(parents=True)
    (ops / "retired" / "jdoe.pem").write_bytes(soft_card.pem())
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", _fp(cert)))
    facts = CardAuthenticator(
        ops, module=soft_card.module, token=soft_card.token
    ).presented()
    assert facts["user"] == "jdoe" and facts["pinned"] is False  # the name is kept
    assert "is not pinned" in facts["problem"]


# -- a reissued card is the same person ----------------------------------------------


def test_a_reissued_card_carries_the_person(tmp_path, capsys):
    store = _store(tmp_path)
    first, second, third = _cert(), _cert(), _cert()
    assert _cli(tmp_path, "--cert", str(_write(tmp_path, first)), "--user", "jdoe") == 0
    path = _write(tmp_path, second, "second.pem")
    assert (
        _cli(tmp_path, "--cert", str(path), "--user", "jdoe2", "--replaces", "jdoe")
        == 0
    )
    path = _write(tmp_path, third, "third.pem")
    assert (
        _cli(tmp_path, "--cert", str(path), "--user", "jdoe3", "--replaces", "jdoe2")
        == 0
    )
    identities = load_identities(store / "operators")
    assert "person" not in identities[_fp(first)]
    assert identities[_fp(second)]["person"] == "jdoe"
    assert identities[_fp(third)]["person"] == "jdoe"  # the first id, not the last
    pinned = [e for e in _entries(store) if e["action"] == "operator_pinned"]
    assert pinned[2]["details"] == {
        "name": "Jane Q. Doe", "fingerprint": _fp(third), "replaces": "jdoe2", "person": "jdoe",
    }  # fmt: skip
    assert "replaces" not in pinned[0]["details"]


def test_piv_cac_names_what_a_reissue_writes(tmp_path):
    from pathlib import Path

    store = _store(tmp_path)
    assert (
        _cli(tmp_path, "--cert", str(_write(tmp_path, _cert())), "--user", "jdoe") == 0
    )
    path = _write(tmp_path, _cert(), "second.pem")
    assert (
        _cli(tmp_path, "--cert", str(path), "--user", "jdoe2", "--replaces", "jdoe")
        == 0
    )
    record = json.loads((store / "operators" / "jdoe2.json").read_text())
    details = _entries(store, "operator_pinned")[-1]["details"]
    doc = (Path(__file__).resolve().parent.parent / "docs" / "PIV_CAC.md").read_text()
    table = doc.split("| Field | Rule |", 1)[1].split("\n\n", 1)[0]
    rows = {line.split("`")[1] for line in table.splitlines() if line.startswith("| `")}
    assert rows == set(record) - {"version", "fingerprint"}  # what the operator gives
    flat = " ".join(doc.split())
    gate = flat.split("The gate reads every `.json`", 1)[1].split(". ", 1)[0]
    assert all(f"`{field}`" in gate for field in record), gate
    pin = flat.split("Each pin writes an `operator_pinned` entry", 1)[1].split(". ", 1)[
        0
    ]
    assert all(
        (f"`{key}`" if key in ("replaces", "person") else key) in pin for key in details
    ), pin


@pytest.mark.parametrize(
    ("replaces", "why"),
    [("nobody", "there is no operator nobody to replace"),
     ("jroe", "is not another user id"), ("j/doe", "is not another user id")],
)  # fmt: skip
def test_a_replacement_must_name_another_existing_operator(
    tmp_path, capsys, replaces, why
):
    store = _store(tmp_path)
    path = _write(tmp_path, _cert())
    args = ["--cert", str(path), "--user", "jroe", f"--replaces={replaces}"]
    assert _cli(tmp_path, *args) == 1
    assert why in capsys.readouterr().err
    assert _files(store) == []


@pytest.mark.parametrize("person", ["", "j/doe", 7, "jane doe"])
def test_an_operator_file_with_a_bad_person_fails_closed(tmp_path, person):
    ops = tmp_path / "operators"
    _identity_file(ops, "jdoe", person=person)
    with pytest.raises(OperatorAuthError, match="person|not valid"):
        load_identities(ops)


def test_signatures_from_both_cards_are_one_person(soft_card, tmp_path):
    from core.kernel.data_plane import records_cli
    from core.kernel.data_plane.operator_auth import CardAuthenticator

    store = _store(tmp_path)
    ops = store / "operators"
    ops.mkdir()
    old = soft_card.issue(cn="Jane Doe", key_id="01")
    (ops / "jdoe.pem").write_bytes(soft_card.pem())
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", _fp(old)))
    new = soft_card.issue(cn="Jane Doe", key_id="02")
    (ops / "jdoe2.pem").write_bytes(soft_card.pem())
    (ops / "jdoe2.json").write_bytes(
        identity_bytes("jdoe2", "Jane Doe", _fp(new), "jdoe")
    )
    record = tmp_path / "r.txt"
    record.write_text("r\n")
    pin = tmp_path / "pin"
    pin.write_text("123456")
    env = {
        "NGARI_PKCS11_MODULE": soft_card.module,
        "NGARI_PKCS11_TOKEN": soft_card.token,
    }
    records_cli.sign(
        store, {**env, "NGARI_PKCS11_KEY_ID": "01"}, record, "authorship", str(pin)
    )
    (ops / "retired").mkdir()
    (ops / "jdoe.pem").rename(ops / "retired" / "jdoe.pem")  # the first card is retired
    records_cli.sign(
        store, {**env, "NGARI_PKCS11_KEY_ID": "02"}, record, "review", str(pin)
    )
    found = records_cli.checked_signatures(store, record)[1]
    assert [(s["user"], s["person"], s["valid"]) for s in found] == [
        ("jdoe", "jdoe", True), ("jdoe2", "jdoe", True),
    ]  # fmt: skip
    holder = CardAuthenticator(
        ops, module=soft_card.module, token=soft_card.token, key_id="02"
    )
    assert holder.presented()["person"] == "jdoe"


def test_an_invalid_signature_is_not_put_on_the_person_it_names(soft_card, tmp_path):
    from core.kernel.data_plane import append_audit, records_cli

    store = _store(tmp_path)
    ops = store / "operators"
    ops.mkdir()
    cert = soft_card.issue(cn="Jane Doe")
    (ops / "jdoe2.pem").write_bytes(soft_card.pem())
    (ops / "jdoe2.json").write_bytes(
        identity_bytes("jdoe2", "Jane Doe", _fp(cert), "jdoe")
    )
    record = tmp_path / "r.txt"
    record.write_text("r\n")
    digest = records_cli.record_digest(record)
    append_audit(
        store / "audit" / "sovereign_audit.log", "esignature", "mallory", digest,
        {"meaning": "approval", "name": "Jane Doe", "fingerprint": _fp(cert),
         "signed_at": "2026-10-31T09:00:00Z", "nonce": "ab" * 16, "signature": "00"},
    )  # fmt: skip
    [found] = records_cli.checked_signatures(store, record)[1]
    assert found["valid"] is False
    assert found["person"] == "mallory"  # not jdoe, whose card it names


# -- a store made by the key commands is owner-only ------------------------------------


@pytest.fixture
def umask_022():
    old = os.umask(0o022)
    yield
    os.umask(old)


def test_pinning_the_first_operator_on_a_new_store_makes_it_owner_only(
    tmp_path, capsys, umask_022
):
    # PIV_CAC.md and the demo start with pin-operator, so it can be the
    # command that makes the store. mkdir's mode covers only the last
    # directory: every directory made must be 0700, or the store lists its
    # file names to other users.
    path = _write(tmp_path, _cert())
    assert _cli(tmp_path, "--cert", str(path), "--user", "jdoe") == 0
    data = tmp_path / "data"
    made = [data, data / "sovereign", data / "sovereign" / "operators",
            data / "sovereign" / "audit"]  # fmt: skip
    assert {
        str(d.relative_to(tmp_path)): oct(stat.S_IMODE(d.stat().st_mode)) for d in made
    } == {str(d.relative_to(tmp_path)): "0o700" for d in made}


def test_making_a_private_dir_leaves_what_exists_alone(tmp_path, umask_022):
    from core.kernel.data_plane import append_audit
    from core.kernel.data_plane.keys import make_private_dir

    (tmp_path / "shared").mkdir(mode=0o755)
    make_private_dir(tmp_path / "shared" / "a" / "b")
    modes = {
        p: stat.S_IMODE((tmp_path / p).stat().st_mode)
        for p in ("shared", "shared/a", "shared/a/b")
    }
    assert modes == {"shared": 0o755, "shared/a": 0o700, "shared/a/b": 0o700}
    make_private_dir(tmp_path / "shared" / "a" / "b")  # exists: no error
    append_audit(tmp_path / "fresh" / "audit" / "log", "x", "system", "r", {})
    assert stat.S_IMODE((tmp_path / "fresh").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "fresh" / "audit").stat().st_mode) == 0o700


def test_a_private_dir_is_0700_whatever_the_umask_takes(tmp_path):
    from core.kernel.data_plane.keys import make_private_dir

    old = os.umask(0o277)  # would leave the owner unable to write
    try:
        make_private_dir(tmp_path / "x" / "y")
    finally:
        os.umask(old)
    assert [stat.S_IMODE((tmp_path / p).stat().st_mode) for p in ("x", "x/y")] == [
        0o700,
        0o700,
    ]
