"""`keys card-check`, on a SoftHSM token standing in for a PIV card. It
proves the card holds the key for its certificate, says whether that
certificate is pinned, and with --out writes it for an administrator to
pin. It changes nothing: no audit entry, no pinned file."""

import os
import shutil

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from core.kernel.data_plane import keys_cli
from core.kernel.data_plane.operator_auth import (
    CARD_CHECK,
    CardAuthenticator,
    challenge,
)

PIN = "123456"


@pytest.fixture
def store(tmp_path):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    return store


def _env(tmp_path, card, **extra):
    return {
        "NGARI_DATA_DIR": str(tmp_path / "data"),
        "NGARI_PKCS11_MODULE": card.module,
        "NGARI_PKCS11_TOKEN": card.token,
        **extra,
    }


def _pin_file(tmp_path, pin=PIN):
    path = tmp_path / "pin"
    path.write_text(pin + "\n")
    return path


def _check(tmp_path, card, *args, pin=PIN, **extra):
    argv = ["card-check", "--pin-file", str(_pin_file(tmp_path, pin)), *args]
    return keys_cli.cli(argv, _env(tmp_path, card, **extra))


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


@pytest.mark.parametrize(("kind", "key"), [("ec", "EC secp256r1"), ("rsa", "RSA 2048")])
def test_a_card_that_holds_its_key_passes(
    soft_card, tmp_path, store, capsys, kind, key
):
    cert = soft_card.issue(kind)
    assert _check(tmp_path, soft_card) == 0
    out = capsys.readouterr()
    lines = out.out.splitlines()
    assert lines[0] == (
        f"card: Test Operator ({key}), certificate {_fp(cert)[:16]}, "
        f"valid {cert.not_valid_before_utc.date()} to {cert.not_valid_after_utc.date()}"
    )
    assert lines[1].startswith("signature: the card signed a fresh challenge")
    assert lines[2] == f"pinned on this store: no ({store / 'operators'})"
    assert lines[3].startswith("To pin it, run again with --out FILE")
    assert PIN not in out.out + out.err
    # The store is unchanged.
    assert sorted(p.name for p in store.rglob("*")) == ["keys"]


def test_out_writes_the_verified_certificate_once(soft_card, tmp_path, capsys):
    cert = soft_card.issue()
    out = tmp_path / "operator.pem"
    assert _check(tmp_path, soft_card, "--out", str(out)) == 0
    assert x509.load_pem_x509_certificate(out.read_bytes()) == cert
    assert out.stat().st_mode & 0o777 == 0o600
    assert f"certificate written to {out}" in capsys.readouterr().out
    before = out.read_bytes()
    assert _check(tmp_path, soft_card, "--out", str(out)) == 1
    assert "already exists; it was not overwritten" in capsys.readouterr().err
    assert out.read_bytes() == before


def test_the_written_certificate_pinned_by_hand_opens_the_gate(
    soft_card, tmp_path, store, capsys
):
    soft_card.issue()
    out = tmp_path / "operator.pem"
    assert _check(tmp_path, soft_card, "--out", str(out)) == 0
    (store / "operators").mkdir()
    shutil.copy(out, store / "operators" / "operator.pem")
    capsys.readouterr()
    assert _check(tmp_path, soft_card) == 0
    pinned = capsys.readouterr().out
    assert f"pinned on this store: yes ({store / 'operators'})" in pinned
    assert "To pin it" not in pinned
    # Once pinned, the card passes the gate for a key command.
    auth = CardAuthenticator(
        store / "operators", module=soft_card.module, token=soft_card.token
    )
    assert auth.authenticate("keys export-recovery", store, PIN.encode())[
        "subject"
    ] == ("Test Operator")


def test_a_copied_certificate_without_its_key_fails(soft_card, tmp_path, capsys):
    soft_card.issue(card_key="other")
    assert _check(tmp_path, soft_card) == 1
    assert "does not verify against its own certificate" in capsys.readouterr().err


def test_an_expired_certificate_fails(soft_card, tmp_path, capsys):
    soft_card.issue(days=1, start_days_ago=10)
    assert _check(tmp_path, soft_card) == 1
    assert "has expired (valid " in capsys.readouterr().err


def test_a_wrong_pin_fails_without_echoing_it(soft_card, tmp_path, capsys):
    soft_card.issue()
    assert _check(tmp_path, soft_card, pin="999999") == 1
    err = capsys.readouterr().err
    assert "pkcs11-tool failed" in err and "999999" not in err


def test_it_needs_no_gate_and_writes_no_audit_entry(soft_card, tmp_path, store, capsys):
    # With the gate on and nothing pinned, every key command is refused; a
    # card check still runs, because it reads no key.
    soft_card.issue()
    assert _check(tmp_path, soft_card, NGARI_OPERATOR_AUTH="card") == 0
    assert "operator:" not in capsys.readouterr().out
    assert not (store / "audit").exists()


def test_the_signature_is_bound_to_card_check_and_the_store(
    soft_card, tmp_path, store, monkeypatch
):
    soft_card.issue()
    signed = []
    real = CardAuthenticator._sign
    monkeypatch.setattr(
        CardAuthenticator, "_sign",
        lambda self, work, cert, message, pin, fp: signed.append(message)
        or real(self, work, cert, message, pin, fp),
    )  # fmt: skip
    auth = CardAuthenticator(
        store / "operators", module=soft_card.module, token=soft_card.token
    )
    facts = auth.check(store, PIN.encode())
    [message] = signed
    # The nonce is the last 32 bytes. It is random, so it can hold a NUL
    # itself: splitting on the last separator would cut it short.
    nonce = message[-32:]
    assert message == challenge(CARD_CHECK, store, facts["fingerprint"], nonce)
    assert len(nonce) == 32
    assert CARD_CHECK != "keys export-recovery"


def test_a_missing_pin_file_is_reported(soft_card, tmp_path, capsys):
    soft_card.issue()
    env = _env(tmp_path, soft_card)
    argv = ["card-check", "--pin-file", str(tmp_path / "missing")]
    assert keys_cli.cli(argv, env) == 1
    assert capsys.readouterr().err.startswith("card-check: ")
    assert os.environ.get("NGARI_CARD_PIN") is None
