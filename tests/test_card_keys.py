"""Keys a card certificate may hold (docs/PIV_CAC.md, docs/FIPS.md): EC on
P-256, P-384 or P-521, or RSA of at least 2048 bits with an exponent of at
least 65537. Anything else is refused when pinning, at the gate, by
card-check and by records sign before the card is asked to sign, and
reported invalid by records signatures."""

import datetime
import hashlib
import json
import math

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from core.kernel.data_plane import append_audit, keys_cli, records_cli
from core.kernel.data_plane.operator_auth import (
    esign_message,
    identity_bytes,
    key_problem,
)


def _cert(key, cn="Jane Doe"):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
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


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _rsa(bits=2048, e=65537):
    return rsa.generate_private_key(public_exponent=e, key_size=bits)


@pytest.mark.parametrize(
    "key",
    [ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP384R1()),
     ec.generate_private_key(ec.SECP521R1()), _rsa(2048), _rsa(3072)],
    ids=["P-256", "P-384", "P-521", "RSA-2048", "RSA-3072"],
)  # fmt: skip
def test_accepted_keys(key):
    assert key_problem(_cert(key)) is None


@pytest.mark.parametrize(
    ("key", "why"),
    [(ec.generate_private_key(ec.SECP256K1()),
      "an EC key on secp256k1; only P-256, P-384 and P-521 are accepted"),
     (ec.generate_private_key(ec.SECP224R1()), "an EC key on secp224r1"),
     (ec.generate_private_key(ec.BrainpoolP256R1()), "an EC key on brainpoolP256r1"),
     (_rsa(1024), "an RSA key of 1024 bits; at least 2048 are needed"),
     (_rsa(2047), "an RSA key of 2047 bits"),
     (_rsa(2048, e=3), "an RSA key with exponent 3; at least 65537 is needed"),
     (ed25519.Ed25519PrivateKey.generate(),
      "an unsupported key type (Ed25519PublicKey)")],
    ids=["secp256k1", "P-224", "brainpool", "RSA-1024", "RSA-2047", "e=3", "Ed25519"],
)  # fmt: skip
def test_refused_keys(key, why):
    assert why in key_problem(_cert(key))


def _rsa_public(e, bits=2048):
    numbers = _rsa(bits).private_numbers()
    return rsa.RSAPublicNumbers(e, numbers.p * numbers.q).public_key()


def _universal():
    """RSA-2048 with e = 1 + lambda(n): odd, below n, s^e = s mod n."""
    k = _rsa(2048).private_numbers()
    e = 1 + (k.p - 1) * (k.q - 1) // math.gcd(k.p - 1, k.q - 1)
    return rsa.RSAPublicNumbers(e, k.p * k.q).public_key()


def _cert_for(public_key, cn="Jane Doe"):
    signer = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(signer, hashes.SHA256())
    )


def test_the_exponent_must_be_below_2_to_the_256():
    assert key_problem(_cert_for(_rsa_public(2**256 - 1))) is None
    assert "a 257-bit exponent; it must be below 2^256" in key_problem(
        _cert_for(_rsa_public(2**256 + 1))
    )
    assert "-bit exponent; it must be below 2^256" in key_problem(
        _cert_for(_universal())
    )


def test_a_signature_anyone_could_make_is_not_reported_valid(tmp_path, capsys):
    # With e = 1 + lambda(n) the PKCS#1 v1.5 encoding of a message is its own
    # signature: no private key, no card.
    store = _store(tmp_path)
    cert = _cert_for(_universal())
    ops = store / "operators"
    ops.mkdir()
    (ops / "jdoe.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )  # copied
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", _fp(cert)))
    record = tmp_path / "batch-42.txt"
    record.write_text("Batch 42 released\n")
    digest = hashlib.sha256(record.read_bytes()).hexdigest()
    fields = {"meaning": "approval", "name": "Jane Doe", "fingerprint": _fp(cert),
              "signed_at": "2026-10-31T09:00:00Z", "nonce": "ab" * 16}  # fmt: skip
    message = esign_message(digest, "approval", "jdoe", "Jane Doe", _fp(cert),
                            fields["signed_at"], fields["nonce"])  # fmt: skip
    info = bytes.fromhex("3031300d060960864801650304020105000420")
    info += hashlib.sha256(message).digest()
    forged = b"\x00\x01" + b"\xff" * (256 - 3 - len(info)) + b"\x00" + info
    append_audit(
        store / "audit" / "sovereign_audit.log", "esignature", "jdoe", digest,
        {**fields, "signature": forged.hex(), "file": record.name},
    )  # fmt: skip
    assert (
        records_cli.cli(
            ["signatures", str(record)], {"NGARI_DATA_DIR": str(tmp_path / "data")}
        )
        == 1
    )
    out = capsys.readouterr().out
    assert ": valid" not in out and "it must be below 2^256" in out
    path = tmp_path / "universal.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    args = ["pin-operator", "--cert", str(path), "--user", "mallory"]
    assert keys_cli.cli(args, {"NGARI_DATA_DIR": str(tmp_path / "data")}) == 1


def _unknown_curve_der():
    """A P-256 certificate whose curve OID is changed to one cryptography
    cannot load (1.2.840.10045.3.1.9)."""
    der = _cert_for(ec.generate_private_key(ec.SECP256R1()).public_key()).public_bytes(
        serialization.Encoding.DER
    )
    p256 = bytes.fromhex("06072a8648ce3d020106082a8648ce3d030107")
    assert der.count(p256) == 1
    return der.replace(p256, bytes.fromhex("06072a8648ce3d020106082a8648ce3d030109"))


def test_a_key_that_cannot_be_read_is_refused_not_a_crash(tmp_path, capsys):
    cert = x509.load_der_x509_certificate(_unknown_curve_der())
    assert "a key that cannot be read" in key_problem(cert)
    _store(tmp_path)
    path = tmp_path / "card.der"
    path.write_bytes(_unknown_curve_der())
    args = ["pin-operator", "--cert", str(path), "--user", "jdoe"]
    assert keys_cli.cli(args, {"NGARI_DATA_DIR": str(tmp_path / "data")}) == 1
    assert "has a key that cannot be read" in capsys.readouterr().err


def test_a_signature_by_an_unreadable_key_is_invalid(tmp_path, capsys):
    store = _store(tmp_path)
    der = _unknown_curve_der()
    fp = hashlib.sha256(der).hexdigest()
    ops = store / "operators"
    ops.mkdir()
    (ops / "jdoe.der").write_bytes(der)
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", fp))
    record = tmp_path / "r.txt"
    record.write_text("r\n")
    digest = hashlib.sha256(record.read_bytes()).hexdigest()
    append_audit(
        store / "audit" / "sovereign_audit.log", "esignature", "jdoe", digest,
        {"meaning": "approval", "name": "Jane Doe", "fingerprint": fp,
         "signed_at": "2026-10-31T09:00:00Z", "nonce": "ab" * 16, "signature": "00"},
    )  # fmt: skip
    assert (
        records_cli.cli(
            ["signatures", str(record)], {"NGARI_DATA_DIR": str(tmp_path / "data")}
        )
        == 1
    )
    assert "has a key that cannot be read" in capsys.readouterr().out


# -- pinning --------------------------------------------------------------------------


def _store(tmp_path):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    return store


def test_a_weak_certificate_is_not_pinned(tmp_path, capsys):
    store = _store(tmp_path)
    cert = _cert(_rsa(1024))
    path = tmp_path / "weak.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    args = ["pin-operator", "--cert", str(path), "--user", "jdoe"]
    assert keys_cli.cli(args, {"NGARI_DATA_DIR": str(tmp_path / "data")}) == 1
    assert f"certificate {_fp(cert)[:16]} has an RSA key of 1024 bits" in (
        capsys.readouterr().err
    )
    assert not (store / "operators").exists()


# -- a card with a weak key ------------------------------------------------------------


@pytest.fixture
def weak_card(soft_card, tmp_path):
    store = _store(tmp_path)
    cert = soft_card.issue(kind="rsa", rsa_bits=1024)
    ops = store / "operators"
    ops.mkdir()
    (ops / "jdoe.pem").write_bytes(soft_card.pem())  # pinned by copying
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", _fp(cert)))
    env = {
        "NGARI_DATA_DIR": str(tmp_path / "data"),
        "NGARI_PKCS11_MODULE": soft_card.module,
        "NGARI_PKCS11_TOKEN": soft_card.token,
    }
    # A wrong PIN: were the card asked to sign, the reason would be "pin".
    pin = tmp_path / "pin"
    pin.write_text("999999")
    return store, cert, env, str(pin)


def _entries(store):
    log = store / "audit" / "sovereign_audit.log"
    return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []


def test_the_gate_refuses_a_weak_card_before_it_signs(weak_card, tmp_path, capsys):
    store, cert, env, pin = weak_card
    secret = tmp_path / "pass"
    secret.write_bytes(b"correct horse battery staple")
    out = tmp_path / "bundle.json"
    args = ["export-recovery", "--out", str(out), "--passphrase-file", str(secret),
            "--pin-file", pin]  # fmt: skip
    assert keys_cli.cli(args, {**env, "NGARI_OPERATOR_AUTH": "card"}) == 1
    assert not out.exists()
    assert "has an RSA key of 1024 bits" in capsys.readouterr().err
    [auth] = _entries(store)
    assert (auth["actor"], auth["details"]) == (
        _fp(cert),
        {"ok": False, "reason": "weak key"},
    )


def test_card_check_refuses_a_weak_card(weak_card, capsys):
    _, _, env, pin = weak_card
    assert keys_cli.cli(["card-check", "--pin-file", pin], env) == 1
    assert "has an RSA key of 1024 bits" in capsys.readouterr().err


def test_a_weak_card_cannot_sign_a_record(weak_card, tmp_path, capsys):
    store, _, env, pin = weak_card
    record = tmp_path / "report.txt"
    record.write_text("Batch 42\n")
    args = ["sign", str(record), "--meaning", "approval", "--pin-file", pin]
    assert records_cli.cli(args, env) == 1
    [refused] = _entries(store)
    assert (refused["action"], refused["details"]["reason"]) == (
        "esignature_refused",
        "weak key",
    )


# -- checking --------------------------------------------------------------------------


def test_a_signature_by_a_weak_certificate_is_invalid(tmp_path, capsys):
    store = _store(tmp_path)
    key = _rsa(1024)
    cert = _cert(key)
    ops = store / "operators"
    ops.mkdir()
    (ops / "jdoe.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", _fp(cert)))
    record = tmp_path / "report.txt"
    record.write_text("Batch 42\n")
    digest = hashlib.sha256(record.read_bytes()).hexdigest()
    details = {"meaning": "approval", "name": "Jane Doe", "fingerprint": _fp(cert),
               "signed_at": "2026-10-30T09:00:00Z", "nonce": "ab" * 16}  # fmt: skip
    message = esign_message(digest, "approval", "jdoe", "Jane Doe", _fp(cert),
                            details["signed_at"], details["nonce"])  # fmt: skip
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())  # a real one
    append_audit(
        store / "audit" / "sovereign_audit.log", "esignature", "jdoe", digest,
        {**details, "signature": signature.hex(), "file": record.name},
    )  # fmt: skip
    env = {"NGARI_DATA_DIR": str(tmp_path / "data")}
    assert records_cli.cli(["signatures", str(record)], env) == 1
    assert (
        f"INVALID: certificate {_fp(cert)[:16]} has an RSA key of 1024 bits"
        in capsys.readouterr().out
    )


def test_verify_refuses_another_key_type_instead_of_crashing():
    from core.kernel.data_plane.operator_auth import (
        CardAuthenticator,
        OperatorAuthError,
    )

    cert = _cert(ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(OperatorAuthError, match="unsupported key type") as caught:
        CardAuthenticator._verify(cert, b"\0" * 64, b"message", _fp(cert))
    assert caught.value.reason == "unsupported key"
