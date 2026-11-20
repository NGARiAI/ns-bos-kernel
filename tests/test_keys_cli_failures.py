"""Failure paths of the keys commands and the card check: bad input stops
the command with a clear message, and nothing that holds the key is
renamed, replaced or lost on the way."""

import datetime
import json

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from core.kernel.data_plane import keys_cli, operator_auth
from core.kernel.data_plane.keys import KeyProviderError
from core.kernel.data_plane.keys_cli import (
    MigrationError,
    current_key,
    export_recovery,
    migrate,
    read_passphrase,
    restore,
)
from core.kernel.data_plane.operator_auth import CardAuthenticator, OperatorAuthError
from core.kernel.data_plane.recovery import wrap
from core.kernel.data_plane.tpm import TPMKeyProvider

PASS = b"correct horse battery staple"


def _store(tmp_path, key=None):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    if key is not None:
        (store / "keys" / "master.key").write_bytes(key)
    return store


def _tree(path):
    return sorted(
        (str(p.relative_to(path)), p.read_bytes())
        for p in path.rglob("*")
        if p.is_file()
    )


def test_migrate_refuses_a_master_key_that_is_not_a_key(soft_tpm, tmp_path):
    store = _store(tmp_path, b"not-a-fernet-key-but-secret-looking-bytes!!")
    with pytest.raises(
        MigrationError, match="cannot read .*not a valid Fernet key"
    ) as caught:
        migrate(store, {"NGARI_TPM_TCTI": soft_tpm})
    assert "secret-looking" not in str(caught.value)
    assert [p.name for p in (store / "keys").iterdir()] == ["master.key"]


def test_export_with_no_key_or_a_bad_key(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(MigrationError, match="no master key"):
        current_key(store, {})
    (store / "keys" / "master.key").write_bytes(b"short")
    with pytest.raises(KeyProviderError, match="not a valid Fernet key"):
        current_key(store, {})


def test_export_to_a_place_it_cannot_write(tmp_path):
    store = _store(tmp_path, Fernet.generate_key())
    with pytest.raises(MigrationError, match="cannot write"):
        export_recovery(store, {}, tmp_path / "missing-dir" / "bundle.json", PASS)


def test_restore_from_a_bundle_that_is_not_there(soft_tpm, tmp_path):
    store = _store(tmp_path)
    with pytest.raises(MigrationError, match="cannot read .*No such file"):
        restore(store, {"NGARI_TPM_TCTI": soft_tpm}, tmp_path / "nope.json", PASS)


def test_restore_stops_if_the_set_aside_name_is_taken(
    soft_tpm, other_tpm, tmp_path, monkeypatch
):
    key = Fernet.generate_key()
    store = _store(tmp_path)
    TPMKeyProvider(store / "keys", tcti=soft_tpm).seal(key)  # unusable on other_tpm
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(key, PASS))

    class Fixed(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 28, 3, 0, 0, tzinfo=tz)

    monkeypatch.setattr(keys_cli, "datetime", Fixed)
    taken = store / "keys" / "master.key.sealed.unusable-20261028T030000Z"
    taken.write_text("an earlier set-aside file")
    before = _tree(store)
    with pytest.raises(MigrationError, match="already exists"):
        restore(store, {"NGARI_TPM_TCTI": other_tpm}, bundle, PASS)
    assert _tree(store) == before


def test_restore_refuses_when_another_process_sealed_a_different_key(
    soft_tpm, tmp_path, monkeypatch
):
    key = Fernet.generate_key()
    store = _store(tmp_path)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(key, PASS))
    other = Fernet.generate_key()
    monkeypatch.setattr(
        TPMKeyProvider, "seal", lambda self, k, pcrs=None: (other, False)
    )
    with pytest.raises(MigrationError, match="sealed a different key meanwhile"):
        restore(store, {"NGARI_TPM_TCTI": soft_tpm}, bundle, PASS)


def test_a_passphrase_file_that_cannot_be_read(tmp_path):
    with pytest.raises(MigrationError, match="cannot read .*No such file"):
        read_passphrase(str(tmp_path / "missing"), confirm=False)


def test_a_matching_confirmation_is_accepted(monkeypatch):
    answers = iter(["same passphrase!", "same passphrase!"])
    monkeypatch.setattr(keys_cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(keys_cli.getpass, "getpass", lambda prompt: next(answers))
    assert read_passphrase(None, confirm=True) == b"same passphrase!"


# -- card check -----------------------------------------------------------------


def test_the_default_module_falls_back_to_the_first_candidate(monkeypatch):
    monkeypatch.setattr(operator_auth.Path, "exists", lambda self: False)
    assert operator_auth.default_module() == operator_auth._MODULE_CANDIDATES[0]


def test_only_certificate_files_are_pinned(tmp_path):
    ops = tmp_path / "operators"
    ops.mkdir()
    (ops / "README.txt").write_text("notes, not a certificate")
    (ops / "key.json").write_text(json.dumps({"x": 1}))
    assert operator_auth.load_pinned(ops) == {}


def test_a_card_certificate_that_does_not_parse(tmp_path, monkeypatch):
    ops = tmp_path / "operators"
    monkeypatch.setattr(operator_auth, "load_pinned", lambda d: {"fp": None})

    def tool(self, work, *args, **kwargs):
        (work / "card.der").write_bytes(b"\x00not a certificate")

    monkeypatch.setattr(CardAuthenticator, "_tool", tool)
    with pytest.raises(OperatorAuthError, match="could not be read") as caught:
        CardAuthenticator(ops).authenticate("keys migrate", tmp_path, b"123456")
    assert caught.value.reason == "card"


def test_an_unsupported_card_key_type(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ed")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, None)
    )  # fmt: skip
    fp = cert.fingerprint(hashes.SHA256()).hex()
    with pytest.raises(OperatorAuthError, match="unsupported key type") as caught:
        CardAuthenticator(tmp_path)._sign(tmp_path, cert, b"m", b"123456", fp)
    assert caught.value.reason == "unsupported key"
