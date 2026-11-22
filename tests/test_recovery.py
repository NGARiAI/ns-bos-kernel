"""Recovery bundle: a passphrase-wrapped copy of the master key, and restoring
it into a different TPM after the one that sealed the key is gone."""

import base64
import hashlib
import json
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import SovereignDataPlane, keys_cli, recovery
from core.kernel.data_plane.keys import KeyProviderError
from core.kernel.data_plane.keys_cli import (
    MigrationError,
    export_recovery,
    migrate,
    read_passphrase,
    restore,
)
from core.kernel.data_plane.recovery import RecoveryError, unwrap, wrap
from core.kernel.data_plane.tpm import TPMKeyProvider

V010 = Path(__file__).resolve().parent / "vectors" / "v0.1.0"
V010_PLAINTEXT = {
    "msg": "written by the v0.1.0 data plane",
    "n": 7,
    "nested": {"ok": True},
}
PASS = b"correct horse battery staple"


def _store(tmp_path, key=None, files=None):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    if key is not None:
        (store / "keys" / "master.key").write_bytes(key)
        (store / "keys" / "master.key").chmod(0o600)
    for name, data in (files or {}).items():
        (store / "encrypted" / name).write_bytes(data)
    return store


def _tree(path):
    return sorted(
        (str(p.relative_to(path)), hashlib.sha256(p.read_bytes()).hexdigest())
        for p in path.rglob("*")
        if p.is_file()
    )


# -- the bundle format -------------------------------------------------------


def test_a_bundle_opens_with_its_passphrase_only():
    key = Fernet.generate_key()
    data = wrap(key, PASS)
    assert unwrap(data, PASS) == key
    with pytest.raises(RecoveryError, match="passphrase is wrong") as caught:
        unwrap(data, PASS + b"!")
    assert key.decode() not in str(caught.value)
    assert PASS.decode() not in str(caught.value)


def test_a_bundle_holds_neither_key_nor_passphrase():
    key = Fernet.generate_key()
    data = wrap(key, PASS)
    for secret in (key, base64.urlsafe_b64decode(key), PASS):
        assert secret not in data
    bundle = json.loads(data)
    assert bundle["kdf"] == {"name": "scrypt", "n": 2**15, "r": 8, "p": 1}
    assert json.loads(wrap(key, PASS))["salt"] != bundle["salt"]  # fresh salt


def _edit(field, value):
    def change(bundle):
        if field.startswith("kdf."):
            bundle["kdf"][field[4:]] = value
        else:
            bundle[field] = value

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_edit("version", 2), "not a valid"),
        (_edit("salt", "!!"), "not a valid"),
        (_edit("salt", base64.b64encode(b"short").decode()), "not a valid"),
        (_edit("kdf.name", "pbkdf2"), "not a valid"),
        (_edit("kdf.n", 2**30), "not a valid"),
        (_edit("kdf.n", 3 * 2**14), "not a valid"),
        (_edit("kdf.r", 1000), "not a valid"),
        (_edit("kdf.p", "1"), "not a valid"),
        (_edit("salt", base64.b64encode(b"x" * 16).decode()), "passphrase is wrong"),
        (_edit("token", "gAAAAAB" + "A" * 80), "passphrase is wrong"),
    ],
)
def test_an_edited_bundle_fails_closed_and_fast(change, message):
    bundle = json.loads(wrap(Fernet.generate_key(), PASS))
    change(bundle)
    start = time.monotonic()
    with pytest.raises(RecoveryError, match=message):
        unwrap(json.dumps(bundle).encode(), PASS)
    assert time.monotonic() - start < 5


def test_a_bundle_that_holds_something_other_than_a_key_is_rejected():
    salt = b"s" * 16
    token = recovery._derive(PASS, salt, 2**15, 8, 1).encrypt(b"not a fernet key")
    bundle = {
        "version": 1,
        "kdf": {"name": "scrypt", "n": 2**15, "r": 8, "p": 1},
        "salt": base64.b64encode(salt).decode(),
        "token": token.decode(),
    }
    with pytest.raises(KeyProviderError, match="not a valid Fernet key"):
        unwrap(json.dumps(bundle).encode(), PASS)


def test_a_bundle_that_does_not_open_again_is_never_returned(monkeypatch):
    monkeypatch.setattr(recovery, "unwrap", lambda data, passphrase: b"other")
    with pytest.raises(RecoveryError, match="did not open to the same key"):
        wrap(Fernet.generate_key(), PASS)


def test_garbage_is_not_a_bundle():
    with pytest.raises(RecoveryError, match="not a valid recovery bundle"):
        unwrap(b"\x00\xff", PASS)


def test_a_short_passphrase_is_refused():
    with pytest.raises(RecoveryError, match="at least 12"):
        wrap(Fernet.generate_key(), b"short")


# -- export ------------------------------------------------------------------


def test_export_from_a_plaintext_key(tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key, {"a.enc": Fernet(key).encrypt(b"x")})
    out = tmp_path / "bundle.json"
    lines = export_recovery(store, {}, out, PASS)
    assert unwrap(out.read_bytes(), PASS) == key
    assert oct(out.stat().st_mode & 0o777) == "0o600"
    assert all(key.decode() not in line for line in lines)


def test_export_from_a_sealed_key(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    migrate(store, env)
    (store / "keys" / "master.key").unlink()
    out = tmp_path / "bundle.json"
    export_recovery(store, env, out, PASS)
    assert unwrap(out.read_bytes(), PASS) == key


def test_export_never_overwrites_a_file(tmp_path):
    store = _store(tmp_path, Fernet.generate_key())
    out = tmp_path / "bundle.json"
    out.write_bytes(b"older bundle")
    with pytest.raises(MigrationError, match="already exists"):
        export_recovery(store, {}, out, PASS)
    assert out.read_bytes() == b"older bundle"


def test_export_refuses_a_key_that_does_not_open_the_data(tmp_path):
    store = _store(
        tmp_path,
        Fernet.generate_key(),
        {"a.enc": Fernet(Fernet.generate_key()).encrypt(b"x")},
    )
    out = tmp_path / "bundle.json"
    with pytest.raises(MigrationError, match="does not decrypt a.enc"):
        export_recovery(store, {}, out, PASS)
    assert not out.exists()


def test_export_refuses_when_sealed_and_plaintext_keys_differ(soft_tpm, tmp_path):
    store = _store(tmp_path, Fernet.generate_key())
    TPMKeyProvider(store / "keys", tcti=soft_tpm).seal(Fernet.generate_key())
    out = tmp_path / "bundle.json"
    with pytest.raises(MigrationError, match="hold different keys"):
        export_recovery(store, {"NGARI_TPM_TCTI": soft_tpm}, out, PASS)
    assert not out.exists()


# -- restore -----------------------------------------------------------------


def test_after_a_board_swap_the_bundle_brings_v010_data_back(
    soft_tpm, other_tpm, tmp_path, monkeypatch
):
    store = _store(
        tmp_path,
        (V010 / "master.key").read_bytes(),
        {"greeting.enc": (V010 / "greeting.enc").read_bytes()},
    )
    old = {"NGARI_TPM_TCTI": soft_tpm}
    migrate(store, old)
    bundle = tmp_path / "offsite" / "bundle.json"
    bundle.parent.mkdir()
    export_recovery(store, old, bundle, PASS)
    (store / "keys" / "master.key").unlink()
    dead_blob = (store / "keys" / "master.key.sealed").read_bytes()

    new = {"NGARI_TPM_TCTI": other_tpm}  # the replacement board's TPM
    lines = restore(store, new, bundle, PASS)
    assert any("kept as" in line for line in lines)
    kept = [p for p in (store / "keys").iterdir() if ".unusable-" in p.name]
    assert len(kept) == 1
    assert kept[0].read_bytes() == dead_blob

    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    monkeypatch.setenv("NGARI_TPM_TCTI", other_tpm)
    plane = SovereignDataPlane(data_dir=str(store))
    assert plane.retrieve_decrypted("greeting") == V010_PLAINTEXT
    assert plane.export_compliance_report()["key_provider"]["ok"] is True


def test_restore_with_the_wrong_passphrase_changes_nothing(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    bundle = tmp_path / "bundle.json"
    export_recovery(store, {}, bundle, PASS)
    (store / "keys" / "master.key").unlink()
    before = _tree(store)
    with pytest.raises(RecoveryError, match="passphrase is wrong"):
        restore(store, {"NGARI_TPM_TCTI": soft_tpm}, bundle, b"wrong passphrase!")
    assert _tree(store) == before


def test_restore_refuses_a_bundle_for_other_data(soft_tpm, tmp_path):
    store = _store(
        tmp_path, files={"a.enc": Fernet(Fernet.generate_key()).encrypt(b"x")}
    )
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(Fernet.generate_key(), PASS))
    before = _tree(store)
    with pytest.raises(MigrationError, match="does not decrypt a.enc"):
        restore(store, {"NGARI_TPM_TCTI": soft_tpm}, bundle, PASS)
    assert _tree(store) == before


def test_restore_refuses_a_different_plaintext_key(soft_tpm, tmp_path):
    store = _store(tmp_path, Fernet.generate_key())
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(Fernet.generate_key(), PASS))
    before = _tree(store)
    with pytest.raises(MigrationError, match="different key than the bundle"):
        restore(store, {"NGARI_TPM_TCTI": soft_tpm}, bundle, PASS)
    assert _tree(store) == before


def test_restore_of_the_key_already_sealed_changes_nothing(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    migrate(store, env)
    bundle = tmp_path / "bundle.json"
    export_recovery(store, env, bundle, PASS)
    before = _tree(store)
    assert "Nothing changed" in restore(store, env, bundle, PASS)[0]
    assert _tree(store) == before


def test_restore_never_replaces_a_working_sealed_key(soft_tpm, tmp_path):
    store = _store(tmp_path)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    working = Fernet.generate_key()
    TPMKeyProvider(store / "keys", tcti=soft_tpm).seal(working)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(Fernet.generate_key(), PASS))
    before = _tree(store)
    with pytest.raises(MigrationError, match="different key that unseals"):
        restore(store, env, bundle, PASS)
    assert _tree(store) == before


def test_a_failed_restore_puts_the_old_sealed_file_back(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    migrate(store, {"NGARI_TPM_TCTI": soft_tpm})
    (store / "keys" / "master.key").unlink()
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(key, PASS))
    before = _tree(store)
    unreachable = {"NGARI_TPM_TCTI": f"libtpms:{tmp_path / 'gone' / 'state'}"}
    with pytest.raises(Exception, match="failed"):
        restore(store, unreachable, bundle, PASS)
    assert _tree(store) == before


# -- passphrase input and the command line -----------------------------------


def test_a_passphrase_file_loses_one_trailing_newline(tmp_path):
    path = tmp_path / "pass"
    path.write_bytes(PASS + b"\n")
    assert read_passphrase(str(path), confirm=True) == PASS
    path.write_bytes(PASS + b"\r\n")
    assert read_passphrase(str(path), confirm=True) == PASS


def test_without_a_file_or_terminal_there_is_no_passphrase(monkeypatch):
    monkeypatch.setattr(keys_cli.sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(MigrationError, match="no terminal"):
        read_passphrase(None, confirm=False)


def test_a_mistyped_confirmation_is_refused(monkeypatch):
    answers = iter(["first passphrase", "second passphrase"])
    monkeypatch.setattr(keys_cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(keys_cli.getpass, "getpass", lambda prompt: next(answers))
    with pytest.raises(MigrationError, match="did not match"):
        read_passphrase(None, confirm=True)


def test_cli_export_and_restore(soft_tpm, tmp_path, capsys):
    key = Fernet.generate_key()
    _store(tmp_path, key)
    secret = tmp_path / "pass"
    secret.write_bytes(PASS + b"\n")
    bundle = tmp_path / "bundle.json"
    env = {"NGARI_DATA_DIR": str(tmp_path / "data"), "NGARI_TPM_TCTI": soft_tpm}

    assert (
        keys_cli.cli(
            ["export-recovery", "--out", str(bundle), "--passphrase-file", str(secret)],
            env,
        )
        == 0
    )
    assert (
        keys_cli.cli(
            ["restore", "--bundle", str(bundle), "--passphrase-file", str(secret)], env
        )
        == 0
    )
    out = capsys.readouterr()
    for leaked in (key.decode(), PASS.decode()):
        assert leaked not in out.out + out.err
    assert (
        TPMKeyProvider(tmp_path / "data" / "sovereign" / "keys", tcti=soft_tpm).unseal()
        == key
    )

    secret.write_bytes(b"not the passphrase")
    assert (
        keys_cli.cli(
            ["restore", "--bundle", str(bundle), "--passphrase-file", str(secret)], env
        )
        == 1
    )
    assert "passphrase is wrong" in capsys.readouterr().err


def test_the_bundle_parameters_are_what_the_design_says():
    assert (recovery.SCRYPT_N, recovery.SCRYPT_R, recovery.SCRYPT_P) == (2**15, 8, 1)
    assert recovery.MAXMEM == 64 * 1024 * 1024
