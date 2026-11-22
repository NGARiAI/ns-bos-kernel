"""`keys status` and `keys migrate`, against a software TPM.

Migration must leave master.key byte for byte as it was, and data written
under the file provider (including by the v0.1.0 release) must decrypt under
the tpm2 provider afterwards.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import SovereignDataPlane, keys_cli
from core.kernel.data_plane.keys import KeyProviderError
from core.kernel.data_plane.keys_cli import MigrationError, migrate, status
from core.kernel.data_plane.tpm import TPMKeyProvider

REPO_ROOT = Path(__file__).resolve().parent.parent
V010 = REPO_ROOT / "tests" / "vectors" / "v0.1.0"
V010_PLAINTEXT = {
    "msg": "written by the v0.1.0 data plane",
    "n": 7,
    "nested": {"ok": True},
}


def _store(tmp_path, key=None, files=None):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    if key is not None:
        plain = store / "keys" / "master.key"
        plain.write_bytes(key)
        plain.chmod(0o600)
    for name, data in (files or {}).items():
        (store / "encrypted" / name).write_bytes(data)
    return store


def _tree(path):
    return sorted(
        (str(p.relative_to(path)), hashlib.sha256(p.read_bytes()).hexdigest())
        for p in path.rglob("*")
        if p.is_file()
    )


def _env(tcti):
    return {"NGARI_TPM_TCTI": tcti}


def test_same_boot_round_trip(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key, {"a.enc": Fernet(key).encrypt(b"x")})
    lines = migrate(store, _env(soft_tpm))
    assert "unseal matches; decrypts a.enc" in lines[0]
    assert TPMKeyProvider(store / "keys", tcti=soft_tpm).load_or_create() == key
    assert (store / "keys" / "master.key").read_bytes() == key
    assert all(key.decode() not in line for line in lines)


@pytest.mark.part11("11.10(c)")
def test_v010_data_decrypts_under_tpm2_after_migration(soft_tpm, tmp_path, monkeypatch):
    store = _store(
        tmp_path,
        (V010 / "master.key").read_bytes(),
        {"greeting.enc": (V010 / "greeting.enc").read_bytes()},
    )
    before = (store / "keys" / "master.key").read_bytes()
    migrate(store, _env(soft_tpm))

    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    monkeypatch.setenv("NGARI_TPM_TCTI", soft_tpm)
    plane = SovereignDataPlane(data_dir=str(store))
    assert plane.key_provider.name == "tpm2"
    assert plane.retrieve_decrypted("greeting") == V010_PLAINTEXT
    assert (store / "keys" / "master.key").read_bytes() == before
    facts = plane.key_provider.describe()
    assert facts["plaintext_key_present"] is True
    assert facts["ok"] is False  # until the operator removes master.key

    (store / "keys" / "master.key").unlink()
    again = SovereignDataPlane(data_dir=str(store))
    assert again.retrieve_decrypted("greeting") == V010_PLAINTEXT
    assert again.export_compliance_report()["key_provider"]["ok"] is True


def test_migrating_twice_changes_nothing(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    migrate(store, _env(soft_tpm))
    before = _tree(store)
    lines = migrate(store, _env(soft_tpm))
    assert "was already sealed" in lines[0]
    assert _tree(store) == before


def test_a_different_sealed_key_is_never_replaced(soft_tpm, tmp_path):
    store = _store(tmp_path, Fernet.generate_key())
    keys_dir = store / "keys"
    other = Fernet.generate_key()
    TPMKeyProvider(keys_dir, tcti=soft_tpm).seal(other)
    before = _tree(store)
    with pytest.raises(MigrationError, match="already holds a different key"):
        migrate(store, _env(soft_tpm))
    assert _tree(store) == before
    assert TPMKeyProvider(keys_dir, tcti=soft_tpm).unseal() == other


def test_a_key_that_does_not_open_the_data_is_not_sealed(soft_tpm, tmp_path):
    store = _store(
        tmp_path,
        Fernet.generate_key(),
        {"a.enc": Fernet(Fernet.generate_key()).encrypt(b"x")},
    )
    before = _tree(store)
    with pytest.raises(MigrationError, match=r"master\.key does not decrypt a\.enc"):
        migrate(store, _env(soft_tpm))
    assert _tree(store) == before


def test_nothing_to_migrate_without_a_plaintext_key(soft_tpm, tmp_path):
    store = _store(tmp_path)
    with pytest.raises(MigrationError, match="nothing to migrate"):
        migrate(store, _env(soft_tpm))
    assert _tree(store) == []


def test_a_sealing_failure_leaves_only_the_plaintext_key(tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    bad = {"NGARI_TPM_TCTI": f"libtpms:{tmp_path / 'missing-dir' / 'state'}"}
    with pytest.raises(MigrationError, match="sealing failed") as caught:
        migrate(store, bad)
    assert key.decode() not in str(caught.value)
    assert _tree(store) == [
        ("keys/master.key", hashlib.sha256(key).hexdigest()),
    ]


def test_a_failed_verification_removes_only_the_blob_it_wrote(
    soft_tpm, tmp_path, monkeypatch
):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    before = _tree(store)

    def broken_unseal(self):
        raise KeyProviderError("tpm2_unseal failed: simulated")

    monkeypatch.setattr(TPMKeyProvider, "unseal", broken_unseal)
    with pytest.raises(MigrationError, match="verification failed"):
        migrate(store, _env(soft_tpm))
    assert _tree(store) == before


def test_an_unseal_that_returns_another_key_removes_the_blob(
    soft_tpm, tmp_path, monkeypatch
):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    before = _tree(store)
    monkeypatch.setattr(TPMKeyProvider, "unseal", lambda self: Fernet.generate_key())
    with pytest.raises(MigrationError, match="did not unseal to master.key"):
        migrate(store, _env(soft_tpm))
    assert _tree(store) == before


def test_status_reads_without_writing(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key, {"a.enc": b"x", "b.enc": b"y"})
    before = _tree(store)
    facts = status(store, {"NGARI_KEY_PROVIDER": "TPM2"})
    assert facts == {
        "data_directory": str(store),
        "selected_provider": "tpm2",
        "master_key": {"present": True, "mode": "0o600"},
        "sealed_key": {"present": False, "mode": None, "pcrs": None},
        "encrypted_files": 2,
    }
    assert _tree(store) == before
    assert not (store / "audit").exists()


def test_cli_exit_codes_and_output(soft_tpm, tmp_path, capsys):
    key = Fernet.generate_key()
    _store(tmp_path, key)
    data_dir = str(tmp_path / "data")
    env = {"NGARI_DATA_DIR": data_dir, "NGARI_TPM_TCTI": soft_tpm}

    assert keys_cli.cli(["migrate"], env) == 0
    out = capsys.readouterr()
    assert "unseal matches" in out.out
    assert key.decode() not in out.out + out.err

    assert keys_cli.cli(["status"], env) == 0
    assert json.loads(capsys.readouterr().out)["sealed_key"]["present"] is True

    empty = {"NGARI_DATA_DIR": str(tmp_path / "nowhere"), "NGARI_TPM_TCTI": soft_tpm}
    assert keys_cli.cli(["migrate"], empty) == 1
    assert "nothing to migrate" in capsys.readouterr().err


def test_python_dash_m_runs_the_keys_command(tmp_path):
    _store(tmp_path, Fernet.generate_key())
    env = {**os.environ, "NGARI_DATA_DIR": str(tmp_path / "data")}
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel", "keys", "status"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["master_key"]["present"] is True
    assert not (tmp_path / "data" / "logs").exists()
