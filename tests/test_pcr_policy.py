"""Optional PCR policy, only reachable through `keys restore` with a
recovery bundle in hand. Every PCR here belongs to a software TPM; nothing
extends a PCR on the hardware chip."""

import json
import os
import subprocess
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import SovereignDataPlane, keys_cli
from core.kernel.data_plane.keys import KeyProviderError
from core.kernel.data_plane.keys_cli import MigrationError, migrate, restore, status
from core.kernel.data_plane.recovery import wrap
from core.kernel.data_plane.tpm import TPMKeyProvider, parse_pcrs

PASS = b"correct horse battery staple"
DEBUG_PCR = "sha256:16"  # resettable debug PCR, safe to extend on a simulator


def _store(tmp_path, key):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    (store / "encrypted" / "a.enc").write_bytes(Fernet(key).encrypt(b"held"))
    return store


def _bundle(tmp_path, key):
    path = tmp_path / "bundle.json"
    path.write_bytes(wrap(key, PASS))
    return path


def _extend(tcti, pcr=16):
    assert tcti.startswith("libtpms:"), "PCRs are only ever extended on a simulator"
    env = {**os.environ, "TPM2TOOLS_TCTI": tcti, "TSS2_LOG": "all+NONE"}
    subprocess.run(
        ["tpm2_pcrextend", f"{pcr}:sha256=" + "11" * 32],
        cwd=Path(tcti.partition(":")[2]).parent,
        env=env,
        capture_output=True,
        check=True,
    )


def test_a_pcr_bound_key_unseals_while_the_pcrs_hold(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    lines = restore(store, env, _bundle(tmp_path, key), PASS, DEBUG_PCR)
    assert any("bound to PCRs sha256:16" in line for line in lines)
    provider = TPMKeyProvider(store / "keys", tcti=soft_tpm)
    assert provider.unseal() == key
    assert provider.pcrs() == DEBUG_PCR
    assert provider.describe()["pcrs"] == DEBUG_PCR
    assert status(store, env)["sealed_key"]["pcrs"] == DEBUG_PCR
    blob = json.loads((store / "keys" / "master.key.sealed").read_text())
    assert blob["pcrs"] == DEBUG_PCR


def test_a_changed_pcr_fails_closed_and_the_bundle_brings_the_key_back(
    soft_tpm, tmp_path, monkeypatch
):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    bundle = _bundle(tmp_path, key)
    restore(store, env, bundle, PASS, DEBUG_PCR)

    _extend(soft_tpm)  # the "firmware update"
    sealed = (store / "keys" / "master.key.sealed").read_bytes()
    with pytest.raises(KeyProviderError, match="tpm2_unseal failed") as caught:
        TPMKeyProvider(store / "keys", tcti=soft_tpm).load_or_create()
    assert key.decode() not in str(caught.value)
    assert (store / "keys" / "master.key.sealed").read_bytes() == sealed
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    monkeypatch.setenv("NGARI_TPM_TCTI", soft_tpm)
    with pytest.raises(KeyProviderError):
        SovereignDataPlane(data_dir=str(store))

    lines = restore(store, env, bundle, PASS, DEBUG_PCR)  # bound to the new value
    assert any("kept as" in line for line in lines)
    plane = SovereignDataPlane(data_dir=str(store))
    assert plane.fernet.decrypt((store / "encrypted" / "a.enc").read_bytes()) == b"held"


def test_restore_rebinds_an_existing_seal_to_pcrs_and_back(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    (store / "keys" / "master.key").write_bytes(key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    migrate(store, env)
    (store / "keys" / "master.key").unlink()
    bundle = _bundle(tmp_path, key)
    provider = TPMKeyProvider(store / "keys", tcti=soft_tpm)

    restore(store, env, bundle, PASS, DEBUG_PCR)
    assert provider.pcrs() == DEBUG_PCR
    assert provider.unseal() == key
    assert [p.name for p in (store / "keys").iterdir()] == ["master.key.sealed"]

    restore(store, env, bundle, PASS, None)
    assert provider.pcrs() is None
    _extend(soft_tpm)
    assert provider.unseal() == key  # not bound to the PCR


def test_new_keys_never_get_a_pcr_policy(soft_tpm, tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_TPM_PCRS", DEBUG_PCR)
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    provider.load_or_create()
    assert provider.pcrs() is None


def test_rebinding_needs_a_bundle_that_holds_the_sealed_key(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    TPMKeyProvider(store / "keys", tcti=soft_tpm).seal(key)
    other = Fernet.generate_key()
    with pytest.raises(MigrationError):
        restore(store, env, _bundle(tmp_path, other), PASS, DEBUG_PCR)
    assert TPMKeyProvider(store / "keys", tcti=soft_tpm).pcrs() is None


def test_reseal_refuses_a_different_key(soft_tpm, tmp_path):
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    provider.seal(Fernet.generate_key())
    before = (keys_dir / "master.key.sealed").read_bytes()
    with pytest.raises(KeyProviderError, match="holds a different key"):
        provider.reseal(Fernet.generate_key(), DEBUG_PCR)
    assert (keys_dir / "master.key.sealed").read_bytes() == before


def test_a_forged_pcr_field_fails_closed(soft_tpm, tmp_path):
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    key = Fernet.generate_key()
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    provider.seal(key, DEBUG_PCR)
    sealed = keys_dir / "master.key.sealed"
    blob = json.loads(sealed.read_text())
    blob.pop("pcrs")  # pretend there is no policy
    sealed.write_text(json.dumps(blob))
    with pytest.raises(KeyProviderError, match="tpm2_unseal failed"):
        provider.unseal()
    blob["pcrs"] = "sha256:99"
    sealed.write_text(json.dumps(blob))
    with pytest.raises(KeyProviderError, match="not a valid sealed key"):
        provider.unseal()


def test_no_sessions_or_objects_are_left_behind(soft_tpm, tmp_path):
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    provider.seal(Fernet.generate_key(), DEBUG_PCR)
    for _ in range(4):
        provider.unseal()
    _extend(soft_tpm)
    with pytest.raises(KeyProviderError):
        provider.unseal()
    env = {**os.environ, "TPM2TOOLS_TCTI": soft_tpm, "TSS2_LOG": "all+NONE"}
    for kind in (
        "handles-transient",
        "handles-loaded-session",
        "handles-saved-session",
    ):
        out = subprocess.run(
            ["tpm2_getcap", kind],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            check=True,
        )
        assert out.stdout.strip() == b"", kind


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        (" SHA256:7 ", "sha256:7"),
        ("sha256:0,7,23", "sha256:0,7,23"),
    ],
)
def test_pcr_selections_that_parse(value, expected):
    assert parse_pcrs(value) == expected


@pytest.mark.parametrize(
    "value", ["7", "sha1:7", "sha256:24", "sha256:", "sha256:7,7", "sha256:7;rm"]
)
def test_pcr_selections_that_are_rejected(value):
    with pytest.raises(KeyProviderError, match="PCR"):
        parse_pcrs(value)


def test_cli_takes_pcrs_from_the_flag_or_environment(soft_tpm, tmp_path, capsys):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    bundle = _bundle(tmp_path, key)
    secret = tmp_path / "pass"
    secret.write_bytes(PASS)
    env = {
        "NGARI_DATA_DIR": str(tmp_path / "data"),
        "NGARI_TPM_TCTI": soft_tpm,
        "NGARI_TPM_PCRS": DEBUG_PCR,
    }
    args = ["restore", "--bundle", str(bundle), "--passphrase-file", str(secret)]
    assert keys_cli.cli(args, env) == 0
    provider = TPMKeyProvider(store / "keys", tcti=soft_tpm)
    assert provider.pcrs() == DEBUG_PCR
    assert keys_cli.cli([*args, "--pcrs", "none"], env) == 0
    assert provider.pcrs() is None
    assert keys_cli.cli([*args, "--pcrs", "sha256:99"], env) == 1
    assert "PCR selection" in capsys.readouterr().err


# -- a PCR bank the TPM has not allocated ---------------------------------------------


def _without_sha256(monkeypatch):
    real = TPMKeyProvider.identity

    def identity(self):
        facts = real(self)
        facts["pcr_banks"] = ["sha1"]
        return facts

    monkeypatch.setattr(TPMKeyProvider, "identity", identity)


def test_restore_with_pcrs_stops_before_sealing_on_a_tpm_without_the_bank(
    soft_tpm, tmp_path, monkeypatch
):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    _without_sha256(monkeypatch)
    with pytest.raises(MigrationError) as caught:
        restore(
            store, {"NGARI_TPM_TCTI": soft_tpm}, _bundle(tmp_path, key), PASS, DEBUG_PCR
        )
    assert str(caught.value) == (
        "the TPM has no allocated sha256 PCR bank, so a sha256 PCR policy cannot be used "
        "(allocated: sha1). Nothing was changed."
    )
    assert sorted(p.name for p in (store / "keys").iterdir()) == []


def test_rebinding_an_existing_seal_stops_the_same_way(soft_tpm, tmp_path, monkeypatch):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    restore(store, env, _bundle(tmp_path, key), PASS)
    sealed = store / "keys" / "master.key.sealed"
    before = sealed.read_bytes()
    _without_sha256(monkeypatch)
    with pytest.raises(MigrationError, match="no allocated sha256 PCR bank"):
        restore(store, env, _bundle(tmp_path, key), PASS, DEBUG_PCR)
    assert sealed.read_bytes() == before


def test_restore_without_pcrs_does_not_ask_the_tpm_for_banks(
    soft_tpm, tmp_path, monkeypatch
):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    monkeypatch.setattr(
        TPMKeyProvider, "identity", lambda self: pytest.fail("identity was read")
    )
    restore(store, {"NGARI_TPM_TCTI": soft_tpm}, _bundle(tmp_path, key), PASS)
    assert (store / "keys" / "master.key.sealed").exists()


def test_the_cli_reports_the_missing_bank(soft_tpm, tmp_path, monkeypatch, capsys):
    key = Fernet.generate_key()
    _store(tmp_path, key)
    secret = tmp_path / "pass"
    secret.write_bytes(PASS)
    _without_sha256(monkeypatch)
    env = {"NGARI_DATA_DIR": str(tmp_path / "data"), "NGARI_TPM_TCTI": soft_tpm}
    argv = ["restore", "--bundle", str(_bundle(tmp_path, key)), "--passphrase-file",
            str(secret), "--pcrs", DEBUG_PCR]  # fmt: skip
    assert keys_cli.cli(argv, env) == 1
    assert (
        "restore: the TPM has no allocated sha256 PCR bank" in capsys.readouterr().err
    )


@pytest.mark.parametrize(
    ("pcrs", "banks", "expected"),
    [(None, [], None), ("sha256:7", ["sha1", "sha256"], None),
     ("sha256:7", [], ("the TPM has no allocated sha256 PCR bank, so a sha256 PCR "
                       "policy cannot be used (allocated: none)"))],
)  # fmt: skip
def test_missing_pcr_bank(pcrs, banks, expected):
    from core.kernel.data_plane.tpm import missing_pcr_bank

    assert missing_pcr_bank(pcrs, banks) == expected
