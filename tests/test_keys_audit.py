"""keys migrate, export-recovery and restore record what they changed in
the audit chain, keyed from the key they used, with no key material, and
record nothing when they change nothing or fail."""

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import audit_key, check_audit_chain
from core.kernel.data_plane.keys import KeyProviderError
from core.kernel.data_plane.keys_cli import (
    MigrationError,
    export_recovery,
    migrate,
    restore,
)
from core.kernel.data_plane.recovery import wrap

PASS = b"correct horse battery staple"
DEBUG_PCR = "sha256:16"


def _store(tmp_path, key, name="data"):
    store = tmp_path / name / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    (store / "encrypted" / "a.enc").write_bytes(Fernet(key).encrypt(b"held"))
    return store


def _entries(store):
    import json

    log = store / "audit" / "sovereign_audit.log"
    return (
        [json.loads(line) for line in log.read_text().splitlines()]
        if log.exists()
        else []
    )


def _keyed_and_clean(store, key, *secrets):
    log = store / "audit" / "sovereign_audit.log"
    assert check_audit_chain(log, audit_key(key)) is None
    text = log.read_bytes()
    for secret in (key, *secrets):
        assert secret not in text


def test_a_migration_is_recorded_once(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    (store / "keys" / "master.key").write_bytes(key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    migrate(store, env, actor="ab12")
    migrate(store, env, actor="ab12")  # already sealed: nothing changes
    [entry] = _entries(store)
    assert (entry["action"], entry["actor"], entry["resource"]) == (
        "key_migrated",
        "ab12",
        "tpm2",
    )
    assert entry["details"] == {"tcti": soft_tpm}
    assert "mac" in entry
    _keyed_and_clean(store, key)


def test_an_export_is_recorded_with_its_path_and_no_passphrase(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    (store / "keys" / "master.key").write_bytes(key)
    out = tmp_path / "bundle.json"
    export_recovery(store, {"NGARI_TPM_TCTI": soft_tpm}, out, PASS)
    [entry] = _entries(store)
    assert (entry["action"], entry["actor"], entry["resource"]) == (
        "recovery_exported", "local", str(out)
    )  # fmt: skip
    _keyed_and_clean(store, key, PASS)


def test_a_restore_is_recorded_and_a_repeat_is_not(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(key, PASS))
    env = {"NGARI_TPM_TCTI": soft_tpm}
    restore(store, env, bundle, PASS)
    restore(store, env, bundle, PASS)  # already holds this key: nothing changes
    restore(store, env, bundle, PASS, DEBUG_PCR)  # rebinds to PCRs
    first, rebind = _entries(store)
    assert first["action"] == rebind["action"] == "key_restored"
    assert first["details"] == {"pcrs": None, "rebound": False, "set_aside": None}
    assert rebind["details"] == {"pcrs": DEBUG_PCR, "rebound": True, "set_aside": None}
    _keyed_and_clean(store, key, PASS)


def test_a_restore_onto_another_tpm_names_the_file_it_set_aside(
    soft_tpm, other_tpm, tmp_path
):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(key, PASS))
    restore(store, {"NGARI_TPM_TCTI": soft_tpm}, bundle, PASS)
    restore(store, {"NGARI_TPM_TCTI": other_tpm}, bundle, PASS)
    last = _entries(store)[-1]
    assert last["action"] == "key_restored"
    assert last["details"]["set_aside"].startswith("master.key.sealed.unusable-")
    assert (store / "keys" / last["details"]["set_aside"]).exists()


def test_a_failed_command_records_nothing(soft_tpm, tmp_path):
    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(key, PASS))
    with pytest.raises(KeyProviderError, match="passphrase is wrong"):
        restore(store, {"NGARI_TPM_TCTI": soft_tpm}, bundle, b"the wrong passphrase!!")
    with pytest.raises(MigrationError):
        migrate(store, {"NGARI_TPM_TCTI": soft_tpm})  # no master.key to migrate
    assert _entries(store) == []


def test_the_kernel_still_verifies_the_chain_after_key_commands(
    soft_tpm, tmp_path, monkeypatch
):
    from core.kernel.data_plane import SovereignDataPlane

    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    (store / "keys" / "master.key").write_bytes(key)
    env = {"NGARI_TPM_TCTI": soft_tpm}
    migrate(store, env)
    export_recovery(store, env, tmp_path / "bundle.json", PASS)
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    monkeypatch.setenv("NGARI_TPM_TCTI", soft_tpm)
    plane = SovereignDataPlane(str(store))
    assert plane.verify_audit_integrity()
    assert [e["action"] for e in plane.get_audit_log(10)] == [
        "key_migrated", "recovery_exported", "key_provider"
    ]  # fmt: skip


# -- a stale sealed file beside a master.key that still works -------------------------


def _board_swapped_store(tmp_path, old_tpm, with_data=True):
    from core.kernel.data_plane.tpm import TPMKeyProvider

    key = Fernet.generate_key()
    store = _store(tmp_path, key)
    if not with_data:
        (store / "encrypted" / "a.enc").unlink()
    (store / "keys" / "master.key").write_bytes(key)
    (store / "keys" / "master.key").chmod(0o600)
    TPMKeyProvider(store / "keys", tcti=old_tpm).seal(key)  # sealed on the old board
    return store, key


def test_export_uses_master_key_when_the_sealed_file_is_from_another_board(
    soft_tpm, other_tpm, tmp_path
):
    store, key = _board_swapped_store(tmp_path, soft_tpm)
    out = tmp_path / "bundle.json"
    lines = export_recovery(store, {"NGARI_TPM_TCTI": other_tpm}, out, PASS)
    assert (
        "cannot be unsealed on this TPM, so the key is master.key, which decrypts a.enc"
        in lines[0]
    )
    from core.kernel.data_plane.recovery import unwrap

    assert unwrap(out.read_bytes(), PASS) == key
    assert _entries(store)[-1]["action"] == "recovery_exported"
    _keyed_and_clean(store, key, PASS)


def test_the_fallback_is_refused_when_master_key_does_not_decrypt_the_data(
    soft_tpm, other_tpm, tmp_path
):
    store, _ = _board_swapped_store(tmp_path, soft_tpm)
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())  # some other key
    with pytest.raises(KeyProviderError, match="different TPM owner hierarchy"):
        export_recovery(store, {"NGARI_TPM_TCTI": other_tpm}, tmp_path / "b.json", PASS)
    assert not (tmp_path / "b.json").exists() and _entries(store) == []


def test_the_fallback_is_refused_with_no_data_to_prove_the_key_against(
    soft_tpm, other_tpm, tmp_path
):
    store, _ = _board_swapped_store(tmp_path, soft_tpm, with_data=False)
    with pytest.raises(KeyProviderError, match="different TPM owner hierarchy"):
        export_recovery(store, {"NGARI_TPM_TCTI": other_tpm}, tmp_path / "b.json", PASS)
    assert not (tmp_path / "b.json").exists()


def test_without_master_key_the_stale_sealed_file_still_stops_the_export(
    soft_tpm, other_tpm, tmp_path
):
    store, _ = _board_swapped_store(tmp_path, soft_tpm)
    (store / "keys" / "master.key").unlink()
    with pytest.raises(KeyProviderError, match="different TPM owner hierarchy"):
        export_recovery(store, {"NGARI_TPM_TCTI": other_tpm}, tmp_path / "b.json", PASS)


def test_a_sealed_file_that_unseals_is_still_the_key_and_a_difference_still_stops(
    soft_tpm, tmp_path
):
    store, _key = _board_swapped_store(tmp_path, soft_tpm)
    lines = export_recovery(
        store, {"NGARI_TPM_TCTI": soft_tpm}, tmp_path / "b.json", PASS
    )
    assert not any("cannot be unsealed" in line for line in lines)
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    with pytest.raises(MigrationError, match="hold different keys"):
        export_recovery(store, {"NGARI_TPM_TCTI": soft_tpm}, tmp_path / "c.json", PASS)
