"""Two guards on the master key: the file provider never creates a key
beside a sealed one, and keys restore never leaves the store without a
sealed file, so an interrupted restore or a kernel starting meanwhile
cannot end in a new key."""

import datetime
import os

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import SovereignDataPlane, keys_cli
from core.kernel.data_plane.keys import (
    FileKeyProvider,
    KeyNotProvisionedError,
    KeyProviderError,
)
from core.kernel.data_plane.keys_cli import MigrationError, restore
from core.kernel.data_plane.recovery import wrap
from core.kernel.data_plane.tpm import TPMKeyProvider

PASS = b"correct horse battery staple"


@pytest.fixture
def keys_dir(tmp_path):
    keys = tmp_path / "sovereign" / "keys"
    keys.mkdir(parents=True)
    return keys


def _files(keys_dir):
    return {p.name: p.read_bytes() for p in keys_dir.iterdir()}


# -- the file provider beside a sealed key -------------------------------------------


def test_the_file_provider_refuses_to_create_a_key_beside_a_sealed_one(
    soft_tpm, keys_dir
):
    TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    before = _files(keys_dir)
    with pytest.raises(KeyProviderError) as caught:
        FileKeyProvider(keys_dir / "master.key").load_or_create()
    assert "Refusing to create a second key" in str(caught.value)
    assert "NGARI_KEY_PROVIDER=tpm2" in str(caught.value)
    assert _files(keys_dir) == before
    with pytest.raises(KeyNotProvisionedError):
        FileKeyProvider(keys_dir / "master.key").load_or_create(may_create=False)


def test_a_data_plane_without_the_provider_setting_stops_on_a_tpm2_store(
    soft_tpm, tmp_path, monkeypatch
):
    # A store on tpm2 with no data stored yet, as right after an install:
    # the guard that counts encrypted files has nothing to go on.
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    monkeypatch.setenv("NGARI_TPM_TCTI", soft_tpm)
    store = tmp_path / "sovereign"
    SovereignDataPlane(str(store))
    before = _files(store / "keys")
    assert list(before) == ["master.key.sealed"]
    monkeypatch.delenv("NGARI_KEY_PROVIDER")
    with pytest.raises(KeyProviderError, match="Refusing to create a second key"):
        SovereignDataPlane(str(store))
    assert _files(store / "keys") == before
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    SovereignDataPlane(str(store)).store_encrypted("k", {"v": 1})
    assert _files(store / "keys") == before


def test_a_plaintext_key_beside_a_sealed_one_still_loads(soft_tpm, keys_dir):
    # The state after keys migrate, before the operator removes master.key.
    key = Fernet.generate_key()
    (keys_dir / "master.key").write_bytes(key)
    (keys_dir / "master.key").chmod(0o600)
    TPMKeyProvider(keys_dir, tcti=soft_tpm).seal(key)
    assert FileKeyProvider(keys_dir / "master.key").load_or_create() == key


# -- restore never leaves the store without a sealed file -----------------------------


def _unusable_store(tmp_path, soft_tpm):
    key = Fernet.generate_key()
    store = tmp_path / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    (store / "encrypted" / "a.enc").write_bytes(Fernet(key).encrypt(b"held"))
    TPMKeyProvider(store / "keys", tcti=soft_tpm).seal(key)  # unusable on other_tpm
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(wrap(key, PASS))
    return store, key, bundle


def test_the_old_sealed_file_stays_in_place_until_the_new_one_is_proven(
    soft_tpm, other_tpm, tmp_path, monkeypatch
):
    store, key, bundle = _unusable_store(tmp_path, soft_tpm)
    sealed = store / "keys" / "master.key.sealed"
    old = sealed.read_bytes()
    seen = {}
    real = TPMKeyProvider._publish_over

    def publish(self, data):
        aside = next(p for p in sealed.parent.iterdir() if ".unusable-" in p.name)
        seen.update(sealed=sealed.read_bytes(), same=os.path.samefile(sealed, aside))
        return real(self, data)

    monkeypatch.setattr(TPMKeyProvider, "_publish_over", publish)
    lines = restore(store, {"NGARI_TPM_TCTI": other_tpm}, bundle, PASS)
    assert seen == {"sealed": old, "same": True}  # the old blob, under both names
    [aside] = [p for p in sealed.parent.iterdir() if ".unusable-" in p.name]
    assert aside.read_bytes() == old and sealed.read_bytes() != old
    assert TPMKeyProvider(store / "keys", tcti=other_tpm).unseal() == key
    assert any("kept as" in line for line in lines)


def test_an_interrupted_restore_leaves_the_store_failing_closed(
    soft_tpm, other_tpm, tmp_path, monkeypatch
):
    store, key, bundle = _unusable_store(tmp_path, soft_tpm)
    keys = store / "keys"
    before = _files(keys)

    def interrupted(self, data):
        raise KeyboardInterrupt

    monkeypatch.setattr(TPMKeyProvider, "_publish_over", interrupted)
    with pytest.raises(KeyboardInterrupt):
        restore(store, {"NGARI_TPM_TCTI": other_tpm}, bundle, PASS)
    assert _files(keys) == before  # the old sealed file, and nothing else
    monkeypatch.undo()
    # A kernel starting at this point fails closed on the old blob: no new key.
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    monkeypatch.setenv("NGARI_TPM_TCTI", other_tpm)
    with pytest.raises(KeyProviderError, match="different TPM owner hierarchy"):
        SovereignDataPlane(str(store))
    assert _files(keys) == before
    # And the restore can be run again.
    restore(store, {"NGARI_TPM_TCTI": other_tpm}, bundle, PASS)
    assert (
        SovereignDataPlane(str(store)).retrieve_decrypted("a") is None
    )  # not stored by the plane
    assert TPMKeyProvider(keys, tcti=other_tpm).unseal() == key


def test_a_leftover_link_from_an_interrupted_run_is_reused(
    soft_tpm, other_tpm, tmp_path, monkeypatch
):
    store, key, bundle = _unusable_store(tmp_path, soft_tpm)
    sealed = store / "keys" / "master.key.sealed"

    class Fixed(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 29, 3, 0, 0, tzinfo=tz)

    monkeypatch.setattr(keys_cli, "datetime", Fixed)
    aside = sealed.with_name("master.key.sealed.unusable-20261029T030000Z")
    os.link(sealed, aside)  # what a run killed after the link leaves
    restore(store, {"NGARI_TPM_TCTI": other_tpm}, bundle, PASS)
    assert TPMKeyProvider(store / "keys", tcti=other_tpm).unseal() == key
    assert not os.path.samefile(sealed, aside)


def test_a_different_file_under_the_set_aside_name_stops_the_restore(
    soft_tpm, other_tpm, tmp_path, monkeypatch
):
    store, _key, bundle = _unusable_store(tmp_path, soft_tpm)
    sealed = store / "keys" / "master.key.sealed"

    class Fixed(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 29, 3, 0, 0, tzinfo=tz)

    monkeypatch.setattr(keys_cli, "datetime", Fixed)
    sealed.with_name("master.key.sealed.unusable-20261029T030000Z").write_text("other")
    before = _files(store / "keys")
    with pytest.raises(MigrationError, match="already exists"):
        restore(store, {"NGARI_TPM_TCTI": other_tpm}, bundle, PASS)
    assert _files(store / "keys") == before


# -- seal_over keeps the old blob, whoever calls it ------------------------------------


def test_seal_over_never_replaces_another_file_under_the_old_name(
    soft_tpm, other_tpm, tmp_path
):
    store, key, _ = _unusable_store(tmp_path, soft_tpm)
    keys = store / "keys"
    kept = keys / "master.key.sealed.unusable-x"
    kept.write_bytes(b"someone else's file")
    before = _files(keys)
    with pytest.raises(KeyProviderError, match="unusable-x already exists"):
        TPMKeyProvider(keys, tcti=other_tpm).seal_over(key, None, kept)
    assert _files(keys) == before
    assert TPMKeyProvider(keys, tcti=soft_tpm).unseal() == key  # still the old blob


def test_seal_over_stops_when_the_old_blob_cannot_be_kept(
    soft_tpm, other_tpm, tmp_path, monkeypatch
):
    store, key, _ = _unusable_store(tmp_path, soft_tpm)
    keys = store / "keys"
    before = _files(keys)

    def no_links(src, dst, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "link", no_links)
    with pytest.raises(
        KeyProviderError, match="cannot keep .*: Operation not permitted"
    ):
        TPMKeyProvider(keys, tcti=other_tpm).seal_over(
            key, None, keys / "master.key.sealed.unusable-x"
        )
    monkeypatch.undo()
    assert _files(keys) == before
    assert TPMKeyProvider(keys, tcti=soft_tpm).unseal() == key


def test_seal_over_reuses_its_own_link_to_the_old_blob(soft_tpm, other_tpm, tmp_path):
    store, key, _ = _unusable_store(tmp_path, soft_tpm)
    keys = store / "keys"
    sealed, kept = keys / "master.key.sealed", keys / "master.key.sealed.unusable-x"
    old = sealed.read_bytes()
    os.link(sealed, kept)  # what an interrupted run leaves
    TPMKeyProvider(keys, tcti=other_tpm).seal_over(key, None, kept)
    assert kept.read_bytes() == old and sealed.read_bytes() != old
    assert TPMKeyProvider(keys, tcti=other_tpm).unseal() == key
