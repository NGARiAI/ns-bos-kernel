"""Failure paths of the tpm2 provider. The rule they serve: a failed write
never leaves the key unrecoverable, and every failure is reported."""

import base64
import errno
import json
import os

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import tpm as tpm_mod
from core.kernel.data_plane.keys import KeyNotProvisionedError, KeyProviderError
from core.kernel.data_plane.tpm import TPMKeyProvider


@pytest.fixture
def keys_dir(tmp_path):
    path = tmp_path / "keys"
    path.mkdir()
    return path


def _fail(*args, **kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


def test_a_failed_reseal_keeps_the_old_sealed_key(soft_tpm, keys_dir, monkeypatch):
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    key, _ = provider.seal(Fernet.generate_key())
    before = provider.sealed_file.read_bytes()
    monkeypatch.setattr(tpm_mod.os, "replace", _fail)
    with pytest.raises(KeyProviderError, match="No space left") as caught:
        provider.reseal(key, "sha256:16")
    assert key.decode() not in str(caught.value)
    monkeypatch.undo()
    assert provider.sealed_file.read_bytes() == before
    assert [p.name for p in keys_dir.iterdir()] == ["master.key.sealed"]
    assert TPMKeyProvider(keys_dir, tcti=soft_tpm).unseal() == key


def test_a_failed_first_seal_leaves_nothing(soft_tpm, keys_dir, monkeypatch):
    monkeypatch.setattr(tpm_mod, "publish_new_file", _fail)
    with pytest.raises(KeyProviderError, match="cannot write"):
        TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    assert list(keys_dir.iterdir()) == []


def test_unseal_without_a_sealed_key_says_so(soft_tpm, keys_dir):
    with pytest.raises(KeyNotProvisionedError, match="no sealed key"):
        TPMKeyProvider(keys_dir, tcti=soft_tpm).unseal()


def test_an_unreadable_sealed_file_fails_closed(soft_tpm, keys_dir, monkeypatch):
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    provider.load_or_create()
    real = type(provider.sealed_file).read_bytes

    def denied(self):
        if self.name == "master.key.sealed":
            raise OSError(errno.EACCES, "Permission denied")
        return real(self)

    monkeypatch.setattr(type(provider.sealed_file), "read_bytes", denied)
    with pytest.raises(KeyProviderError, match="cannot read .*Permission denied"):
        TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    facts = TPMKeyProvider(keys_dir, tcti=soft_tpm).describe()
    assert facts["pcrs"] is None and facts["ok"] is False


@pytest.mark.parametrize("field", ["parent", "pub", "priv"])
def test_an_empty_field_is_not_a_sealed_key(soft_tpm, keys_dir, field):
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    provider.load_or_create()
    blob = json.loads(provider.sealed_file.read_text())
    blob[field] = "" if field == "parent" else base64.b64encode(b"").decode()
    provider.sealed_file.write_text(json.dumps(blob))
    with pytest.raises(KeyProviderError, match="not a valid sealed key"):
        provider.unseal()


def test_describe_without_a_sealed_file(keys_dir):
    facts = TPMKeyProvider(keys_dir, tcti="libtpms:/nowhere").describe()
    assert facts["sealed_file_mode"] is None
    assert facts["ok"] is False


def test_a_tool_that_cannot_start_gives_a_clear_error(keys_dir, tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in tpm_mod.TOOLS:
        path = bin_dir / tool
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o644)  # on PATH but not executable
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setattr(tpm_mod.shutil, "which", lambda name: str(bin_dir / name))
    with pytest.raises(KeyProviderError, match="cannot run tpm2_createprimary"):
        TPMKeyProvider(keys_dir, tcti="device:/dev/tpmrm0").load_or_create()


def test_a_failed_flush_at_the_end_is_reported(keys_dir, tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in tpm_mod.TOOLS:
        body = "exit 1" if tool == "tpm2_flushcontext" else "exit 0"
        (bin_dir / tool).write_text(f"#!/bin/sh\n{body}\n")
        (bin_dir / tool).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    session = tpm_mod._Session("libtpms:/x", 5)  # no resource manager: flushes
    with pytest.raises(KeyProviderError, match="tpm2_flushcontext failed"), session:
        pass
    assert not os.path.exists(session.dir)


# -- a device TCTI that cannot be opened says why ----------------------------------


def _fake_tools(tmp_path, monkeypatch, stderr: str):
    """Every tool the provider needs, failing with stderr. No TPM is used."""
    from core.kernel.data_plane.tpm import TOOLS

    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    for tool in TOOLS:
        script = bin_dir / tool
        script.write_text(f"#!/bin/sh\nprintf '%s\\n' '{stderr}' >&2\nexit 1\n")
        script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))


def test_a_missing_device_is_named(tmp_path, keys_dir, monkeypatch):
    device = tmp_path / "no-such-tpm"
    _fake_tools(
        tmp_path, monkeypatch, f'ERROR: Could not load tcti, got: "device:{device}"'
    )
    with pytest.raises(KeyProviderError) as caught:
        TPMKeyProvider(keys_dir, tcti=f"device:{device}").identity()
    assert str(caught.value) == (
        f"tpm2_getcap failed (TCTI device:{device}): Could not load tcti, got: "
        f'"device:{device}"; {device} does not exist: no TPM is exposed there (in a '
        "container, pass the host's /dev/tpmrm0 through; on a board, enable the TPM or fTPM)"
    )


def test_a_device_this_process_cannot_open_names_owner_group_and_mode(
    tmp_path, monkeypatch
):
    import grp
    import pwd

    device = tmp_path / "tpmrm0"
    device.write_bytes(b"")
    device.chmod(0o660)
    # Readable but not writable: the TCTI needs both.
    monkeypatch.setattr(tpm_mod.os, "access", lambda path, mode: not mode & os.W_OK)
    st = device.stat()
    owner, group = pwd.getpwuid(st.st_uid)[0], grp.getgrgid(st.st_gid)[0]
    assert tpm_mod.device_problem(f"device:{device}") == (
        f"this process (uid {os.getuid()}) cannot open {device} ({owner}:{group}, "
        f"mode 0o660); run the kernel as a user in the {group} group, or as {owner}"
    )


def test_an_openable_device_and_other_tctis_get_no_diagnosis(tmp_path, soft_tpm):
    device = tmp_path / "tpmrm0"
    device.write_bytes(b"")
    assert tpm_mod.device_problem(f"device:{device}") is None
    assert tpm_mod.device_problem(soft_tpm) is None
    assert tpm_mod.device_problem("tabrmd:bus_type=system") is None


def test_a_bare_device_tcti_means_dev_tpm0(monkeypatch):
    # The device TCTI's own default path. Whether or not it exists here, the
    # diagnosis names it.
    monkeypatch.setattr(tpm_mod.os, "access", lambda path, mode: False)
    assert "/dev/tpm0" in tpm_mod.device_problem("device:")


def test_other_tool_errors_are_not_blamed_on_the_device(
    tmp_path, keys_dir, monkeypatch
):
    device = tmp_path / "no-such-tpm"
    _fake_tools(
        tmp_path,
        monkeypatch,
        "ERROR: Esys_CreatePrimary(0x902) - tpm:error(2.0): out of memory",
    )
    with pytest.raises(KeyProviderError) as caught:
        TPMKeyProvider(keys_dir, tcti=f"device:{device}").identity()
    assert "does not exist" not in str(caught.value)
    assert str(caught.value).endswith("out of memory")


def test_an_owner_without_a_name_is_shown_as_its_number():
    def missing(number):
        raise KeyError(number)

    assert tpm_mod._name(missing, 4242) == "4242"
