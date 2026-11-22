"""TPM 2.0 key provider, against an in-process software TPM (libtpms TCTI).

Never the hardware chip: every TPM here is a state file in tmp_path. Tests that
need the simulator skip when tpm2-tools or the libtpms TCTI are missing, and
NGARI_REQUIRE_TPM_SIM=1 (set in CI) turns that skip into a failure.
"""

import base64
import json
import logging
import os
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import KeyProviderError, SovereignDataPlane
from core.kernel.data_plane import tpm as tpm_mod
from core.kernel.data_plane.keys import (
    KeyNotProvisionedError,
    create_provider,
    provider_from_env,
    validate_key,
)
from core.kernel.data_plane.tpm import TPMKeyProvider, resource_managed


@pytest.fixture
def keys_dir(tmp_path):
    path = tmp_path / "keys"
    path.mkdir()
    return path


def _tcti_dir(tcti: str) -> Path:
    """The directory a TCTI's state lives in: a libtpms state file or a swtpm
    socket path (swtpm:path=...). The tools drop NVChip in cwd."""
    spec = tcti.partition(":")[2]
    spec = spec.removeprefix("path=")
    return Path(spec).parent


def _transient_handles(tcti: str) -> str:
    env = {**os.environ, "TPM2TOOLS_TCTI": tcti, "TSS2_LOG": "all+NONE"}
    run = subprocess.run(
        ["tpm2_getcap", "handles-transient"],
        cwd=_tcti_dir(tcti),
        env=env,
        capture_output=True,
        check=True,
    )
    return run.stdout.decode().strip()


# -- with a software TPM -----------------------------------------------------


def test_a_sealed_key_unseals_to_the_same_key(soft_tpm, keys_dir):
    first = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    key = first.load_or_create()
    assert validate_key(key) == key
    token = Fernet(key).encrypt(b"sovereign")

    again = TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create(may_create=False)
    assert again == key
    assert Fernet(again).decrypt(token) == b"sovereign"
    assert [p.name for p in keys_dir.iterdir()] == ["master.key.sealed"]
    assert stat.S_IMODE((keys_dir / "master.key.sealed").stat().st_mode) == 0o600


def test_the_sealed_file_holds_no_key_bytes(soft_tpm, keys_dir):
    key = TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    raw = (keys_dir / "master.key.sealed").read_bytes()
    blob = json.loads(raw)
    assert set(blob) == {"version", "parent", "pub", "priv"}
    for form in (key, base64.urlsafe_b64decode(key)):
        assert form not in raw
        assert form not in base64.b64decode(blob["pub"])
        assert form not in base64.b64decode(blob["priv"])


def test_the_parent_is_the_same_on_every_use(soft_tpm, keys_dir):
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    names = []
    for _ in range(2):
        with provider._session() as run:
            names.append(provider._primary(run))
    assert names[0] == names[1]
    provider.load_or_create()
    blob = json.loads((keys_dir / "master.key.sealed").read_text())
    assert blob["parent"] == names[0]


def test_no_transient_objects_are_left_in_the_tpm(soft_tpm, keys_dir):
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    for _ in range(5):  # without flushing, the fourth load runs out of slots
        provider.load_or_create()
    assert _transient_handles(soft_tpm) == ""


def test_a_plaintext_key_beside_it_is_never_replaced(soft_tpm, keys_dir):
    plain = keys_dir / "master.key"
    original = Fernet.generate_key()
    plain.write_bytes(original)
    with pytest.raises(KeyProviderError, match="plaintext key exists") as caught:
        TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    assert original.decode() not in str(caught.value)
    assert plain.read_bytes() == original
    assert [p.name for p in keys_dir.iterdir()] == ["master.key"]


def test_without_permission_to_create_nothing_is_sealed(soft_tpm, keys_dir):
    with pytest.raises(KeyNotProvisionedError):
        TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create(may_create=False)
    assert list(keys_dir.iterdir()) == []


def test_the_data_plane_refuses_a_new_sealed_key_over_existing_data(soft_tpm, tmp_path):
    data_dir = tmp_path / "data"
    (data_dir / "encrypted").mkdir(parents=True)
    (data_dir / "encrypted" / "old.enc").write_bytes(b"written under another key")
    (data_dir / "keys").mkdir()
    provider = TPMKeyProvider(data_dir / "keys", tcti=soft_tpm)
    with pytest.raises(KeyProviderError, match="Refusing to create a new key"):
        SovereignDataPlane(data_dir=str(data_dir), key_provider=provider)
    assert list((data_dir / "keys").iterdir()) == []


def _tamper_priv(blob):
    priv = bytearray(base64.b64decode(blob["priv"]))
    priv[-1] ^= 0x01
    blob["priv"] = base64.b64encode(bytes(priv)).decode()


def _truncate_priv(blob):
    blob["priv"] = base64.b64encode(base64.b64decode(blob["priv"])[:20]).decode()


def _swap_pub(blob):
    pub = bytearray(base64.b64decode(blob["pub"]))
    pub[-1] ^= 0x01
    blob["pub"] = base64.b64encode(bytes(pub)).decode()


@pytest.mark.parametrize(
    "damage",
    [
        _tamper_priv,
        _truncate_priv,
        _swap_pub,
        lambda blob: blob.update(version=2),
        lambda blob: blob.update(priv="not base64!"),
        lambda blob: blob.pop("pub"),
    ],
    ids=["flipped-priv", "truncated-priv", "flipped-pub", "version", "b64", "field"],
)
def test_a_damaged_sealed_file_fails_closed_and_is_left_alone(
    soft_tpm, keys_dir, damage
):
    key = TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    sealed = keys_dir / "master.key.sealed"
    blob = json.loads(sealed.read_text())
    damage(blob)
    damaged = json.dumps(blob).encode()
    sealed.write_bytes(damaged)

    for may_create in (True, False):
        with pytest.raises(KeyProviderError) as caught:
            TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create(
                may_create=may_create
            )
        assert key.decode() not in str(caught.value)
    assert sealed.read_bytes() == damaged
    assert [p.name for p in keys_dir.iterdir()] == ["master.key.sealed"]
    assert _transient_handles(soft_tpm) == ""


def test_an_unreadable_sealed_file_fails_closed(soft_tpm, keys_dir):
    (keys_dir / "master.key.sealed").write_bytes(b"\x00not json")
    with pytest.raises(KeyProviderError, match="not a valid sealed key"):
        TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()


def test_a_key_sealed_by_another_tpm_does_not_unseal(soft_tpm, other_tpm, keys_dir):
    TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    sealed = keys_dir / "master.key.sealed"
    before = sealed.read_bytes()
    with pytest.raises(KeyProviderError, match="different TPM owner hierarchy"):
        TPMKeyProvider(keys_dir, tcti=other_tpm).load_or_create()
    assert sealed.read_bytes() == before


def test_a_forged_parent_name_still_fails_at_load(soft_tpm, other_tpm, keys_dir):
    TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    other = TPMKeyProvider(keys_dir, tcti=other_tpm)
    with other._session() as run:
        other_parent = other._primary(run)
    sealed = keys_dir / "master.key.sealed"
    blob = json.loads(sealed.read_text())
    blob["parent"] = other_parent
    sealed.write_text(json.dumps(blob))
    with pytest.raises(KeyProviderError, match="tpm2_load failed"):
        other.load_or_create()
    assert _transient_handles(other_tpm) == ""


def test_the_loser_of_a_provisioning_race_uses_the_winners_key(
    soft_tpm, keys_dir, monkeypatch
):
    winner = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    real_publish = tpm_mod.publish_new_file
    winners_key = []

    def lose_the_race(path, data):
        monkeypatch.setattr(tpm_mod, "publish_new_file", real_publish)
        winners_key.append(winner.load_or_create())
        return real_publish(path, data)

    monkeypatch.setattr(tpm_mod, "publish_new_file", lose_the_race)
    loser_key = TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    assert loser_key == winners_key[0]
    assert TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create() == loser_key


def test_the_data_plane_runs_on_a_sealed_key(soft_tpm, tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    monkeypatch.setenv("NGARI_TPM_TCTI", soft_tpm)
    data_dir = tmp_path / "data"
    plane = SovereignDataPlane(data_dir=str(data_dir))
    assert plane.key_provider.name == "tpm2"
    plane.store_encrypted("note", {"n": 1})
    assert not (data_dir / "keys" / "master.key").exists()

    restarted = SovereignDataPlane(data_dir=str(data_dir))
    assert restarted.retrieve_decrypted("note") == {"n": 1}
    report = restarted.export_compliance_report()
    assert report["key_provider"]["ok"] is True
    assert report["data_sovereignty"] == "enforced"
    starts = [
        e for e in restarted.get_audit_log(10**9) if e["action"] == "key_provider"
    ]
    assert [e["resource"] for e in starts] == ["tpm2", "tpm2"]
    assert starts[-1]["details"] == {
        "hardware_bound": False, "ok": True, "air_gap": True
    }  # fmt: skip


def test_describe_reports_a_leftover_plaintext_key(soft_tpm, keys_dir):
    TPMKeyProvider(keys_dir, tcti=soft_tpm).load_or_create()
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    assert provider.describe()["ok"] is False  # sealed, but not unsealed by it
    provider.load_or_create()
    facts = provider.describe()
    assert facts["ok"] is True
    assert facts["sealed_file_mode"] == "0o600"
    assert facts["hardware_bound"] is False

    (keys_dir / "master.key").write_bytes(Fernet.generate_key())
    facts = provider.describe()
    assert facts["plaintext_key_present"] is True
    assert facts["ok"] is False


def test_describe_is_not_ok_when_the_sealed_file_is_readable_by_others(
    soft_tpm, keys_dir
):
    # KEY_PROVIDERS.md: ok only when the sealed file is mode 0600, this
    # process has unsealed it and no plaintext key is beside it. This test
    # holds describe() to the mode.
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    provider.load_or_create()
    assert provider.describe()["ok"] is True
    sealed = keys_dir / "master.key.sealed"
    for mode in (0o644, 0o640, 0o604, 0o700):
        os.chmod(sealed, mode)
        facts = provider.describe()
        assert (facts["sealed_file_mode"], facts["ok"]) == (oct(mode), False)
    os.chmod(sealed, 0o600)
    assert provider.describe()["ok"] is True


def test_nothing_about_the_key_reaches_the_log(soft_tpm, keys_dir, caplog):
    caplog.set_level(logging.DEBUG)
    provider = TPMKeyProvider(keys_dir, tcti=soft_tpm)
    key = provider.load_or_create()
    assert key.decode() not in caplog.text
    assert key.decode() not in repr(provider)
    assert key.decode() not in json.dumps(provider.describe())


# -- with fake tools ---------------------------------------------------------


def _fake_tools(directory: Path, scripts: dict) -> str:
    directory.mkdir()
    for tool in tpm_mod.TOOLS:
        body = scripts.get(tool, "exit 0")
        path = directory / tool
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    return f"{directory}:/usr/bin:/bin"  # fakes shadow the real tools


def test_missing_tpm2_tools_give_an_actionable_error(keys_dir, tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(KeyProviderError, match="tpm2-tools"):
        TPMKeyProvider(keys_dir, tcti="libtpms:/nonexistent").load_or_create()
    assert list(keys_dir.iterdir()) == []


def test_a_hung_tpm_times_out_and_creates_nothing(keys_dir, tmp_path, monkeypatch):
    bin_dir = _fake_tools(tmp_path / "bin", {"tpm2_createprimary": "exec sleep 30"})
    monkeypatch.setenv("PATH", bin_dir)
    provider = TPMKeyProvider(keys_dir, tcti="device:/dev/tpmrm0", timeout=0.5)
    with pytest.raises(KeyProviderError, match="did not finish within 0.5s"):
        provider.load_or_create()
    assert list(keys_dir.iterdir()) == []


def test_a_tool_that_echoes_the_key_does_not_leak_it(keys_dir, tmp_path, monkeypatch):
    bin_dir = _fake_tools(
        tmp_path / "bin",
        {
            "tpm2_readpublic": "printf 'name' > primary.name",
            "tpm2_create": "printf 'ERROR: bad input: ' >&2; cat >&2; exit 1",
        },
    )
    monkeypatch.setenv("PATH", bin_dir)
    seen = []
    real = Fernet.generate_key

    def spy():
        seen.append(real())
        return seen[-1]

    monkeypatch.setattr(tpm_mod.Fernet, "generate_key", staticmethod(spy))
    with pytest.raises(KeyProviderError, match="tpm2_create failed") as caught:
        TPMKeyProvider(keys_dir, tcti="device:/dev/tpmrm0").load_or_create()
    assert seen and seen[0].decode() not in str(caught.value)
    assert "[key]" in str(caught.value)
    assert list(keys_dir.iterdir()) == []


_SEALING_TOOLS = {
    "tpm2_readpublic": "printf 'name' > primary.name",
    "tpm2_create": "cat > /dev/null; printf pub > sealed.pub; printf priv > sealed.priv",
}


def test_a_key_that_does_not_unseal_identically_is_never_published(
    keys_dir, tmp_path, monkeypatch
):
    other = Fernet.generate_key().decode()
    bin_dir = _fake_tools(
        tmp_path / "bin", {**_SEALING_TOOLS, "tpm2_unseal": f"printf '%s' '{other}'"}
    )
    monkeypatch.setenv("PATH", bin_dir)
    with pytest.raises(KeyProviderError, match="did not unseal to the same key"):
        TPMKeyProvider(keys_dir, tcti="device:/dev/tpmrm0").load_or_create()
    assert list(keys_dir.iterdir()) == []


def test_unsealed_bytes_that_are_not_a_key_are_rejected(
    keys_dir, tmp_path, monkeypatch
):
    blob = {
        "version": 1,
        "parent": b"name".hex(),
        "pub": base64.b64encode(b"pub").decode(),
        "priv": base64.b64encode(b"priv").decode(),
    }
    (keys_dir / "master.key.sealed").write_text(json.dumps(blob))
    bin_dir = _fake_tools(
        tmp_path / "bin", {**_SEALING_TOOLS, "tpm2_unseal": "printf 'short'"}
    )
    monkeypatch.setenv("PATH", bin_dir)
    with pytest.raises(KeyProviderError, match="not a valid Fernet key"):
        TPMKeyProvider(keys_dir, tcti="device:/dev/tpmrm0").load_or_create()


def test_an_explicit_tcti_overrides_the_callers_environment(
    keys_dir, tmp_path, monkeypatch
):
    bin_dir = _fake_tools(
        tmp_path / "bin",
        {"tpm2_createprimary": 'echo "ERROR: tcti=$TPM2TOOLS_TCTI" >&2; exit 1'},
    )
    monkeypatch.setenv("PATH", bin_dir)
    monkeypatch.setenv("TPM2TOOLS_TCTI", "device:/dev/tpm0")
    with pytest.raises(KeyProviderError, match=r"tcti=libtpms:/x\b"):
        TPMKeyProvider(keys_dir, tcti="libtpms:/x").load_or_create()


# -- configuration -----------------------------------------------------------


def test_the_registry_builds_a_tpm2_provider_from_the_environment(keys_dir):
    env = {"NGARI_KEY_PROVIDER": "tpm2", "NGARI_TPM_TCTI": "swtpm:port=2321"}
    provider = provider_from_env(keys_dir, env)
    assert isinstance(provider, TPMKeyProvider)
    assert provider.tcti == "swtpm:port=2321"
    assert provider.timeout == 30.0
    assert create_provider("tpm2", keys_dir, {}).tcti == "device:/dev/tpmrm0"


@pytest.mark.parametrize("raw", ["0", "-1", "soon", "nan", "inf"])
def test_a_bad_timeout_is_rejected(keys_dir, raw):
    with pytest.raises(KeyProviderError, match="NGARI_TPM_TIMEOUT"):
        TPMKeyProvider.from_env(keys_dir, {"NGARI_TPM_TIMEOUT": raw})


def test_a_timeout_can_be_set(keys_dir):
    assert (
        TPMKeyProvider.from_env(keys_dir, {"NGARI_TPM_TIMEOUT": "2.5"}).timeout == 2.5
    )


@pytest.mark.parametrize(
    ("tcti", "managed"),
    [
        ("device:/dev/tpmrm0", True),
        ("device:/dev/tpmrm1", True),
        ("tabrmd:bus_type=system", True),
        ("device:/dev/tpm0", False),
        ("libtpms:/tmp/state", False),
        ("swtpm:port=2321", False),
        ("mssim:host=localhost", False),
    ],
)
def test_only_resource_managed_tctis_skip_the_flush(tcti, managed):
    assert resource_managed(tcti) is managed


def test_sealing_into_a_new_keys_directory_makes_it_owner_only(soft_tpm, tmp_path):
    # keys restore seals into a store that may not exist yet: the directories
    # it makes are 0700 whatever the umask.
    old = os.umask(0o022)
    try:
        keys = tmp_path / "data" / "sovereign" / "keys"
        TPMKeyProvider(keys, tcti=soft_tpm).load_or_create()
    finally:
        os.umask(old)
    for d in (keys, keys.parent, keys.parent.parent):
        assert oct(os.stat(d).st_mode & 0o777) == "0o700", d
