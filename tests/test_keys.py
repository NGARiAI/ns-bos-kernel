"""Key providers.

The file provider has to match what existing deployments hold on disk. The
data plane must never replace a key while encrypted data exists, and a provider
that fails stops the data plane instead of being worked around.
"""

import errno
import json
import logging
import multiprocessing
import os
import shutil
import stat
import traceback
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import (
    FileKeyProvider,
    KeyProvider,
    KeyProviderError,
    SovereignDataPlane,
    keys,
)
from core.kernel.data_plane.keys import (
    PROVIDER_ENV,
    KeyNotProvisionedError,
    create_provider,
    provider_from_env,
    publish_new_file,
    validate_key,
)

V010 = Path(__file__).parent / "vectors" / "v0.1.0"
V010_PLAINTEXT = {
    "msg": "written by the v0.1.0 data plane",
    "n": 7,
    "nested": {"ok": True},
}


@pytest.fixture(autouse=True)
def _provider_unset(monkeypatch):
    monkeypatch.delenv(PROVIDER_ENV, raising=False)


class MemoryProvider(KeyProvider):
    """Holds its key in memory and reports itself as hardware bound."""

    name = "memory"

    def __init__(self):
        self.key = Fernet.generate_key()
        self.ok = True
        self.may_create_seen = []

    def load_or_create(self, *, may_create=True):
        self.may_create_seen.append(may_create)
        return self.key

    def describe(self):
        return {"provider": self.name, "hardware_bound": True, "ok": self.ok}


class BrokenProvider(KeyProvider):
    name = "broken"

    def load_or_create(self, *, may_create=True):
        raise KeyProviderError("cannot unseal the master key")

    def describe(self):
        return {"provider": self.name, "hardware_bound": True, "ok": False}


class EmptyProvider(KeyProvider):
    """Creates a key on request and has none to give otherwise."""

    name = "empty"

    def load_or_create(self, *, may_create=True):
        if not may_create:
            raise KeyNotProvisionedError("nothing is sealed here")
        return Fernet.generate_key()

    def describe(self):
        return {"provider": self.name, "hardware_bound": True, "ok": True}


def _key_file(base):
    return base / "keys" / "master.key"


def _install_v010_deployment(base):
    keys = base / "keys"
    keys.mkdir(parents=True)
    shutil.copyfile(V010 / "master.key", keys / "master.key")
    os.chmod(keys / "master.key", 0o600)
    (base / "encrypted").mkdir()
    shutil.copyfile(V010 / "greeting.enc", base / "encrypted" / "greeting.enc")


@pytest.mark.part11("11.10(c)")
def test_data_written_by_v0_1_0_opens_through_the_file_provider(tmp_path):
    _install_v010_deployment(tmp_path)
    key_before = _key_file(tmp_path).read_bytes()
    dp = SovereignDataPlane(data_dir=str(tmp_path))
    assert isinstance(dp.key_provider, FileKeyProvider)
    assert dp.retrieve_decrypted("greeting") == V010_PLAINTEXT
    assert _key_file(tmp_path).read_bytes() == key_before


def test_an_existing_key_file_is_left_untouched(tmp_path):
    _install_v010_deployment(tmp_path)
    before = _key_file(tmp_path).stat()
    SovereignDataPlane(data_dir=str(tmp_path))
    after = _key_file(tmp_path).stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode) == (
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_mode,
    )


def test_a_hand_edited_key_file_with_a_trailing_newline_still_works(tmp_path):
    _install_v010_deployment(tmp_path)
    edited = _key_file(tmp_path).read_bytes() + b"\n"
    _key_file(tmp_path).write_bytes(edited)
    dp = SovereignDataPlane(data_dir=str(tmp_path))
    assert dp.retrieve_decrypted("greeting") == V010_PLAINTEXT
    assert _key_file(tmp_path).read_bytes() == edited


def test_a_missing_key_is_not_recreated_while_encrypted_files_exist(tmp_path):
    first = SovereignDataPlane(data_dir=str(tmp_path))
    first.store_encrypted("k", {"v": 1})
    original = _key_file(tmp_path).read_bytes()
    _key_file(tmp_path).unlink()

    with pytest.raises(KeyProviderError, match="Refusing to create a new key"):
        SovereignDataPlane(data_dir=str(tmp_path))
    assert not _key_file(tmp_path).exists()

    _key_file(tmp_path).write_bytes(original)
    os.chmod(_key_file(tmp_path), 0o600)
    restored = SovereignDataPlane(data_dir=str(tmp_path))
    assert restored.retrieve_decrypted("k") == {"v": 1}


def test_an_empty_key_file_is_rejected_and_not_replaced(tmp_path):
    _install_v010_deployment(tmp_path)
    _key_file(tmp_path).write_bytes(b"")
    with pytest.raises(KeyProviderError, match="not a valid Fernet key"):
        SovereignDataPlane(data_dir=str(tmp_path))
    assert _key_file(tmp_path).read_bytes() == b""


def test_only_an_empty_store_lets_a_provider_create_a_key(tmp_path):
    fresh = MemoryProvider()
    SovereignDataPlane(data_dir=str(tmp_path), key_provider=fresh)
    assert fresh.may_create_seen == [True]

    (tmp_path / "encrypted" / "x.enc").write_bytes(b"x")
    stocked = MemoryProvider()
    SovereignDataPlane(data_dir=str(tmp_path), key_provider=stocked)
    assert stocked.may_create_seen == [False]


def test_a_provider_with_no_key_cannot_start_a_store_that_holds_data(tmp_path):
    SovereignDataPlane(data_dir=str(tmp_path), key_provider=EmptyProvider())
    (tmp_path / "encrypted" / "x.enc").write_bytes(b"x")
    with pytest.raises(
        KeyProviderError, match="Refusing to create a new key"
    ) as raised:
        SovereignDataPlane(data_dir=str(tmp_path), key_provider=EmptyProvider())
    assert PROVIDER_ENV in str(raised.value)
    assert "empty" in str(raised.value)


def test_a_failing_provider_stops_the_data_plane_and_leaves_no_key(tmp_path):
    with pytest.raises(KeyProviderError, match="cannot unseal"):
        SovereignDataPlane(data_dir=str(tmp_path), key_provider=BrokenProvider())
    assert not _key_file(tmp_path).exists()
    assert list((tmp_path / "encrypted").iterdir()) == []
    assert not (tmp_path / "audit" / "sovereign_audit.log").exists()


def test_an_injected_provider_supplies_the_key(tmp_path):
    provider = MemoryProvider()
    dp = SovereignDataPlane(data_dir=str(tmp_path), key_provider=provider)
    dp.store_encrypted("k", {"v": 1})
    assert dp.retrieve_decrypted("k") == {"v": 1}
    assert not _key_file(tmp_path).exists()
    token = (tmp_path / "encrypted" / "k.enc").read_bytes()
    assert json.loads(Fernet(provider.key).decrypt(token)) == {"v": 1}


SECRET_LOOKING = b"hunter2-hunter2-hunter2-hunter2-not-a-fernet-key"


@pytest.mark.parametrize(
    "bad", [b"", SECRET_LOOKING, Fernet.generate_key()[:30], None, 12345]
)
def test_a_key_that_fernet_rejects_is_refused_without_echoing_it(tmp_path, bad):
    provider = MemoryProvider()
    provider.key = bad
    with pytest.raises(KeyProviderError, match="not a valid Fernet key") as raised:
        SovereignDataPlane(data_dir=str(tmp_path), key_provider=provider)
    rendered = "".join(traceback.format_exception(raised.value))
    rendered += repr(raised.value) + str(raised.value)
    if isinstance(bad, bytes) and bad:
        assert bad.decode() not in rendered


def test_validate_key_returns_a_good_key_unchanged():
    key = Fernet.generate_key()
    assert validate_key(key) is key


def test_the_key_never_appears_in_logs_the_report_or_the_audit_log(tmp_path, caplog):
    with caplog.at_level(logging.DEBUG):
        dp = SovereignDataPlane(data_dir=str(tmp_path))
        dp.store_encrypted("k", {"v": 1})
        dp.retrieve_decrypted("k")
        os.chmod(dp.key_file, 0o644)  # provokes the "tightening" warning
        SovereignDataPlane(data_dir=str(tmp_path))
        report = json.dumps(dp.export_compliance_report())
    key = _key_file(tmp_path).read_bytes().decode()
    assert "tightening" in caplog.text
    assert key not in caplog.text
    assert key not in report
    assert key not in (tmp_path / "audit" / "sovereign_audit.log").read_text()
    assert key not in repr(dp) + repr(dp.key_provider) + repr(dp.fernet)


def test_the_provider_defaults_to_file(tmp_path):
    dp = SovereignDataPlane(data_dir=str(tmp_path))
    assert isinstance(dp.key_provider, FileKeyProvider)
    assert dp.key_provider.key_file == _key_file(tmp_path)


def test_the_environment_picks_the_provider(tmp_path, monkeypatch):
    monkeypatch.setenv(PROVIDER_ENV, "file")
    assert SovereignDataPlane(data_dir=str(tmp_path)).key_provider.name == "file"

    provider = provider_from_env(tmp_path, {PROVIDER_ENV: "file"})
    assert isinstance(provider, FileKeyProvider)
    assert provider.key_file == tmp_path / "master.key"
    assert isinstance(provider_from_env(tmp_path, {}), FileKeyProvider)


def test_an_unknown_provider_stops_the_data_plane_before_a_key_exists(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(PROVIDER_ENV, "carrier-pigeon")
    with pytest.raises(KeyProviderError, match="carrier-pigeon"):
        SovereignDataPlane(data_dir=str(tmp_path))
    assert not _key_file(tmp_path).exists()
    assert list((tmp_path / "encrypted").iterdir()) == []


def test_provider_names_are_matched_loosely_and_unknown_names_fail(tmp_path):
    for name in (None, "", "file", "FILE", "  File  "):
        assert isinstance(create_provider(name, tmp_path), FileKeyProvider)
    with pytest.raises(
        KeyProviderError, match="unknown key provider 'tpm3'; known: .*file"
    ):
        create_provider("tpm3", tmp_path)


def test_a_provider_must_implement_the_whole_interface():
    class NoDescribe(KeyProvider):
        name = "incomplete"

        def load_or_create(self, *, may_create=True):
            return b""

    with pytest.raises(TypeError):
        NoDescribe()


def test_the_file_provider_makes_a_private_key_in_a_private_directory(tmp_path):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    os.chmod(key_file.parent, 0o755)
    provider = FileKeyProvider(key_file)
    key = provider.load_or_create()
    assert validate_key(key) == key
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(key_file.parent.stat().st_mode) == 0o700
    assert provider.load_or_create() == key


def test_the_file_provider_creates_nothing_when_told_not_to(tmp_path):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    with pytest.raises(KeyNotProvisionedError):
        FileKeyProvider(key_file).load_or_create(may_create=False)
    assert not key_file.exists()


def test_the_file_provider_still_returns_an_existing_key_when_creation_is_off(tmp_path):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    key = FileKeyProvider(key_file).load_or_create()
    assert FileKeyProvider(key_file).load_or_create(may_create=False) == key


def test_the_file_provider_reports_os_failures_as_provider_errors(tmp_path):
    provider = FileKeyProvider(tmp_path / "missing" / "master.key")
    with pytest.raises(KeyProviderError, match="cannot use key file"):
        provider.load_or_create()


def test_the_file_provider_describes_what_is_on_disk_now(tmp_path):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    provider = FileKeyProvider(key_file)

    missing = provider.describe()
    assert missing["key_file_mode"] is None
    assert missing["ok"] is False

    provider.load_or_create()
    held = provider.describe()
    assert held["provider"] == "file"
    assert held["hardware_bound"] is False
    assert held["key_file_mode"] == "0o600"
    assert held["ok"] is True

    os.chmod(key_file, 0o644)
    assert provider.describe()["ok"] is False


def test_the_file_provider_repr_shows_the_path_and_nothing_else(tmp_path):
    provider = FileKeyProvider(tmp_path / "master.key")
    provider.load_or_create()
    shown = repr(provider)
    assert str(tmp_path / "master.key") in shown
    assert (tmp_path / "master.key").read_bytes().decode() not in shown


def test_the_report_names_the_provider_and_follows_the_measured_state(tmp_path):
    dp = SovereignDataPlane(data_dir=str(tmp_path))
    report = dp.export_compliance_report()
    assert report["key_provider"]["provider"] == "file"
    assert report["key_provider"]["hardware_bound"] is False
    assert report["key_file_mode"] == "0o600"
    assert report["data_sovereignty"] == "enforced"

    os.chmod(dp.key_file, 0o644)
    report = dp.export_compliance_report()
    assert report["key_provider"]["ok"] is False
    assert report["key_file_mode"] == "0o644"
    assert report["data_sovereignty"] == "violations_detected"


def test_a_provider_without_a_key_file_is_reported_from_its_own_facts(tmp_path):
    provider = MemoryProvider()
    dp = SovereignDataPlane(data_dir=str(tmp_path), key_provider=provider)
    report = dp.export_compliance_report()
    assert report["key_provider"] == {
        "provider": "memory",
        "hardware_bound": True,
        "ok": True,
    }
    assert report["key_file_mode"] is None
    assert report["data_sovereignty"] == "enforced"
    assert not _key_file(tmp_path).exists()

    provider.ok = False
    assert dp.export_compliance_report()["data_sovereignty"] == "violations_detected"


def test_main_exits_with_status_2_when_the_key_provider_is_unknown(
    tmp_path, monkeypatch, caplog
):
    from core import kernel

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(PROVIDER_ENV, "carrier-pigeon")
    with (
        caplog.at_level(logging.ERROR, logger="ns_bos_kernel"),
        pytest.raises(SystemExit) as raised,
    ):
        kernel.main([])  # not sys.argv, which is pytest's own
    assert raised.value.code == 2
    assert "unknown key provider 'carrier-pigeon'" in caplog.text
    assert not (tmp_path / "sovereign" / "keys" / "master.key").exists()


def _first_start(key_file, barrier, results):
    barrier.wait()
    try:
        results.put(FileKeyProvider(Path(key_file)).load_or_create())
    except Exception as exc:  # noqa: BLE001 - the parent must see any crash, not hang
        results.put(repr(exc))


def test_processes_starting_together_on_a_new_store_share_one_key(tmp_path):
    ctx = multiprocessing.get_context("fork")
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    barrier = ctx.Barrier(8)
    results = ctx.Queue()
    workers = [
        ctx.Process(target=_first_start, args=(str(key_file), barrier, results))
        for _ in range(8)
    ]
    for worker in workers:
        worker.start()
    keys = [results.get(timeout=30) for _ in workers]
    for worker in workers:
        worker.join(timeout=30)

    assert all(isinstance(key, bytes) for key in keys), keys
    assert len(set(keys)) == 1
    assert key_file.read_bytes() == keys[0]
    assert [entry.name for entry in key_file.parent.iterdir()] == ["master.key"]


def test_the_key_is_not_at_its_final_path_until_it_is_complete(tmp_path, monkeypatch):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    synced = []
    real_fsync = os.fsync

    def spy(fd):
        synced.append((key_file.exists(), stat.S_IMODE(os.fstat(fd).st_mode)))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    FileKeyProvider(key_file).load_or_create()

    # The key is synced while unpublished and already private, then the directory.
    assert [published for published, _ in synced] == [False, True]
    assert synced[0][1] == 0o600
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert [entry.name for entry in key_file.parent.iterdir()] == ["master.key"]


@pytest.mark.parametrize("failing_call", ["fsync", "link"])
def test_a_failed_creation_leaves_no_key_file_and_no_debris(
    tmp_path, monkeypatch, failing_call
):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()

    def fail(*args, **kwargs):
        raise OSError(errno.EIO, "Input/output error")

    with monkeypatch.context() as patched:
        patched.setattr(os, failing_call, fail)
        with pytest.raises(KeyProviderError, match="Input/output error"):
            FileKeyProvider(key_file).load_or_create()
    assert list(key_file.parent.iterdir()) == []

    key = FileKeyProvider(key_file).load_or_create()
    assert validate_key(key) == key


def test_creation_still_works_where_the_filesystem_has_no_hard_links(
    tmp_path, monkeypatch
):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()

    def no_links(*args, **kwargs):
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", no_links)
    key = FileKeyProvider(key_file).load_or_create()
    assert validate_key(key) == key
    assert key_file.read_bytes() == key
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert [entry.name for entry in key_file.parent.iterdir()] == ["master.key"]


def test_a_failed_in_place_creation_removes_its_partial_key(tmp_path, monkeypatch):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    calls = {"fsync": 0}
    real_fsync = os.fsync

    def no_links(*args, **kwargs):
        raise OSError(errno.EPERM, "Operation not permitted")

    def second_sync_fails(fd):
        calls["fsync"] += 1
        if calls["fsync"] == 2:
            raise OSError(errno.ENOSPC, "No space left on device")
        real_fsync(fd)

    with monkeypatch.context() as patched:
        patched.setattr(os, "link", no_links)
        patched.setattr(os, "fsync", second_sync_fails)
        with pytest.raises(KeyProviderError, match="No space left"):
            FileKeyProvider(key_file).load_or_create()
    assert list(key_file.parent.iterdir()) == []


def test_a_failed_directory_sync_does_not_withdraw_a_published_key(
    tmp_path, monkeypatch
):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()

    def fail(directory):
        raise OSError(errno.EIO, "Input/output error")

    with monkeypatch.context() as patched:
        patched.setattr(keys, "_sync_directory", fail)
        with pytest.raises(KeyProviderError, match="Input/output error"):
            FileKeyProvider(key_file).load_or_create()

    published = key_file.read_bytes()
    assert validate_key(published) == published
    assert FileKeyProvider(key_file).load_or_create() == published
    assert [entry.name for entry in key_file.parent.iterdir()] == ["master.key"]


def test_each_new_store_gets_its_own_key(tmp_path):
    created = []
    for n in range(3):
        key_file = tmp_path / str(n) / "master.key"
        key_file.parent.mkdir()
        created.append(FileKeyProvider(key_file).load_or_create())
    assert len(set(created)) == 3


def test_publish_new_file_says_whether_it_created_the_file(tmp_path):
    target = tmp_path / "blob"
    assert publish_new_file(target, b"first") is True
    assert publish_new_file(target, b"second") is False
    assert target.read_bytes() == b"first"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [entry.name for entry in tmp_path.iterdir()] == ["blob"]


def test_publish_new_file_leaves_an_existing_file_alone_without_hard_links(
    tmp_path, monkeypatch
):
    target = tmp_path / "blob"
    target.write_bytes(b"first")

    def no_links(*args, **kwargs):
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", no_links)
    assert publish_new_file(target, b"second") is False
    assert target.read_bytes() == b"first"
    assert [entry.name for entry in tmp_path.iterdir()] == ["blob"]


def test_the_loser_of_a_creation_race_uses_the_winners_key(tmp_path, monkeypatch):
    key_file = tmp_path / "keys" / "master.key"
    key_file.parent.mkdir()
    winners_key = Fernet.generate_key()
    real_link = os.link

    def lose_the_race(src, dst, *args, **kwargs):
        Path(dst).write_bytes(winners_key)
        os.chmod(dst, 0o600)
        return real_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "link", lose_the_race)
    assert FileKeyProvider(key_file).load_or_create() == winners_key
    assert key_file.read_bytes() == winners_key
    assert [entry.name for entry in key_file.parent.iterdir()] == ["master.key"]


def _provider_entries(plane):
    log = plane.get_audit_log(limit=10**9)
    return [entry for entry in log if entry["action"] == "key_provider"]


def test_start_records_the_key_provider_first_in_the_audit_chain(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    (entry,) = _provider_entries(plane)
    assert plane.get_audit_log()[0] == entry
    assert entry["actor"] == "system"
    assert entry["resource"] == "file"
    assert entry["details"] == {"hardware_bound": False, "ok": True, "air_gap": True}
    assert plane.verify_audit_integrity()


def test_each_start_adds_an_entry_so_a_change_of_provider_shows(tmp_path):
    first = SovereignDataPlane(data_dir=str(tmp_path))
    held_elsewhere = MemoryProvider()
    held_elsewhere.key = first.key_provider.load_or_create()
    SovereignDataPlane(data_dir=str(tmp_path), key_provider=held_elsewhere)
    SovereignDataPlane(data_dir=str(tmp_path))

    entries = _provider_entries(first)
    assert [e["resource"] for e in entries] == ["file", "memory", "file"]
    assert [e["details"]["hardware_bound"] for e in entries] == [False, True, False]
    assert first.verify_audit_integrity()


def test_facts_a_provider_adds_to_describe_stay_out_of_the_audit_log(tmp_path):
    class Chatty(MemoryProvider):
        def describe(self):
            return {
                "provider": self.name,
                "hardware_bound": "yes",
                "ok": 1,
                "debug": self.key.decode(),
            }

    chatty = Chatty()
    plane = SovereignDataPlane(data_dir=str(tmp_path), key_provider=chatty)
    (entry,) = _provider_entries(plane)
    assert entry["details"] == {"hardware_bound": True, "ok": True, "air_gap": True}
    assert chatty.key.decode() not in plane.audit_log.read_text()


def test_a_start_the_provider_reports_as_not_ok_is_recorded_as_such(tmp_path):
    provider = MemoryProvider()
    provider.ok = False
    plane = SovereignDataPlane(data_dir=str(tmp_path), key_provider=provider)
    (entry,) = _provider_entries(plane)
    assert entry["details"] == {"hardware_bound": True, "ok": False, "air_gap": True}
