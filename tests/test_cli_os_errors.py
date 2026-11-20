"""The keys and audit commands, when a file they need cannot be used (the
wrong user, a directory where a file should be), print one line and exit 1
instead of a traceback."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from core.kernel.data_plane import SovereignDataPlane, audit_cli, keys_cli
from core.kernel.data_plane.keys_cli import describe_os_error

REPO_ROOT = Path(__file__).resolve().parent.parent
OWNER_HINT = "; run this as the user that owns the data directory"


@pytest.fixture
def store(tmp_path):
    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    plane.store_encrypted("k", {"v": 1})
    return tmp_path / "sovereign"


def _env(store):
    return {"NGARI_DATA_DIR": str(store.parent)}


@pytest.mark.parametrize("command", ["verify", "anchor"])
def test_an_audit_log_that_is_a_directory_is_named(store, capsys, command):
    log = store / "audit" / "sovereign_audit.log"
    log.unlink()
    log.mkdir()
    assert audit_cli.cli([command], _env(store)) == 1
    assert capsys.readouterr().err.strip() == f"audit {command}: {log}: Is a directory"


def _deny(monkeypatch, name):
    real = Path.exists

    def exists(self, *args, **kwargs):
        if self.name == name:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", exists)


@pytest.mark.parametrize("command", ["status", "migrate"])
def test_a_key_file_this_user_cannot_see_is_named(store, capsys, monkeypatch, command):
    _deny(monkeypatch, "master.key")
    assert keys_cli.cli([command], _env(store)) == 1
    key = store / "keys" / "master.key"
    assert (
        capsys.readouterr().err.strip()
        == f"{command}: {key}: Permission denied{OWNER_HINT}"
    )


def test_card_check_reports_a_file_it_cannot_use(store, tmp_path, capsys, monkeypatch):
    from core.kernel.data_plane.operator_auth import CardAuthenticator

    def denied(self, store, pin):
        raise PermissionError(13, "Permission denied", "/dev/bus/usb/001/004")

    monkeypatch.setattr(CardAuthenticator, "check", denied)
    pin = tmp_path / "pin"
    pin.write_text("123456\n")
    assert keys_cli.cli(["card-check", "--pin-file", str(pin)], _env(store)) == 1
    assert capsys.readouterr().err.strip() == (
        f"card-check: /dev/bus/usb/001/004: Permission denied{OWNER_HINT}"
    )


def _as_other_user(store):
    """argv prefix that runs a command as a user who cannot read store."""
    if os.geteuid() == 0:
        if shutil.which("setpriv") is None:
            pytest.skip("running as root without setpriv")
        return ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]
    for path in (store, store / "keys", store / "audit"):
        path.chmod(0o000)
    return []


@pytest.mark.parametrize(
    "command", [["keys", "status"], ["keys", "migrate"], ["audit", "verify"], ["audit", "anchor"]],
    ids=" ".join,
)  # fmt: skip
def test_every_command_run_as_another_user_fails_cleanly(store, command):
    prefix = _as_other_user(store)
    env = {**os.environ, "NGARI_DATA_DIR": str(store.parent), "HOME": str(store.parent)}
    try:
        run = subprocess.run(
            [*prefix, sys.executable, "-m", "core.kernel", *command], cwd=REPO_ROOT,
            env=env, capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
    finally:
        for path in (store, store / "keys", store / "audit"):
            path.chmod(0o700)
    output = run.stdout + run.stderr
    assert run.returncode == 1, output
    assert "Traceback" not in output
    assert "Permission denied" in output


def test_the_line_names_the_file_and_hints_only_for_permissions():
    assert describe_os_error(IsADirectoryError(21, "Is a directory", "/d/log")) == (
        "/d/log: Is a directory"
    )
    assert describe_os_error(PermissionError(13, "Permission denied")) == (
        f"Permission denied{OWNER_HINT}"
    )
    assert describe_os_error(OSError("no detail")) == "no detail"
