"""get_capabilities() reports isolation from a real bwrap run, not from
configuration. Fake bwrap binaries stand in for broken installs."""

import shutil

import pytest

from core.kernel.sandbox import bwrap

ISOLATION = (
    "namespace_isolation",
    "network_isolation",
    "filesystem_isolation",
    "process_isolation",
    "user_isolation",
)


def _fake_bwrap(tmp_path, body):
    path = tmp_path / "bwrap"
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return str(path)


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed")
def test_a_working_bwrap_is_reported_as_isolating():
    caps = bwrap.BwrapSandbox().get_capabilities()
    if not caps["bwrap_probe"]["ok"]:
        pytest.skip(f"bwrap here cannot run: {caps['bwrap_probe']['error']}")
    assert caps["sandbox"] == "bubblewrap"
    assert all(caps[k] is True for k in ISOLATION)
    assert caps["uid"] == 65534


def test_an_installed_bwrap_that_fails_is_not_reported_as_isolating(
    tmp_path, monkeypatch
):
    fake = _fake_bwrap(
        tmp_path,
        'echo "bwrap: setting up uid map: Permission denied" >&2; exit 1',
    )
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", fake)
    caps = bwrap.BwrapSandbox().get_capabilities()
    assert caps["sandbox"] == "bubblewrap-not-working"
    assert caps["bwrap_probe"] == {
        "ok": False,
        "error": "exit 1: bwrap: setting up uid map: Permission denied",
    }
    assert all(caps[k] is False for k in ISOLATION)
    assert "uid" not in caps


def test_a_hanging_bwrap_times_out(tmp_path, monkeypatch):
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", _fake_bwrap(tmp_path, "exec sleep 30"))
    monkeypatch.setattr(bwrap, "PROBE_TIMEOUT", 0.5)
    probe = bwrap.probe_bwrap()
    assert probe == {"ok": False, "error": "timed out after 0.5s"}


def test_a_vanished_bwrap_is_not_working(monkeypatch):
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", "/nonexistent/bwrap")
    probe = bwrap.probe_bwrap()
    assert probe["ok"] is False
    assert "No such file" in probe["error"]


def test_without_bwrap_bwrap_is_never_started(monkeypatch):
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    calls = []
    real, real_popen = bwrap.subprocess.run, bwrap.subprocess.Popen
    monkeypatch.setattr(
        bwrap.subprocess,
        "run",
        lambda cmd, *a, **k: calls.append(cmd) or real(cmd, *a, **k),
    )
    monkeypatch.setattr(
        bwrap.subprocess,
        "Popen",
        lambda cmd, *a, **k: calls.append(cmd) or real_popen(cmd, *a, **k),
    )
    caps = bwrap.BwrapSandbox(require_bwrap=False).get_capabilities()
    # Only the seccomp probe runs, through the same fallback agent code gets.
    assert [cmd[0] for cmd in calls] == [bwrap.sys.executable]
    assert caps["sandbox"] == "subprocess-fallback"
    assert caps["bwrap_probe"] == {"ok": False, "error": "bwrap not found"}
    assert all(caps[k] is False for k in ISOLATION)


def test_the_probe_uses_the_arguments_agent_code_gets(tmp_path, monkeypatch):
    log = tmp_path / "argv"
    fake = _fake_bwrap(tmp_path, f'echo "$@" > {log}; exit 0')
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", fake)
    assert bwrap.probe_bwrap() == {"ok": True, "error": ""}
    expected = " ".join(bwrap._build_bwrap_args()[1:] + ["true"])
    assert log.read_text().strip() == expected
