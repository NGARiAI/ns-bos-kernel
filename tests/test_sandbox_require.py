"""NGARI_SANDBOX_REQUIRE_BWRAP=1: no plain-subprocess fallback. These tests
fake a missing bubblewrap, so they run on machines with or without it."""

import subprocess

import pytest

from core.kernel.sandbox import bwrap


@pytest.fixture
def runs(monkeypatch):
    calls = []
    real = subprocess.run

    real_popen = subprocess.Popen

    def spy(cmd, *args, **kwargs):
        calls.append(cmd)
        return real(cmd, *args, **kwargs)

    def spy_popen(cmd, *args, **kwargs):  # how agent code is started
        calls.append(cmd)
        return real_popen(cmd, *args, **kwargs)

    monkeypatch.setattr(bwrap.subprocess, "run", spy)
    monkeypatch.setattr(bwrap.subprocess, "Popen", spy_popen)
    return calls


@pytest.fixture
def no_bwrap(monkeypatch):
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)


def test_required_and_missing_the_code_never_runs(no_bwrap, runs):
    sandbox = bwrap.BwrapSandbox(require_bwrap=True)
    result = sandbox.execute_python("print('ran')")
    assert runs == []
    assert result.exit_code == -1
    assert result.error == "sandbox_unavailable"
    assert result.stdout == ""
    assert "NGARI_SANDBOX_REQUIRE_BWRAP=1" in result.stderr
    assert [r.error for r in sandbox.batch_execute(["1", "2"])] == [
        "sandbox_unavailable"
    ] * 2
    assert runs == []


def test_with_the_gap_off_a_missing_bwrap_still_falls_back(no_bwrap, runs, monkeypatch):
    monkeypatch.delenv(bwrap.REQUIRE_BWRAP_ENV, raising=False)
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    sandbox = bwrap.BwrapSandbox()
    assert sandbox.require_bwrap is False
    result = sandbox.execute_python("print('ran')")
    assert result.stdout.strip() == "ran"
    assert len(runs) == 1


def test_a_bwrap_that_vanishes_is_not_worked_around(monkeypatch, runs):
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", "/nonexistent/bwrap")
    required = bwrap.BwrapSandbox(require_bwrap=True).execute_python("print('ran')")
    assert required.error == "sandbox_unavailable"
    assert len(runs) == 1  # the bwrap attempt only
    lenient = bwrap.BwrapSandbox(require_bwrap=False).execute_python("print('ran')")
    assert lenient.stdout.strip() == "ran"


@pytest.mark.parametrize(
    ("value", "required"), [("1", True), ("0", False), ("true", False), ("", False)]
)
def test_only_1_turns_the_requirement_on(monkeypatch, value, required):
    monkeypatch.setenv("NGARI_AIR_GAP", "0")  # the gap would require it too
    monkeypatch.setenv(bwrap.REQUIRE_BWRAP_ENV, value)
    assert bwrap.BwrapSandbox().require_bwrap is required


def test_an_explicit_argument_beats_the_environment(monkeypatch):
    monkeypatch.setenv(bwrap.REQUIRE_BWRAP_ENV, "1")
    assert bwrap.BwrapSandbox(require_bwrap=False).require_bwrap is False


def test_capabilities_say_unavailable_rather_than_fallback(no_bwrap):
    required = bwrap.BwrapSandbox(require_bwrap=True).get_capabilities()
    assert required["sandbox"] == "unavailable"
    assert required["require_bwrap"] is True
    assert required["namespace_isolation"] is False
    lenient = bwrap.BwrapSandbox(require_bwrap=False).get_capabilities()
    assert lenient["sandbox"] == "subprocess-fallback"


def test_the_missing_bwrap_is_logged_as_an_error_when_required(no_bwrap, caplog):
    bwrap.BwrapSandbox(require_bwrap=True)
    assert any(
        r.levelname == "ERROR" and "will not run" in r.getMessage()
        for r in caplog.records
    )
