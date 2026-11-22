"""Extra read-only binds reach agent code, and only read-only; the
capability probe runs with the same binds. Plus the sandbox's catch-all
error paths."""

import shutil

import pytest

from core.kernel.sandbox import bwrap

HAS_BWRAP = pytest.mark.skipif(shutil.which("bwrap") is None, reason="needs bubblewrap")


@pytest.fixture
def dataset(tmp_path):
    data = tmp_path / "dataset"
    data.mkdir()
    (data / "rows.csv").write_text("a,b\n1,2\n")
    return data


@HAS_BWRAP
def test_an_extra_bind_is_readable_and_read_only(dataset):
    box = bwrap.BwrapSandbox(
        require_bwrap=True, extra_ro_binds=[(str(dataset), "/data")]
    )
    if not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    code = (
        "import os\n"
        "print(sorted(os.listdir('/data')))\n"
        "try:\n"
        "    os.mkdir('/data/new')\n    print('wrote')\n"
        "except OSError as e:\n    print('read-only', e.errno)\n"
    )
    r = box.execute_python(code)
    assert r.exit_code == 0, r.stderr
    lines = r.stdout.splitlines()
    assert lines[0] == "['rows.csv']"
    assert lines[1].startswith("read-only")
    assert not (dataset / "new").exists()


@HAS_BWRAP
def test_without_the_bind_the_directory_is_not_there(dataset):
    r = bwrap.BwrapSandbox(require_bwrap=True).execute_python(
        "import os\nprint(os.path.exists('/data'))"
    )
    assert r.stdout.strip() == "False"


def test_the_probe_uses_the_same_binds(dataset, monkeypatch):
    seen = []
    monkeypatch.setattr(
        bwrap.subprocess, "run",
        lambda cmd, *a, **k: seen.append(cmd) or type("R", (), {"returncode": 1, "stderr": "x"})(),
    )  # fmt: skip
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", "/usr/bin/bwrap")
    bwrap.BwrapSandbox(extra_ro_binds=[(str(dataset), "/data")]).get_capabilities()
    probe = seen[0]
    i = probe.index(str(dataset))
    assert probe[i - 1 : i + 2] == ["--ro-bind", str(dataset), "/data"]


def test_an_unexpected_error_is_reported_in_the_result(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("something odd")

    monkeypatch.setattr(bwrap, "_BWRAP_PATH", "/usr/bin/bwrap")
    monkeypatch.setattr(bwrap.subprocess, "Popen", boom)
    r = bwrap.BwrapSandbox().execute_python("print(1)")
    assert (r.exit_code, r.error) == (-1, "something odd")
    assert "Sandbox error" in r.stderr

    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    r = bwrap.BwrapSandbox(require_bwrap=False).execute_python("print(1)")
    assert (r.exit_code, r.error) == (-1, "something odd")


def test_extra_tmpfs_is_added(monkeypatch):
    args = bwrap._build_bwrap_args(extra_tmpfs=["/scratch"])
    # Before the read-only root, which comes last.
    assert args[-4:] == ["--tmpfs", "/scratch", "--remount-ro", "/"]


# -- elapsed time does not follow the wall clock ------------------------------------


def _backwards_wall_clock(monkeypatch):
    """A wall clock that is set back an hour each time it is read, as on a
    board without a real-time clock while someone fixes its time."""
    from core.kernel.sandbox import bwrap

    readings = iter(range(10**9, 0, -3600))
    monkeypatch.setattr(bwrap.time, "time", lambda: float(next(readings)))


def test_a_refused_run_reports_monotonic_elapsed_time(monkeypatch):
    from core.kernel.sandbox import bwrap

    _backwards_wall_clock(monkeypatch)
    ticks = iter([100.0, 102.5])
    monkeypatch.setattr(bwrap.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    result = bwrap.BwrapSandbox(require_bwrap=True).execute_python("print(1)")
    assert result.error == "sandbox_unavailable"
    assert result.elapsed_seconds == 2.5


def test_a_fallback_run_never_reports_negative_time(monkeypatch):
    from core.kernel.sandbox import bwrap

    _backwards_wall_clock(monkeypatch)
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    result = bwrap.BwrapSandbox(require_bwrap=False).execute_python(
        "print(1)", seccomp_level=""
    )
    assert result.stdout.strip() == "1"
    assert 0 <= result.elapsed_seconds < 30


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed")
def test_a_bwrap_run_never_reports_negative_time(monkeypatch):
    from core.kernel.sandbox import bwrap

    if not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot create namespaces here")
    _backwards_wall_clock(monkeypatch)
    result = bwrap.BwrapSandbox().execute_python("print(1)", seccomp_level="")
    assert result.stdout.strip() == "1"
    assert 0 <= result.elapsed_seconds < 30


@pytest.mark.parametrize("path", ["bwrap", "fallback"])
def test_a_failed_launch_reports_monotonic_elapsed_time(monkeypatch, path):
    from core.kernel.sandbox import bwrap

    if path == "bwrap" and shutil.which("bwrap") is None:
        pytest.skip("bubblewrap not installed")
    monkeypatch.setattr(bwrap, "_has_bwrap", lambda: path == "bwrap")
    _backwards_wall_clock(monkeypatch)
    ticks = iter([10.0, 10.25])
    monkeypatch.setattr(bwrap.time, "monotonic", lambda: next(ticks))

    def denied(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(bwrap.subprocess, "Popen", denied)
    result = bwrap.BwrapSandbox(require_bwrap=False).execute_python(
        "print(1)", seccomp_level=""
    )
    assert (result.exit_code, result.error) == (-1, "denied")
    assert result.elapsed_seconds == 0.25


# -- a bubblewrap older than 0.7.0, without --size -------------------------------------


def _old_bwrap(tmp_path, monkeypatch, help_exit=0):
    """A bwrap that behaves as 0.6.1 does: --size is an unknown option and
    --help does not list it. Anything else goes to the real bwrap."""
    import shutil

    real = shutil.which("bwrap")
    if real is None or not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    shim = tmp_path / "bwrap"
    shim.write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do\n'
        '  case "$a" in\n'
        '    --size) echo "bwrap: Unknown option --size" >&2; exit 1;;\n'
        f"    --help) {real} --help | grep -v -- --size; exit {help_exit};;\n"
        "  esac\n"
        "done\n"
        f'exec {real} "$@"\n'
    )
    shim.chmod(0o755)
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", str(shim))
    monkeypatch.setattr(bwrap, "_SIZES_TMPFS", {})
    return shim


def test_an_older_bubblewrap_runs_with_unsized_mounts_and_says_so(
    tmp_path, monkeypatch, caplog
):
    import logging

    _old_bwrap(tmp_path, monkeypatch)
    caplog.set_level(logging.WARNING)
    args = bwrap._build_bwrap_args(extra_tmpfs=["/scratch"])
    assert "--size" not in args
    assert args[-4:] == ["--tmpfs", "/scratch", "--remount-ro", "/"]
    box = bwrap.BwrapSandbox(require_bwrap=True)
    result = box.execute_python("print('ran')")
    assert (result.stdout, result.error) == ("ran\n", ""), result.to_dict()
    caps = box.get_capabilities()
    assert caps["sandbox"] == "bubblewrap" and caps["tmpfs_sized"] is False
    warned = [r for r in caplog.records if "does not take --size" in r.getMessage()]
    assert len(warned) == 1  # read once, not on every run


def test_a_current_bubblewrap_sizes_its_mounts(monkeypatch):
    if not bwrap.probe_bwrap()["ok"]:
        pytest.skip("bubblewrap cannot run here")
    monkeypatch.setattr(bwrap, "_SIZES_TMPFS", {})
    args = bwrap._build_bwrap_args()
    assert args.count("--size") == 7  # /dev/shm, /tmp and five small mounts
    assert (
        bwrap.BwrapSandbox(require_bwrap=True).get_capabilities()["tmpfs_sized"] is True
    )


def test_a_bubblewrap_whose_help_cannot_be_read_keeps_the_sizes(tmp_path, monkeypatch):
    # Unsized only on evidence: a bwrap that fails loudly beats one that
    # runs unsized without a word.
    _old_bwrap(tmp_path, monkeypatch, help_exit=1)
    assert bwrap._build_bwrap_args().count("--size") == 7
    result = bwrap.BwrapSandbox(require_bwrap=True).execute_python("print('ran')")
    assert result.error == bwrap.SANDBOX_NOT_STARTED and "--size" in result.stderr


def test_without_a_bubblewrap_to_ask_the_sizes_stay(tmp_path, monkeypatch):
    monkeypatch.setattr(bwrap, "_SIZES_TMPFS", {})
    assert bwrap._sizes_tmpfs(None) is True
    assert bwrap._sizes_tmpfs(str(tmp_path / "no-such-bwrap")) is True
