"""Release tooling tests: version agreement, wheel contents, checksums, and
a byte-for-byte reproducible wheel build."""

import hashlib
import importlib.util
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "ngari_release", REPO_ROOT / "scripts" / "release.py"
)
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)


def test_versions_agree_with_kernel_constant():
    from core.kernel import VERSION

    assert release.check() == VERSION


def test_tag_must_be_v_plus_version():
    version = release.check()
    assert release.check(f"v{version}") == version
    for bad in (version, "v9.9.9", f"V{version}", f"v{version}-rc1"):
        with pytest.raises(release.ReleaseError):
            release.check(bad)


def test_version_mismatch_between_sources_is_rejected(tmp_path, monkeypatch):
    bad_init = tmp_path / "__init__.py"
    bad_init.write_text('VERSION = "9.9.9"\n', encoding="utf-8")
    monkeypatch.setattr(release, "INIT", bad_init)
    with pytest.raises(release.ReleaseError, match="mismatch"):
        release.check()


def test_changelog_section_is_required(tmp_path, monkeypatch):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## [Unreleased]\n", encoding="utf-8")
    monkeypatch.setattr(release, "CHANGELOG", changelog)
    with pytest.raises(release.ReleaseError, match="CHANGELOG"):
        release.check()


def _declare_version(tmp_path, monkeypatch, version):
    init = tmp_path / "__init__.py"
    init.write_text(f'VERSION = "{version}"\n', encoding="utf-8")
    setup = tmp_path / "setup.py"
    setup.write_text(f'    version="{version}",\n', encoding="utf-8")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(f"## [{version}] - 2026-01-01\n\n- x\n", encoding="utf-8")
    monkeypatch.setattr(release, "INIT", init)
    monkeypatch.setattr(release, "SETUP", setup)
    monkeypatch.setattr(release, "CHANGELOG", changelog)


@pytest.mark.parametrize(
    "version", ["0.2.0", "10.20.30", "0.2.0a1", "0.2.0b2", "0.2.0rc1"]
)
def test_versions_that_setuptools_keeps_are_accepted(tmp_path, monkeypatch, version):
    _declare_version(tmp_path, monkeypatch, version)
    assert release.check(f"v{version}") == version


@pytest.mark.parametrize(
    "version", ["0.2.0-rc1", "0.2.0+local", "0.2", "0.2.0.dev1", "0.2.0rc"]
)
def test_versions_that_setuptools_rewrites_are_rejected(tmp_path, monkeypatch, version):
    _declare_version(tmp_path, monkeypatch, version)
    with pytest.raises(release.ReleaseError, match="MAJOR.MINOR.PATCH"):
        release.check()


CHANGELOG_SAMPLE = """# Changelog

## [Unreleased]

- pending work

## [1.0.0-rc1] - 2026-01-01

- release candidate

## [1.0.0] - 2026-02-01

### Added

- the thing

### Fixed

- the other thing

## [0.9.0] - 2025-12-01

- older
"""


def _use_changelog(tmp_path, monkeypatch, text):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(text, encoding="utf-8")
    monkeypatch.setattr(release, "CHANGELOG", changelog)


def test_release_notes_hold_only_the_requested_section(tmp_path, monkeypatch):
    _use_changelog(tmp_path, monkeypatch, CHANGELOG_SAMPLE)
    notes = release.changelog_section("1.0.0")
    assert notes.startswith("### Added")
    assert notes.endswith("- the other thing")
    for other in ("pending work", "release candidate", "older", "## ["):
        assert other not in notes


def test_release_notes_for_the_last_section_run_to_the_end(tmp_path, monkeypatch):
    _use_changelog(tmp_path, monkeypatch, CHANGELOG_SAMPLE)
    assert release.changelog_section("0.9.0") == "- older"


def test_release_notes_reject_missing_and_empty_sections(tmp_path, monkeypatch):
    _use_changelog(
        tmp_path, monkeypatch, "## [1.0.0] - 2026-02-01\n\n## [0.9.0]\n\n- x\n"
    )
    with pytest.raises(release.ReleaseError, match="is empty"):
        release.changelog_section("1.0.0")
    with pytest.raises(release.ReleaseError, match="has no"):
        release.changelog_section("2.0.0")


def test_repository_changelog_has_notes_for_the_current_version():
    assert release.changelog_section(release.check())


def test_notes_command_prints_the_section_and_checks_the_tag(capsys):
    version = release.check()
    assert release.main(["notes", "--tag", f"v{version}"]) == 0
    assert capsys.readouterr().out.strip() == release.changelog_section(version)

    assert release.main(["notes", "--tag", "v9.9.9"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "does not match" in captured.err


def _make_wheel(path: Path, names: list) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name in names:
            zf.writestr(name, "x")


def test_wheel_check_accepts_only_the_kernel_package(tmp_path):
    good = tmp_path / "good.whl"
    _make_wheel(good, ["core/kernel/__init__.py", "ns_bos-1.0.0.dist-info/METADATA"])
    release.check_wheel(good, "1.0.0")

    for stray in (
        "core/kernel/build/lib/core/kernel/x.py",
        "core/kernel/__pycache__/x.cpython-312.pyc",
        "tests/test_x.py",
        "scripts/sbom.py",
    ):
        bad = tmp_path / "bad.whl"
        _make_wheel(bad, ["core/kernel/__init__.py", stray])
        with pytest.raises(release.ReleaseError, match="unexpected"):
            release.check_wheel(bad, "1.0.0")


def test_checksums_are_sorted_complete_and_verifiable(tmp_path):
    (tmp_path / "b.whl").write_bytes(b"two")
    (tmp_path / "a.tar.gz").write_bytes(b"one")
    sums = release.write_checksums(tmp_path)
    lines = sums.read_text(encoding="utf-8").splitlines()
    assert [ln.split("  ")[1] for ln in lines] == ["a.tar.gz", "b.whl"]
    assert lines[0].split("  ")[0] == hashlib.sha256(b"one").hexdigest()
    release.write_checksums(tmp_path)  # rewriting must not hash its own output
    assert len(sums.read_text(encoding="utf-8").splitlines()) == 2
    if shutil.which("sha256sum"):
        run = subprocess.run(
            ["sha256sum", "-c", "SHA256SUMS"],
            cwd=tmp_path,
            capture_output=True,
            check=False,
        )
        assert run.returncode == 0


def test_build_refuses_a_non_empty_outdir(tmp_path):
    (tmp_path / "leftover").write_text("x", encoding="utf-8")
    with pytest.raises(release.ReleaseError, match="not empty"):
        release.build(tmp_path, allow_dirty=True)


@pytest.mark.skipif(
    not (REPO_ROOT / ".git").exists(), reason="the build exports files with git"
)
def test_wheel_build_is_reproducible(tmp_path):
    pytest.importorskip("build")
    pytest.importorskip("setuptools")
    pytest.importorskip("wheel")
    import os

    env = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000"}
    digests = []
    for n in (1, 2):
        out = tmp_path / f"out{n}"
        wheel = release.build_wheel(out, env)
        release.check_wheel(wheel, release.check())
        digests.append(hashlib.sha256(wheel.read_bytes()).hexdigest())
    assert digests[0] == digests[1]
