"""RELEASING.md against .github/workflows/release.yml and the release
script. tests/test_release.py covers the script's checks; this file covers
what the document says the workflow does and what a release holds."""

import base64
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "RELEASING.md").read_text()
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
JOBS = WORKFLOW["jobs"]


def _flat(text: str) -> str:
    return " ".join(text.split())


def _runs(job: str) -> str:
    return "\n".join(step.get("run", "") for step in JOBS[job].get("steps", []))


def _uses(job: str) -> list[dict]:
    return [step for step in JOBS[job].get("steps", []) if "uses" in step]


def test_a_pushed_v_tag_starts_the_workflow():
    on = WORKFLOW.get("on", WORKFLOW.get(True))  # YAML 1.1 reads `on` as True
    assert on == {"push": {"tags": ["v[0-9]+.[0-9]+.[0-9]+*"]}}
    assert "A release is a tag. Pushing `vX.Y.Z` builds the release files" in DOC


def test_the_four_jobs_and_their_order_are_the_documented_ones():
    names = re.findall(r"^\d\. \*\*([a-z ]+)\*\*:", DOC, re.MULTILINE)
    assert names == [JOBS[j]["name"] for j in ("verify", "ci", "build", "publish")]
    assert set(JOBS) == {"verify", "ci", "build", "publish"}
    # verify and ci start together; build waits for both, publish for build.
    assert "needs" not in JOBS["verify"] and "needs" not in JOBS["ci"]
    assert sorted(JOBS["build"]["needs"]) == ["ci", "verify"]
    assert JOBS["publish"]["needs"] == "build"
    assert (
        "The first two run side by side; build and attest starts only when both pass"
        in _flat(DOC)
    )


def test_verify_checks_the_tag_versions_changelog_and_branch():
    runs = _runs("verify")
    assert 'python3 scripts/release.py check --tag "$TAG"' in runs
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" "origin/$DEFAULT_BRANCH"' in runs
    assert JOBS["verify"]["steps"][0]["with"]["fetch-depth"] == 0


def test_ci_is_the_full_ci_workflow():
    assert JOBS["ci"]["uses"] == "./.github/workflows/ci.yml"


def test_build_builds_smokes_compares_and_attests():
    runs = _runs("build")
    assert "make build PYTHON=python" in runs
    assert 'make smoke PYTHON=python WHEEL="$(ls dist/*.whl)"' in runs
    assert 'cmp "dist/$wheel" "$CI_DIST/$wheel"' in runs
    download = next(s for s in _uses("build") if "download-artifact" in s["uses"])
    assert download["with"]["name"] == "ci-dist"
    attest = next(s for s in _uses("build") if "attest-build-provenance" in s["uses"])
    assert attest["with"] == {"subject-checksums": "dist/SHA256SUMS"}
    assert JOBS["build"]["permissions"] == {
        "contents": "read", "id-token": "write", "attestations": "write"
    }  # fmt: skip
    assert (
        "Build provenance is then attested for every file listed in `SHA256SUMS`"
        in _flat(DOC)
    )


def test_publish_rechecks_the_files_and_uses_the_changelog_section():
    runs = _runs("publish")
    assert "sha256sum -c SHA256SUMS" in runs
    assert 'python3 scripts/release.py notes --tag "$TAG"' in runs
    assert "gh release create" in runs and "--verify-tag" in runs
    assert JOBS["publish"]["permissions"] == {"contents": "write"}


@pytest.mark.parametrize(
    ("tag", "pre"),
    [("v0.2.0", False), ("v10.0.1", False), ("v0.2.0rc1", True), ("v0.2.0a1", True),
     ("v0.2.0b2", True)],
)  # fmt: skip
def test_only_a_plain_version_tag_is_a_full_release(tag, pre):
    pattern = re.search(r'\[\[ ! "\$TAG" =~ (\S+) \]\]', _runs("publish")).group(1)
    assert (re.fullmatch(pattern, tag) is None) is pre
    assert "A tag that is not plain `vX.Y.Z` is marked as a pre-release" in _flat(DOC)


def test_a_release_holds_the_four_documented_files(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "release", ROOT / "scripts" / "release.py"
    )
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    version = release.check()
    files = sorted(p.name for p in release.build(tmp_path / "dist", allow_dirty=True))
    documented = re.search(r"A release holds (.*?)\.\n\n", DOC, re.DOTALL).group(1)
    names = [n.replace("X.Y.Z", version) for n in re.findall(r"`([^`]+)`", documented)]
    assert files == sorted(names)
    sums = (tmp_path / "dist" / "SHA256SUMS").read_text().splitlines()
    assert sorted(line.split()[1] for line in sums) == sorted(
        n for n in names if n != "SHA256SUMS"
    )


def test_tag_access_is_restricted_where_the_document_points():
    assert "restrict tag creation as described in `CI.md`" in _flat(DOC)
    ci_doc = _flat((ROOT / "CI.md").read_text())
    assert (
        "Tags matching `v*`: restrict creation, update and deletion to maintainers"
        in ci_doc
    )


def test_the_signing_commands_match_what_verify_checks(tmp_path):
    import importlib.util
    import shutil
    import subprocess

    spec = importlib.util.spec_from_file_location(
        "release", ROOT / "scripts" / "release.py"
    )
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    flat = _flat(DOC)
    assert f"-n {release.NAMESPACE} vX.Y.Z/SHA256SUMS" in flat
    assert (
        "python scripts/release.py verify --dir vX.Y.Z --key ngari-release.pub "
        "--version X.Y.Z" in flat
    )
    assert (
        "python3 scripts/release.py verify --dir vX.Y.Z --key ngari-release.pub "
        "--version X.Y.Z" in flat
    )
    assert f"-I {release.PRINCIPAL} -n {release.NAMESPACE}" in flat
    assert "Once signed (next section), it also holds `SHA256SUMS.sig`." in flat
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen missing")
    # The by-hand commands, run as written, with KEY outside the release.
    block = re.search(r"\n    KEY=.*?\n\n", DOC, re.DOTALL).group(0)
    lines = [x[4:] for x in block.strip("\n").splitlines()]
    assert lines[0].startswith("KEY=")
    script = "set -e\n" + "\n".join(lines[1:]).replace("\\\n", " ")

    def key(where):
        where.mkdir()
        path = where / "ngari-release"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True
        )
        return path, Path(f"{path}.pub")

    def signed(root, signer, extra=()):
        out = root / "vX.Y.Z"
        out.mkdir()
        for name in release.RELEASE_FILES:
            (out / name.format(v="0.2.0")).write_bytes(name.encode() + b"\n")
        release.write_checksums(out)
        subprocess.run(
            ["ssh-keygen", "-q", "-Y", "sign", "-f", str(signer), "-n", release.NAMESPACE,
             str(out / "SHA256SUMS")], check=True, capture_output=True,
        )  # fmt: skip
        for name, data in extra:
            (out / name).write_bytes(data)
        return out

    def by_hand(root, trusted):
        return subprocess.run(
            ["bash", "-c", script], cwd=root, capture_output=True, text=True, check=False,
            env={"PATH": "/usr/bin:/bin", "KEY": str(trusted)},
        )  # fmt: skip

    signer, trusted = key(tmp_path / "maintainer")
    good = tmp_path / "good"
    good.mkdir()
    out = signed(good, signer)
    run = by_hand(good, trusted)
    assert run.returncode == 0, run.stderr
    blob = base64.b64decode(trusted.read_text().split()[1])
    assert release.key_fingerprint(blob) in run.stdout  # the fingerprint to compare
    assert run.stdout.split()[-5:] == sorted(p.name for p in out.iterdir())
    (out / "SHA256SUMS").write_text(
        (out / "SHA256SUMS").read_text().replace("a", "b", 1)
    )
    assert by_hand(good, trusted).returncode != 0  # changed after signing
    # A release signed by someone else, shipping their own key inside it.
    attacker, theirs = key(tmp_path / "attacker")
    forged = tmp_path / "forged"
    forged.mkdir()
    signed(forged, attacker, [("ngari-release.pub", theirs.read_bytes())])
    assert by_hand(forged, trusted).returncode != 0
    # A hidden file shows in the listing to check.
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    signed(hidden, signer, [(".pth-hook", b"import os\n")])
    run = by_hand(hidden, trusted)
    assert run.returncode == 0 and ".pth-hook" in run.stdout.split()
