"""SBOM integrity tests.

The kernel's SBOM must (1) reflect only the *declared* runtime deps from
requirements.txt, (2) carry sha256 checksums + purl refs for every package,
and (3) match a fresh generation from the pinned requirements. CI runs the
same checks; these tests keep the repository honest without a network.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REQ = REPO_ROOT / "core" / "kernel" / "requirements.txt"
SBOM = REPO_ROOT / "sbom" / "ns-bos-kernel.spdx.json"
SYS_PLATFORM = None  # windows/linux; assert file layout only


def _pins() -> dict:
    pins = {}
    for raw in REQ.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            pins[name.lower()] = ver.split()[0]
    return pins


def test_requirements_fully_pinned_with_hashes():
    out = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "sbom.py"),
            "--verify-requirements",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, (
        f"sbom.py --verify-requirements failed:\n{out.stdout}\n{out.stderr}"
    )


def test_sbom_is_valid_spdx():
    doc = json.loads(SBOM.read_text(encoding="utf-8"))
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert any("Bison Venture Partners" in c for c in doc["creationInfo"]["creators"])
    assert len(doc["packages"]) >= 1


def test_sbom_covers_all_declared_runtime_deps():
    pins = _pins()
    assert pins, "requirements.txt has no pinned packages"
    doc = json.loads(SBOM.read_text(encoding="utf-8"))
    sbom_names = {p["name"].lower(): p for p in doc["packages"]}
    missing = [n for n in pins if n not in sbom_names]
    assert not missing, f"SBOM missing declared packages: {missing}"
    for name, ver in pins.items():
        pkg = sbom_names[name]
        assert pkg["versionInfo"] == ver, (
            f"{name}: SBOM version {pkg['versionInfo']} != req {ver}"
        )


def test_sbom_packages_checksummed_with_purl():
    doc = json.loads(SBOM.read_text(encoding="utf-8"))
    for pkg in doc["packages"]:
        assert pkg["checksums"], f"{pkg['name']} has no checksums"
        for c in pkg["checksums"]:
            assert c["algorithm"] == "SHA256" and len(c["checksumValue"]) == 64
        refs = {r["referenceType"] for r in pkg["externalRefs"]}
        assert "purl" in refs, f"{pkg['name']} missing purl externalRef"
    # every pinned hash must appear on its package
    pinned_hashes: dict[str, set] = {}
    current = None
    for raw in REQ.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            current = line.split("==", 1)[0].lower()
            pinned_hashes.setdefault(current, set())
        elif "--hash=sha256:" in line and current:
            pinned_hashes[current].add(line.split("sha256:", 1)[1][:64])
    by_name = {p["name"].lower(): p for p in doc["packages"]}
    for name, want in pinned_hashes.items():
        have = {c["checksumValue"].lower() for c in by_name[name]["checksums"]}
        assert want <= have, f"{name}: SBOM missing some pinned hashes"


def test_sbom_contains_no_tooling():
    doc = json.loads(SBOM.read_text(encoding="utf-8"))
    names = {p["name"].lower() for p in doc["packages"]}
    for tool in ("ruff", "bandit", "pip-audit", "pytest", "setuptools"):
        assert tool not in names, (
            f"build/dev tool {tool} leaked into SBOM runtime packages"
        )
