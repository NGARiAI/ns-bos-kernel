"""SPDX 2.3 SBOM generator for NS-BOS Kernel.

Builds the SBOM from the *declared* runtime dependencies in
``core/kernel/requirements.txt`` (pinned with ``==`` versions and
``--hash=sha256:`` checksums), so build/dev tooling (ruff, bandit,
pip-audit, pip itself) never leaks into the package inventory.

Usage:
    python scripts/sbom.py [--requirements PATH] [--output PATH]
    python scripts/sbom.py --verify-requirements   # exit 1 on any unpinned/missing hash

Runtime deps: stdlib only.
"""

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REQ_DEFAULT = REPO_ROOT / "core" / "kernel" / "requirements.txt"
OUT_DEFAULT = REPO_ROOT / "sbom" / "ns-bos-kernel.spdx.json"

REQ_LINE = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[^ \t]+)")
HASH_LINE = re.compile(r"--hash=sha256:(?P<hex>[0-9a-f]{64})\b")


def parse_requirements(path: Path) -> list[dict]:
    """Return [{'name', 'version', 'sha256': set[str]}] for each pinned req."""
    packages: dict[str, dict] = {}
    current: dict | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = REQ_LINE.match(line)
        if m:
            current = {
                "name": m.group("name"),
                "version": m.group("version"),
                "sha256": set(),
            }
            packages[current["name"].lower()] = current
            continue
        m = HASH_LINE.search(line)
        if m and current is not None:
            current["sha256"].add(m.group("hex").lower())
    return list(packages.values())


def verify_requirements(path: Path) -> None:
    """Fail hard (exit 1) if any declared dep is unpinned or hash-less."""
    errors = []
    for pkg in parse_requirements(path):
        name = pkg["name"]
        if not pkg["version"]:
            errors.append(f"{name}: version must be pinned with ==")
        if not pkg["sha256"]:
            errors.append(f"{name}: missing --hash=sha256 pin")
        if not re.match(r"^[0-9][A-Za-z0-9.!+_~.-]*$", pkg["version"]):
            errors.append(f"{name}: invalid version specifier {pkg['version']!r}")
    if errors:
        print("SBOM require-hashes validation FAILED:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print(f"requirements OK: {len(parse_requirements(path))} pinned packages")


def generate_sbom(requirements_path: Path, output_path: Path) -> int:
    pkgs = parse_requirements(requirements_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = str(uuid.uuid4())

    spdx_packages = []
    for pkg in sorted(pkgs, key=lambda p: p["name"].lower()):
        purl = f"pkg:pypi/{pkg['name']}@{pkg['version']}"
        spdx_packages.append(
            {
                "SPDXID": f"SPDXRef-PACKAGE-{pkg['name']}",
                "name": pkg["name"],
                "versionInfo": pkg["version"],
                "supplier": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": h}
                    for h in sorted(pkg["sha256"])
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    }
                ],
            }
        )

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "ns-bos-kernel",
        "documentNamespace": f"https://ngari.xyz/ns-bos-kernel/{doc_id}",
        "creationInfo": {
            "created": now,
            "creators": [
                "Tool: scripts/sbom.py",
                "Organization: Bison Venture Partners LLC dba NGARI",
            ],
        },
        "packages": spdx_packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": p["SPDXID"],
            }
            for p in spdx_packages
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    print(f"SBOM written: {output_path} ({len(spdx_packages)} runtime packages)")
    return len(spdx_packages)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--requirements", default=str(REQ_DEFAULT))
    ap.add_argument("--output", default=str(OUT_DEFAULT))
    ap.add_argument("--verify-requirements", action="store_true")
    args = ap.parse_args()

    req_path = Path(args.requirements)
    if args.verify_requirements:
        verify_requirements(req_path)
    else:
        generate_sbom(req_path, Path(args.output))
