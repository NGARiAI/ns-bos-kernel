"""SPDX 2.3 SBOM generator for NS BOS Kernel"""

import json
import subprocess
import sys
from pathlib import Path


def generate_sbom(output_path: str = "sbom/ns-bos-kernel.spdx.json"):
    result = subprocess.run(
        ["pip", "list", "--format=json"],
        capture_output=True, text=True, check=True
    )
    pkgs = json.loads(result.stdout)

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "ns-bos-kernel",
        "creationInfo": {
            "created": subprocess.run(
                ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                capture_output=True, text=True
            ).stdout.strip(),
            "creators": [
                "Tool: sbom.py",
                "Organization: NGARI Corporation"
            ]
        },
        "packages": []
    }

    for pkg in pkgs:
        sbom["packages"].append({
            "SPDXID": f"SPDXRef-{pkg['name']}",
            "name": pkg["name"],
            "versionInfo": pkg["version"],
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION"
        })

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(sbom, f, indent=2)

    print(f"SBOM written: {output} ({len(pkgs)} packages)")
    return len(pkgs)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "sbom/ns-bos-kernel.spdx.json"
    generate_sbom(path)
