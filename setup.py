#!/usr/bin/env python3
"""Root installer for the NS-BOS kernel.

Why this file exists
--------------------
The kernel package lives at ``core/kernel/`` and its historical packaging is
executed from there. Because the repository root had no installer at all, the
obvious first thing a contributor or participant tries --::

    git clone https://github.com/NGARiAI/ns-bos-kernel.git
    cd ns-bos-kernel
    pip install .

...failed with::

    ERROR: Directory '.' is not installable. Neither 'setup.py' nor
    'pyproject.toml' found.

This shim delegates to the canonical packaging in ``core/kernel/`` so the root
works too. It adds no metadata of its own: there is exactly one source of truth
for the package name, version and dependencies.
"""

from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

KERNEL_DIR = Path(__file__).resolve().parent / "core" / "kernel"

if not (KERNEL_DIR / "setup.py").is_file():
    sys.exit(
        "ns-bos: cannot find core/kernel/setup.py beside this file. "
        "Install from a full clone of github.com/NGARiAI/ns-bos-kernel."
    )

_prev = os.getcwd()
os.chdir(KERNEL_DIR)
try:
    sys.path.insert(0, str(KERNEL_DIR))
    runpy.run_path(str(KERNEL_DIR / "setup.py"), run_name="__main__")
finally:
    os.chdir(_prev)
