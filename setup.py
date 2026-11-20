"""Root installer for the NS-BOS kernel.

The kernel package and its packaging live in ``core/kernel/``. This shim makes
``pip install .`` work from the repository root by running that packaging from
its own directory. It adds no metadata of its own: there is exactly one source
of truth for the package name, version and dependencies.
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
