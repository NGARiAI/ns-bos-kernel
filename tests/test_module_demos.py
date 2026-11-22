"""Every module demo runs. A package's demo is its __main__.py
(`python -m core.kernel.<package>`); a demo at the bottom of an __init__.py
runs as a script, which a relative import at the top of that file stops.
The kernel's own entry point is tested in test_main.py."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL = REPO_ROOT / "core" / "kernel"
GUARD = 'if __name__ == "__main__":'


def _demos():
    found = []
    for package in sorted(p for p in KERNEL.iterdir() if (p / "__init__.py").exists()):
        if (package / "__main__.py").exists():
            found.append(("-m", f"core.kernel.{package.name}"))
        elif GUARD in (package / "__init__.py").read_text():
            found.append(("file", str(package / "__init__.py")))
    return found


def test_the_demo_list_is_complete():
    assert sorted(_name(d) for d in _demos()) == [
        "agent_runtime", "data_plane", "generative_ui", "hal", "inference", "network_sync",
    ]  # fmt: skip


def test_no_package_keeps_a_demo_it_cannot_run():
    # A guard block in an __init__.py with a relative import never runs:
    # not as a script (the import fails) and not with -m (that runs __main__.py).
    for package in KERNEL.iterdir():
        init = package / "__init__.py"
        if init.exists() and GUARD in init.read_text():
            relative = [
                line for line in init.read_text().splitlines()
                if line.lstrip().startswith("from .")
            ]  # fmt: skip
            assert relative == [], f"{package.name}: demo cannot run as a script"


def _name(demo):
    how, target = demo
    return target.rsplit(".", 1)[-1] if how == "-m" else Path(target).parent.name


@pytest.mark.parametrize(("how", "target"), _demos(), ids=[_name(d) for d in _demos()])
def test_every_demo_runs(tmp_path, how, target):
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("NGARI_")},
        "HOME": str(tmp_path / "home"),
        "NGARI_DATA_DIR": str(tmp_path / "data"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    command = (
        [sys.executable, "-m", target] if how == "-m" else [sys.executable, target]
    )
    run = subprocess.run(
        command, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120,
        check=False,
    )  # fmt: skip
    output = run.stdout + run.stderr
    assert run.returncode == 0, output[-2000:]
    assert "Traceback" not in output
