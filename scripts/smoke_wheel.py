"""Install a built wheel into a fresh venv and start the ns-bos command.

    python scripts/smoke_wheel.py [WHEEL]

Without WHEEL, one is built from the tracked files first. Runtime
dependencies come from the hash-pinned lock and the wheel goes in with
--no-deps, so the check sees what `pip install` gives a user. It fails on a
missing module, a broken console-script entry point, or an import that only
works from the source tree. The command is stopped with SIGINT once it prints
its status banner, and a clean exit is required.

Linux and macOS only (venv layout). Stdlib only.
"""

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import venv
from pathlib import Path

import release

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK = REPO_ROOT / "core" / "kernel" / "requirements.txt"
BANNER = "Data Sovereignty:"
BANNER_TIMEOUT = 60
STOP_TIMEOUT = 30


class SmokeError(Exception):
    pass


def _clean_env(**extra: str) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update(extra)
    return env


def _pip_install(python: Path, *args: str) -> None:
    cmd = [
        str(python),
        "-m",
        "pip",
        "install",
        "--quiet",
        "--disable-pip-version-check",
    ]
    proc = subprocess.run(
        [*cmd, *args], capture_output=True, text=True, check=False, env=_clean_env()
    )
    if proc.returncode != 0:
        raise SmokeError(
            f"pip install {' '.join(args)} failed:\n{proc.stdout}{proc.stderr}"
        )


def _check_import(python: Path, work: Path, prefix: Path) -> None:
    code = (
        "import importlib.metadata as m, core.kernel as k\n"
        "print(k.__file__)\n"
        "assert m.version('ns-bos') == k.VERSION, (m.version('ns-bos'), k.VERSION)\n"
    )
    proc = subprocess.run(
        [str(python), "-I", "-c", code],
        cwd=work,
        capture_output=True,
        text=True,
        check=False,
        env=_clean_env(),
    )
    if proc.returncode != 0:
        raise SmokeError(f"importing core.kernel failed:\n{proc.stdout}{proc.stderr}")
    location = Path(proc.stdout.strip().splitlines()[0]).resolve()
    if prefix.resolve() not in location.parents:
        raise SmokeError(f"core.kernel was imported from {location}, not the venv")


def _run_entry_point(command: Path, work: Path) -> None:
    env = _clean_env(NGARI_DATA_DIR=str(work / "data"), PYTHONUNBUFFERED="1")
    proc = subprocess.Popen(
        [str(command)],
        cwd=work,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines: list[str] = []
    banner_line: list[str] = []
    seen = threading.Event()

    def pump() -> None:
        for line in proc.stdout:
            lines.append(line)
            if BANNER in line:
                banner_line.append(line.strip())
                seen.set()

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    deadline = time.monotonic() + BANNER_TIMEOUT
    while not seen.is_set() and proc.poll() is None and time.monotonic() < deadline:
        seen.wait(0.2)

    if seen.is_set():
        proc.send_signal(signal.SIGINT)
    elif proc.poll() is None:
        proc.kill()
    try:
        code = proc.wait(timeout=STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise SmokeError("ns-bos ignored SIGINT and had to be killed") from None
    reader.join(timeout=5)
    output = "".join(lines)

    if not banner_line:
        raise SmokeError(f"ns-bos never printed its status banner:\n{output}")
    if "enforced" not in banner_line[0]:
        raise SmokeError(
            f"data sovereignty is not enforced on a fresh data dir:\n{output}"
        )
    if code != 0:
        raise SmokeError(f"ns-bos exited with {code} after SIGINT:\n{output}")
    if "stopped" not in output.splitlines()[-1]:
        raise SmokeError(f"ns-bos did not log a clean stop:\n{output}")


def smoke(wheel: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        prefix = root / "venv"
        venv.EnvBuilder(with_pip=True).create(prefix)
        python = prefix / "bin" / "python"
        work = root / "work"
        work.mkdir()

        _pip_install(python, "--require-hashes", "-r", str(LOCK))
        _pip_install(python, "--no-deps", str(wheel))
        _check_import(python, work, prefix)
        _run_entry_point(prefix / "bin" / "ns-bos", work)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "wheel", nargs="?", type=Path, help="wheel to test (default: build one)"
    )
    args = ap.parse_args(argv)
    # A parent that ignores SIGINT would pass that on to the child, which
    # then could not be stopped cleanly.
    signal.signal(signal.SIGINT, signal.default_int_handler)

    try:
        if args.wheel:
            wheel = args.wheel.resolve()
            smoke(wheel)
        else:
            version = release.check()
            env = os.environ.copy()
            env.setdefault(
                "SOURCE_DATE_EPOCH", release._git("log", "-1", "--format=%ct")
            )
            with tempfile.TemporaryDirectory() as tmp:
                wheel = release.build_wheel(Path(tmp), env)
                release.check_wheel(wheel, version)
                smoke(wheel)
    except (SmokeError, release.ReleaseError) as exc:
        print(f"smoke: {exc}", file=sys.stderr)
        return 1
    print(f"smoke: {wheel.name} installs and ns-bos starts and stops cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
