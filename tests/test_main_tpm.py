"""`python -m core.kernel` on the tpm2 provider, as an operator runs it,
against the software TPM only. It boots, keeps its data across a restart,
and when the TPM cannot give it the key it stops with exit status 2 and
leaves every key file as it found it: no key is created or replaced."""

import base64
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import core.kernel as kernel_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
STARTED = f"{kernel_mod.KERNEL_FULL_NAME} v{kernel_mod.VERSION} started"


def _env(data_dir, tcti):
    return {**os.environ, "NGARI_DATA_DIR": str(data_dir), "NGARI_KEY_PROVIDER": "tpm2",
            "NGARI_TPM_TCTI": tcti, "PYTHONUNBUFFERED": "1"}  # fmt: skip


def _boot_and_stop(data_dir, tcti) -> str:
    """Start the kernel, send SIGTERM once it has started, return its output."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "core.kernel"], cwd=REPO_ROOT, env=_env(data_dir, tcti),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )  # fmt: skip
    lines = queue.Queue()
    reader = threading.Thread(
        target=lambda: [lines.put(ln) for ln in proc.stdout], daemon=True
    )
    reader.start()
    seen = []
    try:
        deadline = time.monotonic() + 90
        while True:
            line = lines.get(timeout=max(0.1, deadline - time.monotonic()))
            seen.append(line)
            if line.rstrip().endswith(STARTED):
                proc.send_signal(signal.SIGTERM)
                break
        proc.wait(timeout=60)
    except (queue.Empty, subprocess.TimeoutExpired):
        pytest.fail("kernel did not start and stop in time:\n" + "".join(seen))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    reader.join(timeout=10)
    while not lines.empty():
        seen.append(lines.get())
    output = "".join(seen)
    assert proc.returncode == 0, output
    return output


def _refused(data_dir, tcti) -> str:
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel"], cwd=REPO_ROOT, env=_env(data_dir, tcti),
        capture_output=True, text=True, timeout=90, check=False,
    )  # fmt: skip
    output = run.stdout + run.stderr
    assert run.returncode == 2, output
    assert "Traceback" not in output
    return output


def _keys(data_dir) -> dict:
    keys = Path(data_dir) / "sovereign" / "keys"
    return {p.name: p.read_bytes() for p in keys.iterdir()} if keys.is_dir() else {}


def test_the_kernel_runs_on_a_sealed_key_and_keeps_its_data(soft_tpm, tmp_path):
    data_dir = tmp_path / "data"
    first = _boot_and_stop(data_dir, soft_tpm)
    assert "Traceback" not in first
    keys = _keys(data_dir)
    assert list(keys) == ["master.key.sealed"]
    assert (
        data_dir / "sovereign" / "keys" / "master.key.sealed"
    ).stat().st_mode & 0o777 == 0o600

    second = _boot_and_stop(data_dir, soft_tpm)
    assert "Traceback" not in second
    assert _keys(data_dir) == keys  # the same sealed key, not a new one

    from core.kernel.data_plane import SovereignDataPlane
    from core.kernel.data_plane.tpm import TPMKeyProvider

    provider = TPMKeyProvider(data_dir / "sovereign" / "keys", tcti=soft_tpm)
    plane = SovereignDataPlane(str(data_dir / "sovereign"), key_provider=provider)
    assert plane.retrieve_decrypted("kernel_state")["version"] == kernel_mod.VERSION
    starts = [e for e in plane.get_audit_log(10**6) if e["action"] == "key_provider"]
    assert [e["resource"] for e in starts] == ["tpm2", "tpm2", "tpm2"]
    assert plane.verify_audit_integrity()


def test_an_unreachable_tpm_stops_the_kernel_and_creates_no_key(tmp_path):
    data_dir = tmp_path / "data"
    missing = tmp_path / "no-tpm"
    output = _refused(data_dir, f"device:{missing}")
    assert "Cannot start:" in output
    assert f"{missing} does not exist" in output
    assert _keys(data_dir) == {}


def test_a_plaintext_key_with_nothing_sealed_is_never_replaced(soft_tpm, tmp_path):
    data_dir = tmp_path / "data"
    keys = data_dir / "sovereign" / "keys"
    keys.mkdir(parents=True)
    from cryptography.fernet import Fernet

    (keys / "master.key").write_bytes(Fernet.generate_key())
    before = _keys(data_dir)
    output = _refused(data_dir, soft_tpm)
    assert "Refusing to create a second key" in output
    assert "keys migrate" in output
    assert _keys(data_dir) == before


def test_a_tampered_sealed_key_stops_the_kernel_and_is_kept(soft_tpm, tmp_path):
    data_dir = tmp_path / "data"
    _boot_and_stop(data_dir, soft_tpm)
    sealed = data_dir / "sovereign" / "keys" / "master.key.sealed"
    blob = json.loads(sealed.read_text())
    priv = bytearray(base64.b64decode(blob["priv"]))
    priv[-1] ^= 0x01
    blob["priv"] = base64.b64encode(bytes(priv)).decode()
    sealed.write_text(json.dumps(blob, sort_keys=True) + "\n")
    before = _keys(data_dir)
    output = _refused(data_dir, soft_tpm)
    assert "Cannot start:" in output
    assert _keys(data_dir) == before


def test_a_sealed_key_from_another_tpm_stops_the_kernel(soft_tpm, other_tpm, tmp_path):
    data_dir = tmp_path / "data"
    _boot_and_stop(data_dir, soft_tpm)
    before = _keys(data_dir)
    output = _refused(data_dir, other_tpm)
    assert "sealed under a different TPM owner hierarchy" in output
    assert "restore it from a recovery bundle" in output
    assert _keys(data_dir) == before
