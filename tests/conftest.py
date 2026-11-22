"""Shared fixtures. The software TPM is a swtpm instance in tmp_path, never the
hardware chip. NGARI_REQUIRE_TPM_SIM=1 turns a skip into a failure.

A raw libtpms state file comes up with no PCR banks, so a PCR policy cannot be
tested on it, and two such states can share a seed, so they are not two
distinct TPMs. The state is therefore manufactured with swtpm_setup, which
allocates a sha256 bank and gives each state its own seed, and reached over a
unix socket for as long as the test runs."""

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest


def _start_soft_tpm(directory: Path):
    """(tcti, stop) for a swtpm with a sha256 PCR bank, unique to directory."""
    directory.mkdir(parents=True, exist_ok=True)
    reason = None
    for tool in ("swtpm", "swtpm_setup"):
        if shutil.which(tool) is None:
            reason = f"{tool} not installed (packages swtpm and swtpm-tools)"
            break
    if reason is None:
        setup = subprocess.run(
            [
                "swtpm_setup",
                "--tpm2",
                "--tpmstate",
                str(directory),
                "--pcr-banks",
                "sha256",
            ],
            capture_output=True,
            check=False,
        )
        if setup.returncode != 0:
            reason = (
                f"swtpm_setup failed: {setup.stderr.decode(errors='replace')[-300:]}"
            )
    if reason:
        if os.environ.get("NGARI_REQUIRE_TPM_SIM") == "1":
            pytest.fail(f"software TPM required but {reason}")
        pytest.skip(reason)

    sock = directory / "sock"
    pid_file = directory / "pid"
    start = subprocess.run(
        [
            "swtpm",
            "socket",
            "--tpm2",
            "--tpmstate",
            f"dir={directory}",
            "--ctrl",
            f"type=unixio,path={sock}.ctrl",
            "--server",
            f"type=unixio,path={sock}",
            "--flags",
            "not-need-init,startup-clear",
            "--daemon",
            "--pid",
            f"file={pid_file}",
        ],
        capture_output=True,
        check=False,
    )
    if start.returncode != 0:
        pytest.fail(
            "swtpm did not start: " + start.stderr.decode(errors="replace")[-300:]
        )

    deadline = time.monotonic() + 10
    while not sock.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not sock.exists():
        pytest.fail(f"swtpm socket {sock} did not appear")

    pid = int(pid_file.read_text().strip())

    def stop():
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

    return f"swtpm:path={sock}", stop


@pytest.fixture(autouse=True)
def air_gap_default(monkeypatch):
    """Tests run with the setting unset, as shipped; a test that needs it
    set does so itself."""
    monkeypatch.delenv("NGARI_AIR_GAP", raising=False)


@pytest.fixture
def soft_tpm(tmp_path):
    tcti, stop = _start_soft_tpm(tmp_path / "tpm-a")
    yield tcti
    stop()


@pytest.fixture
def other_tpm(tmp_path):
    tcti, stop = _start_soft_tpm(tmp_path / "tpm-b")
    yield tcti
    stop()


SOFTHSM_MODULE = "/usr/lib/softhsm/libsofthsm2.so"


class SoftCard:
    """A SoftHSM token standing in for a PIV card, in tmp_path."""

    pin = "123456"

    def __init__(self, root: Path):
        self.root = root
        self.module = SOFTHSM_MODULE
        self.token = "operator"
        self.cert = None
        self.ids = set()  # key IDs that hold a key and a certificate

    def _p11(self, *args):
        subprocess.run(
            ["pkcs11-tool", "--module", self.module, "--token-label", self.token,
             "--login", "--pin", self.pin, *args],
            cwd=self.root, capture_output=True, check=True,
        )  # fmt: skip

    def issue(
        self,
        kind="ec",
        days=30,
        start_days_ago=1,
        card_key=None,
        cn="Test Operator",
        rsa_bits=2048,
        key_id="01",
    ):
        """Put a key and a certificate on the card. card_key, when given,
        replaces the private key so the card holds a copied certificate."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import NameOID

        def new_key():
            if kind == "ec":
                return ec.generate_private_key(ec.SECP256R1())
            return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)

        key = new_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=start_days_ago)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(start + datetime.timedelta(days=days))
            .sign(key, hashes.SHA256())
        )
        on_card = new_key() if card_key == "other" else key
        (self.root / "key.der").write_bytes(
            on_card.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (self.root / "cert.der").write_bytes(
            cert.public_bytes(serialization.Encoding.DER)
        )
        if key_id in self.ids:  # one key and one cert per ID, as on a card
            self._p11("--delete-object", "--type", "privkey", "--id", key_id)
            self._p11("--delete-object", "--type", "cert", "--id", key_id)
        self._p11("--write-object", "key.der", "--type", "privkey", "--id", key_id)
        self._p11("--write-object", "cert.der", "--type", "cert", "--id", key_id)
        (self.root / "key.der").unlink()
        self.ids.add(key_id)
        self.cert = cert
        return cert

    def pem(self):
        from cryptography.hazmat.primitives import serialization

        return self.cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def soft_card(tmp_path, monkeypatch):
    reason = None
    if not (shutil.which("softhsm2-util") and shutil.which("pkcs11-tool")):
        reason = "softhsm2 or opensc not installed"
    elif not Path(SOFTHSM_MODULE).exists():
        reason = f"{SOFTHSM_MODULE} missing"
    if reason:
        if os.environ.get("NGARI_REQUIRE_PKCS11_SIM") == "1":
            pytest.fail(f"SoftHSM required but {reason}")
        pytest.skip(reason)
    root = tmp_path / "card"
    (root / "tokens").mkdir(parents=True)
    conf = root / "softhsm2.conf"
    conf.write_text(
        f"directories.tokendir = {root / 'tokens'}\n"
        "objectstore.backend = file\nlog.level = ERROR\n"
    )
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))
    card = SoftCard(root)
    subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", card.token,
         "--so-pin", "87654321", "--pin", card.pin],
        capture_output=True, check=True,
    )  # fmt: skip
    return card


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "part11(*clauses): the 21 CFR Part 11 clauses a test shows "
        "(docs/validation/TRACE.md, scripts/trace.py)",
    )
