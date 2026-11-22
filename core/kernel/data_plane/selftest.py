"""`keys selftest`: the tpm2 key provider's whole lifecycle against a TPM, in
a scratch directory. The kernel's data directory and key are never read.

Each step runs the code the real commands and the kernel run:

1. file key: a data plane on a new file key stores a probe value.
2. migrate: `keys migrate` seals that key; a fresh provider unseals it.
3. tpm2 only: master.key is deleted, and a data plane on the tpm2 provider
   reads the probe written under the file key. Its compliance entry is ok.
4. export-recovery: a bundle under a random passphrase, never shown.
5. restore: `keys restore` seals the bundle's key into a second store that
   holds a copy of the encrypted data, which then reads back.
6. tamper: a sealed blob with one byte changed is refused, and no key is
   created in its place.
7. pcr policy, with --pcrs: `keys restore` binds a third store to those PCRs
   and the data reads back under the policy. PCRs are only read, never
   extended, so the host's measurements are left as they are.

The provider uses transient TPM objects only: nothing is written to NV
storage and nothing stays on the chip.
"""

import base64
import json
import os
import secrets
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from . import SovereignDataPlane
from .keys import FileKeyProvider, KeyProviderError
from .keys_cli import MigrationError, export_recovery, migrate, restore
from .tpm import TPMKeyProvider, missing_pcr_bank, parse_pcrs

PROBE = "selftest"


class SelftestFailure(Exception):
    """A step ran but did not see what it should."""


def _flip(sealed: Path) -> None:
    """Change one byte of the sealed private part, so the TPM's integrity
    check on load must fail."""
    blob = json.loads(sealed.read_text())
    priv = bytearray(base64.b64decode(blob["priv"]))
    priv[-1] ^= 0x01
    blob["priv"] = base64.b64encode(bytes(priv)).decode()
    sealed.write_text(json.dumps(blob, sort_keys=True) + "\n")


class _Run:
    def __init__(self, root: Path, environ: Mapping[str, str], pcrs: str | None):
        self.env = dict(environ)
        self.pcrs = pcrs
        self.a = root / "a" / "sovereign"
        self.b = root / "b" / "sovereign"
        self.c = root / "c" / "sovereign"
        self.bundle = root / "bundle.json"
        self.passphrase = secrets.token_urlsafe(24).encode()
        self.probe = {"probe": secrets.token_hex(16)}

    def tpm(self, store: Path) -> TPMKeyProvider:
        return TPMKeyProvider.from_env(store / "keys", self.env)

    def read_probe(self, store: Path, provider) -> SovereignDataPlane:
        plane = SovereignDataPlane(str(store), key_provider=provider)
        if plane.retrieve_decrypted(PROBE) != self.probe:
            raise SelftestFailure(f"the probe did not read back from {store.name}")
        return plane

    def file_key(self) -> str:
        provider = FileKeyProvider(self.a / "keys" / "master.key")
        SovereignDataPlane(str(self.a), key_provider=provider).store_encrypted(
            PROBE, self.probe
        )
        self.read_probe(self.a, FileKeyProvider(self.a / "keys" / "master.key"))
        return "a data plane on a new file key stored and read a probe value"

    def migrate(self) -> str:
        migrate(self.a, self.env)
        if not self.tpm(self.a).sealed_file.exists():
            raise SelftestFailure("migrate reported success but sealed nothing")
        return "keys migrate sealed the key; a fresh provider unsealed the same key"

    def tpm2_only(self) -> str:
        (self.a / "keys" / "master.key").unlink()
        provider = self.tpm(self.a)
        plane = self.read_probe(self.a, provider)
        if not provider.describe()["ok"]:
            raise SelftestFailure("the tpm2 provider's compliance entry is not ok")
        if not plane.verify_audit_integrity():
            raise SelftestFailure("the audit log did not verify")
        return (
            "master.key deleted; a data plane on the sealed key read the probe "
            "written under the file key; compliance entry ok"
        )

    def export(self) -> str:
        export_recovery(self.a, self.env, self.bundle, self.passphrase)
        return "keys export-recovery wrote a bundle (random passphrase, not shown)"

    def restore(self) -> str:
        (self.b / "encrypted").mkdir(parents=True)
        for enc in (self.a / "encrypted").glob("*.enc"):
            shutil.copy2(enc, self.b / "encrypted" / enc.name)
        restore(self.b, self.env, self.bundle, self.passphrase)
        self.read_probe(self.b, self.tpm(self.b))
        return "keys restore sealed the bundle's key into a second store; the data read back"

    def pcr_policy(self) -> str:
        (self.c / "encrypted").mkdir(parents=True)
        for enc in (self.a / "encrypted").glob("*.enc"):
            shutil.copy2(enc, self.c / "encrypted" / enc.name)
        restore(self.c, self.env, self.bundle, self.passphrase, self.pcrs)
        provider = self.tpm(self.c)
        if provider.pcrs() != self.pcrs:
            raise SelftestFailure(f"the sealed key is not bound to {self.pcrs}")
        self.read_probe(self.c, provider)
        return (
            f"keys restore bound a third store to PCRs {self.pcrs}; the data read "
            "back under the policy"
        )

    def tamper(self) -> str:
        provider = self.tpm(self.b)
        _flip(provider.sealed_file)
        changed = provider.sealed_file.read_bytes()
        try:
            SovereignDataPlane(str(self.b), key_provider=provider)
        except KeyProviderError:
            pass
        else:
            raise SelftestFailure("a sealed blob with a changed byte still unsealed")
        if provider.sealed_file.read_bytes() != changed or provider.plain_file.exists():
            raise SelftestFailure("a key was created in place of the refused one")
        return "a sealed blob with one byte changed was refused; no key was created"


STEPS: list[tuple[str, Callable[[_Run], str]]] = [
    ("file key", _Run.file_key),
    ("migrate", _Run.migrate),
    ("tpm2 only", _Run.tpm2_only),
    ("export-recovery", _Run.export),
    ("restore", _Run.restore),
    ("tamper", _Run.tamper),
]


PCR_STEP = ("pcr policy", _Run.pcr_policy)


def run_selftest(
    environ: Mapping[str, str], pcrs: str | None = None, progress=None
) -> dict:
    """Run every step against the TPM environ's TCTI names, and the PCR
    step when pcrs is given. Stops at the first failure; the scratch
    directory is removed either way. progress, if given, is called with
    each report line as soon as it is known: a hardware TPM can take many
    seconds per step, and a run that prints nothing until the end looks
    like one that hung."""
    say = progress or (lambda line: None)
    provider = TPMKeyProvider.from_env(Path("unused"), environ)
    report = {"tcti": provider.tcti, "pcrs": None, "tpm": None, "steps": [],
              "passed": False}  # fmt: skip
    try:
        report["pcrs"] = parse_pcrs(pcrs)
    except KeyProviderError as exc:
        report["error"] = str(exc)
        return report
    say(
        f"Reaching the TPM ({provider.tcti}). On a hardware TPM each step can take "
        "a minute; each prints when it finishes."
    )
    try:
        report["tpm"] = provider.identity()
        say(_tpm_line(report))
    except KeyProviderError as exc:
        report["error"] = f"cannot reach the TPM: {exc}"
        return report
    problem = missing_pcr_bank(report["pcrs"], report["tpm"]["pcr_banks"])
    if problem:
        report["error"] = problem
        return report
    steps = STEPS + ([PCR_STEP] if report["pcrs"] else [])
    with tempfile.TemporaryDirectory(prefix="ngari-selftest-") as tmp:
        os.chmod(tmp, 0o700)
        run = _Run(Path(tmp), environ, report["pcrs"])
        for name, step in steps:
            start = time.monotonic()
            try:
                detail, ok = step(run), True
            except (SelftestFailure, KeyProviderError, MigrationError, OSError) as exc:
                detail, ok = str(exc), False
            report["steps"].append(
                {"step": name, "ok": ok, "detail": detail,
                 "seconds": round(time.monotonic() - start, 2)}
            )  # fmt: skip
            say(_step_line(len(report["steps"]), report["steps"][-1]))
            if not ok:
                return report
    report["passed"] = True
    return report


def _tpm_line(report: dict) -> str:
    tpm = report["tpm"]
    return (
        f"TPM: {tpm['manufacturer']} {tpm['vendor']}, TPM {tpm['family']} "
        f"revision {tpm['revision']}, firmware {tpm['firmware']}, PCR banks "
        f"{', '.join(tpm['pcr_banks']) or 'none'} (TCTI {report['tcti']})"
    )


def _step_line(i: int, step: dict) -> str:
    mark = "ok  " if step["ok"] else "FAIL"
    return f"{mark} {i} {step['step']:<16} {step['seconds']:6.2f}s  {step['detail']}"


def format_report(report: dict) -> list[str]:
    lines = [_tpm_line(report)] if report["tpm"] else []
    for i, step in enumerate(report["steps"], 1):
        lines.append(_step_line(i, step))
    if report["passed"]:
        count = len(report["steps"])
        lines.append(
            f"selftest passed: {count} of {count} steps. The scratch "
            "directory is removed; the kernel's data and key were not read."
        )
    else:
        reason = report.get("error") or "a step failed"
        lines.append(f"selftest FAILED: {reason}.")
    return lines
