"""Master key sealed to a TPM 2.0 through the tpm2-tools command line.

The key is sealed in a keyedhash object under an ECC P-256 storage primary in
the owner hierarchy. The primary is recreated from a pinned template on every
use, so nothing is written to TPM NV memory and all objects are transient. The
sealed public and private parts are kept in <keys dir>/master.key.sealed.

The key passes through tool stdin and stdout only: never argv, never a file,
never a log line or an exception. A sealed key is bound to the chip's owner
seed. A replaced board or a reset owner hierarchy makes it unrecoverable
without a recovery bundle.
"""

import base64
import binascii
import contextlib
import grp
import hmac
import json
import math
import os
import pwd
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import final

from cryptography.fernet import Fernet

from .keys import (
    PROVIDER_ENV,
    SEALED_NAME,
    KeyNotProvisionedError,
    KeyProvider,
    KeyProviderError,
    _sync_directory,
    _write_synced,
    make_private_dir,
    publish_new_file,
    validate_key,
)

TCTI_ENV = "NGARI_TPM_TCTI"
TIMEOUT_ENV = "NGARI_TPM_TIMEOUT"
DEFAULT_TCTI = "device:/dev/tpmrm0"
DEFAULT_TIMEOUT = 30.0
FORMAT_VERSION = 1

# Pinned so that a tpm2-tools upgrade cannot change the parent and orphan the
# sealed key. Changing any of these values orphans every key sealed before.
PRIMARY_TEMPLATE = (
    "-C", "o", "-g", "sha256", "-G", "ecc256:null:aes128cfb", "-a",
    "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt",
)  # fmt: skip
SEALED_ATTRIBUTES = "fixedtpm|fixedparent|userwithauth|noda"
# With a PCR policy the key opens only through a policy session: no auth value.
POLICY_ATTRIBUTES = "fixedtpm|fixedparent|noda"
PCRS_ENV = "NGARI_TPM_PCRS"
_PCRS = re.compile(r"sha256:(?:[0-9]|1[0-9]|2[0-3])(?:,(?:[0-9]|1[0-9]|2[0-3]))*")

TOOLS = (
    "tpm2_createprimary",
    "tpm2_readpublic",
    "tpm2_create",
    "tpm2_load",
    "tpm2_unseal",
    "tpm2_flushcontext",
    "tpm2_startauthsession",
    "tpm2_policypcr",
    "tpm2_getcap",
)

_PROPERTY = re.compile(
    r"^(TPM2_PT_[A-Z0-9_]+):\n\s+raw: (\S+)(?:\n\s+value: (.*))?", re.MULTILINE
)


_BANK = re.compile(r"^\s*-\s*(\w+):\s*\[([^\]]*)\]", re.MULTILINE)


def parse_pcr_banks(getcap: str) -> list[str]:
    """The PCR banks with at least one PCR allocated, from `tpm2_getcap pcrs`.
    A bank listed with an empty selection is not allocated."""
    return [bank for bank, pcrs in _BANK.findall(getcap) if pcrs.strip()]


def missing_pcr_bank(pcrs: str | None, banks: list[str]) -> str | None:
    """Why a PCR selection cannot be used on a TPM with these allocated banks,
    or None. Some chips leave a bank, often sha256, unallocated."""
    if not pcrs:
        return None
    bank = pcrs.split(":", 1)[0]
    if bank in banks:
        return None
    return (
        f"the TPM has no allocated {bank} PCR bank, so a {bank} PCR policy cannot "
        f"be used (allocated: {', '.join(banks) or 'none'})"
    )


def parse_identity(getcap: str) -> dict:
    """Maker, model and firmware from `tpm2_getcap properties-fixed` output.
    Firmware is reported as raw words: their layout is vendor-specific."""
    props = {
        name: (raw, (value or "").strip().strip('"'))
        for name, raw, value in _PROPERTY.findall(getcap)
    }

    def value(name: str) -> str:
        return props.get(name, ("", ""))[1]

    vendor = "".join(value(f"TPM2_PT_VENDOR_STRING_{i}") for i in range(1, 5))
    return {
        "manufacturer": value("TPM2_PT_MANUFACTURER"),
        "vendor": vendor.strip(),
        "family": value("TPM2_PT_FAMILY_INDICATOR"),
        "revision": value("TPM2_PT_REVISION"),
        "firmware": " ".join(
            props[name][0]
            for name in ("TPM2_PT_FIRMWARE_VERSION_1", "TPM2_PT_FIRMWARE_VERSION_2")
            if name in props
        ),
    }


def parse_pcrs(value: str | None) -> str | None:
    """A PCR selection in the sha256 bank ("sha256:7" or "sha256:0,7"), or None.

    On a VM or container the TPM's PCRs are the host's boot measurements, so a
    host firmware or kernel update changes them. A key sealed against them then
    comes back only from a recovery bundle.
    """
    if value is None or not value.strip():
        return None
    value = value.strip().lower()
    if not _PCRS.fullmatch(value):
        raise KeyProviderError(
            f"PCR selection must look like sha256:7 or sha256:0,7 (PCRs 0-23), "
            f"got {value!r}"
        )
    indexes = value.split(":", 1)[1].split(",")
    if len(set(indexes)) != len(indexes):
        raise KeyProviderError(f"PCR selection repeats a PCR: {value!r}")
    return value


def resource_managed(tcti: str) -> bool:
    """True when transient objects die with the client: the kernel resource
    manager (/dev/tpmrm*) or tpm2-abrmd. Everything else is flushed by hand."""
    kind, _, conf = tcti.partition(":")
    if kind == "tabrmd":
        return True
    return kind == "device" and Path(conf.split(",")[0]).name.startswith("tpmrm")


def device_problem(tcti: str) -> str | None:
    """Why this process cannot open a device TCTI's path, or None. Checks
    the file only; nothing is sent to a TPM."""
    kind, _, conf = tcti.partition(":")
    if kind != "device":
        return None
    path = Path(conf or "/dev/tpm0")  # the device TCTI's own default
    try:
        st = path.stat()
    except FileNotFoundError:
        return (
            f"{path} does not exist: no TPM is exposed there (in a container, pass "
            "the host's /dev/tpmrm0 through; on a board, enable the TPM or fTPM)"
        )
    except OSError as exc:
        return f"cannot inspect {path}: {exc.strerror}"
    if os.access(path, os.R_OK | os.W_OK):
        return None
    owner = _name(pwd.getpwuid, st.st_uid)
    group = _name(grp.getgrgid, st.st_gid)
    return (
        f"this process (uid {os.getuid()}) cannot open {path} ({owner}:{group}, "
        f"mode {oct(st.st_mode & 0o777)}); run the kernel as a user in the "
        f"{group} group, or as {owner}"
    )


def _name(lookup, number: int) -> str:
    try:
        return lookup(number)[0]
    except KeyError:
        return str(number)


def _error_line(stderr: bytes, secret: bytes | None) -> str:
    """The tool's own ERROR line, printable and short, with no key bytes."""
    text = stderr.decode("utf-8", "replace")
    if secret:
        text = text.replace(secret.decode("ascii", "replace"), "[key]")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    errors = [ln for ln in lines if ln.startswith("ERROR")]
    line = (errors or lines or ["no error output"])[0]
    line = line.removeprefix("ERROR:").strip()
    return "".join(ch if ch.isprintable() else "?" for ch in line)[:200]


class TPMKeyProvider(KeyProvider):
    """Fernet key sealed to a TPM 2.0. Fails closed: there is no fallback."""

    name = "tpm2"

    def __init__(
        self,
        keys_dir: Path,
        *,
        tcti: str = DEFAULT_TCTI,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.keys_dir = Path(keys_dir)
        self.sealed_file = self.keys_dir / SEALED_NAME
        self.plain_file = self.keys_dir / "master.key"
        self.tcti = tcti
        self.timeout = timeout
        self._unsealed = False

    @classmethod
    def from_env(
        cls, keys_dir: Path, environ: Mapping[str, str] | None = None
    ) -> "TPMKeyProvider":
        env = os.environ if environ is None else environ
        tcti = env.get(TCTI_ENV, "").strip() or DEFAULT_TCTI
        raw = env.get(TIMEOUT_ENV, "").strip()
        try:
            timeout = float(raw) if raw else DEFAULT_TIMEOUT
        except ValueError:
            timeout = -1.0
        if not (math.isfinite(timeout) and timeout > 0):
            raise KeyProviderError(
                f"{TIMEOUT_ENV} must be a positive number of seconds, got {raw!r}"
            )
        return cls(keys_dir, tcti=tcti, timeout=timeout)

    def __repr__(self) -> str:
        return f"TPMKeyProvider({str(self.keys_dir)!r}, tcti={self.tcti!r})"

    # -- KeyProvider ---------------------------------------------------------

    def load_or_create(self, *, may_create: bool = True) -> bytes:
        blob = self._read_blob()
        if blob is not None:
            key = self._unseal(blob)
        elif self.plain_file.exists():
            raise KeyProviderError(
                f"a plaintext key exists at {self.plain_file} and nothing is sealed "
                "yet. Refusing to create a second key. Seal the existing key with "
                f"`python -m core.kernel keys migrate`, or set {PROVIDER_ENV}=file "
                "to keep using it."
            )
        elif not may_create:
            raise KeyNotProvisionedError(f"no sealed key at {self.sealed_file}")
        else:
            key = self._provision()
        self._unsealed = True
        return key

    def describe(self) -> dict:
        try:
            mode = self.sealed_file.stat().st_mode & 0o777
        except OSError:
            mode = None
        plaintext = self.plain_file.exists()
        return {
            "provider": self.name,
            "hardware_bound": self.tcti.partition(":")[0] in ("device", "tabrmd"),
            "at_rest": "sealed to a TPM 2.0 owner-hierarchy key, bound to this chip",
            "tcti": self.tcti,
            "sealed_file": str(self.sealed_file),
            "sealed_file_mode": oct(mode) if mode is not None else None,
            "plaintext_key_present": plaintext,
            "pcrs": self._pcrs_quiet(),
            "unsealed_this_process": self._unsealed,
            "ok": mode == 0o600 and not plaintext and self._unsealed,
        }

    def identity(self) -> dict:
        """The TPM's maker, model, firmware and allocated PCR banks. Reads
        fixed properties and the PCR allocation only."""
        with self._session() as run:
            fixed = run("tpm2_getcap", "properties-fixed", secret_out=True)
            banks = run("tpm2_getcap", "pcrs", secret_out=True)
        facts = parse_identity(fixed.decode(errors="replace"))
        facts["pcr_banks"] = parse_pcr_banks(banks.decode(errors="replace"))
        return facts

    def _pcrs_quiet(self) -> str | None:
        try:
            return self.pcrs()
        except KeyProviderError:
            return None

    # -- sealing -------------------------------------------------------------

    def _provision(self) -> bytes:
        """Seal a new key. If another process published first, its key wins."""
        key, _ = self.seal(Fernet.generate_key())
        return key

    def seal(self, key: bytes, pcrs: str | None = None) -> tuple[bytes, bool]:
        """Seal key, prove it unseals, then publish the blob.

        Returns the key now in effect and whether this call wrote the blob.
        When a blob already exists it is left alone and its key is returned.
        """
        data = self._sealed_blob(key, parse_pcrs(pcrs))
        try:
            make_private_dir(self.keys_dir)
            created = publish_new_file(self.sealed_file, data)
        except OSError as exc:
            raise KeyProviderError(
                f"cannot write {self.sealed_file}: {exc.strerror}"
            ) from None
        if created:
            return key, True
        return self.unseal(), False

    def reseal(self, key: bytes, pcrs: str | None) -> None:
        """Replace the blob with key sealed under a new PCR selection. The old
        blob must already hold key; the new one is proven before it replaces
        the old one in a single rename."""
        if not hmac.compare_digest(self.unseal(), key):
            raise KeyProviderError(f"{self.sealed_file} holds a different key")
        self._publish_over(self._sealed_blob(key, parse_pcrs(pcrs)))

    def seal_over(self, key: bytes, pcrs: str | None, keep_old_as: Path) -> None:
        """Replace a sealed file that does not unseal here with key sealed
        afresh, keeping the old file under keep_old_as. The new blob is
        proven first, the old file gets its second name, and then one rename
        swaps the new blob in: at no moment is there no sealed file, so an
        interrupted run, or a kernel starting meanwhile, still fails closed
        on the old one instead of provisioning a new key."""
        data = self._sealed_blob(key, parse_pcrs(pcrs))
        try:
            if keep_old_as.exists():
                if not os.path.samefile(keep_old_as, self.sealed_file):
                    raise KeyProviderError(f"{keep_old_as} already exists")
            else:
                os.link(self.sealed_file, keep_old_as)
        except OSError as exc:
            raise KeyProviderError(
                f"cannot keep {keep_old_as}: {exc.strerror}"
            ) from None
        try:
            self._publish_over(data)
        except BaseException:
            with contextlib.suppress(OSError):
                if os.path.samefile(keep_old_as, self.sealed_file):
                    os.unlink(keep_old_as)
            raise

    def _publish_over(self, data: bytes) -> None:
        """Put data in place of the sealed file in a single rename, synced."""
        tmp = self.sealed_file.with_name(f".{self.sealed_file.name}.{os.getpid()}.new")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            _write_synced(fd, data)
            os.replace(tmp, self.sealed_file)
            _sync_directory(self.keys_dir)
        except OSError as exc:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise KeyProviderError(
                f"cannot write {self.sealed_file}: {exc.strerror}"
            ) from None

    def _sealed_blob(self, key: bytes, pcrs: str | None) -> bytes:
        validate_key(key)
        with self._session() as run:
            parent = self._primary(run)
            if pcrs:
                run("tpm2_startauthsession", "-S", "trial.ctx")
                run("tpm2_policypcr", "-Q", "-S", "trial.ctx", "-l", pcrs,
                    "-L", "policy.digest")  # fmt: skip
                policy = ("-a", POLICY_ATTRIBUTES, "-L", "policy.digest")
            else:
                policy = ("-a", SEALED_ATTRIBUTES)
            run(
                "tpm2_create", "-Q", "-C", "primary.ctx", "-g", "sha256", *policy,
                "-i", "-", "-u", "sealed.pub", "-r", "sealed.priv",
                stdin=key, secret=key,
            )  # fmt: skip
            blob = {
                "version": FORMAT_VERSION,
                "parent": parent,
                "pub": base64.b64encode(run.read("sealed.pub")).decode(),
                "priv": base64.b64encode(run.read("sealed.priv")).decode(),
            }
            if pcrs:
                blob["pcrs"] = pcrs
            check = self._load_and_unseal(run, "sealed.pub", "sealed.priv", pcrs)
        if not hmac.compare_digest(check, key):
            raise KeyProviderError("sealed key did not unseal to the same key")
        return (json.dumps(blob, sort_keys=True) + "\n").encode()

    def pcrs(self) -> str | None:
        """The PCR selection the published blob is bound to, or None."""
        blob = self._read_blob()
        return blob["pcrs"] if blob else None

    def unseal(self) -> bytes:
        """Unseal the published blob, ignoring any plaintext key beside it."""
        blob = self._read_blob()
        if blob is None:
            raise KeyNotProvisionedError(f"no sealed key at {self.sealed_file}")
        return self._unseal(blob)

    def _unseal(self, blob: dict) -> bytes:
        with self._session() as run:
            parent = self._primary(run)
            if not hmac.compare_digest(parent, blob["parent"]):
                raise KeyProviderError(
                    f"{self.sealed_file} was sealed under a different TPM owner "
                    "hierarchy (replaced board, reset TPM, or another machine). The "
                    "key cannot be unsealed here; restore it from a recovery bundle."
                )
            run.write("sealed.pub", blob["pub"])
            run.write("sealed.priv", blob["priv"])
            key = self._load_and_unseal(run, "sealed.pub", "sealed.priv", blob["pcrs"])
        return validate_key(key)

    @staticmethod
    def _primary(run: "_Session") -> str:
        run("tpm2_createprimary", "-Q", *PRIMARY_TEMPLATE, "-c", "primary.ctx")
        run("tpm2_readpublic", "-Q", "-c", "primary.ctx", "-n", "primary.name")
        return run.read("primary.name").hex()

    @staticmethod
    def _load_and_unseal(
        run: "_Session", pub: str, priv: str, pcrs: str | None = None
    ) -> bytes:
        run(
            "tpm2_load", "-Q", "-C", "primary.ctx", "-u", pub, "-r", priv,
            "-c", "sealed.ctx",
        )  # fmt: skip
        if not pcrs:
            return run("tpm2_unseal", "-c", "sealed.ctx", secret_out=True)
        run("tpm2_startauthsession", "--policy-session", "-S", "policy.ctx")
        run("tpm2_policypcr", "-Q", "-S", "policy.ctx", "-l", pcrs)
        return run(
            "tpm2_unseal", "-c", "sealed.ctx", "-p", "session:policy.ctx",
            secret_out=True,
        )  # fmt: skip

    def _read_blob(self) -> dict | None:
        try:
            raw = self.sealed_file.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise KeyProviderError(
                f"cannot read {self.sealed_file}: {exc.strerror}"
            ) from None
        try:
            blob = json.loads(raw)
            if not isinstance(blob, dict) or blob.get("version") != FORMAT_VERSION:
                raise ValueError("unknown format version")
            parsed = {
                "parent": str(bytes.fromhex(blob["parent"]).hex()),
                "pub": base64.b64decode(blob["pub"], validate=True),
                "priv": base64.b64decode(blob["priv"], validate=True),
                "pcrs": parse_pcrs(blob["pcrs"]) if "pcrs" in blob else None,
            }
            if not (parsed["parent"] and parsed["pub"] and parsed["priv"]):
                raise ValueError("empty field")
        except (
            ValueError, KeyError, TypeError, AttributeError, binascii.Error,
            KeyProviderError, RecursionError,
        ) as exc:  # fmt: skip
            raise KeyProviderError(
                f"{self.sealed_file} is not a valid sealed key ({type(exc).__name__})"
            ) from None
        return parsed

    def _session(self) -> "_Session":
        return _Session(self.tcti, self.timeout)


@final
class _Session:
    """One private working directory and an explicit TCTI for a run of tools.
    On TCTIs without a resource manager, transient objects are flushed after
    every tool and on exit, or the TPM runs out of object slots."""

    def __init__(self, tcti: str, timeout: float):
        self.tcti = tcti
        self.timeout = timeout
        self.flush = not resource_managed(tcti)
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("TPM2TOOLS_", "TSS2_", "TPM2_"))
        }
        env.update(TPM2TOOLS_TCTI=tcti, TSS2_LOG="all+NONE", LC_ALL="C")
        self.env = env
        self.paths = {}
        for tool in TOOLS:
            path = shutil.which(tool)
            if path is None:
                raise KeyProviderError(
                    f"{tool} not found on PATH. The tpm2 key provider needs "
                    "tpm2-tools 5.x (Debian and Ubuntu package: tpm2-tools)."
                )
            self.paths[tool] = path

    def __enter__(self) -> "_Session":
        self._tmp = tempfile.TemporaryDirectory(prefix="ngari-tpm-")
        self.dir = Path(self._tmp.name)
        os.chmod(self.dir, 0o700)
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self.flush:
                try:
                    # Sessions too: a resource manager flushes them when the
                    # client closes, nothing else does.
                    for scope in ("-t", "-l", "-s"):
                        self._exec("tpm2_flushcontext", (scope,), None, None)
                except KeyProviderError:
                    if exc[0] is None:
                        raise
        finally:
            self._tmp.cleanup()

    def __call__(
        self,
        tool: str,
        *args: str,
        stdin: bytes | None = None,
        secret: bytes | None = None,
        secret_out: bool = False,
    ) -> bytes:
        out = self._exec(tool, args, stdin, secret)
        if self.flush:
            self._exec("tpm2_flushcontext", ("-t",), None, None)
        return out if secret_out else b""

    def _exec(self, tool, args, stdin, secret) -> bytes:
        try:
            proc = subprocess.run(
                [self.paths[tool], *args],
                input=stdin if stdin is not None else b"",
                capture_output=True,
                cwd=self.dir,
                env=self.env,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise KeyProviderError(
                f"{tool} did not finish within {self.timeout:g}s (TCTI {self.tcti})"
            ) from None
        except OSError as exc:
            raise KeyProviderError(f"cannot run {tool}: {exc.strerror}") from None
        if proc.returncode != 0:
            reason = _error_line(proc.stderr, secret)
            # TSS2_LOG is off, so a TCTI that cannot be opened only says
            # "Could not load tcti". Find out why for a device TCTI.
            problem = (
                device_problem(self.tcti)
                if b"Could not load tcti" in proc.stderr
                else None
            )
            if problem:
                reason = f"{reason}; {problem}"
            raise KeyProviderError(
                f"{tool} failed (TCTI {self.tcti}): {reason}"
            ) from None
        return proc.stdout

    def read(self, name: str) -> bytes:
        return (self.dir / name).read_bytes()

    def write(self, name: str, data: bytes) -> None:
        fd = os.open(self.dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
