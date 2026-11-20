"""
NS-BOS Kernel - Sovereign Data Plane
Encrypted local storage, audit logging, and data sovereignty enforcement.
Zero external telemetry.
"""

import base64
import collections
import contextlib
import dataclasses
import errno
import fcntl
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .keys import (
    PROVIDER_ENV,
    FileKeyProvider,
    KeyNotProvisionedError,
    KeyProvider,
    KeyProviderError,
    _sync_directory,
    _write_synced,
    make_private_dir,
    provider_from_env,
    publish_new_file,
    validate_key,
)
from .redact import redact, redact_values
from .state import StateCipher

__all__ = [
    "GENESIS_HASH",
    "AuditEntry",
    "FileKeyProvider",
    "KeyProvider",
    "KeyProviderError",
    "SovereignDataPlane",
    "append_audit",
    "audit_anchor",
    "audit_key",
    "check_audit_chain",
    "scan_audit_chain",
]

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
AUDIT_KEY_INFO = b"ngari-audit-v1"
# key_provider is written by every data plane start, so it always carries a
# MAC: a log with an unkeyed one was rewritten, or predates keyed entries and
# was edited. legacy_history is written by `audit adopt-legacy`: a keyed entry
# that vouches for the entries written before the log had a key (v0.1.0
# history). Without it, unkeyed history does not verify: anyone who can write
# the file could strip every MAC, drop the keyed entries and rewrite the rest.
LEGACY_HISTORY = "legacy_history"
ALWAYS_KEYED = frozenset({"key_provider", LEGACY_HISTORY})
AIR_GAP_ENV = "NGARI_AIR_GAP"
_AIR_GAP_OFF = frozenset({"0", "false", "no", "off"})
_AIR_GAP_ON = frozenset({"", "1", "true", "yes", "on"})


def air_gap_enabled(environ=None) -> bool:
    """On unless NGARI_AIR_GAP is 0, false, no or off (case and whitespace
    ignored). Any other value keeps it on and logs one warning naming the
    accepted values."""
    env = os.environ if environ is None else environ
    raw = (env.get(AIR_GAP_ENV) or "").strip().lower()
    if raw in _AIR_GAP_OFF:
        return False
    if raw not in _AIR_GAP_ON:
        logger.warning(
            "%s=%r is not a known value; air gap stays on (0, false, no or off turn it off)",
            AIR_GAP_ENV,
            raw[:32],
        )
    return True


PROC_NET_DEV = Path("/proc/net/dev")


def _host_interfaces() -> dict | None:
    """Receive and transmit byte counters of every network interface but lo,
    from /proc/net/dev, or None where that file is missing, unreadable or
    has no line in the Linux format. A line that does not parse is skipped,
    not the whole file. Host-wide: every process on the machine counts."""
    try:
        lines = PROC_NET_DEV.read_text().splitlines()[2:]
    except (OSError, ValueError):
        return None
    found, bad = {}, 0
    for line in lines:
        name, colon, rest = line.partition(":")
        name, fields = name.strip(), rest.split()
        if not line.strip():
            continue
        try:
            if not colon or not name or len(fields) < 9:
                raise ValueError(line)
            counters = {"rx_bytes": int(fields[0]), "tx_bytes": int(fields[8])}
        except ValueError:
            bad += 1
            continue
        if name != "lo":
            found[name] = counters
    return None if bad and not found else found


def _egress_since(baseline: dict | None, now: dict | None) -> dict | None:
    """What each interface's counters moved by since baseline, or None when
    either side is None. An interface that was not there counts from zero;
    one that has gone since is listed as gone, since it may have carried
    traffic; a counter that went down was reset (the interface came back, a
    driver reloaded), and what it holds now is the least that moved."""
    if baseline is None or now is None:
        return None
    zero = {"rx_bytes": 0, "tx_bytes": 0}
    moved = {}
    for name, counters in now.items():
        before, entry = baseline.get(name, zero), {}
        for k in zero:
            delta = counters[k] - before[k]
            if delta < 0:
                entry["reset"] = True
                delta = counters[k]
            entry[k] = delta
        moved[name] = entry
    for name in sorted(baseline.keys() - now.keys()):
        moved[name] = {"gone": True}
    return moved


# What JSON treats as whitespace. bytes.strip() would also drop \x0b and
# \x0c, which JSON does not, and the two must agree on what a blank line is.
_WS = b" \t\r\n"
# Recorded by an append that found the log ending in bytes that are not an
# entry (a write cut short by a crash or power loss), after keeping them aside.
TAIL_SET_ASIDE = "audit_tail_set_aside"
# Written by `keys`, `records` and `agents` commands, which record before they
# may read the key or never read it (pin-operator, set-roles, sign, sponsor),
# and by a tail repair during one. An esignature entry carries the card's own
# signature, and an agent_sponsored entry names a manifest that carries one.
KEYLESS_ACTIONS = frozenset(
    {
        "operator_auth",
        "operator_pinned",
        "roles_changed",
        "esignature",
        "esignature_refused",
        "agent_sponsored",
        "agent_sponsor_refused",
        TAIL_SET_ASIDE,
    }
)


def _read_config(path: Path) -> dict | None:
    """A JSON object from path, or None if it is unreadable or not an object."""
    try:
        config = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError):  # also nested too deep
        return None
    return config if isinstance(config, dict) else None


def _replace_file(path: Path, data: bytes) -> None:
    """Write data to path through a synced temporary file and a rename, so a
    crash leaves the old file or the new one."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_synced(fd, data)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    _sync_directory(path.parent)


def audit_key(master_key: bytes) -> bytes:
    """The audit MAC key: HKDF-SHA256 of the raw master key, info
    ngari-audit-v1. Separate from the encryption keys inside Fernet."""
    raw = base64.urlsafe_b64decode(master_key)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=AUDIT_KEY_INFO
    ).derive(raw)


def _entry_mac(mac_key: bytes, entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k not in ("hash", "mac")}
    data = json.dumps(body, sort_keys=True).encode()
    return hmac.new(mac_key, data, hashlib.sha256).hexdigest()


@dataclass
class AuditEntry:
    timestamp: str
    action: str
    actor: str
    resource: str
    details: dict
    hash: str
    prev_hash: str = GENESIS_HASH


# errno values for a filesystem that has no hard links (vfat, some FUSE mounts).
_NO_LINKS = frozenset({errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS})


def _keep_aside(path: Path, kind: str) -> Path:
    """Move path to <name>.<kind>-<UTC time>, never over an existing file: a
    second file kept aside in the same second gets -1, -2 and so on, so no
    earlier copy is lost. A hard link takes the new name or fails, so no
    other process can race it; where the filesystem has no hard links, the
    name is checked first."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for n in range(1000):
        aside = path.with_name(f"{path.name}.{kind}-{stamp}" + (f"-{n}" if n else ""))
        try:
            os.link(path, aside)
        except FileExistsError:
            continue
        except OSError as exc:
            if exc.errno not in _NO_LINKS:
                raise
            if os.path.lexists(aside):
                continue
            os.replace(path, aside)
            return aside
        os.unlink(path)
        return aside
    raise FileExistsError(f"no free name to keep {path.name} aside")


class SovereignDataPlane:
    """
    Sovereign data plane with encryption, audit logging,
    and data sovereignty enforcement.
    """

    def __init__(
        self,
        data_dir: str | None = None,
        key_provider: KeyProvider | None = None,
        *,
        sealed_state: int = 0,
        state_key_ids=(),
    ):
        """sealed_state and state_key_ids describe agent state encrypted under
        the master key outside this directory (agent_runtime.sealed_state):
        with any, no new key is created, and a key that is not theirs stops
        the start before anything is written."""
        base = (
            data_dir
            or os.environ.get("NGARI_DATA_DIR")
            or str(Path.home() / ".ngari" / "kernel")
        )
        self.data_dir = Path(base)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.encrypted_dir = self.data_dir / "encrypted"
        self.encrypted_dir.mkdir(exist_ok=True)

        self.audit_log = self.data_dir / "audit" / "sovereign_audit.log"
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)

        # Where the file provider keeps its key; other providers do not use it.
        self.key_file = self.data_dir / "keys" / "master.key"
        self.key_file.parent.mkdir(parents=True, exist_ok=True)

        # Owner only: file names and sizes in encrypted/ are visible to anyone
        # who can list the directory, even though the contents are not.
        for directory in (self.data_dir, self.encrypted_dir, self.audit_log.parent):
            if directory.stat().st_mode & 0o077:
                os.chmod(directory, 0o700)
        # A delete cut short after its rename leaves the value under a name no
        # key has; finish it, so a deleted value does not stay on disk.
        for left in sorted(self.encrypted_dir.glob(f"{self._DELETING}*")):
            if self._LEFT_ASIDE.fullmatch(left.name):  # not a key's .enc file
                self._erase(left)

        self.key_provider = (
            key_provider
            if key_provider is not None
            else provider_from_env(self.key_file.parent)
        )
        # What the last audit check that passed covered; see _check_appended.
        self._audit_mark = None
        self._sealed_state = sealed_state
        self._state_key_ids = set(state_key_ids)
        self.air_gap = air_gap_enabled()
        self._net_baseline = _host_interfaces()
        self.fernet = self._load_or_create_key()
        self._audit_key_provider()
        self._enforce_sovereignty()

    def _load_or_create_key(self) -> Fernet:
        """Get the master key from the provider. A new key is only created
        when no encrypted file exists that it would orphan."""
        stored = sum(1 for _ in self.encrypted_dir.glob("*.enc")) + self._sealed_state
        try:
            key = self.key_provider.load_or_create(may_create=stored == 0)
        except KeyNotProvisionedError:
            noun = "file" if stored == 1 else "files"
            raise KeyProviderError(
                f"key provider {self.key_provider.name!r} has no key, and encrypted "
                f"data exists ({stored} {noun}). Refusing to create a new key. "
                f"Restore the key, or set {PROVIDER_ENV} to the provider that "
                "holds it."
            ) from None
        self._audit_mac_key = audit_key(validate_key(key))
        self.state_cipher = StateCipher(key)
        others = sorted(self._state_key_ids - {self.state_cipher.key_id})
        if others:
            raise KeyProviderError(
                f"agent state was encrypted under another master key (key id "
                f"{', '.join(others)}; the key from provider {self.key_provider.name!r} "
                f"has {self.state_cipher.key_id}). Refusing to start. Restore the key "
                f"it was written under, or set {PROVIDER_ENV} to the provider that "
                "holds it."
            )
        return Fernet(key)

    def _audit_key_provider(self) -> None:
        """Record which provider holds the key at this start, so a switch from
        one provider to another shows in the chain. Only two facts every
        provider reports, plus whether air-gap mode was on at this start, as
        plain booleans: anything else a provider puts in describe() stays out
        of the log."""
        facts = self.key_provider.describe()
        self._audit(
            "key_provider",
            "system",
            self.key_provider.name,
            {
                "hardware_bound": bool(facts.get("hardware_bound")),
                "ok": bool(facts.get("ok")),
                "air_gap": self.air_gap,
            },
        )

    def _enforce_sovereignty(self):
        """Switch off external telemetry in telemetry_config.json. A file that
        cannot be read is renamed aside, never deleted, and replaced with one
        that has telemetry off: a crash during an earlier rewrite must not
        stop the data plane from starting."""
        telemetry_file = self.data_dir / "telemetry_config.json"
        if not telemetry_file.exists():
            return
        config = _read_config(telemetry_file)
        if config is None:
            aside = _keep_aside(telemetry_file, "corrupt")
            logger.error(
                "%s unreadable; kept as %s, telemetry set off",
                telemetry_file.name,
                aside.name,
            )
            config = {}
        elif not config.get("external_telemetry", False):
            return
        else:
            logger.warning("External telemetry detected - disabling")
        config["external_telemetry"] = False
        _replace_file(telemetry_file, json.dumps(config).encode())

    # NAME_MAX is 255 bytes on Linux filesystems, and ".enc" takes four.
    MAX_KEY_BYTES = 251

    def _path(self, key: str) -> Path:
        """The file for key, which must stay a plain name inside encrypted/."""
        if not isinstance(key, str):
            raise TypeError(f"key must be a str, not {type(key).__name__}")
        if not key or "/" in key or "\0" in key:
            raise ValueError(f"invalid key name {key[:64]!r}: empty, '/' or NUL")
        try:
            # Strict: a lone surrogate maps to the file name of some other
            # key ("\udcc3\udca9" is the bytes of "é"), so two keys would
            # share one file.
            size = len(key.encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError(f"key name {key[:64]!r} is not UTF-8 text") from None
        if size > self.MAX_KEY_BYTES:
            raise ValueError(f"key name longer than {self.MAX_KEY_BYTES} bytes")
        return self.encrypted_dir / f"{key}.enc"

    def store_encrypted(self, key: str, data: Any) -> str:
        """Store data encrypted on disk, replacing any old value atomically.

        The token is written and synced under a temporary name, renamed over
        the old file, then the directory is synced. A crash at any point
        leaves the old value or the new one, never a partial file.
        """
        file_path = self._path(key)
        data_json = json.dumps(data, default=str).encode()
        encrypted = self.fernet.encrypt(data_json)

        tmp = self.encrypted_dir / f".tmp-{secrets.token_hex(8)}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            _write_synced(fd, encrypted)
            os.replace(tmp, file_path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        _sync_directory(self.encrypted_dir)

        self._audit("store_encrypted", "system", key, {"size": len(encrypted)})
        return str(file_path)

    def retrieve_decrypted(self, key: str) -> Any | None:
        """Retrieve and decrypt data"""
        file_path = self._path(key)
        try:  # no exists() first: a key deleted in between is just absent
            with open(file_path, "rb") as f:
                encrypted = f.read()
        except FileNotFoundError:
            return None

        try:
            decrypted = self.fernet.decrypt(encrypted)
            data = json.loads(decrypted)
            self._audit("retrieve_decrypted", "system", key, {})
            return data
        except (InvalidToken, ValueError, TypeError) as e:
            logger.error(f"Decryption failed for {key}: {e}")
            return None

    # Where a value goes while it is erased: a name no key can have (it is
    # not <key>.enc), so a delete cut short never leaves random bytes under
    # the key's own name.
    _DELETING = ".deleting-"
    # Exactly what delete() names a file it sets aside. A key may start with
    # ".deleting-" too, and its file, "<key>.enc", must never match.
    _LEFT_ASIDE = re.compile(r"\.deleting-[0-9a-f]{16}")

    def delete(self, key: str) -> bool:
        """Overwrite the file contents with random bytes, then unlink.

        Best effort only. Journaling, copy-on-write filesystems, SSD wear
        leveling and snapshots can retain the old blocks. The data is
        encrypted at rest, so exposure is bounded by the master key.

        The file is renamed aside first and the directory synced, so a delete
        stopped at any point leaves the old value under its name or nothing
        there; a value left aside is erased at the next start.
        """
        file_path = self._path(key)
        aside = self.encrypted_dir / f"{self._DELETING}{secrets.token_hex(8)}"
        try:
            os.rename(file_path, aside)
        except FileNotFoundError:  # not stored, or deleted meanwhile
            return False
        _sync_directory(self.encrypted_dir)
        self._erase(aside)
        self._audit("delete", "system", key, {})
        return True

    def _erase(self, path: Path) -> None:
        """Overwrite path with random bytes, synced, then unlink it and sync
        the directory. A symbolic link found there is removed, and what it
        points to, outside the store, is left alone. A file already gone is
        erased: another process opening the same store sweeps files set
        aside, and may get to this one first."""
        try:
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        except FileNotFoundError:
            return
        except OSError as exc:
            if exc.errno != errno.ELOOP:  # ELOOP: a symbolic link
                raise
        else:
            with os.fdopen(fd, "r+b") as f:
                f.write(os.urandom(os.fstat(f.fileno()).st_size))
                f.flush()
                os.fsync(f.fileno())
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        _sync_directory(self.encrypted_dir)

    @staticmethod
    def _entry_hash(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def record(self, action: str, actor: str, resource: str, details: dict) -> None:
        """Append a keyed entry for something the kernel above this plane did.
        The arguments are checked, and the details dumped once, before the log
        is locked, so a bad value raises here and writes nothing."""
        for name, value in (
            ("action", action),
            ("actor", actor),
            ("resource", resource),
        ):
            if not isinstance(value, str) or not value:
                raise TypeError(f"audit {name} must be a non-empty string")
        if not isinstance(details, dict):
            raise TypeError("audit details must be a dict")
        if action in ALWAYS_KEYED | KEYLESS_ACTIONS:
            raise ValueError(
                f"audit action {action!r} is written by the data plane only"
            )
        # The entry is hashed as a reader will see it: JSON turns keys into
        # strings, which sort differently from the ints or bools they were, so
        # an entry hashed as given would never verify. A value JSON cannot
        # hold raises here, before anything is written.
        details = json.loads(json.dumps(details, sort_keys=True))
        self._audit(action, actor, resource, details)

    def audit_tail(self) -> str:
        """Hash of the last audit entry, or GENESIS_HASH for an empty log: the
        value `audit anchor` would print, for checking a status snapshot
        against an anchor kept off the machine."""
        if not self.audit_log.exists():
            return GENESIS_HASH
        with _reading(self.audit_log) as f:
            return _last_entry(f)[1]

    def _audit(self, action: str, actor: str, resource: str, details: dict):
        """Append an audit entry chained to the previous entry's hash"""
        append_audit(
            self.audit_log, action, actor, resource, details, self._audit_mac_key
        )

    def verify_audit_integrity(self, anchor: dict | None = None) -> bool:
        """Verify every entry hash, the chain linking them, and every MAC.

        Detects edited, reordered, inserted and mid-log deleted entries, and
        removal of the head, up to the last keyed entry. MACs are keyed from
        the master key, so a writer of the file without the key cannot
        rebuild a keyed log; keyless entries after the last keyed one (from
        `keys` and `records` commands) can be rewritten without it.
        Truncating the tail, and that rewrite, are detected only against an
        anchor kept off the machine (see `audit anchor`).

        Without an anchor, a later call checks only the entries added since
        the last one that passed, after hashing the bytes that one checked to
        prove they are unchanged. The answer is the full check's.
        """
        if anchor is None:
            reason, self._audit_mark = _check_appended(
                self.audit_log, self._audit_mac_key, self._audit_mark
            )
        else:
            reason = check_audit_chain(self.audit_log, self._audit_mac_key, anchor)
        if reason:
            logger.error("Audit integrity violation: %s", reason)
        return reason is None

    def get_audit_log(self, limit: int = 100) -> list:
        """The last `limit` audit entries, oldest first. The log is read one
        line at a time and only the entries returned are parsed, so memory
        stays bounded by `limit`, not by the size of the log."""
        if limit <= 0 or not self.audit_log.exists():
            return []
        with _reading(self.audit_log) as f:
            last = collections.deque(_entry_lines(f), maxlen=limit)
        return [json.loads(line) for line in last]

    def audit_entry_count(self) -> int:
        """Number of entries in the audit log, counted without loading it."""
        if not self.audit_log.exists():
            return 0
        with _reading(self.audit_log) as f:
            return sum(1 for _ in _entry_lines(f))

    def export_compliance_report(self) -> dict:
        """Export compliance report for audit purposes.

        Every field is measured at call time.
        """
        audit_ok = self.verify_audit_integrity()
        key = self.key_provider.describe()
        telemetry_file = self.data_dir / "telemetry_config.json"
        telemetry_on = False
        if telemetry_file.exists():
            config = _read_config(telemetry_file)
            # Unreadable since start: neither on nor off can be confirmed.
            telemetry_on = (
                None
                if config is None
                else bool(config.get("external_telemetry", False))
            )
        sovereign = audit_ok and bool(key.get("ok")) and telemetry_on is False
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_sovereignty": "enforced" if sovereign else "violations_detected",
            "external_telemetry": telemetry_on,
            "encryption": "AES-128-CBC + HMAC-SHA256 (Fernet)",
            "audit_entries": self.audit_entry_count(),
            "audit_integrity": audit_ok,
            "key_provider": key,
            "key_file_mode": key.get("key_file_mode"),
            "data_directory": str(self.data_dir),
            "encrypted_files": len(list(self.encrypted_dir.glob("*.enc"))),
            "air_gap": self._air_gap_report(),
            "audit_tail": self.audit_tail(),
        }

    def _air_gap_report(self) -> dict:
        """The setting now, and what the host's network counters did since
        this data plane started. The counters are shared with every process on
        the machine; this measures, it does not verify anything."""
        now = _host_interfaces()
        return {
            "on": air_gap_enabled(),
            "source": "environment" if AIR_GAP_ENV in os.environ else "default",
            "host_interfaces": now,
            "since_start": _egress_since(self._net_baseline, now),
        }


def append_audit(
    audit_log: Path,
    action: str,
    actor: str,
    resource: str,
    details: dict,
    mac_key: bytes | None = None,
) -> None:
    """Append one entry to the chain in audit_log, under an exclusive lock.
    Needs no key, so commands that must not load the key can still record.

    A log that ends in bytes that are not an entry, as a write cut short by
    a crash or power loss leaves, would otherwise stop every append and so
    the kernel. Those bytes are copied to a new file beside the log, then
    cut from it, and an audit_tail_set_aside entry records their size,
    SHA-256 and where they are kept. Nothing before the last entry that
    parses is touched.

    The resource and every string in details are redacted first (email
    addresses, phone, SSN and card numbers, street addresses; see redact.py),
    before the entry is hashed: the log is kept for decades and never
    deleted, so PII must not reach it."""
    resource = redact(resource)
    details = redact_values(details)
    audit_log = Path(audit_log)
    make_private_dir(audit_log.parent)
    fd = os.open(audit_log, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a+b") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        end, prev, terminated = _last_entry(f)
        size = f.seek(0, os.SEEK_END)
        f.seek(end)
        tail = f.read(size - end)
        if tail.strip(_WS):
            prev = _set_aside_tail(f, audit_log, end, tail, prev, mac_key)
        elif not terminated:
            f.write(b"\n")  # a whole last entry, missing only its newline
        _write_entry(f, prev, action, actor, resource, details, mac_key)
        f.flush()
        os.fsync(f.fileno())


@contextlib.contextmanager
def _reading(audit_log: Path):
    """The log open for reading under a shared lock. append_audit writes under
    the exclusive one, so a reader never sees a line half written: Linux makes
    the bytes of one write() visible page by page."""
    with open(audit_log, "rb") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        yield f


def _parse_entry(line: bytes) -> dict | None:
    try:
        entry = json.loads(line)
    except (ValueError, RecursionError):
        return None
    return (
        entry
        if isinstance(entry, dict) and isinstance(entry.get("hash"), str)
        else None
    )


def _entry_lines(f):
    """The log's non-blank lines up to its last entry. A tail a crash cut
    short is not one: append_audit sets it aside at the next append, and
    until then a reader neither parses it nor counts it."""
    end = _last_entry(f)[0]
    f.seek(0)
    read = 0
    for line in f:
        if read >= end:
            return
        read += len(line)
        if line.strip(_WS):
            yield line


def _last_entry(f) -> tuple[int, str, bool]:
    """(end, hash, terminated) of the last line that parses as an entry in
    an open binary log, scanning back from the end. end is the offset just
    after it, after its newline if it has one. (0, GENESIS_HASH, True) when
    there is none."""
    size = f.seek(0, os.SEEK_END)
    window = 4096
    while True:
        start = max(0, size - window)
        f.seek(start)
        parts = f.read(size - start).split(b"\n")
        spans, pos = [], start
        for k, part in enumerate(parts):
            terminated = k < len(parts) - 1
            spans.append((pos, part, terminated))
            pos += len(part) + terminated
        # A window that does not start the file may cut its first line.
        for pos, part, terminated in reversed(spans[1:] if start else spans):
            entry = _parse_entry(part) if part.strip(_WS) else None
            if entry is not None:
                return pos + len(part) + terminated, entry["hash"], terminated
        if start == 0:
            return 0, GENESIS_HASH, True
        window *= 2


def _set_aside_tail(
    f, audit_log: Path, end: int, tail: bytes, prev: str, mac_key
) -> str:
    """Keep tail in a new file beside the log, cut it from the log, record
    that in the chain, and return the new last hash."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    aside = audit_log.with_name(f"{audit_log.name}.damaged-{stamp}-{end}")
    if not publish_new_file(aside, tail):
        raise OSError(
            errno.EEXIST, f"{aside} already exists; the audit log was not changed"
        )
    os.ftruncate(f.fileno(), end)
    os.fsync(f.fileno())
    digest = hashlib.sha256(tail).hexdigest()
    logger.error(
        "Audit log ended in %d bytes that are not an entry; kept as %s",
        len(tail),
        aside.name,
    )
    details = {"bytes": len(tail), "sha256": digest, "kept_as": aside.name}
    return _write_entry(f, prev, TAIL_SET_ASIDE, "system", aside.name, details, mac_key)


def _write_entry(f, prev, action, actor, resource, details, mac_key) -> str:
    entry = asdict(
        AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            actor=actor,
            resource=resource,
            details=details,
            hash="",
            prev_hash=prev,
        )
    )
    if mac_key is not None:
        entry["mac"] = _entry_mac(mac_key, entry)
    entry["hash"] = SovereignDataPlane._entry_hash(entry)
    f.write((json.dumps(entry) + "\n").encode())
    return entry["hash"]


def audit_anchor(audit_log: Path) -> dict:
    """Entry count and tail hash, to keep off the machine. A later log that
    is shorter, or holds another entry at that position, fails against it."""
    count, tail = 0, GENESIS_HASH
    if Path(audit_log).exists():
        with _reading(audit_log) as f:
            for line in f:
                if line.strip(_WS):
                    count += 1
                    tail = json.loads(line)["hash"]
    return {"entries": count, "tail": tail}


@dataclass
class _Chain:
    """Where a check of the audit chain stands after some entries."""

    prev: str = GENESIS_HASH
    chained: bool = False
    keyed: bool = False
    count: int = 0
    want: int | None = None
    at_want: str | None = None
    # Entries written before the log had a key, and the hash of the last of
    # them. They verify only once a keyed legacy_history entry names both.
    unkeyed: int = 0
    unkeyed_tail: str = GENESIS_HASH
    attested: bool = False


def _unique(pairs: list) -> dict:
    """pairs as a dict; a repeated key raises. json.loads keeps the last of
    two, so an entry could show one value and be hashed with the other."""
    entry = {}
    for key, value in pairs:
        if key in entry:
            raise ValueError(f"{key!r} twice")
        entry[key] = value
    return entry


def _check_entries(lines, chain: _Chain, mac_key: bytes | None) -> str | None:
    """Check each entry line in turn, advancing chain. The first problem
    found, or None."""
    for line in lines:
        if not line.strip(_WS):
            continue
        try:
            # As written: UTF-8 (json.loads would also take UTF-16 bytes) with
            # each key once, so the line says exactly what was hashed.
            entry = json.loads(line.decode("utf-8"), object_pairs_hook=_unique)
            stored = entry["hash"]
            action = entry.get("action")
            if not isinstance(action, str) or not isinstance(stored, str):
                raise TypeError
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
            return "unreadable entry"
        chain.count += 1
        count = chain.count
        if "prev_hash" in entry:
            chain.chained = True
            if entry["prev_hash"] != chain.prev:
                return f"broken chain at entry {count}"
        elif chain.chained:
            return f"unchained entry {count}"
        if stored != SovereignDataPlane._entry_hash(entry):
            return f"entry {count} does not match its hash"
        if "mac" in entry:
            chain.keyed = True
            mac = entry["mac"]
            if mac_key is not None and not (
                isinstance(mac, str)
                and mac.isascii()
                and hmac.compare_digest(mac, _entry_mac(mac_key, entry))
            ):
                return f"entry {count} has a bad MAC"
            if action == LEGACY_HISTORY and mac_key is not None:
                vouched = {"entries": chain.unkeyed, "tail": chain.unkeyed_tail}
                if (
                    chain.attested
                    or not chain.unkeyed
                    or entry.get("details") != vouched
                ):
                    return f"entry {count} attests history that is not there"
                chain.attested = True
        elif mac_key is not None:
            if action in ALWAYS_KEYED:
                return f"entry {count} ({action}) has no MAC"
            if action not in KEYLESS_ACTIONS:
                if chain.keyed:
                    return f"entry {count} has no MAC after keyed entries"
                chain.unkeyed += 1
                chain.unkeyed_tail = stored
        if count == chain.want:
            chain.at_want = stored
        chain.prev = stored
    return None


def _unattested(chain: _Chain, mac_key: bytes | None) -> str | None:
    """The problem with a log whose unkeyed history nobody has vouched for."""
    if mac_key is None or not chain.unkeyed or chain.attested:
        return None
    return (
        f"{chain.unkeyed} unkeyed entries from before the key are not attested; "
        "run audit adopt-legacy"
    )


def scan_audit_chain(
    audit_log: Path, mac_key: bytes | None
) -> tuple[str | None, _Chain]:
    """The chain state after every entry, without the attestation rule, and
    the first problem found. For `audit adopt-legacy`."""
    chain = _Chain()
    audit_log = Path(audit_log)
    if not audit_log.exists():
        return None, chain
    with _reading(audit_log) as f:
        return _check_entries(f, chain, mac_key), chain


def _anchored_chain(anchor: dict | None) -> _Chain:
    chain = _Chain(want=(anchor or {}).get("entries"))
    if chain.want == 0:
        chain.at_want = GENESIS_HASH
    return chain


def _against_anchor(chain: _Chain, anchor: dict | None) -> str | None:
    if anchor is not None:
        if chain.count < chain.want:
            return f"log has {chain.count} entries, the anchor recorded {chain.want}"
        if chain.at_want != anchor.get("tail"):
            return f"entry {chain.want} is not the one the anchor recorded"
    return None


def check_audit_chain(
    audit_log: Path, mac_key: bytes | None = None, anchor: dict | None = None
) -> str | None:
    """None when the log verifies, else the first problem found. Without
    mac_key, MACs are not checked."""
    audit_log = Path(audit_log)
    chain = _anchored_chain(anchor)
    if audit_log.exists():
        with _reading(audit_log) as f:
            reason = _check_entries(f, chain, mac_key) or _unattested(chain, mac_key)
        if reason:
            return reason
    return _against_anchor(chain, anchor)


def checked_copy(
    audit_log: Path, mac_key: bytes | None = None, anchor: dict | None = None
):
    """The log's bytes in an unnamed temporary file beside it, and the first
    problem a check of exactly those bytes found, or None. The shared lock
    is held only while the bytes are copied and checked, so whoever reads
    the copy, however slowly, never holds up an append. After a problem
    the rest of the log is copied unchecked; after a check that passed,
    nothing more is, since the lock is advisory and a writer that ignores
    it could have added a line no check has seen."""
    audit_log = Path(audit_log)
    chain = _anchored_chain(anchor)
    if not audit_log.exists():
        return _against_anchor(chain, anchor), io.BytesIO()
    copy = tempfile.TemporaryFile(dir=audit_log.parent)  # noqa: SIM115 - caller closes
    try:
        with _reading(audit_log) as f:

            def lines():
                for line in f:
                    copy.write(line)
                    yield line

            reason = _check_entries(lines(), chain, mac_key)
            if reason:
                shutil.copyfileobj(f, copy)
        reason = reason or _unattested(chain, mac_key) or _against_anchor(chain, anchor)
        copy.seek(0)
    except BaseException:
        copy.close()
        raise
    return reason, copy


def _check_appended(
    audit_log: Path, mac_key: bytes | None, mark: tuple | None
) -> tuple[str | None, tuple | None]:
    """check_audit_chain without an anchor, resuming from mark, the result
    of the last check that passed: (bytes checked, their SHA-256, chain).

    Those bytes are read and hashed again, and must be the same; then only
    what follows them is checked, from the chain state they left. A log
    that is shorter or differs anywhere in them is checked in full. The
    result is always the one a full check gives. Returns the problem or
    None, and the mark for the next call (None after a failure)."""
    audit_log = Path(audit_log)
    if not audit_log.exists():
        return None, None
    with _reading(audit_log) as f:
        hasher, offset, chain = hashlib.sha256(), 0, _Chain()
        if mark is not None:
            length, digest, saved = mark
            remaining = length
            while remaining:
                chunk = f.read(min(remaining, 1 << 20))
                if not chunk:
                    break
                hasher.update(chunk)
                remaining -= len(chunk)
            if remaining == 0 and hmac.compare_digest(hasher.hexdigest(), digest):
                offset, chain = length, dataclasses.replace(saved)
            else:
                f.seek(0)
                hasher = hashlib.sha256()

        before_tail = None

        def complete_lines():
            # Only whole lines move the mark, so a line still being written
            # is read again next time. The mark's chain state must stop there
            # too: it is taken before that line is checked.
            nonlocal offset, before_tail
            for line in f:
                if line.endswith(b"\n"):
                    hasher.update(line)
                    offset += len(line)
                else:
                    before_tail = dataclasses.replace(chain)
                yield line

        reason = _check_entries(complete_lines(), chain, mac_key) or _unattested(
            chain, mac_key
        )
    if reason:
        return reason, None
    state = chain if before_tail is None else before_tail
    return None, (offset, hasher.hexdigest(), dataclasses.replace(state))
