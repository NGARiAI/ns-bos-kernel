"""
NS-BOS Kernel - Network Synchronization
Digital twin, fleet records and a hash-chained sync ledger, kept on this
machine. Nothing is sent between machines.
"""

import collections
import contextlib
import errno
import fcntl
import hashlib
import json
import logging
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

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


class AirGapError(RuntimeError):
    """A call refused because air-gap mode is on."""


class SyncMode(Enum):
    LOCAL_ONLY = "local_only"
    PEER_TO_PEER = "peer_to_peer"
    CLOUD_SYNC = "cloud_sync"
    HYBRID = "hybrid"


@dataclass
class DigitalTwinState:
    """State that is synced across all devices in the fleet"""

    user_id: str
    agent_states: dict
    preferences: dict
    memory_index: dict
    last_sync: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    version: int = 0
    checksum: str = ""

    def compute_checksum(self) -> str:
        """Compute checksum for integrity verification"""
        data = {
            "user_id": self.user_id,
            "agent_states": self.agent_states,
            "preferences": self.preferences,
            "memory_index": self.memory_index,
            "version": self.version,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def validate(self) -> bool:
        """Validate state integrity"""
        return self.checksum == self.compute_checksum()

    def _shape_problem(self) -> str | None:
        """Why this state cannot be the twin, or None. The checksum is not
        keyed, so a valid one says nothing about the field types, and a
        section that is not an object makes every later update raise."""
        for name in ("agent_states", "preferences", "memory_index"):
            if not isinstance(getattr(self, name), dict):
                return f"{name} is not an object"
        if not isinstance(self.version, int):
            return "version is not an integer"
        return None


@dataclass
class FleetNode:
    """Represents a node in the NGARi fleet"""

    node_id: str
    hostname: str
    platform: str
    ip_address: str
    status: str = "offline"
    last_seen: str = ""
    capabilities: dict = field(default_factory=dict)
    sync_mode: SyncMode = SyncMode.LOCAL_ONLY


def _write_json(path: Path, data, **dump_kwargs) -> None:
    """Write data as JSON, complete or not at all, and durably: a synced
    temporary file renamed over the old one, then the directory synced, so
    a crash or power loss leaves the old file or the new one, never an empty
    one. Each call has its own temporary name, so threads do not collide."""
    _write_durably(path, json.dumps(data, indent=2, **dump_kwargs).encode())


def _write_durably(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner only
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


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


def _set_aside(path: Path, exc: Exception, what: str) -> Path:
    """Rename an unreadable file to <name>.corrupt-<UTC time>, never delete
    it, so the kernel can start without it and nothing is lost. Returns the
    new path."""
    aside = _keep_aside(path, "corrupt")
    logger.error(
        "%s unreadable (%s); kept as %s, starting empty",
        what,
        type(exc).__name__,
        aside.name,
    )
    return aside


GENESIS_HASH = "0" * 64


def _ledger_hash(entry: dict) -> str:
    """SHA-256 of an entry without its own hash, canonical JSON: the audit
    log's rule, so one reader understands both."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _is_chained(line: bytes) -> dict | None:
    """The entry on this line if it carries a hash (a ledger entry), else None."""
    try:
        entry = json.loads(line)
    except (ValueError, RecursionError):
        return None
    ok = isinstance(entry, dict) and isinstance(entry.get("hash"), str)
    return entry if ok else None


def _file_sha256(f, length: int) -> str:
    """SHA-256 of the first length bytes of an open binary file."""
    digest, remaining = hashlib.sha256(), length
    f.seek(0)
    while remaining:
        chunk = f.read(min(remaining, 1 << 20))
        if not chunk:
            break
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def _sync_mode(value) -> "SyncMode":
    """A SyncMode from any member or value. The kernel imports this module
    both as `network_sync` and as `core.kernel.network_sync`, each with its
    own SyncMode class, so members are matched by value."""
    return SyncMode(getattr(value, "value", value))


class NetworkSynchronization:
    """
    The digital twin, the fleet file and the sync ledger of one machine.
    No sync mode sends data to another machine.
    """

    def __init__(self, sync_dir: str | None = None):
        sync_dir = sync_dir or (
            os.environ.get("NGARI_DATA_DIR")
            or str(Path.home() / ".ngari" / "kernel" / "sync")
        )
        self.sync_dir = Path(sync_dir)
        self.sync_dir.mkdir(parents=True, exist_ok=True)

        self.twin_file = self.sync_dir / "digital_twin.json"
        self.fleet_file = self.sync_dir / "fleet.json"
        self.sync_log = self.sync_dir / "sync.log"

        self.local_state = self._load_twin()
        self.fleet_nodes = self._load_fleet()
        self.sync_mode = SyncMode.LOCAL_ONLY

    def _load_twin(self) -> DigitalTwinState:
        """Load digital twin state. An unreadable file is set aside and the
        twin starts empty."""
        if self.twin_file.exists():
            try:
                raw = self.twin_file.read_bytes()
                state = DigitalTwinState(**json.loads(raw))
                problem = state._shape_problem()
                if problem:
                    raise ValueError(problem)
            except (ValueError, TypeError, AttributeError, RecursionError) as exc:
                aside = _set_aside(self.twin_file, exc, "Digital twin")
                self._ledger(
                    "twin_set_aside",
                    aside.name,
                    reason=type(exc).__name__,
                    kept_as=aside.name,
                )
            else:
                if state.validate():
                    return state
                # The checksum is the only integrity check a twin has. A twin
                # that fails it was edited or damaged: keep the file as it
                # is under another name and start empty, not on its contents.
                aside = _keep_aside(self.twin_file, "rejected")
                logger.error(
                    "Digital twin checksum mismatch in %s; kept as %s, starting empty",
                    self.twin_file.name,
                    aside.name,
                )
                self._ledger(
                    "twin_rejected",
                    aside.name,
                    reason="checksum",
                    kept_as=aside.name,
                    bytes=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(),
                )

        return DigitalTwinState(
            user_id="ngari-default", agent_states={}, preferences={}, memory_index={}
        )

    def _save_twin(self):
        """Save digital twin state"""
        self.local_state.version += 1
        self.local_state.checksum = self.local_state.compute_checksum()
        self.local_state.last_sync = datetime.now(timezone.utc).isoformat()

        _write_json(self.twin_file, asdict(self.local_state))

    def _load_fleet(self) -> dict[str, FleetNode]:
        """Load fleet configuration. A file that does not parse is renamed
        aside, never deleted, and the fleet starts empty, so a truncated
        fleet.json cannot stop the kernel starting."""
        if not self.fleet_file.exists():
            return {}
        try:
            data = json.loads(self.fleet_file.read_text())
            nodes = {}
            for node_id, node_data in data.items():
                node_data = dict(node_data)
                node_data["sync_mode"] = _sync_mode(
                    node_data.get("sync_mode", SyncMode.LOCAL_ONLY.value)
                )
                nodes[node_id] = FleetNode(**node_data)
            return nodes
        except (ValueError, TypeError, AttributeError, KeyError, RecursionError) as exc:
            _set_aside(self.fleet_file, exc, "Fleet file")
            return {}

    def _save_fleet(self):
        """Save fleet configuration: complete or not at all."""
        data = {}
        for node_id, node in self.fleet_nodes.items():
            entry = asdict(node)
            entry["sync_mode"] = _sync_mode(node.sync_mode).value
            data[node_id] = entry
        _write_json(self.fleet_file, data)

    def update_twin(self, key: str, value: Any):
        """Update digital twin state"""
        # The key's prefix selects the section; a key without one is a preference.
        if key.startswith("agent."):
            agent_name = key.split(".", 1)[1]
            self.local_state.agent_states[agent_name] = value
        elif key.startswith("pref."):
            pref_name = key.split(".", 1)[1]
            self.local_state.preferences[pref_name] = value
        elif key.startswith("memory."):
            memory_key = key.split(".", 1)[1]
            self.local_state.memory_index[memory_key] = value
        else:
            self.local_state.preferences[key] = value

        self._save_twin()
        self._log_sync("update", key)

    def get_twin_value(self, key: str) -> Any | None:
        """Get value from digital twin state"""
        if key.startswith("agent."):
            agent_name = key.split(".", 1)[1]
            return self.local_state.agent_states.get(agent_name)
        elif key.startswith("pref."):
            pref_name = key.split(".", 1)[1]
            return self.local_state.preferences.get(pref_name)
        elif key.startswith("memory."):
            memory_key = key.split(".", 1)[1]
            return self.local_state.memory_index.get(memory_key)
        else:
            return self.local_state.preferences.get(key)

    def get_full_twin(self) -> DigitalTwinState:
        """Get complete digital twin state"""
        return self.local_state

    def register_node(self, node: FleetNode):
        """Register a new fleet node"""
        node.sync_mode = _sync_mode(node.sync_mode)
        self.fleet_nodes[node.node_id] = node
        self._save_fleet()
        logger.info(f"Fleet node registered: {node.hostname} ({node.node_id})")

    def update_node_status(self, node_id: str, status: str):
        """Update fleet node status"""
        if node_id in self.fleet_nodes:
            self.fleet_nodes[node_id].status = status
            self.fleet_nodes[node_id].last_seen = datetime.now(timezone.utc).isoformat()
            self._save_fleet()

    def get_fleet_status(self) -> dict:
        """Get fleet status overview"""
        return {
            "total_nodes": len(self.fleet_nodes),
            "online_nodes": len(
                [n for n in self.fleet_nodes.values() if n.status == "online"]
            ),
            "offline_nodes": len(
                [n for n in self.fleet_nodes.values() if n.status == "offline"]
            ),
            "nodes": {
                node_id: {
                    "hostname": node.hostname,
                    "platform": node.platform,
                    "status": node.status,
                    "last_seen": node.last_seen,
                }
                for node_id, node in self.fleet_nodes.items()
            },
        }

    def set_sync_mode(self, mode: SyncMode):
        """Set synchronization mode. With air-gap mode on, only local_only is
        allowed: every other mode means data leaves this machine."""
        mode = _sync_mode(mode)
        if mode is not SyncMode.LOCAL_ONLY and air_gap_enabled():
            raise AirGapError(
                f"sync mode {mode.value} would send data off this machine; air-gap "
                f"mode allows local_only only ({AIR_GAP_ENV}=0 allows it)"
            )
        self.sync_mode = mode
        logger.info(f"Sync mode set to: {self.sync_mode.value}")

    def export_twin(self) -> dict:
        """Export digital twin state for migration or backup"""
        return asdict(self.local_state)

    def import_twin(self, data: dict) -> bool:
        """Import digital twin state. A refused import, or one whose save
        fails, leaves the current twin as it was."""
        try:
            state = DigitalTwinState(**data)
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to import twin: {e}")
            return False
        problem = state._shape_problem()
        if problem:
            logger.error(f"Imported twin refused: {problem}")
            return False
        if not state.validate():
            logger.error("Imported twin checksum mismatch")
            return False
        previous = self.local_state
        self.local_state = state
        try:
            self._save_twin()
        except BaseException:
            self.local_state = previous
            raise
        return True

    def _log_sync(self, action: str, key: str):
        """Log synchronization event"""
        self._ledger(
            action,
            key,
            version=self.local_state.version,
            checksum=self.local_state.checksum,
        )

    def _ledger(self, action: str, key: str, **fields) -> None:
        """Append one chained entry to sync.log under an exclusive lock and
        sync it. Each entry carries the hash of the one before it. A log
        written before the ledger was chained (v0.1.0) is left byte for byte as
        it is: the first chained entry, ledger_chained, records its length and
        SHA-256. Nothing in sync.log is ever rewritten or truncated."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "key": key,
            **fields,
        }
        fd = os.open(self.sync_log, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a+b") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            size = f.seek(0, os.SEEK_END)
            prev = GENESIS_HASH
            if size:
                f.seek(size - 1)
                ends_with_newline = f.read(1) == b"\n"
                last = self._last_hash(f, size)
                if last is None:
                    # Nothing chained yet: a v0.1.0 log, or a first write cut
                    # short. Its bytes are recorded once, and the chain starts.
                    prefix = {
                        "prefix_bytes": size,
                        "prefix_sha256": _file_sha256(f, size),
                    }
                    if not ends_with_newline:
                        f.write(b"\n")
                    prev = self._write_entry(
                        f, GENESIS_HASH, "ledger_chained", "sync.log", prefix
                    )
                else:
                    prev = last
                    if not ends_with_newline:
                        f.write(b"\n")
            self._write_entry(f, prev, entry.pop("action"), entry.pop("key"), entry)
            f.flush()
            os.fsync(f.fileno())

    @staticmethod
    def _write_entry(f, prev: str, action: str, key: str, fields: dict) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "key": key,
            **{k: v for k, v in fields.items() if k not in ("timestamp",)},
            "prev_hash": prev,
        }
        entry["hash"] = _ledger_hash(entry)
        f.write((json.dumps(entry) + "\n").encode())
        return entry["hash"]

    @staticmethod
    def _last_hash(f, size: int) -> str | None:
        """Hash of the last chained entry, scanning back from the end."""
        window = 4096
        while True:
            start = max(0, size - window)
            f.seek(start)
            lines = f.read(size - start).split(b"\n")
            for line in reversed(lines[1:] if start else lines):
                entry = _is_chained(line)
                if entry is not None:
                    return entry["hash"]
            if start == 0:
                return None
            window *= 2

    def verify_sync_ledger(self) -> str | None:
        """None when sync.log verifies, else the first problem: a chained
        entry whose hash or link is wrong, a line that is not an entry after
        the chain began, or a v0.1.0 prefix that does not match the length
        and SHA-256 recorded for it. Without a key this shows damage and
        edits to the middle of the log, not a rewrite of all of it, nor
        entries cut from the end."""
        if not self.sync_log.exists():
            return None
        prev, count, began = GENESIS_HASH, 0, False
        first_unchained, offset = None, 0
        with open(self.sync_log, "rb") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            for number, line in enumerate(f, 1):
                start, offset = offset, offset + len(line)
                if not line.strip():
                    continue
                entry = _is_chained(line)
                if entry is None:
                    if began:
                        return f"line {number} is not a ledger entry"
                    first_unchained = first_unchained or number
                    continue  # a v0.1.0 line, if a ledger_chained entry follows
                if not began and first_unchained is not None:
                    # Lines without a hash are allowed only as the v0.1.0 part,
                    # and only ending exactly where its ledger_chained entry
                    # says (one newline is added after a torn last line).
                    if entry.get("action") != "ledger_chained":
                        return f"line {first_unchained} is not a ledger entry"
                    length = entry.get("prefix_bytes")
                    if type(length) is not int or start not in (length, length + 1):
                        return "the v0.1.0 part of sync.log has changed"
                if not began and entry.get("action") == "ledger_chained":
                    problem = self._check_prefix(f, entry)
                    if problem:
                        return problem
                began = True
                count += 1
                if entry.get("prev_hash") != prev:
                    return f"broken chain at entry {count}"
                if entry["hash"] != _ledger_hash(entry):
                    return f"entry {count} does not match its hash"
                prev = entry["hash"]
        return None

    def _check_prefix(self, chained, entry: dict) -> str | None:
        length, digest = entry.get("prefix_bytes"), entry.get("prefix_sha256")
        if type(length) is not int or length < 0 or not isinstance(digest, str):
            return "the v0.1.0 prefix record is malformed"
        with open(self.sync_log, "rb") as f:
            if _file_sha256(f, length) != digest:
                return "the v0.1.0 part of sync.log has changed"
        return None

    def get_sync_history(self, limit: int = 50) -> list:
        """The last `limit` sync events, oldest first. The log is read one
        line at a time and only those lines are parsed, so memory stays
        bounded by `limit`. A line that does not read, cut short by a crash or
        damaged (bytes that are not UTF-8), is skipped."""
        if limit <= 0 or not self.sync_log.exists():
            return []
        with open(self.sync_log, "rb") as f:
            last = collections.deque((ln for ln in f if ln.strip()), maxlen=limit)
        entries = []
        for line in last:
            try:
                entries.append(json.loads(line))
            except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
                logger.warning("Skipping an unreadable line in %s", self.sync_log.name)
        return entries


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    sync = NetworkSynchronization()

    sync.update_twin("agent.ceo", {"status": "running", "revenue_target": 1000})
    sync.update_twin("pref.theme", "kemet")
    sync.update_twin("memory.last_query", "What is NS-BOS?")

    print(f"CEO Agent: {sync.get_twin_value('agent.ceo')}")
    print(f"Theme: {sync.get_twin_value('pref.theme')}")

    node = FleetNode(
        node_id="node-01",
        hostname="ngari-jetson-01",
        platform="jetson_agx_orin",
        ip_address="203.0.113.1",
        status="online",
        capabilities={"gpu": True, "memory_gb": 64},
    )
    sync.register_node(node)

    print(f"Fleet status: {json.dumps(sync.get_fleet_status(), indent=2)}")

    twin = sync.export_twin()
    print(f"Twin version: {twin['version']}")
    print(f"Twin checksum: {twin['checksum']}")
