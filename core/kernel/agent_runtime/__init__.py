"""
NS-BOS Kernel - Agent Runtime Framework
Agent lifecycle management, inter-agent communication, task scheduling,
and memory/state management.
"""

import asyncio
import contextlib
import errno
import json
import logging
import os
import re
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.fernet import InvalidToken

logger = logging.getLogger(__name__)


class AgentStateEnum(Enum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    IDLE = "idle"
    PAUSED = "paused"
    ERROR = "error"
    TERMINATED = "terminated"


class TaskPriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class AgentConfig:
    name: str
    agent_type: str
    version: str = "1.0.0"
    description: str = ""
    max_memory_mb: int = 512
    restart_on_failure: bool = True
    max_restarts: int = 5
    environment: dict = field(default_factory=dict)


@dataclass
class Task:
    task_id: str
    agent_id: str
    action: str
    payload: dict
    priority: TaskPriority = TaskPriority.NORMAL
    status: str = "pending"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: str | None = None
    completed_at: str | None = None
    result: Any | None = None
    error: str | None = None


@dataclass
class AgentState:
    agent_id: str
    config: AgentConfig
    state: AgentStateEnum = AgentStateEnum.INITIALIZING
    memory: dict = field(default_factory=dict)
    tasks_completed: int = 0
    tasks_failed: int = 0
    uptime_seconds: float = 0
    last_heartbeat: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error_count: int = 0


ENCRYPT_STATE_ENV = "NGARI_ENCRYPT_STATE"
ENVELOPE_FORMAT = "ngari-encrypted-v1"
# How an encrypted state file begins when this module wrote it, with any
# spacing: json.dumps puts format and key_id first, so the key id is usually
# known without parsing. A file another tool rewrote is recognised by parsing.
_ENVELOPE_HEAD = re.compile(
    rb'\A\s*\{\s*"format"\s*:\s*"ngari-encrypted-v1"\s*,\s*"key_id"\s*:\s*"([0-9a-f]{32})"'
)
_FORMAT_MARK = b'"ngari-encrypted-v1"'
# The key id given to an envelope whose own key id cannot be read: it never
# matches a real key, so such a file is refused and left alone, never set aside.
UNKNOWN_KEY_ID = "unreadable"


class StateKeyError(RuntimeError):
    """Encrypted agent state this process cannot open: encrypted under another
    master key, or found by a runtime that was given no key. The file is left
    exactly as it is; it is never set aside as unreadable."""


def encrypt_state_enabled(environ=None) -> bool:
    """NGARI_ENCRYPT_STATE: off unless 1, true, yes or on (case and spaces
    ignored). Any other non-empty value turns it on with one warning: a
    mistyped setting should not leave state in the clear."""
    env = os.environ if environ is None else environ
    raw = (env.get(ENCRYPT_STATE_ENV) or "").strip().lower()
    if raw in ("", "0", "false", "no", "off"):
        return False
    if raw not in ("1", "true", "yes", "on"):
        logger.warning(
            "%s=%r is not a known value; agent state is encrypted "
            "(1, true, yes or on turn it on; 0, false, no or off leave it off)",
            ENCRYPT_STATE_ENV,
            raw[:32],
        )
    return True


def _sealed_key_id(data: bytes) -> str | None:
    """The key id an encrypted state file was written under, or None for
    anything else (plaintext JSON, an empty file). A file whose top-level
    object has format ngari-encrypted-v1 is encrypted whatever its spacing or
    key order; one whose key id cannot be read gets UNKNOWN_KEY_ID. A
    plaintext file that only mentions the format somewhere inside is not."""
    match = _ENVELOPE_HEAD.match(data)
    if match:
        return match.group(1).decode()
    if _FORMAT_MARK not in data:
        return None
    try:
        envelope = json.loads(data)
    except (ValueError, RecursionError):
        return None
    if not isinstance(envelope, dict) or envelope.get("format") != ENVELOPE_FORMAT:
        return None
    key_id = envelope.get("key_id")
    if isinstance(key_id, str) and re.fullmatch(r"[0-9a-f]{32}", key_id):
        return key_id
    return UNKNOWN_KEY_ID


# Topics may hold any character but / and NUL, a newline included, so the
# patterns below match across lines (DOTALL); their digits are ASCII only, as
# publish writes them (\d alone would take full-width or other digits too).
# A message file's whole name, in publish's form or v0.1.0's:
# "<topic>_<stamp>[_<usec>_<hex8>][.enc].json". A topic may start with a dot,
# so hidden names are messages too; temporary files end in .tmp and never match.
_MESSAGE_NAME = re.compile(
    r".+_\d{8}_\d{6}(?:_\d{6}_[0-9a-f]{8})?(?:\.enc)?\.json", re.DOTALL | re.ASCII
)


RETENTION_ENV = "NGARI_RETENTION_DAYS"
# The retention with the variable unset, and the shortest any setting can
# give: 21 years, as records are kept in regulated industries such as
# biopharma, with the six leap days any 21 years can hold, so no message is
# removed before 21 calendar years. A setting can keep messages longer, or
# for ever; none can shorten this.
RETENTION_DEFAULT_DAYS = 21 * 365 + 6
RETENTION_FLOOR_DAYS = RETENTION_DEFAULT_DAYS
# The value that keeps every message.
RETENTION_NEVER = "never"
# The time stamp publish puts in a message's name, from the whole name.
_MESSAGE_TIME = re.compile(
    r".+_(\d{8}_\d{6})(_\d{6}_[0-9a-f]{8})?(?:\.enc)?\.json", re.DOTALL | re.ASCII
)
# No message is older than its name form: <topic>_<stamp>.json dates from
# v0.1.0 (2026-08-23) and the _<usec>_<hex8> form from 2026-10-27. A name
# dated earlier comes from a wrong clock (a board with no real-time clock
# that boots at 1970, or at its image date), so its date says nothing about
# its age, and retention never removes it.
_EARLIEST_V010_NAME = datetime(2026, 8, 23, tzinfo=timezone.utc)
_EARLIEST_CURRENT_NAME = datetime(2026, 10, 27, tzinfo=timezone.utc)
# Where the bus keeps what it knows of the clock between sweeps (see expire).
_CLOCK_FILE = ".retention-clock.json"
# How far behind the latest time seen the clock may be before it counts as
# wrong, and how much later than its cutoff a message is removed, so neither
# stamps cut to the second nor a restart can remove a message early.
_CLOCK_SLACK = timedelta(hours=1)
_SAFETY = timedelta(days=1, seconds=1)
_RESTART_ALLOWANCE = timedelta(days=1)


def retention_days(environ=None) -> int | None:
    """NGARI_RETENTION_DAYS: how many days inter-agent messages are kept, or
    None to keep them all. Unset or empty means 21 years
    (RETENTION_DEFAULT_DAYS); "never" keeps every message; any whole number
    of days from the floor up is taken. A value below the floor, which is
    the 21 years, or one that is not a whole number of days, keeps
    everything and logs an error naming the floor: no setting can expire a
    message sooner than 21 years."""
    env = os.environ if environ is None else environ
    raw = (env.get(RETENTION_ENV) or "").strip()
    if not raw:
        return RETENTION_DEFAULT_DAYS
    if raw.lower() == RETENTION_NEVER:
        return None
    try:
        days = int(raw)
    except ValueError:
        logger.error(
            "%s=%r is not a whole number of days (%d or more) or never; no message "
            "is expired",
            RETENTION_ENV,
            raw[:32],
            RETENTION_FLOOR_DAYS,
        )
        return None
    if days < RETENTION_FLOOR_DAYS:
        logger.error(
            "%s=%d is below the %d-day (21-year) floor; no message is expired",
            RETENTION_ENV,
            days,
            RETENTION_FLOOR_DAYS,
        )
        return None
    return days


def _message_time(name: str) -> datetime | None:
    """The UTC time publish wrote into a message file's name, or None for a
    name that is not a message's, or one dated before the code that writes
    such names existed (the clock was wrong). The name, not the file's mtime:
    a copy or a restore from backup changes mtime."""
    match = _MESSAGE_TIME.fullmatch(name)
    if match is None:
        return None
    try:
        when = datetime.strptime(match.group(1) + "+0000", "%Y%m%d_%H%M%S%z")
    except ValueError:
        return None
    earliest = _EARLIEST_CURRENT_NAME if match.group(2) else _EARLIEST_V010_NAME
    return when if when >= earliest else None


def _retention_record(pending: dict | None, removed: list, days: int) -> dict | None:
    """One retention_expired record: what this sweep removed, with whatever an
    earlier sweep removed and could not record."""
    if not removed and not pending:
        return None
    stamp = "%Y%m%dT%H%M%SZ"
    oldest = [t for t in ((pending or {}).get("oldest"),) if isinstance(t, str)]
    newest = [t for t in ((pending or {}).get("newest"),) if isinstance(t, str)]
    if removed:
        oldest.append(removed[0].strftime(stamp))
        newest.append(removed[-1].strftime(stamp))
    earlier = (pending or {}).get("removed")
    return {
        "removed": len(removed) + (earlier if isinstance(earlier, int) else 0),
        "retention_days": days,
        "oldest": min(oldest) if oldest else None,
        "newest": max(newest) if newest else None,
    }


def _boot_id() -> str | None:
    """This boot's id, to tell a restart from the same run; None if unknown."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() or None
    except OSError:
        return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_iso(value) -> datetime | None:
    try:
        when = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None
    return when if when is not None and when.tzinfo is not None else None


def _is_message_name(name: str) -> bool:
    return _MESSAGE_NAME.fullmatch(name) is not None


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def sealed_state(data_dir) -> dict:
    """What encrypted agent state exists under a runtime's data directory:
    the number of encrypted files and the key ids they name. The registry, the
    task file and one message are read; other messages are counted by name,
    so this costs little at start however many messages there are."""
    base = Path(data_dir)
    key_ids, files = set(), 0
    for path in (base / "registry" / "registry.json", base / "tasks" / "tasks.json"):
        key_id = _sealed_key_id(_read_bytes(path))
        if key_id is not None:
            files += 1
            key_ids.add(key_id)
    comm = base / "comm"
    sample = None
    if comm.is_dir():
        with os.scandir(comm) as entries:
            for entry in entries:
                if entry.name.endswith(".enc.json") and _is_message_name(entry.name):
                    files += 1
                    sample = sample or entry.path
    if sample is not None:
        key_id = _sealed_key_id(_read_bytes(Path(sample)))
        if key_id is not None:
            key_ids.add(key_id)
    return {"files": files, "key_ids": key_ids}


def _open_state(path: Path, cipher) -> tuple[bytes, bool]:
    """A state file's plaintext bytes, and whether it was encrypted. An
    encrypted file under another key, or any encrypted file when there is no
    cipher, raises StateKeyError and is not touched. One under this key that
    does not open raises ValueError, so the loader sets it aside as it does
    any damaged file."""
    raw = path.read_bytes()
    key_id = _sealed_key_id(raw)
    if key_id is None:
        return raw, False
    if cipher is None:
        raise StateKeyError(
            f"{path} is encrypted (key id {key_id}) and this runtime was given no "
            "key; start it through the kernel"
        )
    if key_id != cipher.key_id:
        raise StateKeyError(
            f"{path} was encrypted under another master key (key id {key_id}; "
            f"the key in use has {cipher.key_id}). Restore the master key it was "
            "written under"
        )
    try:
        return cipher.decrypt(json.loads(raw)["token"]), True
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        InvalidToken,
    ) as exc:
        raise ValueError(f"damaged encrypted state ({type(exc).__name__})") from None


def _seal(data: bytes, cipher) -> bytes:
    """The envelope for data, proven to decrypt back to the same bytes before
    it can replace anything."""
    token = cipher.encrypt(data)
    if cipher.decrypt(token) != data:
        raise RuntimeError("encrypted state did not decrypt to what was written")
    envelope = {"format": ENVELOPE_FORMAT, "key_id": cipher.key_id, "token": token}
    return json.dumps(envelope).encode()


def _write_state(path: Path, data: bytes, cipher, seal: bool) -> None:
    _write_durably(path, _seal(data, cipher) if seal else data)


def _no_audit(action: str, resource: str, details: dict) -> None:
    """The default audit hook: a runtime built alone records nothing. The
    kernel passes one that writes to the data plane's chain."""


def _write_json(path: Path, data, **dump_kwargs) -> None:
    """Write data as JSON, complete or not at all, and durably: a synced
    temporary file renamed over the old one, then the directory synced, so
    a crash or power loss leaves the old file or the new one, never an empty
    one. Each call has its own temporary name, so threads do not collide."""
    _write_durably(path, json.dumps(data, indent=2, **dump_kwargs).encode())


def _temp_name(path: Path) -> Path:
    """A temporary name beside path, unique to this write. The name is cut to
    96 bytes, not characters, so the temporary file fits the 255-byte limit
    whenever path itself does: a message file is named after its topic, and
    a long one, or one in a script of 3-byte characters, would not. Cut as
    the file system's bytes: a name already on disk need not be UTF-8,
    and a character cut in two stays two bytes of the name."""
    head = os.fsdecode(os.fsencode(path.name)[:96])
    return path.with_name(f".{head}.{os.getpid()}.{secrets.token_hex(4)}.tmp")


def _write_durably(path: Path, data: bytes) -> None:
    tmp = _temp_name(path)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)  # umask applies
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


def _set_aside(path: Path, exc: Exception, what: str) -> None:
    """Rename an unreadable file to <name>.corrupt-<UTC time>, never delete
    it, so the kernel can start without it and nothing is lost."""
    aside = _keep_aside(path, "corrupt")
    logger.error(
        "%s unreadable (%s); kept as %s, starting empty",
        what,
        type(exc).__name__,
        aside.name,
    )


def _priority(value) -> "TaskPriority":
    """A TaskPriority from any member or value. The kernel imports this
    module both as `agent_runtime` and as `core.kernel.agent_runtime`, each
    with its own TaskPriority class, so members are matched by value."""
    return TaskPriority(getattr(value, "value", value))


def _start_order(agent: "AgentState") -> tuple[bool, str]:
    """Sort key for find_by_name: ISO start times in order, anything else
    after them (it would not compare with a string)."""
    started = agent.started_at
    return (not isinstance(started, str), str(started))


def _settle(store, path: Path, raw: bytes, sealed: bool) -> None:
    """After a load: a file that was encrypted stays encrypted from now on,
    and a plaintext file is encrypted in place, with its exact bytes inside,
    when encryption is on. The plaintext is replaced by one durable rename, so
    a crash leaves the old file or the new one, never neither."""
    if sealed:
        store._encrypt = True
    elif store._encrypt:
        _write_state(path, raw, store._cipher, True)
        store._audit("state_encrypted", path.name, {"bytes": len(raw)})


class AgentRegistry:
    """Registry for managing agent configurations and state"""

    def __init__(
        self,
        registry_dir: str | None = None,
        *,
        audit: Callable[[str, str, dict], None] | None = None,
        cipher=None,
        encrypt: bool = False,
    ):
        """cipher opens encrypted state; encrypt writes it encrypted. A file
        that was already encrypted is written encrypted whatever encrypt says."""
        registry_dir = registry_dir or (
            os.environ.get("NGARI_DATA_DIR")
            or str(Path.home() / ".ngari" / "kernel" / "agents" / "registry")
        )
        if encrypt and cipher is None:
            raise ValueError("encrypting agent state needs a cipher")
        self._audit = audit or _no_audit
        self._cipher = cipher
        self._encrypt = encrypt
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.agents: dict[str, AgentState] = {}
        self._load_registry()

    def _load_registry(self):
        """Load agent registry from disk. An unreadable file is set aside and
        the registry starts empty."""
        registry_file = self.registry_dir / "registry.json"
        if not registry_file.exists():
            return
        try:
            raw, sealed = _open_state(registry_file, self._cipher)
            data = json.loads(raw)
            agents = {}
            for agent_id, agent_data in data.items():
                config = AgentConfig(**agent_data["config"])
                agents[agent_id] = AgentState(
                    agent_id=agent_id,
                    config=config,
                    state=AgentStateEnum(agent_data.get("state", "initializing")),
                    memory=agent_data.get("memory", {}),
                    tasks_completed=agent_data.get("tasks_completed", 0),
                    tasks_failed=agent_data.get("tasks_failed", 0),
                    uptime_seconds=agent_data.get("uptime_seconds", 0),
                    last_heartbeat=agent_data.get(
                        "last_heartbeat", datetime.now(timezone.utc).isoformat()
                    ),
                    started_at=agent_data.get(
                        "started_at", datetime.now(timezone.utc).isoformat()
                    ),
                    error_count=agent_data.get("error_count", 0),
                )
            # Kept only if it can be saved again: asdict recurses in Python and
            # gives up long before the decoder does, and a registry that
            # cannot be saved stops every later change, and the start.
            json.dumps(self._registry_data(agents))
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            _set_aside(registry_file, exc, "Agent registry")
            return
        self.agents.update(agents)
        _settle(self, registry_file, raw, sealed)

    def save_registry(self):
        """Save agent registry to disk"""
        _write_state(
            self.registry_dir / "registry.json",
            json.dumps(self._registry_data(self.agents)).encode(),
            self._cipher,
            self._encrypt,
        )

    @staticmethod
    def _registry_data(agents: dict) -> dict:
        """agents as registry.json holds them."""
        data = {}
        for agent_id, state in agents.items():
            data[agent_id] = {
                "config": asdict(state.config),
                "state": state.state.value,
                "memory": state.memory,
                "tasks_completed": state.tasks_completed,
                "tasks_failed": state.tasks_failed,
                "uptime_seconds": state.uptime_seconds,
                "last_heartbeat": state.last_heartbeat,
                "started_at": state.started_at,
                "error_count": state.error_count,
            }
        return data

    def find_by_name(self, name: str) -> AgentState | None:
        """The agent registered under name. A stored registry can hold
        several under one name; the oldest wins, and one whose started_at is
        not a time stamp never does."""
        matches = [a for a in self.agents.values() if a.config.name == name]
        return min(matches, key=_start_order) if matches else None

    def register_agent(self, config: AgentConfig) -> str:
        """Register an agent, or return the id it already has.

        Names are unique: registering a name again keeps the agent's id,
        state, memory and counters, and takes the new config if it changed.
        """
        _require_text(name=config.name, agent_type=config.agent_type)
        _require_size(
            "the version, description and environment",
            [config.version, config.description, config.environment],
            MAX_DESCRIPTION_BYTES,
        )  # fmt: skip
        existing = self.find_by_name(config.name)
        if existing is not None:
            # By value: the double import makes two AgentConfig classes, and
            # dataclass equality needs the same class.
            if asdict(existing.config) != asdict(config):
                previous = existing.config
                existing.config = config
                try:
                    self.save_registry()
                except BaseException:
                    # Not changed until saved: a retry sees the change again
                    # and records it, instead of a later save storing it
                    # with no audit entry.
                    existing.config = previous
                    raise
                logger.info("Agent config updated: %s", _logged(config.name))
                self._audit(
                    "agent_registered",
                    existing.agent_id,
                    {
                        "name": config.name,
                        "type": config.agent_type,
                        "outcome": "updated",
                    },
                )
            return existing.agent_id
        agent_id = str(uuid.uuid4())
        state = AgentState(agent_id=agent_id, config=config)
        self.agents[agent_id] = state
        try:
            self.save_registry()
        except BaseException:
            del self.agents[agent_id]
            raise
        logger.info("Agent registered: %s (%s)", _logged(config.name), agent_id)
        self._audit(
            "agent_registered",
            agent_id,
            {"name": config.name, "type": config.agent_type, "outcome": "created"},
        )
        return agent_id

    def get_agent(self, agent_id: str) -> AgentState | None:
        """Get agent state by ID"""
        return self.agents.get(agent_id)

    def list_agents(self) -> list[AgentState]:
        """List all registered agents"""
        return list(self.agents.values())

    def update_agent_state(self, agent_id: str, state: AgentStateEnum):
        """Update agent state. The state is taken by value, so the other copy
        of AgentStateEnum that the double import makes is stored as this
        module's own."""
        if agent_id in self.agents:
            agent = self.agents[agent_id]
            before = getattr(agent.state, "value", str(agent.state))
            previous = (agent.state, agent.last_heartbeat)
            agent.state = AgentStateEnum(getattr(state, "value", state))
            agent.last_heartbeat = datetime.now(timezone.utc).isoformat()
            try:
                self.save_registry()
            except BaseException:
                agent.state, agent.last_heartbeat = previous
                raise
            if agent.state.value != before:  # a heartbeat alone is not a change
                self._audit(
                    "agent_state_changed",
                    agent_id,
                    {"from": before, "to": agent.state.value},
                )


def _logged(value: Any, limit: int = 200) -> str:
    """value for a log line: its repr, so a newline an agent put in it cannot
    start a line that reads as the kernel's own, cut to limit characters."""
    text = repr(value if isinstance(value, str) else str(value))
    return text if len(text) <= limit else text[:limit] + "..."


def _require_text(**fields: Any) -> None:
    """Refuse a field that is not a non-empty string of at most
    MAX_TEXT_BYTES, before anything is saved. The state files take any JSON,
    the audit chain does not, so an odd value would be stored and then have
    no entry; and each of these is kept in a file rewritten whole on every
    change and copied into the audit chain."""
    for what, value in fields.items():
        if not isinstance(value, str) or not value:
            raise TypeError(
                f"{what} must be a non-empty string, not {type(value).__name__}"
            )
        size = len(value.encode("utf-8", "surrogatepass"))
        if size > MAX_TEXT_BYTES:
            raise ValueError(
                f"{what} is {size} bytes, over the {MAX_TEXT_BYTES}-byte limit"
            )


UNSTORABLE_RESULT = {"error": "the result could not be stored"}
MAX_RESULT_DEPTH = 64  # lists and objects inside each other, in a task result
# Bytes of JSON one agent may hand the kernel at once. tasks.json is rewritten
# whole on every change, so without a bound one agent's payload is every
# agent's write cost from then on; larger data belongs in the data plane.
# The registry, task and message files are written in the encoding these
# bounds measure: indented, a payload's size would grow with its depth.
MAX_PAYLOAD_BYTES = 256 * 1024  # a task's payload or result, a message
MAX_DESCRIPTION_BYTES = 4 * 1024  # an agent's version, description and environment
MAX_TEXT_BYTES = 256  # a name, an agent type, an agent id, an action
# The longest topic whose message file, <topic>_<stamp>_<8 hex>.enc.json,
# still fits a 255-byte file name.
MAX_TOPIC_BYTES = 255 - len("_20261101_000000_000000_00000000.enc.json")


def _require_size(what: str, value: Any, limit: int) -> None:
    """Refuse value when it nests more than MAX_RESULT_DEPTH deep or its JSON
    is over limit bytes, before it is saved. Saving copies a task
    recursively, from deeper in the stack when the queue runs it, so a
    payload deep enough would stop every later save of the task file."""
    if _deeper_than(value, MAX_RESULT_DEPTH):
        raise ValueError(f"{what} nests more than {MAX_RESULT_DEPTH} deep")
    size = len(json.dumps(value, default=str).encode())
    if size > limit:
        raise ValueError(f"{what} is {size} bytes of JSON, over the {limit}-byte limit")


def _deeper_than(value: Any, limit: int) -> bool:
    """Whether lists, tuples and objects nest more than limit deep in value,
    which need not be JSON yet. Without recursing, and it stops at the first
    item past the limit, so a value that contains itself ends too."""
    todo = [(value, 1)]
    while todo:
        item, depth = todo.pop()
        if isinstance(item, (dict, list, tuple)):
            if depth > limit:
                return True
            children = item.values() if isinstance(item, dict) else item
            todo.extend((child, depth + 1) for child in children)
    return False


def _storable(value: Any) -> Any:
    """value as the task file holds it, read back; or UNSTORABLE_RESULT when
    the file cannot hold it: keys that are not strings, a number too long to
    write, or nesting deeper than MAX_RESULT_DEPTH (saving copies the task
    recursively). A handler's result, which can come from a model's reply,
    must never stop the task file from being saved."""
    try:
        encoded = json.dumps(value, default=str)
        stored = json.loads(encoded)
    except (TypeError, ValueError, RecursionError):
        return dict(UNSTORABLE_RESULT)
    too_large = len(encoded.encode()) > MAX_PAYLOAD_BYTES
    if too_large or _deeper_than(stored, MAX_RESULT_DEPTH):
        return dict(UNSTORABLE_RESULT)
    return stored


class TaskScheduler:
    """Task scheduler with priority queue"""

    def __init__(
        self,
        scheduler_dir: str | None = None,
        *,
        audit: Callable[[str, str, dict], None] | None = None,
        cipher=None,
        encrypt: bool = False,
    ):
        scheduler_dir = scheduler_dir or (
            os.environ.get("NGARI_DATA_DIR")
            or str(Path.home() / ".ngari" / "kernel" / "tasks")
        )
        if encrypt and cipher is None:
            raise ValueError("encrypting agent state needs a cipher")
        self._audit = audit or _no_audit
        self._cipher = cipher
        self._encrypt = encrypt
        self.scheduler_dir = Path(scheduler_dir)
        self.scheduler_dir.mkdir(parents=True, exist_ok=True)
        self.tasks: dict[str, Task] = {}
        self.handlers: dict[str, Callable] = {}
        self._load_tasks()

    def _load_tasks(self):
        """Load tasks from disk. A file that does not parse is renamed aside,
        never deleted, and the scheduler starts empty, so a truncated
        tasks.json cannot stop a start."""
        tasks_file = self.scheduler_dir / "tasks.json"
        if not tasks_file.exists():
            return
        try:
            raw, sealed = _open_state(tasks_file, self._cipher)
            data = json.loads(raw)
            tasks = {}
            for task_id, task_data in data.items():
                task_data = dict(task_data)
                if (
                    not isinstance(task_data.get("task_id"), str)
                    or not task_data["task_id"]
                ):
                    task_data["task_id"] = task_id  # the key it is filed under
                task_data["priority"] = _priority(
                    task_data.get("priority", TaskPriority.NORMAL.value)
                )
                tasks[task_id] = Task(**task_data)
            json.dumps(self._tasks_data(tasks), default=str)  # can be saved again
        except (ValueError, TypeError, AttributeError, KeyError, RecursionError) as exc:
            _set_aside(tasks_file, exc, "Task file")
            return
        self.tasks.update(tasks)
        _settle(self, tasks_file, raw, sealed)

    def save_tasks(self):
        """Save tasks to disk: complete or not at all."""
        _write_state(
            self.scheduler_dir / "tasks.json",
            json.dumps(self._tasks_data(self.tasks), default=str).encode(),
            self._cipher,
            self._encrypt,
        )

    @staticmethod
    def _tasks_data(tasks: dict) -> dict:
        """tasks as tasks.json holds them."""
        data = {}
        for task_id, task in tasks.items():
            entry = asdict(task)
            entry["priority"] = _priority(task.priority).value
            data[task_id] = entry
        return data

    def register_handler(self, action: str, handler: Callable):
        """Register a task handler"""
        self.handlers[action] = handler

    def create_task(
        self,
        agent_id: str,
        action: str,
        payload: dict,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> str:
        """Create a new task"""
        _require_text(agent_id=agent_id, action=action)
        _require_size("the payload", payload, MAX_PAYLOAD_BYTES)
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            agent_id=agent_id,
            action=action,
            payload=payload,
            priority=_priority(priority),
        )
        self.tasks[task_id] = task
        try:
            self.save_tasks()
        except BaseException:
            del self.tasks[task_id]
            raise
        logger.info(
            "Task created: %s - %s (priority: %s)",
            task_id, _logged(action), task.priority.name,
        )  # fmt: skip
        self._audit(
            "task_created",
            task_id,
            {
                "agent_id": agent_id,
                "action": str(action),
                "priority": task.priority.name,
            },
        )
        return task_id

    def get_pending_tasks(self) -> list[Task]:
        """Get pending tasks sorted by priority"""
        pending = [t for t in self.tasks.values() if t.status == "pending"]
        return sorted(pending, key=lambda t: t.priority.value, reverse=True)

    def _moved(self, task: Task, before: str) -> None:
        if before == task.status:
            return  # nothing changed, nothing to record
        task_id = (
            task.task_id
            if isinstance(task.task_id, str) and task.task_id
            else "(no id)"
        )
        self._audit("task_state_changed", task_id, {"from": before, "to": task.status})

    async def execute_task(self, task: Task) -> Any:
        """Execute a task. Every state change is saved and then audited, and
        the audit calls sit outside the handler's try, so a failing append is
        never recorded as the task's own error."""
        # A task file edited by hand can hold any JSON as the action; one that
        # cannot be a handler name fails alone instead of stopping the queue.
        if not isinstance(task.action, str) or task.action not in self.handlers:
            before = task.status
            task.status = "error"
            task.error = f"No handler registered for action: {task.action}"
            self.save_tasks()
            self._moved(task, before)
            return None

        before, started = task.status, task.started_at
        task.status = "running"
        task.started_at = datetime.now(timezone.utc).isoformat()
        self.save_tasks()
        try:
            self._moved(task, before)
        except BaseException:
            # The handler has not run: put the task back so the next run takes
            # it, rather than leave it saved as running and never run.
            task.status, task.started_at = before, started
            with contextlib.suppress(OSError):
                self.save_tasks()
            raise

        failure = None
        result = None
        try:
            handler = self.handlers[task.action]
            result = handler(task.payload)
            if asyncio.iscoroutine(result):
                result = await result
        except Exception as e:  # noqa: BLE001 - task boundary, recorded as task error
            failure = e

        task.completed_at = datetime.now(timezone.utc).isoformat()
        if failure is None:
            task.status = "completed"
            task.result = _storable(result)
        else:
            task.status = "error"
            task.error = str(failure)
            logger.error("Task %s failed: %s", task.task_id, _logged(failure, 500))
        self.save_tasks()
        self._moved(task, "running")
        return result if failure is None else None

    async def process_queue(self):
        """Process all pending tasks"""
        pending = self.get_pending_tasks()
        results = []
        for task in pending:
            result = await self.execute_task(task)
            results.append(result)
        return results


# What publish puts after "<topic>_": the UTC time, then microseconds and four
# random bytes (a v0.1.0 name has the time only).
_MESSAGE_STAMP = re.compile(
    r"(\d{8}_\d{6})(?:_(\d{6})_[0-9a-f]{8})?(?:\.enc)?\.json", re.ASCII
)


def _message_stamp(rest: str) -> tuple[str, str, str] | None:
    """Sort key for a message file name after "<topic>_", or None if the
    name is not one publish writes. A v0.1.0 name sorts before a current
    one from the same second."""
    m = _MESSAGE_STAMP.fullmatch(rest)
    return None if m is None else (m.group(1), m.group(2) or "", rest)


class InterAgentCommunication:
    """Inter-agent message bus"""

    def __init__(
        self,
        comm_dir: str | None = None,
        *,
        audit: Callable[[str, str, dict], None] | None = None,
        cipher=None,
        encrypt: bool = False,
    ):
        comm_dir = comm_dir or (
            os.environ.get("NGARI_DATA_DIR")
            or str(Path.home() / ".ngari" / "kernel" / "comm")
        )
        if encrypt and cipher is None:
            raise ValueError("encrypting agent state needs a cipher")
        self._audit = audit or _no_audit
        self._cipher = cipher
        self._encrypt = encrypt
        self.comm_dir = Path(comm_dir)
        self.comm_dir.mkdir(parents=True, exist_ok=True)
        self.subscribers: dict[str, list[Callable]] = {}
        # The latest time the clock was seen at, kept by expire(); publish
        # compares against it to notice a clock that went back.
        self._high_water = _parse_iso(self._load_clock().get("high_water"))
        self._behind_noted = False

    @staticmethod
    def _check_topic(topic: str, *, publishing: bool = False) -> str:
        """Refuse a topic that is not a file name prefix. The length is
        checked only to publish: stored topics of up to 218 bytes, from
        messages written without encrypted names, are still read."""
        if not isinstance(topic, str) or not topic or "/" in topic or "\0" in topic:
            raise ValueError(f"invalid topic {str(topic)[:64]!r}: empty, '/' or NUL")
        if publishing and len(topic.encode()) > MAX_TOPIC_BYTES:
            raise ValueError(
                f"topic {topic[:64]!r} is over {MAX_TOPIC_BYTES} bytes: its message "
                "files would not fit the 255-byte file name limit"
            )
        return topic

    def publish(self, topic: str, message: dict):
        """Publish a message to a topic. Each message gets its own file, so
        two in the same second do not overwrite each other."""
        self._check_topic(topic, publishing=True)
        _require_size("the message", message, MAX_PAYLOAD_BYTES)
        now = datetime.now(timezone.utc)
        self._note_clock(now)
        name = f"{topic}_{now.strftime('%Y%m%d_%H%M%S_%f')}_{secrets.token_hex(4)}"
        suffix = ".enc.json" if self._encrypt else ".json"
        message_file = self.comm_dir / f"{name}{suffix}"
        message_data = {
            "topic": topic,
            "message": message,
            "timestamp": now.isoformat(),
        }
        encoded = json.dumps(message_data).encode()
        _write_state(message_file, encoded, self._cipher, self._encrypt)
        self._audit(
            "event_published",
            topic,
            {
                "file": message_file.name,
                "bytes": len(encoded),
                "subscribers": len(self.subscribers.get(topic, ())),
            },
        )

        # Each subscriber gets its own copy of what was stored, so one cannot
        # change what the next receives, and those subscribed when it was
        # published: one that subscribes meanwhile waits for the next message.
        for callback in list(self.subscribers.get(topic, ())):
            try:
                callback(json.loads(encoded)["message"])
            except Exception as e:  # noqa: BLE001 - isolate subscriber failures
                logger.error("Subscriber callback failed: %s", _logged(e, 500))

    def _load_clock(self) -> dict:
        try:
            data = json.loads((self.comm_dir / _CLOCK_FILE).read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, RecursionError):
            logger.warning(
                "The retention clock record is unreadable; starting it again"
            )
            return {}
        return data if isinstance(data, dict) else {}

    def _save_clock(self, clock: dict) -> None:
        _write_durably(
            self.comm_dir / _CLOCK_FILE, json.dumps(clock, indent=2).encode()
        )

    def _note_clock(self, now: datetime) -> None:
        """At publish: a clock behind the latest time already seen is wrong,
        and a message written now gets a date older than it is. Noted once,
        so retention holds every message dated before that time."""
        if self._high_water is None:
            return
        if now < self._high_water - _CLOCK_SLACK:
            if not self._behind_noted:
                clock = self._load_clock()
                if not clock.get("behind"):
                    clock["behind"] = True
                    held = _parse_iso(clock.get("hold_below"))
                    clock["hold_below"] = _iso(
                        max(filter(None, (held, self._high_water)))
                    )
                    self._save_clock(clock)
                logger.warning(
                    "The clock (%s) is behind a time already seen (%s); messages "
                    "written now are held from retention until it is right",
                    now.isoformat(),
                    self._high_water.isoformat(),
                )
                self._behind_noted = True
        else:
            self._high_water = max(self._high_water, now)

    def expire(
        self,
        days: int,
        now: datetime | None = None,
        *,
        monotonic: float | None = None,
        boot_id: str | None = None,
    ) -> dict | None:
        """Remove messages older than days, by the time in their names, never
        sooner: whatever the clock does, a mistake can only keep a message
        longer.

        - A name dated before the code that writes it existed is never removed
          by its date (see _message_time).
        - The latest time seen is kept in .retention-clock.json. While the
          clock is behind it, nothing is removed; once it is right again,
          every message dated before that time is aged from the moment it was
          right, since it may have been written while the clock was wrong.
        - The cutoff moves only as fast as time measured on the monotonic
          clock, and by at most a day across a restart, so a clock that jumps
          ahead cannot remove years of messages at once. Time the machine is
          off does not count.
        - A message goes a day and a second after the cutoff passes it.

        Nothing but message files is touched. Each sweep that removes anything
        is synced and then recorded once (counts and times; no names, topics
        or content). Returns that record, or None when nothing was removed."""
        if (
            not isinstance(days, int)
            or isinstance(days, bool)
            or days < RETENTION_FLOOR_DAYS
        ):
            raise ValueError(f"retention below the {RETENTION_FLOOR_DAYS}-day floor")
        now = now or datetime.now(timezone.utc)
        monotonic = time.monotonic() if monotonic is None else monotonic
        boot_id = _boot_id() if boot_id is None else boot_id
        clock = self._load_clock()
        high_water = max(
            filter(None, (_parse_iso(clock.get("high_water")), self._high_water)),
            default=None,
        )
        if high_water is not None and now < high_water - _CLOCK_SLACK:
            if not clock.get("behind"):
                clock["behind"] = True
                held = _parse_iso(clock.get("hold_below"))
                clock["hold_below"] = _iso(max(filter(None, (held, high_water))))
                self._save_clock(clock)
            logger.warning(
                "The clock (%s) is behind a time already seen (%s); no message "
                "expires until it is right",
                now.isoformat(),
                high_water.isoformat(),
            )
            return None
        if clock.get("behind"):
            clock["behind"] = False
            until = _parse_iso(clock.get("hold_until"))
            clock["hold_until"] = _iso(max(filter(None, (until, now))))
        high_water = max(filter(None, (high_water, now)))
        self._high_water, self._behind_noted = high_water, False

        # The directory is opened once and used through that handle, so
        # swapping comm/ for a link during the sweep cannot redirect it.
        directory = os.open(self.comm_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return self._sweep_in(directory, days, now, monotonic, boot_id, clock,
                                  high_water)  # fmt: skip
        finally:
            os.close(directory)

    def _sweep_in(self, directory, days, now, monotonic, boot_id, clock, high_water):
        hold_below = _parse_iso(clock.get("hold_below"))
        hold_until = _parse_iso(clock.get("hold_until"))
        pending = (
            clock.get("unrecorded")
            if isinstance(clock.get("unrecorded"), dict)
            else None
        )
        stamped = []
        with os.scandir(directory) as entries:
            for entry in entries:
                when = _message_time(entry.name)
                if when is not None and entry.is_file(follow_symlinks=False):
                    stamped.append((when, entry.name))
        previous = _parse_iso(clock.get("cutoff"))
        try:
            if not stamped:
                proposed = None
            elif previous is None:
                # The first sweep has no record to go by: it measures back from
                # the newest message, so a clock already far ahead cannot
                # remove anything a newer message does not vouch for.
                proposed = min(now, max(when for when, _ in stamped)) - timedelta(
                    days=days
                )
            else:
                proposed = now - timedelta(days=days)  # held back below
        except OverflowError:  # a retention longer than the calendar
            proposed = None
        cutoff = proposed
        if proposed is not None and previous is not None:
            if boot_id is not None and boot_id == clock.get("boot_id"):
                advance = timedelta(
                    seconds=max(0.0, monotonic - clock.get("monotonic", monotonic))
                )
            else:
                since = now - (_parse_iso(clock.get("sweep_wall")) or now)
                advance = min(max(since, timedelta(0)), _RESTART_ALLOWANCE)
            cutoff = min(proposed, previous + advance)
        clock.update(
            high_water=_iso(high_water),
            cutoff=_iso(cutoff if cutoff is not None else previous),
            boot_id=boot_id,
            monotonic=monotonic,
            sweep_wall=_iso(now),
        )
        self._save_clock(clock)

        removed = []
        for when, name in sorted(stamped) if cutoff is not None else ():
            effective = when
            if hold_below is not None and hold_until is not None and when < hold_below:
                effective = max(when, hold_until)  # may have been written while wrong
            if effective + _SAFETY > cutoff:
                continue
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.warning(
                    "Cannot remove expired message %s: %s", _logged(name), exc.strerror
                )
                continue
            removed.append(when)
        record = _retention_record(pending, removed, days)
        if record is None:
            return None
        if removed:
            # Kept until it is recorded: a failing sync or audit append now is
            # recorded by the next sweep, so no removal goes unrecorded.
            clock["unrecorded"] = record
            self._save_clock(clock)
        os.fsync(directory)
        logger.info(
            "Expired %d message files older than %d days", record["removed"], days
        )
        self._audit("retention_expired", "comm", record)
        clock["unrecorded"] = None
        self._save_clock(clock)
        return record

    def subscribe(self, topic: str, callback: Callable):
        """Subscribe to a topic"""
        if topic not in self.subscribers:
            self.subscribers[topic] = []
        self.subscribers[topic].append(callback)

    def get_messages(self, topic: str, limit: int = 10) -> list[dict]:
        """Recent messages for exactly this topic, newest first.

        Files are picked and ordered by the time stamp in their names, and
        only as many are read as are returned. A name must be the topic and
        a stamp, so "alerts" never reads "alerts_low" files; the stored topic
        is checked as well. Unreadable files are skipped with a warning.
        """
        self._check_topic(topic)
        if limit <= 0:
            return []
        prefix = f"{topic}_"
        stamped = []
        names = set()
        with os.scandir(self.comm_dir) as entries:
            for entry in entries:
                if entry.name.startswith(prefix):
                    key = _message_stamp(entry.name[len(prefix) :])
                    if key is not None:
                        stamped.append((key, entry.name))
                        names.add(entry.name)
        stamped.sort(reverse=True)
        messages, done = [], set()
        for _, name in stamped:
            base = (
                name[: -len(".enc.json")] if name.endswith(".enc.json") else name[:-5]
            )
            if base in done:
                continue
            done.add(base)
            # An interrupted `state encrypt` or `state decrypt` can leave both
            # copies of a message, with the same bytes: the first that opens.
            for candidate in (f"{base}.enc.json", f"{base}.json"):
                if candidate in names:
                    data = self._read_message(self.comm_dir / candidate)
                    if data is not None:
                        break
            else:
                continue
            if isinstance(data, dict) and data.get("topic") == topic:
                messages.append(data)
                if len(messages) == limit:
                    break
        return messages

    def _read_message(self, file: Path):
        """The parsed message, or None with a warning when it cannot be read."""
        try:
            return json.loads(_open_state(file, self._cipher)[0])
        except (OSError, ValueError, RecursionError):
            logger.warning("Skipping unreadable message file %s", _logged(file.name))
        except StateKeyError as exc:
            logger.warning("Skipping message file %s: %s", _logged(file.name), exc)
        return None


class AgentRuntime:
    """
    Main agent runtime - orchestrates agent lifecycle, task scheduling,
    and inter-agent communication.
    """

    def __init__(
        self,
        data_dir: str | None = None,
        *,
        audit: Callable[[str, str, dict], None] | None = None,
        cipher=None,
        encrypt: bool = False,
    ):
        """encrypt turns agent state encryption on; once any state is
        encrypted it stays on, whatever encrypt says, until it is decrypted on
        purpose. A runtime given no cipher refuses encrypted state."""
        data_dir = data_dir or (
            os.environ.get("NGARI_DATA_DIR") or str(Path.home() / ".ngari" / "kernel")
        )
        found = sealed_state(data_dir)
        if found["files"] and cipher is None:
            raise StateKeyError(
                f"agent state in {data_dir} is encrypted ({found['files']} files) and "
                "this runtime was given no key; start it through the kernel"
            )
        self.state_encryption = bool(encrypt or found["files"])
        options = {"audit": audit, "cipher": cipher, "encrypt": self.state_encryption}
        self.registry = AgentRegistry(os.path.join(data_dir, "registry"), **options)
        self.scheduler = TaskScheduler(os.path.join(data_dir, "tasks"), **options)
        self.comm = InterAgentCommunication(os.path.join(data_dir, "comm"), **options)
        self.running = False

    def start(self):
        """Start the agent runtime"""
        self.running = True
        logger.info("Agent Runtime started")

        # Only agents still initializing move to running.
        for agent in self.registry.list_agents():
            if agent.state == AgentStateEnum.INITIALIZING:
                self.registry.update_agent_state(agent.agent_id, AgentStateEnum.RUNNING)

    def stop(self):
        """Stop the agent runtime"""
        self.running = False
        logger.info("Agent Runtime stopped")

    def register_agent(self, config: AgentConfig) -> str:
        """Register a new agent"""
        return self.registry.register_agent(config)

    def create_task(
        self,
        agent_id: str,
        action: str,
        payload: dict,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> str:
        """Create a new task for an agent"""
        return self.scheduler.create_task(agent_id, action, payload, priority)

    def publish_event(self, topic: str, message: dict):
        """Publish an inter-agent event"""
        self.comm.publish(topic, message)

    def subscribe_event(self, topic: str, callback: Callable):
        """Subscribe to an inter-agent event"""
        self.comm.subscribe(topic, callback)

    def get_status(self) -> dict:
        """Get runtime status"""
        agents = self.registry.list_agents()

        states = {}
        for s in AgentStateEnum:
            states[s.value] = 0
        for a in agents:
            key = a.state.value if hasattr(a.state, "value") else str(a.state)
            states[key] = states.get(key, 0) + 1
        return {
            "running": self.running,
            "agents": len(agents),
            "agents_by_state": states,
            "pending_tasks": len(self.scheduler.get_pending_tasks()),
            "total_tasks": len(self.scheduler.tasks),
            "state_encryption": self.state_encryption,
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    runtime = AgentRuntime()
    runtime.start()

    config = AgentConfig(
        name="TestAgent", agent_type="test", description="Test agent for NS-BOS kernel"
    )
    agent_id = runtime.register_agent(config)

    def test_handler(payload):
        return f"Processed: {payload}"

    runtime.scheduler.register_handler("test_action", test_handler)

    task_id = runtime.create_task(agent_id, "test_action", {"data": "hello"})

    runtime.publish_event("agent_status", {"agent_id": agent_id, "status": "running"})

    status = runtime.get_status()
    print(f"Runtime status: {json.dumps(status, indent=2)}")

    runtime.stop()
