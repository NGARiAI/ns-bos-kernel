"""
NS-BOS Kernel - Main Entry Point
NGARi Sovereign Business Operating System

This is the core kernel that provides:
- Hardware Abstraction Layer (HAL)
- Local Inference Engine Interface
- Agent Runtime Framework
- Sovereign Data Plane
- Network Synchronization
- Generative UI Engine

License: Apache 2.0
"""

import fcntl
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# The subsystems are imported by top-level name (hal, data_plane, ...).
sys.path.insert(0, str(Path(__file__).parent))

from agent_runtime import (
    AgentConfig,
    AgentRuntime,
    StateKeyError,
    TaskPriority,
    encrypt_state_enabled,
    retention_days,
    sealed_state,
)
from data_plane import KeyProviderError, SovereignDataPlane
from data_plane.redact import RedactingFormatter
from hal import HardwareAbstractionLayer, PlatformType, create_hal
from network_sync import NetworkSynchronization, SyncMode

__all__ = [
    "VERSION",
    "AgentConfig",
    "AgentRuntime",
    "HardwareAbstractionLayer",
    "NSBOSKernel",
    "NetworkSynchronization",
    "PlatformType",
    "SovereignDataPlane",
    "SyncMode",
    "TaskPriority",
    "create_hal",
]

logger = logging.getLogger("ns_bos_kernel")

VERSION = "0.2.0"
KERNEL_NAME = "NS-BOS"
KERNEL_FULL_NAME = "NGARi Sovereign Business Operating System"
LOG_FORMAT = "%(asctime)s [NSBOS] %(message)s"
# 0, false, no or off keep PII in the kernel's log lines (for debugging). The
# audit log is redacted whatever this says.
REDACT_ENV = "NGARI_REDACT_PII"
# What turning the air gap off allows, as the start warning says it. Each part
# matches a gate: inference, network_sync and sandbox.bwrap.
AIR_GAP_OFF_ALLOWS = (
    "inference endpoints outside loopback, environment proxies for those calls, "
    "model pulls, sync modes other than local_only, and agent code run in a plain "
    "subprocess with the host's network when bubblewrap is missing"
)
# Who the audit log names for what the kernel does. It is the kernel acting on
# a caller's request; nothing here authenticates the caller.
KERNEL_ACTOR = "kernel"


class NSBOSKernel:
    """
    Main NS-BOS Kernel class.
    Initializes and coordinates all kernel subsystems.
    """

    def __init__(self, data_dir: str | None = None):
        # Set but empty counts as unset, as in the keys, audit, state and
        # records commands: "" would otherwise be the current directory.
        data_dir = (
            data_dir
            or os.environ.get("NGARI_DATA_DIR")
            or str(Path.home() / ".ngari" / "kernel")
        )
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Owner only, as the data plane makes sovereign/: tasks, messages,
        # the registry and the twin are kept under it in plaintext unless
        # agent state encryption is on.
        _owner_only(self.data_dir)

        self.version = VERSION
        self.start_time = datetime.now(timezone.utc)
        self.running = False
        # How many entries of each kind this process has written; the log
        # itself is the record, this is a count since the process started.
        self.audited_actions: dict[str, int] = {}
        # Monotonic, so uptime survives the wall clock moving: a board with no
        # real-time clock can boot at an old time and be set later.
        self._running_since: float | None = None
        # Message retention: None keeps every message (NGARI_RETENTION_DAYS).
        self.retention_days = retention_days()
        self._last_sweep: float | None = None

        # Initialize subsystems
        logger.info(f"Initializing {KERNEL_FULL_NAME} v{VERSION}")

        # 1. Hardware Abstraction Layer
        self.hal = create_hal()
        hw_info = self.hal.get_hardware_info()
        logger.info(f"Platform detected: {hw_info.platform.value}")
        logger.info(f"CPU: {hw_info.cpu_model} ({hw_info.cpu_cores} cores)")
        logger.info(f"Memory: {hw_info.total_memory_gb} GB")
        logger.info(f"GPU: {hw_info.gpu_model} ({hw_info.gpu_memory_gb} GB)")

        # 2. Sovereign Data Plane. Agent state encrypted under the master key
        # is counted first, so the plane never mints a key over it and stops on
        # a key that is not the one it was written under.
        agents_dir = os.path.join(data_dir, "agents")
        found = sealed_state(agents_dir)
        self.data_plane = SovereignDataPlane(
            os.path.join(data_dir, "sovereign"),
            sealed_state=found["files"],
            state_key_ids=found["key_ids"],
        )
        if self.data_plane.air_gap:
            logger.info("Air gap: on")
        else:
            logger.warning(
                "Air gap: OFF (NGARI_AIR_GAP is set): %s", AIR_GAP_OFF_ALLOWS
            )
        logger.info("Sovereign Data Plane initialized")

        # 3. Agent Runtime
        wanted = encrypt_state_enabled()
        self.agent_runtime = AgentRuntime(
            agents_dir,
            audit=self._audit,
            cipher=self.data_plane.state_cipher,
            encrypt=wanted,
        )
        if self.agent_runtime.state_encryption:
            logger.info("Agent state encryption: on")
            if not wanted:
                logger.warning(
                    "NGARI_ENCRYPT_STATE is off, but agent state is already "
                    "encrypted; it stays encrypted"
                )
        logger.info("Agent Runtime initialized")

        # 4. Network Synchronization
        self.network_sync = NetworkSynchronization(os.path.join(data_dir, "sync"))
        logger.info("Network Synchronization initialized")

        self.data_plane.store_encrypted(
            "kernel_state",
            {
                "version": VERSION,
                "platform": hw_info.platform.value,
                "started_at": self.start_time.isoformat(),
                "data_dir": str(self.data_dir),
            },
        )

    def _audit(self, action: str, resource: str, details: dict) -> None:
        """Write one keyed entry for something the kernel did, after the state
        it describes is on disk. Nothing in details is a payload, a result,
        an error text, a description or a twin value."""
        self.data_plane.record(action, KERNEL_ACTOR, resource, details)
        self.audited_actions[action] = self.audited_actions.get(action, 0) + 1

    def _twin(self, key: str, value) -> None:
        """Set a twin value and record it, unless it already holds that value:
        an unchanged registration or a repeat start changes nothing."""
        if self.network_sync.get_twin_value(key) == value:
            return
        self.network_sync.update_twin(key, value)
        self._audit("twin_updated", key, {})

    def start(self):
        """Start the kernel. A second call while running does nothing: it is
        not another boot to record, and the uptime runs on."""
        if self.running:
            return
        self.running = True
        self._running_since = time.monotonic()
        try:
            self._audit(
                "kernel_started",
                VERSION,
                {
                    "platform": self.hal.get_hardware_info().platform.value,
                    "agents": len(self.agent_runtime.registry.list_agents()),
                },
            )
        except BaseException:
            # Not started until the boot is recorded: a retry, once the disk
            # has room again, starts the kernel instead of doing nothing.
            self.running = False
            self._running_since = None
            raise
        self.agent_runtime.start()
        logger.info(f"{KERNEL_FULL_NAME} v{VERSION} started")
        self._expire_messages()

        self._twin("kernel.version", VERSION)
        self._twin("kernel.status", "running")

    SWEEP_SECONDS = 24 * 60 * 60

    def _expire_messages(self) -> None:
        """One retention sweep, if retention is set. A failure is logged and
        the kernel goes on; the next sweep tries again."""
        if self.retention_days is None:
            return
        self._last_sweep = time.monotonic()
        try:
            self.agent_runtime.comm.expire(self.retention_days)
        except (OSError, ValueError) as exc:
            logger.error("Message retention sweep failed: %s", exc)

    def tick(self) -> None:
        """Called from the run loop: a retention sweep once a day, timed on
        the monotonic clock so a wall clock that is set does not trigger one."""
        if self._last_sweep is not None and (
            time.monotonic() - self._last_sweep >= self.SWEEP_SECONDS
        ):
            self._expire_messages()

    def stop(self):
        """Stop the kernel. A kernel that is not running has nothing to stop or
        record. A failing twin write or audit append is logged and shutdown
        goes on: a full disk must not stop the signal handler being put back."""
        if not self.running:
            return
        uptime = (
            0.0
            if self._running_since is None
            else time.monotonic() - self._running_since
        )
        self.running = False
        self._running_since = None
        self.agent_runtime.stop()
        try:
            self._twin("kernel.status", "stopped")
        except Exception as exc:  # noqa: BLE001 - shutdown goes on if the twin fails
            logger.error(
                "Cannot record the stopped state in the digital twin: %s",
                type(exc).__name__,
            )
        try:
            self._audit("kernel_stopped", VERSION, {"uptime_seconds": round(uptime, 3)})
        except OSError as exc:
            logger.error("Cannot record the shutdown in the audit log: %s", exc)
        logger.info(f"{KERNEL_FULL_NAME} stopped")

    def get_status(self) -> dict:
        """Get comprehensive kernel status"""
        hw_info = self.hal.get_hardware_info()

        return {
            "kernel": {
                "name": KERNEL_FULL_NAME,
                "version": VERSION,
                "status": "running" if self.running else "stopped",
                "uptime_seconds": (
                    0.0
                    if self._running_since is None
                    else time.monotonic() - self._running_since
                ),
                "audited_actions": dict(self.audited_actions),
                "retention_days": self.retention_days,
            },
            "hardware": {
                "platform": hw_info.platform.value,
                "cpu": hw_info.cpu_model,
                "cpu_cores": hw_info.cpu_cores,
                "memory_gb": hw_info.total_memory_gb,
                "gpu": hw_info.gpu_model,
                "gpu_memory_gb": hw_info.gpu_memory_gb,
                "storage_available_gb": hw_info.storage_available_gb,
                "storage_total_gb": hw_info.storage_total_gb,
                "gpu_utilization": self.hal.get_gpu_utilization(),
                "memory_utilization": self.hal.get_memory_utilization(),
                "cpu_utilization": self.hal.get_cpu_utilization(),
                "temperature": self.hal.get_temperature(),
                "power_watts": self.hal.get_power_consumption(),
            },
            "agents": self.agent_runtime.get_status(),
            "fleet": self.network_sync.get_fleet_status(),
            "data_sovereignty": self.data_plane.export_compliance_report(),
        }

    def register_agent(self, name: str, agent_type: str, description: str = "") -> str:
        """Register a new agent with the kernel"""
        config = AgentConfig(name=name, agent_type=agent_type, description=description)
        agent_id = self.agent_runtime.register_agent(config)

        self._twin(
            f"agent.{name}",
            {"agent_id": agent_id, "type": agent_type, "status": "registered"},
        )

        return agent_id

    def create_task(
        self,
        agent_id: str,
        action: str,
        payload: dict,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> str:
        """Create a task for an agent"""
        return self.agent_runtime.create_task(agent_id, action, payload, priority)

    def publish_event(self, topic: str, message: dict):
        """Publish an inter-agent event"""
        self.agent_runtime.publish_event(topic, message)

    def subscribe_event(self, topic: str, callback):
        """Subscribe to an inter-agent event"""
        self.agent_runtime.subscribe_event(topic, callback)


INSTANCE_LOCK = "kernel.lock"


def _hold_instance_lock(data_dir: Path):
    """The open, exclusively locked kernel.lock with this pid in it, or None
    if another process holds it."""
    fd = os.open(data_dir / INSTANCE_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    lock = os.fdopen(fd, "r+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        return None
    lock.truncate(0)
    lock.write(f"{os.getpid()}\n")
    lock.flush()
    return lock


def _lock_holder(data_dir: Path) -> str | None:
    """The pid the running kernel wrote into kernel.lock, if readable."""
    try:
        text = (data_dir / INSTANCE_LOCK).read_text().strip()
    except OSError:
        return None
    return text if text.isdigit() else None


def _unusable(exc: OSError) -> str:
    """One line for a data directory the kernel cannot use."""
    where = f"{exc.filename}: " if exc.filename else ""
    return (
        f"{where}{exc.strerror or exc}. Check that NGARI_DATA_DIR is a directory "
        "this user owns, on a disk that is writable and not full"
    )


def _owner_only(path: Path) -> None:
    """Leave path readable and writable by its owner alone (mode bits for
    the group and others cleared)."""
    mode = path.stat().st_mode
    if mode & 0o077:
        os.chmod(path, mode & 0o700)


def _interrupt(signum, frame):
    """The first SIGINT or SIGTERM: from here on both are ignored, so a
    second one cannot cut the shutdown short before main's finally ignores
    them itself, then the run loop is left as Ctrl+C leaves it."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt


USAGE = """usage: ns-bos [keys | audit | state | records | agents] ...

With no arguments, start the kernel; it is configured through the environment
(NGARI_DATA_DIR and the other NGARI_ variables). Commands:

  keys    where the master key is held, migrate, recovery bundles (docs/KEY_PROVIDERS.md)
  audit   verify the audit log, keep an anchor (docs/AUDIT_LOG.md)
  state   agent state encryption (docs/AGENT_STATE.md)
  records sign a file with the operator's card, check its signatures (docs/ESIGNATURES.md)
  agents  sponsor an AI agent with your card, check its manifest (docs/AGENT_IDENTITY.md)

Each command takes --help."""


def main(argv=None):
    """Main entry point for NS-BOS Kernel: no arguments start the kernel;
    `keys`, `audit`, `state`, `records` and `agents` run their commands. Any
    other argument is refused, so a mistyped command never starts the kernel."""
    args = sys.argv[1:] if argv is None else list(argv)
    if args[:1] == ["keys"]:
        from data_plane.keys_cli import cli

        raise SystemExit(cli(args[1:]))
    if args[:1] == ["audit"]:
        from data_plane.audit_cli import cli

        raise SystemExit(cli(args[1:]))
    if args[:1] == ["state"]:
        from state_cli import cli

        raise SystemExit(cli(args[1:], hold_lock=_hold_instance_lock))
    if args[:1] == ["records"]:
        from data_plane.records_cli import cli

        raise SystemExit(cli(args[1:]))
    if args[:1] == ["agents"]:
        from data_plane.agents_cli import cli

        raise SystemExit(cli(args[1:]))
    if args[:1] in (["-h"], ["--help"], ["help"]):
        print(USAGE)
        raise SystemExit(0)
    if args:
        print(f"ns-bos: unknown command {args[0]!r}\n\n{USAGE}", file=sys.stderr)
        raise SystemExit(2)

    # The data and log directories exist before the FileHandler is made:
    # `logging.FileHandler` does not create its parent directory.
    data_dir = Path(
        os.environ.get("NGARI_DATA_DIR") or str(Path.home() / ".ngari" / "kernel")
    )
    try:
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        (data_dir / "logs").mkdir(mode=0o700, exist_ok=True)
        log_path = data_dir / "logs" / "kernel.log"
        # Created 0600 before the handler opens it, whatever the umask: log
        # lines can carry what agents and callers pass in.
        os.close(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
        for path in (data_dir, data_dir / "logs", log_path):
            _owner_only(path)
        log_file = logging.FileHandler(str(log_path))
    except OSError as exc:
        print(f"Cannot start: {_unusable(exc)}", file=sys.stderr)
        raise SystemExit(2) from None

    handlers = [log_file, logging.StreamHandler()]
    if os.environ.get(REDACT_ENV, "").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    ):
        # Log lines can carry what agents and callers pass in; PII in them is
        # replaced by its kind (docs/PII_REDACTION.md).
        for handler in handlers:
            handler.setFormatter(RedactingFormatter(LOG_FORMAT))
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=handlers)

    logger.info(f"Starting {KERNEL_FULL_NAME} v{VERSION}")

    # One kernel per data directory. Held until this process exits; the OS
    # drops an flock when the process ends, so a crash leaves no stale lock.
    try:
        instance = _hold_instance_lock(data_dir)
    except OSError as exc:
        logger.error("Cannot start: %s", _unusable(exc))
        raise SystemExit(2) from None
    if instance is None:
        holder = _lock_holder(data_dir)
        logger.error(
            "Cannot start: another kernel is running on %s%s; stop it first",
            data_dir,
            f" (pid {holder})" if holder else "",
        )
        raise SystemExit(2)

    try:
        kernel = NSBOSKernel()
    except (KeyProviderError, StateKeyError) as exc:
        logger.error("Cannot start: %s", exc)
        raise SystemExit(2) from None
    except OSError as exc:
        logger.error("Cannot start: %s", _unusable(exc))
        raise SystemExit(2) from None
    except KeyboardInterrupt:
        logger.info("Startup interrupted")
        raise SystemExit(130) from None

    # The handlers are installed before start(): from there on, Ctrl+C or SIGTERM
    # (what systemd sends) always reaches stop().
    previous = signal.getsignal(signal.SIGTERM)
    interrupt = signal.getsignal(signal.SIGINT)
    try:
        # Inside the try: a signal as they are installed still reaches the
        # finally, which puts the caller's handlers back.
        signal.signal(signal.SIGTERM, _interrupt)
        signal.signal(signal.SIGINT, _interrupt)
        kernel.start()

        # Register the 6 core agents
        agents = [
            ("CEO", "strategic", "Revenue monitoring and strategic oversight"),
            ("CRO", "sales", "Sales pipeline analysis and outreach strategy"),
            ("Engineer", "system", "System health monitoring and diagnostics"),
            ("Worker", "execution", "Task execution and order queue monitoring"),
            (
                "Email",
                "communication",
                "Automated order confirmations and provisioning",
            ),
            (
                "Communications",
                "messaging",
                "Matrix-based customer messaging and support",
            ),
        ]

        agent_ids = {}
        for name, agent_type, description in agents:
            agent_id = kernel.register_agent(name, agent_type, description)
            agent_ids[name] = agent_id
            logger.info(f"Registered agent: {name} ({agent_id})")

        status = kernel.get_status()
        print(f"\n{'=' * 60}")
        print(f"  {KERNEL_FULL_NAME} v{VERSION}")
        print(f"{'=' * 60}")
        print(f"  Platform: {status['hardware']['platform']}")
        print(
            f"  CPU: {status['hardware']['cpu']} ({status['hardware']['cpu_cores']} cores)"
        )
        print(f"  Memory: {status['hardware']['memory_gb']} GB")
        print(
            f"  GPU: {status['hardware']['gpu']} ({status['hardware']['gpu_memory_gb']} GB)"
        )
        print(
            f"  Storage: {status['hardware']['storage_available_gb']:.1f} GB available"
        )
        print(f"  Agents: {status['agents']['agents']} registered")
        print(f"  Fleet: {status['fleet']['total_nodes']} nodes")
        print(f"  Data Sovereignty: {status['data_sovereignty']['data_sovereignty']}")
        print(f"{'=' * 60}\n")

        while kernel.running:
            time.sleep(60)
            kernel.tick()
    except KeyboardInterrupt:
        logger.info("Kernel shutdown requested")
    finally:
        # A second SIGTERM or Ctrl+C during stop() would cut it short: no
        # kernel_stopped entry, the handler not put back, a traceback. The
        # stop is under way, so both are ignored until it is done.
        while True:
            try:
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                break
            except KeyboardInterrupt:
                # A first signal as a shutdown that began another way (the
                # loop ended, start() raised) reached here: it asks for the
                # stop already under way.
                continue
        try:
            kernel.stop()
            logger.info("Kernel stopped")
        finally:
            signal.signal(signal.SIGTERM, previous)
            signal.signal(signal.SIGINT, interrupt)


if __name__ == "__main__":
    main()
