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

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add kernel to path
sys.path.insert(0, str(Path(__file__).parent))

from agent_runtime import AgentConfig, AgentRuntime, TaskPriority
from data_plane import SovereignDataPlane
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

VERSION = "0.1.0"
KERNEL_NAME = "NS-BOS"
KERNEL_FULL_NAME = "NGARi Sovereign Business Operating System"


class NSBOSKernel:
    """
    Main NS-BOS Kernel class.
    Initializes and coordinates all kernel subsystems.
    """

    def __init__(self, data_dir: str | None = None):
        data_dir = data_dir or os.environ.get(
            "NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel")
        )
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.version = VERSION
        self.start_time = datetime.now(timezone.utc)
        self.running = False

        # Initialize subsystems
        logger.info(f"Initializing {KERNEL_FULL_NAME} v{VERSION}")

        # 1. Hardware Abstraction Layer
        self.hal = create_hal()
        hw_info = self.hal.get_hardware_info()
        logger.info(f"Platform detected: {hw_info.platform.value}")
        logger.info(f"CPU: {hw_info.cpu_model} ({hw_info.cpu_cores} cores)")
        logger.info(f"Memory: {hw_info.total_memory_gb} GB")
        logger.info(f"GPU: {hw_info.gpu_model} ({hw_info.gpu_memory_gb} GB)")

        # 2. Sovereign Data Plane
        self.data_plane = SovereignDataPlane(os.path.join(data_dir, "sovereign"))
        logger.info("Sovereign Data Plane initialized")

        # 3. Agent Runtime
        self.agent_runtime = AgentRuntime(os.path.join(data_dir, "agents"))
        logger.info("Agent Runtime initialized")

        # 4. Network Synchronization
        self.network_sync = NetworkSynchronization(os.path.join(data_dir, "sync"))
        logger.info("Network Synchronization initialized")

        # Store kernel state
        self.data_plane.store_encrypted(
            "kernel_state",
            {
                "version": VERSION,
                "platform": hw_info.platform.value,
                "started_at": self.start_time.isoformat(),
                "data_dir": str(self.data_dir),
            },
        )

    def start(self):
        """Start the kernel"""
        self.running = True
        self.agent_runtime.start()
        logger.info(f"{KERNEL_FULL_NAME} v{VERSION} started")

        # Update network sync with kernel state
        self.network_sync.update_twin("kernel.version", VERSION)
        self.network_sync.update_twin("kernel.status", "running")

    def stop(self):
        """Stop the kernel"""
        self.running = False
        self.agent_runtime.stop()
        self.network_sync.update_twin("kernel.status", "stopped")
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
                    datetime.now(timezone.utc) - self.start_time
                ).total_seconds(),
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

        # Update digital twin
        self.network_sync.update_twin(
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


def main():
    """Main entry point for NS-BOS Kernel"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [NSBOS] %(message)s",
        handlers=[
            logging.FileHandler(
                os.path.join(
                    os.environ.get(
                        "NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel")
                    ),
                    "logs",
                    "kernel.log",
                )
            ),
            logging.StreamHandler(),
        ],
    )

    logger.info(f"Starting {KERNEL_FULL_NAME} v{VERSION}")

    kernel = NSBOSKernel()
    kernel.start()

    # Register the 6 core agents
    agents = [
        ("CEO", "strategic", "Revenue monitoring and strategic oversight"),
        ("CRO", "sales", "Sales pipeline analysis and outreach strategy"),
        ("Engineer", "system", "System health monitoring and diagnostics"),
        ("Worker", "execution", "Task execution and order queue monitoring"),
        ("Email", "communication", "Automated order confirmations and provisioning"),
        ("Communications", "messaging", "Matrix-based customer messaging and support"),
    ]

    agent_ids = {}
    for name, agent_type, description in agents:
        agent_id = kernel.register_agent(name, agent_type, description)
        agent_ids[name] = agent_id
        logger.info(f"Registered agent: {name} ({agent_id})")

    # Get and display status
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
    print(f"  Storage: {status['hardware']['storage_available_gb']:.1f} GB available")
    print(f"  Agents: {status['agents']['agents']} registered")
    print(f"  Fleet: {status['fleet']['total_nodes']} nodes")
    print(f"  Data Sovereignty: {status['data_sovereignty']['data_sovereignty']}")
    print(f"{'=' * 60}\n")

    try:
        # Keep running
        import time

        while kernel.running:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Kernel shutdown requested")
    finally:
        kernel.stop()
        logger.info("Kernel stopped")


if __name__ == "__main__":
    main()
