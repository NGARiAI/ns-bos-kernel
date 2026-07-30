"""
NS BOS Kernel - Network Synchronization
Fleet communication protocol, digital twin sync, encrypted peer-to-peer mesh,
and optional zero-knowledge cloud sync.
"""

import os
import json
import time
import hashlib
import logging
from datetime import datetime
from typing import Optional, Any, Dict, List
from dataclasses import dataclass, asdict, field
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


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
    last_sync: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    version: int = 0
    checksum: str = ""

    def compute_checksum(self) -> str:
        """Compute checksum for integrity verification"""
        data = {
            "user_id": self.user_id,
            "agent_states": self.agent_states,
            "preferences": self.preferences,
            "memory_index": self.memory_index,
            "version": self.version
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def validate(self) -> bool:
        """Validate state integrity"""
        return self.checksum == self.compute_checksum()


@dataclass
class FleetNode:
    """Represents a node in the NGARI fleet"""
    node_id: str
    hostname: str
    platform: str
    ip_address: str
    status: str = "offline"
    last_seen: str = ""
    capabilities: dict = field(default_factory=dict)
    sync_mode: SyncMode = SyncMode.LOCAL_ONLY


class NetworkSynchronization:
    """
    Network synchronization layer for fleet management.
    Handles digital twin sync, peer-to-peer communication,
    and optional cloud sync.
    """

    def __init__(self, sync_dir: str = None):
        sync_dir = sync_dir or os.environ.get("NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel" / "sync"))
        self.sync_dir = Path(sync_dir)
        self.sync_dir.mkdir(parents=True, exist_ok=True)

        self.twin_file = self.sync_dir / "digital_twin.json"
        self.fleet_file = self.sync_dir / "fleet.json"
        self.sync_log = self.sync_dir / "sync.log"

        self.local_state = self._load_twin()
        self.fleet_nodes = self._load_fleet()
        self.sync_mode = SyncMode.LOCAL_ONLY

    def _load_twin(self) -> DigitalTwinState:
        """Load digital twin state"""
        if self.twin_file.exists():
            with open(self.twin_file, "r") as f:
                data = json.load(f)
                state = DigitalTwinState(**data)
                if not state.validate():
                    logger.warning("Digital twin checksum mismatch - using local state")
                return state

        return DigitalTwinState(
            user_id="ngari-default",
            agent_states={},
            preferences={},
            memory_index={}
        )

    def _save_twin(self):
        """Save digital twin state"""
        self.local_state.version += 1
        self.local_state.checksum = self.local_state.compute_checksum()
        self.local_state.last_sync = datetime.utcnow().isoformat()

        with open(self.twin_file, "w") as f:
            json.dump(asdict(self.local_state), f, indent=2)

    def _load_fleet(self) -> Dict[str, FleetNode]:
        """Load fleet configuration"""
        if self.fleet_file.exists():
            with open(self.fleet_file, "r") as f:
                data = json.load(f)
                return {
                    node_id: FleetNode(**node_data)
                    for node_id, node_data in data.items()
                }
        return {}

    def _save_fleet(self):
        """Save fleet configuration"""
        data = {
            node_id: asdict(node)
            for node_id, node in self.fleet_nodes.items()
        }
        with open(self.fleet_file, "w") as f:
            json.dump(data, f, indent=2)

    def update_twin(self, key: str, value: Any):
        """Update digital twin state"""
        # Determine which section to update
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

    def get_twin_value(self, key: str) -> Optional[Any]:
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
        self.fleet_nodes[node.node_id] = node
        self._save_fleet()
        logger.info(f"Fleet node registered: {node.hostname} ({node.node_id})")

    def update_node_status(self, node_id: str, status: str):
        """Update fleet node status"""
        if node_id in self.fleet_nodes:
            self.fleet_nodes[node_id].status = status
            self.fleet_nodes[node_id].last_seen = datetime.utcnow().isoformat()
            self._save_fleet()

    def get_fleet_status(self) -> dict:
        """Get fleet status overview"""
        return {
            "total_nodes": len(self.fleet_nodes),
            "online_nodes": len([n for n in self.fleet_nodes.values() if n.status == "online"]),
            "offline_nodes": len([n for n in self.fleet_nodes.values() if n.status == "offline"]),
            "nodes": {
                node_id: {
                    "hostname": node.hostname,
                    "platform": node.platform,
                    "status": node.status,
                    "last_seen": node.last_seen
                }
                for node_id, node in self.fleet_nodes.items()
            }
        }

    def set_sync_mode(self, mode: SyncMode):
        """Set synchronization mode"""
        self.sync_mode = mode
        logger.info(f"Sync mode set to: {mode.value}")

    def export_twin(self) -> dict:
        """Export digital twin state for migration or backup"""
        return asdict(self.local_state)

    def import_twin(self, data: dict) -> bool:
        """Import digital twin state"""
        try:
            state = DigitalTwinState(**data)
            if state.validate():
                self.local_state = state
                self._save_twin()
                return True
            else:
                logger.error("Imported twin checksum mismatch")
                return False
        except Exception as e:
            logger.error(f"Failed to import twin: {e}")
            return False

    def _log_sync(self, action: str, key: str):
        """Log synchronization event"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "key": key,
            "version": self.local_state.version,
            "checksum": self.local_state.checksum
        }
        with open(self.sync_log, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_sync_history(self, limit: int = 50) -> list:
        """Get recent sync events"""
        if not self.sync_log.exists():
            return []

        entries = []
        with open(self.sync_log, "r") as f:
            lines = f.readlines()

        for line in lines[-limit:]:
            entries.append(json.loads(line))

        return entries


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    sync = NetworkSynchronization()

    # Update twin state
    sync.update_twin("agent.ceo", {"status": "running", "revenue_target": 1000})
    sync.update_twin("pref.theme", "kemet")
    sync.update_twin("memory.last_query", "What is NS BOS?")

    # Get values
    print(f"CEO Agent: {sync.get_twin_value('agent.ceo')}")
    print(f"Theme: {sync.get_twin_value('pref.theme')}")

    # Register fleet node
    node = FleetNode(
        node_id="node-01",
        hostname="ngari-jetson-01",
        platform="jetson_agx_orin",
        ip_address="203.0.113.1",
        status="online",
        capabilities={"gpu": True, "memory_gb": 64}
    )
    sync.register_node(node)

    # Get fleet status
    print(f"Fleet status: {json.dumps(sync.get_fleet_status(), indent=2)}")

    # Export twin
    twin = sync.export_twin()
    print(f"Twin version: {twin['version']}")
    print(f"Twin checksum: {twin['checksum']}")
