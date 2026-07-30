# NS-BOS Kernel — Module Interface Reference

## Architecture

```
                    +-----------------------------------+
                    |        Production Agents           |
                    |  (CEO, CRO, CMO, Engineer,        |
                    |   Worker, Comms)                   |
                    +---------+-------------------------+
                              |
                    +---------v-------------------------+
                    |        KernelBridge               |
                    |  core/kernel_bridge.py            |
                    |  - bootstrap()                     |
                    |  - infer() / chat()               |
                    |  - audit() / compliance_report()  |
                    |  - register_agent()               |
                    |  - publish() / subscribe()        |
                    +----+----+----+----+----+----------+
                         |    |    |    |    |
              +----------+    |    |    |    +-----------+
              v               v    v    v                v
    +---------+-----+  +------+----+----+------+  +------+----------+
    | AgentRuntime  |  | InferenceEngineManager |  | SovereignDP    |
    | - registry    |  | - OllamaInterface      |  | - encrypt/store|
    | - scheduler   |  | - LlamaCppInterface    |  | - audit log    |
    | - comm bus    |  | - VLLMInterface        |  | - compliance   |
    +-------+-------+  | - ModelRegistry        |  +------+----------+
            |          +------------------------+         |
            v                                             v
    +-------+----------+                      +----------+-----------+
    | Network Sync     |                      | HardwareAbstraction |
    | - DigitalTwin    |                      | - JetsonHAL         |
    | - FleetNode      |                      | - X86HAL            |
    | - P2P mesh       |                      | - detect_platform() |
    +------------------+                      +---------------------+
```

## Module Contracts

### `core/kernel_bridge.py` — Entry Point
```python
from core.kernel_bridge import bootstrap, get_kernel_bridge

kb = bootstrap()           # Initialize on app startup
kb.infer(prompt, model)    # Route prompt through best inference engine
kb.chat(messages, model)   # Chat through best inference engine
kb.audit(action, agent_id) # Record auditable action
kb.register_agent(...)     # Register with kernel runtime
kb.compliance_report()     # Export compliance report
```

### `core/kernel/hal/` — Hardware Abstraction Layer
```python
from core.kernel.hal import detect_platform, create_hal

platform = detect_platform()   # → PlatformType enum
hal = create_hal()             # Factory: JetsonHAL | X86HAL
info = hal.get_hardware_info() # → HardwareInfo dataclass
hal.get_gpu_utilization()      # → float 0-100
hal.get_memory_utilization()   # → float 0-100
hal.get_temperature()          # → dict {zone: celsius}
```
**Supported platforms:** Jetson Nano/AGX Orin/Thor, x86_64, ARM64, Raspberry Pi, Cloud VMs

### `core/kernel/inference/` — Inference Engine
```python
from core.kernel.inference import InferenceEngineManager

mgr = InferenceEngineManager()
mgr.generate(model, prompt)    # Generate text (auto-select engine)
mgr.chat(model, messages)      # Chat format (auto-select engine)
mgr.get_status()               # → {engines: [...], models: [...]}
```
**Engines:** Ollama, llama.cpp, vLLM (auto-failover)

### `core/kernel/agent_runtime/` — Agent Runtime
```python
from core.kernel.agent_runtime import AgentRuntime, AgentConfig

runtime = AgentRuntime()
runtime.start()
agent_id = runtime.register_agent(config)  # → uuid
runtime.create_task(agent_id, action, payload)
runtime.publish_event(topic, message)
runtime.get_status()
```
**States:** INITIALIZING → RUNNING → IDLE → PAUSED → ERROR → TERMINATED

### `core/kernel/data_plane/` — Sovereign Data Plane
```python
from core.kernel.data_plane import SovereignDataPlane

dp = SovereignDataPlane()
dp.store_encrypted(key, data)  # AES-256-Fernet
dp.retrieve_decrypted(key)     # Returns decrypted data or None
dp.verify_audit_integrity()    # SHA-256 chain verification
dp.export_compliance_report()  # → {encryption, audit_entries, ...}
```

### `core/kernel/network_sync/` — Fleet Sync
```python
from core.kernel.network_sync import NetworkSynchronization, FleetNode

sync = NetworkSynchronization()
sync.register_node(node)           # Add fleet node
sync.update_twin(key, value)       # Update digital twin
sync.get_twin_value(key)           # Read from twin
sync.get_fleet_status()            # Fleet overview
sync.export_twin() / import_twin() # Migration/backup
```
**Modes:** LOCAL_ONLY | PEER_TO_PEER | CLOUD_SYNC | HYBRID

### `core/provisioning/device_identity.py` — Device Identity
```python
from core.provisioning.device_identity import provision_device, onboard_device

identity = provision_device()  # Generate keys + cert (run once)
onboard_device()               # Register with kernel bridge + fleet
```
**Key format:** Ed25519, stored in `$NGARI_DATA_DIR/identity/`

### `core/provisioning/zero_touch.py` — Zero-Touch Onboarding
```python
from core.provisioning.zero_touch import bootstrap_device

bootstrap_device()  # Provision + onboard + discover + register
```

## Agent Integration Pattern

```python
from core.agents.ngari_agent import NGARiAgent

class MyAgent(NGARiAgent):
    def think(self, prompt):
        # Option 1: Use kernel inference (LLM)
        return self._kernel_infer(prompt, model="qwen3:8b")

        # Option 2: Use kernel chat (multi-message)
        return self._kernel_chat([{"role":"user","content":prompt}])

    def act(self, action, params):
        self._kernel_audit(action, params)  # Encrypted audit
        self._kernel_publish("agent.action", {"action": action})
        return {"success": True}

    def health_check(self):
        return {"status": "ok"}

    def _do_some_action(self, params):
        self._kernel_audit("do_some_action", params)
        compliance = self._kernel_compliance()  # Current compliance state
        return {"success": True}
```

## Deployment

```bash
# One-click flash (on Jetson AGX Orin):
sudo bash scripts/orin-flash.sh

# Build redistributable image:
sudo bash scripts/orin-iso-builder.sh

# Output: ngari-orin-rootfs.tar.gz
# Deploy: tar xzf ngari-orin-rootfs.tar.gz -C /opt/ngari/ && sudo bash orin-flash.sh
```

## Quick Reference

| Port | Service | Module |
|------|---------|--------|
| 8888 | Control Tower | `core/agents/sovereign_dashboard.py` |
| 8889 | Stripe Webhook | `core/webhooks/stripe_listener.py` |
| 8893 | Lead Capture | `core/lead_capture/lead_capture_agent.py` |
| 8894 | Fleet Manager | `core/fleet/fleet_manager.py` |
| 11434 | Ollama | `ollama.service` |

## Platform Status

| Platform | HAL | Inference | Agent Runtime | Fleet Sync |
|----------|-----|-----------|---------------|------------|
| Jetson AGX Orin | `JetsonHAL` | Ollama (native) | Active | P2P |
| Jetson Nano | `JetsonHAL` | Ollama | Active | P2P |
| x86_64 | `X86HAL` | Ollama/llama.cpp | Active | P2P |
| Raspberry Pi | `X86HAL`* | Ollama | Active | P2P |
| Cloud VM | `X86HAL`* | vLLM | Active | Cloud Sync |

*Platform-specific HAL implementations pending for ARM/Cloud.
