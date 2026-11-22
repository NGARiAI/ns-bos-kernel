# NS-BOS Kernel: Module Interface Reference

## Architecture

```
+--------------------------------------+
|  Production Agents (application layer)|
+------------------+-------------------+
                   |
        +----------v-----------+
        | KernelBridge         |   <- application facade (app repo)
        +----+----+----+----+--+
             |    |    |    |
   +---------+    |    |    +----------+
   v              v    v               v
+------+   +------------+   +----------------+
| Agent|   | Inference  |   | Sovereign DP   |
| Runtime|  | Manager    |   | - encrypt/store|
| - registry| - Ollama   |   | - audit log    |
| - scheduler| - llama.cpp|   | - compliance   |
| - comm bus | - vLLM     |   +-------+--------+
+---+---+   | - registry |            |
    |       +-----+------+            |
    v             v                   v
+--------+   +----------+   +------------------+
| Network|   | Sandbox   |   | HAL              |
| Sync   |   | - bwrap   |   | - JetsonHAL      |
| - twin |   | - seccomp |   | - X86HAL         |
| - ledger|   +----------+   | - detect_platform|
+--------+                  +------------------+
```

The kernel is a library: applications (agents, dashboards) import it and register
their own tool dispatcher via `set_tool_dispatcher()`.

## Module Contracts

### `core/kernel/hal/`: Hardware Abstraction Layer
```python
from core.kernel.hal import detect_platform, create_hal

platform = detect_platform()  # → PlatformType enum
hal = create_hal()  # Factory: JetsonHAL | X86HAL
info = hal.get_hardware_info()  # → HardwareInfo dataclass
hal.get_gpu_utilization()  # → float 0-100
hal.get_memory_utilization()  # → float 0-100
hal.get_temperature()  # → dict {zone: celsius}
```
**Supported platforms:** Jetson Nano/AGX Orin/Thor, x86_64, ARM64, Raspberry Pi, Cloud VMs

### `core/kernel/inference/`: Inference Engine
```python
from core.kernel.inference import InferenceEngineManager, set_tool_dispatcher

mgr = InferenceEngineManager()
mgr.generate(model, prompt)  # Generate text (auto-select engine)
mgr.chat(model, messages)  # Chat format (auto-select engine)
mgr.get_status()  # → {available_engines: [...], registered_models: n, ...}

# Wire application tool dispatch into chat_with_tools:
set_tool_dispatcher(lambda tool_calls: [...])
```
**Engines:** Ollama, llama.cpp, vLLM (auto-failover). `chat_with_tools`
falls back to `core.tools.dispatch` when present (app repo) and otherwise
returns the call history without dispatch.

### `core/kernel/agent_runtime/`: Agent Runtime
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

### `core/kernel/data_plane/`: Sovereign Data Plane
```python
from core.kernel.data_plane import SovereignDataPlane

dp = SovereignDataPlane()
dp.store_encrypted(key, data)  # Fernet (AES-128-CBC + HMAC-SHA256)
dp.retrieve_decrypted(key)  # Returns decrypted data or None
dp.verify_audit_integrity()  # SHA-256 chain verification
dp.export_compliance_report()  # → {encryption, audit_entries, ...}
```

### `core/kernel/network_sync/`: Digital Twin and Fleet Records
```python
from core.kernel.network_sync import NetworkSynchronization, FleetNode

sync = NetworkSynchronization()
sync.register_node(node)  # Add fleet node
sync.update_twin(key, value)  # Update digital twin
sync.get_twin_value(key)  # Read from twin
sync.get_fleet_status()  # Fleet overview
sync.export_twin() / import_twin()  # Migration/backup
```
**Modes:** LOCAL_ONLY | PEER_TO_PEER | CLOUD_SYNC | HYBRID

No mode sends data today: nodes are recorded locally, and only LOCAL_ONLY is
accepted in air-gap mode.

### `core/kernel/generative_ui/`: Generative UI
```python
from core.kernel.generative_ui import GenerativeUIEngine

ui = GenerativeUIEngine()
layout = ui.generate_layout(context, platform, user_id)  # → UILayout
html = ui.render_layout(layout, format="html")  # or "json"
ui.track_interaction(user_id, component_id)  # adaptive learning
```

### `core/kernel/sandbox/`: Agent Code Sandbox
```python
from core.kernel.sandbox import BwrapSandbox, get_sandbox

sandbox = get_sandbox()
result = sandbox.execute_python("print(2+2)")
# SandboxResult: exit_code, stdout, stderr, elapsed_seconds, truncated, error
```
**Isolation:** bubblewrap namespaces (user/PID/net/mount/IPC/UTS), runs as
`nobody`, read-only root, sized temporary file systems, seccomp-bpf profiles
(`restricted` 36 syscalls / `strict` 54), resource limits, 30 s timeout,
10,000 characters of output per stream. Without bubblewrap, agent code is
refused in air-gap mode and otherwise runs in a plain subprocess with the
same filter and limits (`docs/SANDBOX.md`, `get_capabilities()`).

## Tool-Calling Integration

`chat_with_tools()` requires a tool dispatcher. Applications register one:

```python
from core.kernel.inference import OllamaInterface, set_tool_dispatcher


def my_dispatcher(tool_calls):
    return [{"content": "handled", "name": tc["function"]["name"]} for tc in tool_calls]


set_tool_dispatcher(my_dispatcher)
ollama = OllamaInterface()
out = ollama.chat_with_tools(
    model="qwen3:8b", messages=[{"role": "user", "content": "hi"}], tools=[...]
)
```

## Deployment

```bash
pip install -r core/kernel/requirements.txt
export NGARI_DATA_DIR=/var/lib/ngari/kernel   # default ~/.ngari/kernel
python -c "from core.kernel.inference import InferenceEngineManager; print(InferenceEngineManager().get_status())"
```

- Air-gapped: no cloud dependency; inference talks to local Ollama, llama.cpp or vLLM engines.
- SBOM: `python scripts/sbom.py --verify-requirements` (fails on unpinned deps).

## Platform Status

| Platform | HAL | Inference | Agent Runtime | Sync |
|----------|-----|-----------|---------------|------|
| Jetson AGX Orin | `JetsonHAL` | Ollama (native) | Active | Local only |
| Jetson Nano | `JetsonHAL` | Ollama | Active | Local only |
| x86_64 | `X86HAL` | Ollama/llama.cpp | Active | Local only |
| Raspberry Pi | `X86HAL`* | Ollama | Active | Local only |
| Cloud VM | `X86HAL`* | vLLM | Active | Local only |

*Generic readings; a platform-specific HAL is planned for ARM boards and cloud VMs.
