# NS-BOS Kernel Architecture

## Design Principles
1. **Sovereign by default** — zero cloud dependency; all operations work in air-gap
2. **Minimal kernel** — the kernel does only orchestration; intelligence is layered above
3. **Auditable** — every agent action, inference call, and state change is logged
4. **Hardware-agnostic** — runs on aarch64 and x86_64 with the same codebase
5. **Deterministic governance** — RBAC, audit, and compliance are enforced at the kernel level

## Layer Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Application Layer                   │
│  Agents (CEO, CRO, Engineer, Worker, Comms, Trader)  │
│  Chat frontend, Voice I/O, Dashboard, Agent Store    │
├──────────────────────────────────────────────────────┤
│                   Kernel Interface                    │
│  KernelBridge — singleton bridge between app & kernel │
├──────────────────────────────────────────────────────┤
│                    Kernel Layer                       │
│  ┌────────────┬────────────┬──────────┬───────────┐  │
│  │  Inference  │   Agent    │  Data    │  Network  │  │
│  │  Engine    │  Runtime   │  Plane   │    Sync   │  │
│  │  (Ollama,  │  (registry,│ (encrypt,│ (mDNS,    │  │
│  │   llama.cpp│   scheduler,│ audit,   │  digital  │  │
│  │   , vLLM)  │   comm bus)│  sovereign│  twin)    │  │
│  └────────────┴────────────┴──────────┴───────────┘  │
├──────────────────────────────────────────────────────┤
│               Hardware Abstraction Layer              │
│  Platform detection, GPU monitoring, thermal control  │
├──────────────────────────────────────────────────────┤
│                    Operating System                   │
│  Linux (Ubuntu/Debian/Fedora), AppArmor, systemd      │
└──────────────────────────────────────────────────────┘
```

### Kernel vs Application Boundary
| Component | Kernel | Application | Boundary |
|-----------|--------|-------------|----------|
| Inference orchestration | ✅ | ❌ | Kernel decides which model, app provides prompt |
| Agent lifecycle | ✅ | ❌ | Kernel manages registry/state, app defines behavior |
| Tool execution | ❌ | ✅ | Kernel provides sandbox, app implements tools |
| Data encryption | ✅ | ❌ | Kernel encrypts, app reads via API |
| RBAC enforcement | ✅ | ❌ | Kernel enforces, app defines roles |
| Audit logging | ✅ | ❌ | Kernel writes, app queries |
| User-facing UI | ❌ | ✅ | Kernel serves API, app renders |
| Agent strategy | ❌ | ✅ | Kernel schedules, app decides what to do |

## Module Dependencies

```
NSBOSKernel
 ├── HAL (hardware detection, monitoring)
 │    └── PlatformType enum (ORIN, RPI5, X86_64)
 ├── SovereignDataPlane
 │    ├── Fernet encryption (AES-256-GCM)
 │    ├── Hash-chained audit logging
 │    └── Key management (derived from system entropy)
 ├── AgentRuntime
 │    ├── AgentRegistry (persistent agent state)
 │    ├── TaskScheduler (priority queue)
 │    └── InterAgentCommunication (pub/sub message bus)
 ├── NetworkSynchronization
 │    ├── mDNS peer discovery
 │    ├── Digital twin sync (mesh)
 │    └── SyncMode (LOCAL, MESH, CLOUD_BRIDGE)
 └── GenerativeUIEngine
      ├── Adaptive layout generation
      ├── User behavior tracking
      └── Accessibility-first rendering
```

## Data Flow

### Agent Task Execution
```
User/Agent → create_task(agent_id, action, payload)
  → TaskScheduler.create_task()
    → TaskScheduler.process_queue()
      → AgentRuntime.execute_task()
        → Handler registered for action
          → Inference call (if LLM needed)
          → Tool execution (if action specified)
        → Result stored in task
      → Agent state updated
    → Event published on inter-agent bus
```

### Inter-Agent Commerce
```
Agent A → pay_invoice(Agent B, amount)
  → Wallet.transfer(from=Agent A, to=Agent B, amount)
    → NGARi fee deducted (configurable %)
    → Internal ledger updated
    → Audit logged
  → Invoice settled (instant, no Lightning tx)
```

## State Management
- **Agent state**: JSON files in `$NGARI_DATA_DIR/agents/` (encrypted)
- **Task state**: JSON files in `$NGARI_DATA_DIR/tasks/` (encrypted)
- **Audit log**: Append-only JSONL in `$NGARI_DATA_DIR/audit/` (plaintext, hash-chained)
- **Model registry**: JSON in `$NGARI_DATA_DIR/models/` (plaintext)
- **Vector memory**: JSON in `$NGARI_DATA_DIR/memory/` (plaintext, per-agent namespace)

## Configuration
All configuration is through:
1. Environment variables (`NGARI_*`)
2. `.env` file in kernel root
3. Command-line arguments (override env)

Key variables:
| Variable | Default | Description |
|----------|---------|-------------|
| `NGARI_DATA_DIR` | `~/.ngari/kernel/` | Root data directory |
| `NGARI_LOG_LEVEL` | `INFO` | Logging level |
| `NGARI_MODEL` | `ngari-ft-distilled:stable` | Default inference model |
| `NGARI_AIR_GAP` | `true` | Block all external network calls |
| `NGARI_AUTH_ENABLED` | `false` | Enable RBAC middleware |

## Sandbox Architecture (Phase 2 Complete)
```
Agent {code, tool} → BwrapSandbox.execute_python()
  ┌───────────────────────────────────────────────┐
  │  BwrapSandbox (bubblewrap + namespace isolation) │
  │  ┌─────────────────────────────────────────┐   │
  │  │  Linux namespaces:                      │   │
  │  │  ├── User: nobody (uid 65534)           │   │
  │  │  ├── Mount: /usr /lib /bin ro, /tmp rw  │   │
  │  │  ├── Net: no interfaces (AF_UNIX only)  │   │
  │  │  ├── PID: isolated process tree         │   │
  │  │  ├── IPC: no shared memory/semaphores   │   │
  │  │  └── UTS: hostname 'sandbox'            │   │
  │  │                                          │   │
  │  │  Python-level:                          │   │
  │  │  ├── Module blocklist (subprocess,      │   │
  │  │  │   ctypes, multiprocessing, fcntl,    │   │
  │  │  │   pickle, shelve, crypt, cffi)       │   │
  │  │  ├── Function neutralization            │   │
  │  │  │   (eval/exec/open/compile → no-ops)  │   │
  │  │  ├── 30s timeout (configurable)         │   │
  │  │  └── 10KB output cap                    │   │
  │  └─────────────────────────────────────────┘   │
  │                                                 │
  │  Fallback: subprocess (when bwrap unavailable)  │
  └─────────────────────────────────────────────────┘
```

## Related Documents
- `THREAT_MODEL.md` — Security threat model
- `SECURITY.md` — Security controls and reporting
- `CONTRIBUTING.md` — Development workflow
- `core/kernel/README.md` — Kernel module documentation
