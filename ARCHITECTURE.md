# NS-BOS Kernel Architecture

## Design Principles

1. **Sovereign by default.** No cloud dependency. Air-gap mode is on unless
   it is turned off (`docs/AIR_GAP.md`).
2. **Minimal kernel.** The kernel stores, isolates, records and enforces.
   Agent behavior, tools and user interfaces belong to the application.
3. **Auditable.** Every kernel action, key operation, operator sign-in and
   electronic signature is recorded in a keyed, hash-chained audit log
   (`docs/AUDIT_LOG.md`).
4. **Hardware-agnostic.** One codebase for aarch64 and x86_64.
5. **Accountable.** Operators are named people identified by PIV/CAC cards
   and hold roles. An AI agent is sponsored by a named operator
   (`docs/AGENT_IDENTITY.md`).

## Layers

```
+------------------------------------------------------+
|  Application                                         |
|  Agent behavior, tools, user interface               |
+------------------------------------------------------+
|  NS-BOS Kernel                                       |
|  Data plane      encryption, keys, audit log,        |
|                  operators, roles, signatures        |
|  Agent runtime   registry, task scheduler,           |
|                  message bus                         |
|  Network sync    digital twin, sync ledger           |
|  Libraries       inference clients, sandbox,         |
|                  generative UI                       |
+------------------------------------------------------+
|  Hardware abstraction layer                          |
|  Platform detection, utilization, temperature        |
+------------------------------------------------------+
|  Linux, bubblewrap, TPM 2.0, PKCS#11                 |
+------------------------------------------------------+
```

### Kernel and Application Boundary

| Concern | Owner | Division of work |
|---------|-------|------------------|
| Encryption at rest | Kernel | The kernel encrypts and decrypts; the application reads and writes through it |
| Master key custody | Kernel | A file, or sealed to a TPM 2.0 chip (`docs/KEY_PROVIDERS.md`) |
| Audit logging | Kernel | The kernel writes and verifies; the application reads |
| Operator identity and roles | Kernel | PIV/CAC cards, named operators and roles (`docs/PIV_CAC.md`) |
| Electronic signatures | Kernel | Bound to the record and the signer's card (`docs/ESIGNATURES.md`) |
| Agent sponsorship | Kernel | A card-signed manifest per agent (`docs/AGENT_IDENTITY.md`) |
| Agent lifecycle | Kernel | The kernel keeps the registry and state; the application defines behavior |
| Code isolation | Kernel | The kernel provides the sandbox; the application supplies the code |
| Inference | Shared | The kernel provides clients bound to this machine; the application chooses the model and the prompt |
| Running tasks | Application | The kernel stores tasks; the application runs the queue |
| Tools | Application | The application implements and dispatches tools |
| User interface | Application | The kernel has a command line only |

## Modules

```
NSBOSKernel
 ├── HAL (hardware detection, monitoring)
 │    └── PlatformType enum (JETSON_NANO, JETSON_AGX_ORIN, JETSON_THOR, X86_64,
 │                          ARM64, RASPBERRY_PI, CLOUD_VM, UNKNOWN)
 ├── SovereignDataPlane
 │    ├── Fernet encryption (AES-128-CBC + HMAC-SHA256)
 │    ├── Keyed, hash-chained audit log
 │    ├── Key provider (file or TPM 2.0 sealed)
 │    └── Operators, roles, electronic signatures, agent manifests
 ├── AgentRuntime
 │    ├── AgentRegistry (persistent agent state)
 │    ├── TaskScheduler (priority queue)
 │    └── InterAgentCommunication (publish and subscribe, one file per message)
 └── NetworkSynchronization
      ├── Digital twin (versioned, checksummed)
      ├── Hash-chained sync ledger
      └── SyncMode (LOCAL_ONLY, PEER_TO_PEER, CLOUD_SYNC, HYBRID)

Libraries an application builds itself
 ├── InferenceEngineManager (Ollama, llama.cpp, vLLM clients; model registry)
 ├── BwrapSandbox (bubblewrap namespaces, seccomp filter)
 └── GenerativeUIEngine (layout generation, behavior tracking)
```

Only `LOCAL_ONLY` is accepted while air-gap mode is on. No sync mode sends
data today: the kernel has no peer discovery and no transport between
nodes.

## Data Flow

### Task Execution

```
Application → NSBOSKernel.create_task(agent_id, action, payload)
  → TaskScheduler.create_task()        the task is saved and audited
Application → TaskScheduler.process_queue()
  → TaskScheduler.execute_task()
    → handler registered for the action
  → result stored in the task
```

The kernel stores tasks and does not run them. An application registers a
handler for each action and calls `process_queue()`.

### Tool Calls From a Model

`chat_with_tools` sends a prompt to a local engine and dispatches the tool
calls in the reply through a dispatcher the application supplies. Only
tools the caller declared are dispatched, up to a fixed number per
conversation (`docs/AGENT_RUNTIME.md`).

## Data Layout

Under `$NGARI_DATA_DIR`, mode 0700:

| Path | Holds | Protection |
|------|-------|------------|
| `sovereign/keys/` | The master key, or its TPM-sealed form | Mode 0600; sealed to the TPM with the `tpm2` provider |
| `sovereign/encrypted/` | Records stored through the data plane | Encrypted |
| `sovereign/audit/sovereign_audit.log` | The audit log | Plaintext, hash-chained, keyed |
| `sovereign/operators/`, `sovereign/roles.json` | Operator certificates, names and roles | Mode 0600 |
| `sovereign/agents/` | Agent manifests | Card-signed, mode 0600 |
| `agents/registry/`, `agents/tasks/`, `agents/comm/` | Agent registry, tasks and messages | Plaintext by default; encrypted with `NGARI_ENCRYPT_STATE=1` (`docs/AGENT_STATE.md`) |
| `sync/` | Digital twin, fleet file, sync ledger | Plaintext; the ledger is hash-chained |
| `logs/kernel.log` | The kernel's log | Mode 0600; personal data masked |

A component constructed directly, outside `NSBOSKernel`, takes its
directory as an argument. Given none, it uses its own default under the
data directory, which is not always the kernel's path for it; pass the
directory explicitly to share the kernel's files.

## Configuration

The kernel is configured through environment variables. `python -m
core.kernel` takes no options; its `keys`, `audit`, `state`, `records` and
`agents` commands take `--data-dir`.

| Variable | Default | Description |
|----------|---------|-------------|
| `NGARI_DATA_DIR` | `~/.ngari/kernel/` | Root data directory |
| `NGARI_AIR_GAP` | `true` | Keep the kernel's network calls on this machine (`docs/AIR_GAP.md`) |
| `NGARI_KEY_PROVIDER` | `file` | Where the master key lives: `file` or `tpm2` |
| `NGARI_TPM_TCTI` | `device:/dev/tpmrm0` | TPM connection for the `tpm2` provider |
| `NGARI_TPM_TIMEOUT` | `30` | Seconds per tpm2-tools call |
| `NGARI_TPM_PCRS` | unset | PCR selection used by `keys restore` |
| `NGARI_OPERATOR_AUTH` | `off` | `card`: key commands need the operator's PIV/CAC card |
| `NGARI_PKCS11_MODULE`, `NGARI_PKCS11_TOKEN`, `NGARI_PKCS11_KEY_ID` | see `docs/PIV_CAC.md` | Which card and key to use |
| `NGARI_ENCRYPT_STATE` | unset | `1`: encrypt the agent registry, tasks and messages |
| `NGARI_RETENTION_DAYS` | `7671` | Days inter-agent messages are kept (`docs/RETENTION.md`) |
| `NGARI_REDACT_PII` | on | Mask personal data in the kernel's log lines |
| `NGARI_SANDBOX_REQUIRE_BWRAP` | unset | `1`: refuse agent code when bubblewrap is missing |

## Sandbox

Agent code runs through `BwrapSandbox.execute_python()`: bubblewrap
namespaces (user, PID, network, IPC, UTS, mount), the user `nobody`, no
network interface, a read-only root, sized temporary file systems, a
seccomp filter and resource limits. `docs/SANDBOX.md` gives every limit and
what a run can and cannot reach. The Python import blocklist inside the
sandbox guards against accidents and is not the boundary; bubblewrap and
the seccomp filter are.

## Status

| Area | State |
|------|-------|
| Encryption at rest, key providers (file, TPM 2.0), recovery bundles | Built |
| Keyed, hash-chained audit log with verification and anchors | Built |
| Operator identity (PIV/CAC), roles, electronic signatures | Built |
| Sandbox with seccomp filters for x86_64 and aarch64 | Built |
| Air-gap mode | Built |
| Agent manifests signed by a sponsor | Built |
| Refusing unsponsored agents, enforcing agent permissions | In progress |
| Sync between nodes, peer discovery | Planned |
| Model signing and verification at load | Planned |

## Related Documents

- `THREAT_MODEL.md`: security threat model
- `SECURITY.md`: security controls and reporting
- `CONTRIBUTING.md`: development workflow
- `core/kernel/README.md`: kernel module reference
- `docs/`: one page per feature, listed in `README.md`
