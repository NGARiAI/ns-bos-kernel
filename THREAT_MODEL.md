# NS-BOS Kernel Threat Model

## Overview
This threat model covers the NS-BOS Kernel. The kernel operates on sovereign
edge hardware (aarch64 / x86_64) with no cloud dependency. The primary trust
boundary is between the kernel's components — the agent runtime, inference
engine, data plane, and sandbox — and the external environment (filesystem,
local network, user-supplied payloads, third-party inference endpoints).

## Assets
| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Agent state / memory | High | data plane (encrypted at rest via Fernet) |
| User credentials / tokens | Critical | data plane (encrypted at rest) |
| Inference model weights | Medium | local Ollama / llama.cpp / vLLM instances |
| Kernel configuration | Medium | config / env |
| Inter-agent messages | Medium | data plane |
| Audit / sync ledger | High | data plane, hash-chained |

## Trust Boundaries
```
[Local Network] ──→ [Inference Engine]  ←── [Agent Runtime] ──→ [Sandbox]
        │                                      │                    │
[Filesystem] ──────→ [Data Plane] ◄───encrypted──┘   [seccomp-bpf]   │
        │                                                    │
[Host /proc, /sys] ─→ [HAL]                            (code execution)
```

1. **Filesystem → Data Plane**: byte-level encryption at rest (Fernet); plaintext only in memory
2. **Agent Runtime → Sandbox**: agent code executes only inside `core/kernel/sandbox` isolation
3. **Sandbox → Kernel syscalls**: bounded by seccomp-bpf profiles (`restricted`/`strict`)
4. **Agent Runtime → Inference**: model-level provenance registry; no automatic model loading
5. **Kernel → Network**: zero egress in air-gap mode; inference endpoints are explicit local sockets

## Threat Scenarios

### T1: Malicious Agent Code Execution (HIGH)
- **Risk**: An agent executes code that compromises the host (shell escape, syscall abuse).
- **Controls implemented**: `core/kernel/sandbox/bwrap.py` — bubblewrap namespace isolation
  (user, PID, net, mount, IPC, UTS), runs as `nobody` (uid 65534), read-only system mounts,
  tmpfs `/tmp`; `core/kernel/sandbox/seccomp.py` — generated seccomp-bpf filters blocking
  23 dangerous syscalls (`restricted`) or 39 including network + process creation (`strict`).
  Python-level import blocklist (`subprocess`, `ctypes`, `pickle`, …) and eval/exec/open
  neutralization inside the sandboxed interpreter; 30s timeout; 10KB output cap.
- **Residual gap**: bubblewrap is a pre-requisite binary; when absent the sandbox degrades to
  a subprocess fallback with Python gates only (no namespace isolation). Documented in
  `get_capabilities()`. gVisor/Firecracker considered heavier than warranted for kernel-only code.
- **Verification**: `tests/test_sandbox.py` (execution + namespace + seccomp assertions);
  unit tests for seccomp profile/BPF generation always run.

### T2: Unauthorized Access to Persisted Data
- **Risk**: A compromised caller reads another tenant's encrypted blobs.
- **Controls implemented**: Fernet AEAD encryption keyed per store; keys under `data plane` config.
- **Gap**: No hardware-backed key storage (TPM/PKCS#11) in the kernel today.
- **Mitigation**: Pluggable KMS key provider (TPM/PKCS#11) behind the data-plane key API.

### T3: Compromised Model Injection
- **Risk**: A malicious model is loaded that exfiltrates data through inference output or
  prominence in the registry.
- **Controls implemented**: `ModelRegistry` + `InferenceEngineManager` (no automatic model
  loading); model entries carry engine/size/status provenance.
- **Gap**: No model signing or integrity verification at load time.
- **Mitigation**: Add manifest signing (hash + signature) to `ModelRegistry` enforcement.

### T4: Audit / Sync Tampering
- **Risk**: An attacker modifies or deletes ledger or sync entries to cover traces.
- **Controls implemented**: hash-chained, append-only JSONL ledger (`network_sync`,
  `data_plane`); copies validated against checksum on load.
- **Gap**: Ledger and kernel share a filesystem.
- **Mitigation**: Ship ledgers to read-only media or a separate partition; periodic hash-chain
  verification job.

### T5: Inference Side-Channel
- **Risk**: Inference timing/size reveals data patterns on shared hardware.
- **Controls implemented**: N/A.
- **Gap**: No constant-time or padded inference I/O at the edge.
- **Mitigation**: Accepted residual risk for sovereign single-tenant edge deployment.

### T6: Supply Chain — Dependency Hijack (RESOLVED)
- **Risk**: A compromised PyPI dependency introduces a backdoor.
- **Controls implemented**: `requirements.txt` pinned to exact versions with sha256 hashes
  (`pip-compile --generate-hashes`); `pip install --require-hashes` compatible;
  `scripts/sbom.py --verify-requirements` fails CI on any unpinned/hashless dep; SBOM
  (SPDX 2.3, sha256 checksums + purl) regenerated from declared deps only; CI runs
  `pip-audit -r requirements.txt` and `bandit`. Testable via `tests/test_sbom.py`.
- **Gap**: None outstanding for declared runtime dependencies.

### T7: Memory Scraping
- **Risk**: Another local process reads kernel memory (prompts, outputs, keys).
- **Controls implemented**: N/A.
- **Gap**: No memory-hardening (mlock, memguard) on aarch64.
- **Mitigation**: Use `mlock()` for key material; explore `PR_SET_DUMPABLE=0` and memguard.

## Attack Surface Summary
| Surface | Exposure | Risk | Controls |
|---------|----------|------|----------|
| Agent code execution | Local | High | bwrap namespaces + seccomp-bpf + import gates (T1) |
| Inter-agent comms | Local | Medium | data-plane encryption, hash-chained ledger (T4) |
| Inference engine HTTP | Local sockets | Medium | provenance registry, no auto-load (T3) |
| Filesystem storage | Local | Medium | Fernet at rest (T2) |
| Hardware probing (HAL) | Local | Low | read-only `/proc`/`/sys` reads, debug logging |
| Dependency ingestion | Build time | High | hash pins + SBOM + pip-audit + bandit CI (T6) |

## Compliance Mapping
| Control | SOC 2 | FedRAMP | DISA STIG |
|---------|-------|---------|-----------|
| Audit logging | CC6.1 | AU-2 | 217.1 |
| Access control | CC6.2 | AC-3 | 199.1 |
| Encryption at rest | CC6.7 | SC-28 | 202.1 |
| Data retention | CC6.4 | AU-11 | 192.1 |
| Code isolation | CC8.1 | SC-7 | 241.1 |
| Change management | CC8.1 | CM-6 | 183.1 (hash-pinned deps + CI gates) |

## Reviewer Notes
- Reviewed against current source (Aug 2026): T1 and T6 hardening shipped and verified;
  THREAT_MODEL.md is part of the release gate alongside `tests/test_sandbox.py`.
- Review this document quarterly and on any sandbox or data-plane change.
- PIV/CAC hardware auth closes T2 at the application layer but requires TPM/PKCS#11
  hardware on the edge device; tracked as kernel KMS provider work.