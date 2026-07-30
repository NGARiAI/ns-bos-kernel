# NS BOS Kernel Threat Model

## Overview
This threat model covers the NS BOS Kernel and its agent runtime. The kernel operates on sovereign edge hardware with no cloud dependency. The primary trust boundary is between the kernel process and the external environment (network, user input, filesystem).

## Assets
| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Agent state/memory | High | `data/agents/` (encrypted at rest) |
| User credentials/tokens | Critical | `data/identity/` (encrypted at rest) |
| Inference model weights | Medium | Local Ollama/llama.cpp instance |
| Audit logs | High | `data/audit/` (hash-chained) |
| Kernel configuration | Medium | `config/` |
| Inter-agent messages | Medium | `data/agents/comm/` |

## Trust Boundaries
```
[External Network] ──→ [API Gateway] ──→ [Auth Middleware] ──→ [Kernel Process]
                                                                     │
[Filesystem] ────────→ [Sovereign Data Plane] ←─── [Agent Runtime] ──┤
                                                                     │
[Ollama API] ────────→ [Inference Engine] ←────── [Agent Tools] ─────┘
```

1. **Network → API**: Authenticated users only (HMAC-SHA256 tokens)
2. **API → Kernel**: Authorized role-based access (5 roles)
3. **Kernel → Agents**: Allow-listed tool commands only
4. **Agents → Inference**: Model-level access control
5. **Kernel → Storage**: All data encrypted at rest
6. **Agents → External**: Zero egress in air-gap mode

## Threat Scenarios

### T1: Malicious Agent Command Execution
- **Risk**: An agent executes a shell command that compromises the system.
- **Existing Controls**: Tool allow-list, subprocess with ALLOWED_MODULES, 60s timeout, 32KB output cap.
- **Gap**: No container-level isolation for agent code execution.
- **Mitigation Plan**: Replace subprocess with gVisor sandbox (Phase 2).

### T2: Unauthorized API Access
- **Risk**: A compromised token or brute-force attack gains API access.
- **Existing Controls**: HMAC-SHA256 tokens with configurable expiry, rate limiting, IP allow-listing.
- **Gap**: No hardware-backed key storage (TPM/PKCS#11).
- **Mitigation**: Add PKCS#11 support for token signing (PIV/CAC module exists but not wired).

### T3: Compromised Model Injection
- **Risk**: A malicious model is loaded that exfiltrates data through inference output.
- **Existing Controls**: Model registry tracks provenance; no automatic model loading.
- **Gap**: No model signing or integrity verification.
- **Mitigation**: Add model manifest signing (Phase 1).

### T4: Audit Tampering
- **Risk**: An attacker modifies or deletes audit log entries to cover traces.
- **Existing Controls**: Hash-chained audit log (each entry SHA-256 of previous), JSONL append-only.
- **Gap**: Audit log is stored on the same filesystem as the kernel.
- **Mitigation**: Ship audit logs to read-only media or separate partition.

### T5: Inference Side-Channel
- **Risk**: Model inference timing/size reveals data patterns.
- **Existing Controls**: N/A (not implemented).
- **Gap**: No constant-time or padding for inference I/O on edge devices.
- **Mitigation**: Lower priority — acceptable risk for sovereign edge deployment.

### T6: Supply Chain (Dependency Hijack)
- **Risk**: A compromised PyPI/npm dependency introduces backdoor.
- **Existing Controls**: Pinned versions in requirements.txt, pip-audit in CI, SBOM generation.
- **Gap**: No lockfile for Python dependencies (pip has no native lock).
- **Mitigation**: Use pip-compile or poetry lock files (Phase 1).

### T7: Memory Scraping
- **Risk**: Another process on the same host reads kernel memory (agent prompts, outputs).
- **Existing Controls**: N/A (not implemented).
- **Gap**: No memory isolation between kernel processes on aarch64.
- **Mitigation**: Use mlock() for sensitive memory regions; explore memguard on Linux.

## Attack Surface Summary

| Surface | Exposure | Risk Level | Mitigation Priority |
|---------|----------|------------|---------------------|
| API endpoints (181 routes) | Network | Medium | Rate limiting + auth |
| Agent tool execution | Local | High | gVisor sandbox (Phase 2) |
| Model inference | Local | Medium | Model provenance |
| Audio processing | Local | Low | Input validation |
| Filesystem storage | Local | Medium | Encryption + audit |
| WebSocket (voice) | Network | Medium | Token auth + heartbeat |
| Inter-agent comms | Local | Low | Subprocess isolation |

## Compliance Mapping
| Control | SOC 2 | FedRAMP | DISA STIG |
|---------|-------|---------|-----------|
| Audit logging | CC6.1 | AU-2 | 217.1 |
| Access control | CC6.2 | AC-3 | 199.1 |
| Encryption at rest | CC6.7 | SC-28 | 202.1 |
| Data retention | CC6.4 | AU-11 | 192.1 |
| RBAC | CC6.3 | AC-2 | 286.1 |
| Incident response | CC7.3 | IR-4 | 194.1 |

## Reviewer Notes
- This threat model should be reviewed quarterly.
- As the agent marketplace (third-party skills) matures, T1 escalation becomes critical.
- PIV/CAC hardware auth closes T2 but requires TPM/NitroKey hardware on the edge device.
