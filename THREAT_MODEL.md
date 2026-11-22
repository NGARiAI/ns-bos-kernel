# NS-BOS Kernel Threat Model

## Overview

This threat model covers the NS-BOS Kernel. The kernel runs on edge hardware
the user owns (aarch64 or x86_64) with no cloud dependency. The primary
trust boundary lies between the kernel's components (the data plane, agent
runtime, inference clients and sandbox) and what they handle: the file
system, agent code, model output and local inference engines.

## Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Records stored through the data plane | High | `sovereign/encrypted/`, encrypted at rest via Fernet |
| Data-plane master key | Critical | `keys/master.key` (file provider) or sealed to the TPM in `keys/master.key.sealed` (tpm2 provider) |
| Recovery bundle | Critical | Off the machine, in the operator's custody; opens with a passphrase |
| Audit log | High | `sovereign/audit/`, plaintext, hash-chained and keyed |
| Operator certificates, names and roles | High | `sovereign/operators/`, `sovereign/roles.json` |
| Agent manifests | High | `sovereign/agents/`, signed by the sponsor's card |
| Agent registry, tasks and messages | Medium | `agents/`, plaintext by default; encrypted with `NGARI_ENCRYPT_STATE=1` |
| Digital twin and sync ledger | Medium | `sync/`, plaintext; the ledger is hash-chained |
| Inference model weights | Medium | Local Ollama, llama.cpp or vLLM instances |
| Kernel configuration | Medium | Environment variables |

## Trust Boundaries

```
[Agent code] ──→ [Sandbox: bubblewrap + seccomp] ──→ [Linux kernel]
[Model output] ──→ [Tool loop: declared tools only] ──→ [Application tools]
[Operator + card] ──→ [Operator gate: certificate, PIN, role] ──→ [Key commands, signatures]
[File system] ──→ [Data plane: Fernet, audit chain]
[Local engine] ←── [Inference clients: loopback only in air-gap mode]
```

1. **File system and data plane**: records are encrypted at rest; plaintext exists only in memory.
2. **Agent code and the sandbox**: agent code runs only inside `core/kernel/sandbox`.
3. **Sandbox and system calls**: bounded by the seccomp-bpf profiles (`restricted`, `strict`).
4. **Model output and tools**: only tools the caller declared are dispatched, up to a fixed number.
5. **Kernel and network**: no listening port; in air-gap mode the inference clients reach loopback only.
6. **Operators and the kernel**: gated commands and signatures need a pinned card, its PIN and the role.

## Threat Scenarios

### T1: Malicious Agent Code Execution (HIGH)

- **Risk**: Agent code compromises the host (escape, system call abuse, resource exhaustion).
- **Controls implemented**: `core/kernel/sandbox/bwrap.py` runs the code in
  bubblewrap namespaces (user, PID, network, mount, IPC, UTS) as `nobody`,
  with a read-only root, sized temporary file systems, no network interface
  and limits on time, output, memory, file size, processes and open files.
  `core/kernel/sandbox/seccomp.py` builds a seccomp-bpf filter per
  architecture: 36 system calls refused by `restricted` (the default), 54 by
  `strict`. A filter that cannot be installed stops the run.
- **Residual gap**: Without bubblewrap the code is refused when air-gap mode
  is on or `NGARI_SANDBOX_REQUIRE_BWRAP=1`; otherwise it runs in a subprocess
  with the filter and limits and no namespaces. When the kernel runs as root,
  the per-user process limit does not apply. A machine with no syscall table
  (riscv64, 32-bit ARM) runs without a filter and reports it. The Python
  import blocklist is a guard against accidents, not a boundary.
- **Verification**: `tests/test_sandbox.py`, `tests/test_sandbox_boundary.py`,
  `tests/test_seccomp_arch.py`.

### T2: Unauthorized Access to Persisted Data

- **Risk**: Someone with a copy of the data directory, or another local user, reads stored records.
- **Controls implemented**: Fernet encryption under one master key per store,
  chosen through a key provider (`NGARI_KEY_PROVIDER`). The `tpm2` provider
  seals the key to the TPM, so a copy of the data directory does not decrypt
  elsewhere. Providers fail closed and never create a new key over existing
  data. The data directory is owner-only (0700). See `docs/KEY_PROVIDERS.md`.
- **Gap**: The `file` provider (default) keeps the key in plaintext at mode
  0600, readable by root and by the kernel's user. A sealed key without a PCR
  policy unseals for any local process that can open the TPM. The agent
  registry, tasks and messages are plaintext unless `NGARI_ENCRYPT_STATE=1`.
- **Residual risk**: A sealed key is lost with its TPM (board swap, TPM
  clear). The recovery bundle covers this and is itself a secret: bundle plus
  passphrase decrypts everything.

### T3: Compromised Model

- **Risk**: A malicious or substituted model steers agents or leaks data through its output.
- **Controls implemented**: Models are never loaded or pulled automatically.
  Model output reaches tools only through declared tool names and a bounded
  number of calls. In air-gap mode a model cannot be pulled.
- **Gap**: No model signing or integrity verification at load time.
- **Mitigation**: Planned: a signed manifest per model, verified before use.

### T4: Audit or Sync Ledger Tampering

- **Risk**: An attacker edits, removes or reorders entries to cover traces.
- **Controls implemented**: Each audit entry holds the previous entry's hash
  and an HMAC under a key derived from the master key. `audit verify` names
  the first entry that fails. An anchor (entry count and last hash) kept off
  the machine exposes entries removed from the end. The sync ledger is
  hash-chained, and a digital twin that fails its checksum is not loaded.
- **Gap**: The log and the kernel share a file system. Anyone holding the
  master key can rewrite the log with valid hashes and MACs; only an anchor
  kept elsewhere exposes that (`docs/AUDIT_LOG.md`).
- **Mitigation**: Keep anchors off the machine; ship the log to separate media.

### T5: Inference Side Channel

- **Risk**: Inference timing or size reveals data patterns on shared hardware.
- **Controls implemented**: None.
- **Mitigation**: Accepted residual risk for single-tenant edge deployment.

### T6: Supply Chain Compromise

- **Risk**: A compromised dependency or build introduces a backdoor.
- **Controls implemented**: The runtime lock pins every dependency to an
  exact version with sha256 hashes; `scripts/sbom.py --verify-requirements`
  fails CI on any unpinned or hashless dependency; an SPDX 2.3 SBOM is
  generated from the lock; CI runs `pip-audit` and `bandit`; release builds
  are byte-for-byte reproducible and checked against a detached signature.
- **Gap**: The inference engines and their models are outside the lock.

### T7: Memory Scraping

- **Risk**: Another local process reads kernel memory (prompts, outputs, keys).
- **Controls implemented**: None.
- **Mitigation**: Planned: `mlock()` for key material and `PR_SET_DUMPABLE=0`.

### T8: Unaccountable or Over-Privileged Agent

- **Risk**: An agent acts with no person answerable for it, or beyond what was intended.
- **Controls implemented**: A manifest per agent, signed with the card of a
  named operator who holds the `sponsor` role, lists what the agent may do
  and expires within a year. A manifest stops checking when its sponsor's
  card, role or dates no longer hold (`docs/AGENT_IDENTITY.md`).
- **Gap**: The kernel does not yet refuse an agent without a manifest, record
  agent actions under the agent's identity, or enforce the listed permissions.
- **Mitigation**: In progress.

## Attack Surface Summary

| Surface | Exposure | Risk | Controls |
|---------|----------|------|----------|
| Agent code execution | Local | High | Namespaces, seccomp filter, resource limits (T1) |
| Model output | Local | Medium | Declared tools only, bounded tool calls (T3) |
| Inference engine HTTP | Loopback | Medium | Loopback only in air-gap mode, no redirects, no proxy (T3) |
| Stored records | Local | Medium | Fernet at rest (T2) |
| Master key at rest | Local | High | 0600 file, or TPM-sealed with optional PCR policy; recovery bundle off the machine (T2) |
| Audit log | Local | High | Hash chain, HMAC, off-machine anchor (T4) |
| Operator commands | Local | High | PIV/CAC card, PIN, roles (T2, T8) |
| Hardware probing (HAL) | Local | Low | Read-only `/proc` and `/sys` reads |
| Dependency ingestion | Build time | High | Hash pins, SBOM, pip-audit, bandit, reproducible builds (T6) |

## Control Mapping

The kernel's controls support the following NIST SP 800-53 Rev. 5 controls.
This is a guide for an assessor, not an assessment: no authorization or
certification is claimed.

| Kernel control | NIST SP 800-53 Rev. 5 |
|----------------|-----------------------|
| Audit log of kernel, key, operator and signature events | AU-2, AU-12 |
| Hash-chained, keyed audit log; off-machine anchor | AU-9, AU-10 |
| Message retention | AU-11 |
| Operator identification with PIV/CAC cards | IA-2, IA-2(12) |
| Roles for gated commands and signatures | AC-3, AC-6 |
| Encryption of stored records | SC-28 |
| Master key in a TPM, recovery bundle | SC-12 |
| Air-gap mode, no listening port | SC-7 |
| Sandbox for agent code | SC-39 |
| Pinned dependencies, SBOM, reproducible builds | SR-4, SI-7 |

## Reviewer Notes

- Review this document on any change to the sandbox, the data plane, the
  operator gate or agent identity.
