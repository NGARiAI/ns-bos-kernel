# NS-BOS Kernel

**NGARi Sovereign Business Operating System — Kernel**

The NS-BOS Kernel is the minimal, auditable, sovereign runtime for autonomous edge AI agents. It orchestrates inference, agent lifecycle, data encryption, hardware monitoring, and inter-agent communication — all on user-owned hardware with zero cloud dependency.

License: Apache 2.0

## Architecture

```
┌──────────────────────────────────────┐
│  Application Layer (Agents, UI, API) │
├──────────────────────────────────────┤
│  NS-BOS Kernel                       │
│  ├── Inference Engine   (Ollama,     │
│  │                      llama.cpp,   │
│  │                      vLLM)        │
│  ├── Agent Runtime     (registry,    │
│  │                      scheduler,   │
│  │                      message bus) │
│  ├── Sovereign Data     (encryption, │
│  │   Plane               audit,      │
│  │                      compliance)  │
│  ├── Network Sync      (mDNS,        │
│  │                      digital twin)│
│  ├── Generative UI     (adaptive     │
│  │                      layout gen)  │
│  └── HAL               (platform     │
│                         detection,   │
│                         monitoring)  │
├──────────────────────────────────────┤
│  Linux (Ubuntu/Debian/Fedora)        │
└──────────────────────────────────────┘
```

## Quick Start

Requires **Linux** and **Python >= 3.10**. (Not 3.9: the kernel uses `str | None` unions at
runtime in 35 places with no `from __future__ import annotations`, which raises `TypeError`
below 3.10. Not macOS or Windows.)

```bash
# One-shot installer — read it first, it is short: ./install.sh
./install.sh

# ...or by hand:
python3 -m venv .venv && . .venv/bin/activate
pip install -r core/kernel/requirements.txt
NGARI_DATA_DIR=~/.ngari/kernel python -m core.kernel
```

The kernel orchestrates inference — **it ships no model**. Point it at a runtime
(Ollama, llama.cpp, vLLM) and weights you supply.

## Documentation

| Document | Description |
|----------|-------------|
| `ARCHITECTURE.md` | System architecture, boundaries, data flows |
| `SECURITY.md` | Security posture, controls, reporting |
| `THREAT_MODEL.md` | Threat scenarios, attack surface, mitigations |
| `CONTRIBUTING.md` | Development workflow, conventions, pre-commit |
| `core/kernel/README.md` | Kernel module reference |
| `sbom/ns-bos-kernel.spdx.json` | SPDX 2.3 Software Bill of Materials |

## Design Principles

1. **Sovereign by default** — all operations work fully air-gapped
2. **Minimal kernel** — orchestrates only; intelligence is layered above
3. **Fully auditable** — every action logged in hash-chained audit trail
4. **Hardware-agnostic** — runs on aarch64 and x86_64
5. **Deterministic governance** — RBAC enforced at kernel level

## Supported Platforms

| Platform | Architecture | RAM | Status |
|----------|-------------|-----|--------|
| Jetson Orin Nano/Super | aarch64 | 8GB+ | ✅ Production |
| Jetson AGX Orin | aarch64 | 32GB+ | ✅ Production |
| Raspberry Pi 5 | aarch64 | 8GB+ | ✅ Beta |
| x86_64 Linux | amd64 | 8GB+ | ✅ Beta |

## Related Repositories

- `NGARiAI/ns-bos-kernel` — This repo (kernel only, Apache 2.0)

## License

Apache 2.0. See `LICENSE` in `core/kernel/LICENSE`.
