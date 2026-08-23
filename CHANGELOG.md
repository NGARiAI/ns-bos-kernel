# Changelog

All notable changes to the NS-BOS Kernel are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Agent Runtime: registry, scheduler, message bus
- Sovereign Data Plane: encryption, hash-chained audit trail, compliance
- Network Sync: mDNS discovery, digital twin
- Generative UI: adaptive layout generation
- HAL: platform detection and monitoring
- Independent security audit of audit-chain and zero-telemetry claims
- Signed reproducible builds

## [0.1.0] - 2026-08-23

### Added

- Initial public release (Apache-2.0)
- Minimal auditable kernel for air-gapped autonomous edge AI agents:
  inference orchestration (Ollama, llama.cpp, vLLM), RBAC at kernel level,
  sovereign-by-default operation with zero cloud dependency
- Sandbox isolation: bubblewrap (bwrap) and seccomp modules
- SPDX 2.3 Software Bill of Materials (`sbom/ns-bos-kernel.spdx.json`)
  with generation script (`scripts/sbom.py`)
- Security posture (`SECURITY.md`), threat model (`THREAT_MODEL.md`),
  architecture documentation (`ARCHITECTURE.md`)
- Contributor guide (`core/kernel/CONTRIBUTING.md`)
- CI workflow, gitleaks secret scanning, pre-commit hooks
- Test suite: smoke, sandbox, and SBOM tests
- Production support: Jetson Orin Nano/Super and AGX Orin (aarch64)
- Beta support: Raspberry Pi 5 (aarch64) and x86_64 Linux
