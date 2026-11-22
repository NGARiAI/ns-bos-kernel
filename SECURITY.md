# NS-BOS Kernel Security

## Security Posture

The NS-BOS (NGARi Sovereign Business Operating System) Kernel is built for
edge deployment on hardware the user owns, with no cloud dependency.

### Supported Configurations

- **Platform**: aarch64 (Jetson Orin, Raspberry Pi 5), x86_64
- **Memory**: 4GB minimum (8GB+ recommended)
- **Storage**: 512MB minimum for kernel + metadata
- **Network**: Fully air-gapped operation supported
- **OS**: Ubuntu 22.04+, Debian 12+, Fedora 38+

### Security Properties

- No external telemetry
- No cloud dependency for core operation
- Records stored through the data plane are encrypted at rest (AES-128-CBC + HMAC-SHA256 via Fernet)
- Keyed, hash-chained audit logging
- Role-based access control for operators, identified by PIV/CAC cards
- Air-gap mode on by default, with interface counters measured from `/proc/net/dev`

## Reporting a Vulnerability

**DO NOT** file a public GitHub issue for security vulnerabilities.

Contact the security team at `support@ngari.xyz`.

Reports are acknowledged within 48 hours. A fix is developed within 30 days
for a critical issue and within 90 days for any other, and disclosed in
coordination with the reporter.

### Scope

- `core/kernel/*`: in scope (kernel code)
- `core/kernel/sandbox/*`: in scope (agent code execution sandbox)
- `sbom/` and `scripts/sbom.py`: in scope (supply chain)
- Applications built on the kernel: out of scope here
- Third-party dependencies: reported to their maintainers

### Bug Bounty

This project does not currently offer a bug bounty. Security researchers are
credited in SECURITY.md upon request.

## Security Controls

### Code Level

- All Python dependencies pinned to exact versions with sha256 hashes
  (`core/kernel/requirements.txt`; enforced by `scripts/sbom.py --verify-requirements`)
- No shell: every subprocess call passes an argument list, never a command string
- No eval/exec of caller-provided code outside the sandbox

### Sandbox Level

- Agent code runs in `core/kernel/sandbox`: bubblewrap namespaces (user, PID,
  network, mount, IPC, UTS), running as `nobody` (uid 65534), a read-only
  root, sized temporary file systems and no network interface
- Seccomp-bpf filters block 36 system calls (`restricted`, the default) or 54
  including network and process creation (`strict`), with syscall numbers
  from each architecture's own headers
- A run is bounded: 30 s by default, 10,000 characters of output per stream,
  and limits on memory, file size, processes and open files
- Without bubblewrap, agent code is refused when air-gap mode is on or
  `NGARI_SANDBOX_REQUIRE_BWRAP=1`; otherwise it runs in a plain subprocess
  with the same filter and limits and no namespaces (`docs/SANDBOX.md`)
- The Python import blocklist inside the sandbox guards against accidents;
  it is not the boundary

### Inference Endpoint Security

- The inference clients default to loopback addresses. With air-gap mode
  on, any other address is refused before a request is sent
- The kernel talks to engines over HTTP without authentication: keep engine
  ports on loopback
- Redirects from an engine are never followed, and loopback calls never go
  through an environment proxy
- `InferenceEngineManager` never auto-loads models; pulling a model is
  refused in air-gap mode

### Data Level

- Encryption at rest using `cryptography.fernet.Fernet` (AES-128-CBC + HMAC-SHA256)
- The master key is held in a file readable only by its owner, or sealed to
  a TPM 2.0 chip (`docs/KEY_PROVIDERS.md`)
- Audit log hash-chained: each entry holds the SHA-256 of the previous one
  and an HMAC under a key derived from the master key
- PII redaction by pattern (email, phone, SSN, card number, address) in the
  audit log and the kernel's log lines
- Inter-agent messages are kept 21 years by default and then removed
  (`docs/RETENTION.md`)
- The agent registry, tasks and messages are plaintext by default and
  encrypted with `NGARI_ENCRYPT_STATE=1` (`docs/AGENT_STATE.md`)

### Operator Level

- Operators are named people whose PIV/CAC certificates are pinned on the
  machine; with `NGARI_OPERATOR_AUTH=card`, key commands need the card and PIN
- Roles (`admin`, `author`, `reviewer`, `approver`, `sponsor`) decide which
  commands and signatures an operator may make
- Electronic signatures are bound to the record's SHA-256 and the signer's
  certificate
- An AI agent is sponsored by a named operator through a card-signed manifest
  (`docs/AGENT_IDENTITY.md`); the kernel does not yet enforce an agent's
  permissions

### Network Level

- The kernel listens on no network port
- No external DNS resolution in air-gap mode
- Sync between machines is not implemented; only the `local_only` sync mode
  is accepted in air-gap mode

### Build Level

- SBOM generated at build time (SPDX 2.3)
- Dependency scanning via `pip-audit` in CI
- Static analysis via `bandit` and `ruff`
- No secrets committed (gitleaks pre-commit hook)
- Release builds are byte-for-byte reproducible and checked against a
  detached signature (`RELEASING.md`)

## Responsible Disclosure Timeline

1. Report received: acknowledged within 48 hours
2. Validation: within 5 business days
3. Fix development: within 30 days (critical) or 90 days (other)
4. Coordinated disclosure: fix published with an advisory

## Acknowledgments

Security researchers who have contributed to the security of this project
are listed here (with permission).
