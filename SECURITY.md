# NS BOS Kernel Security

## Security Posture
The NS BOS (NGARi Sovereign Business Operating System) Kernel is designed for sovereign edge deployment. It runs on user-owned hardware with verified zero cloud dependency.

### Supported Configurations
- **Platform**: aarch64 (Jetson Orin, Raspberry Pi 5), x86_64
- **Memory**: 4GB minimum (8GB+ recommended)
- **Storage**: 512MB minimum for kernel + metadata
- **Network**: Fully air-gapped operation supported
- **OS**: Ubuntu 22.04+, Debian 12+, Fedora 38+

### Security Properties
- No external telemetry
- No cloud dependency for core operation
- All data encrypted at rest (AES-256-GCM via Fernet)
- Hash-chained audit logging
- Role-based access control
- Verified air-gap via live `/proc/net/dev` monitoring

## Reporting a Vulnerability

**DO NOT** file a public GitHub issue for security vulnerabilities.

Contact the security team at `support@ngari.xyz`.

Reports are acknowledged within 48 hours. Fixes are coordinated and disclosed after a 90-day remediation window for critical issues, 30 days for medium/high.

### Scope
- `core/kernel/*` — In-scope (kernel code)
- `core/tools/*` — In-scope (agent tool implementations)
- `core/enterprise/*` — In-scope (governance, RBAC, audit)
- `apps/chat/*` — Out-of-scope (frontend applications)
- Third-party dependencies — reported to upstream maintainers

### Bug Bounty
This project does not currently offer a bug bounty. Security researchers are credited in SECURITY.md upon request.

## Security Controls

### Code Level
- All Python dependencies pinned in `requirements.txt`
- `subprocess` calls use allow-listed commands only
- No eval/exec of user-provided code
- Shell injection prevented via `shlex.quote()` where applicable

### Data Level
- Encryption at rest using `cryptography.fernet.Fernet` (AES-256-CBC + HMAC-SHA256)
- Audit log hash-chained: each entry includes SHA-256 of previous entry
- PII redaction via regex (email, phone, SSN, CC, address)
- Configurable data retention with automated expiry

### Network Level
- CORS restricted to configured origins
- API authentication via HMAC-SHA256 tokens with expiry
- No external DNS resolution in air-gap mode
- mDNS for local discovery only

### Build Level
- SBOM generated at build time (SPDX 2.3)
- Dependency scanning via `pip-audit` in CI
- Static analysis via `bandit` and `ruff`
- No secrets committed (gitleaks pre-commit hook)

## Responsible Disclosure Timeline
1. Report received → acknowledged within 48h
2. Validation → within 5 business days
3. Fix development → within 30 days (critical) / 90 days (standard)
4. Coordinated disclosure → fix published + advisory

## Acknowledgments
Security researchers who have contributed to the security of this project are listed here (with permission).
