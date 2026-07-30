# Contributing to NS-BOS Kernel

Thank you for your interest in contributing to the NGARi Sovereign Business Operating System Kernel.

## Code of Conduct
- Be respectful and inclusive
- Focus on what is best for the community
- Welcome newcomers and help them learn
- Give and gracefully accept constructive feedback

## How to Contribute

### Reporting Bugs
1. Check if the bug has already been reported
2. Open a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Platform information (Jetson Orin, Raspberry Pi 5, x86_64, etc.)

### Suggesting Features
1. Open an issue with the "enhancement" label
2. Describe the feature and its use case
3. Explain how it aligns with NS-BOS kernel design principles:
   - Sovereign by default (zero cloud dependency)
   - Minimal kernel surface area
   - Fully auditable
   - Hardware-agnostic

### Pull Requests
1. Fork the repository (`ngarixyz/ns-bos-kernel`)
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. All contributions must pass:
   - Pre-commit hooks (gitleaks + ruff)
   - CI pipeline (lint, typecheck, test)
   - Security review (no new secrets, no eval/exec)
4. Update documentation if changing public API
5. Submit the pull request against `main`

## Development Setup
```bash
git clone https://github.com/ngarixyz/ns-bos-kernel.git
cd ns-bos-kernel
pip install -r core/kernel/requirements.txt
pre-commit install
python -m pytest tests/
python -m core.kernel
```

## Pre-commit Hooks
This repo uses pre-commit hooks to enforce:
- `gitleaks` — no secrets committed
- `ruff` — Python linting and formatting
- `trailing-whitespace` — clean diffs

Install: `pre-commit install`

## Coding Standards
- Follow PEP 8 style guidelines
- Use type hints for all function signatures
- Write docstrings for all public functions and classes
- Keep functions focused and under 50 lines when possible
- Use dataclasses for data containers
- No eval/exec of user-provided code
- No hardcoded paths, credentials, or personal information
- All file paths must be configurable via env vars

## Commit Messages
Follow conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions or changes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks
- `sec:` Security fix
- `perf:` Performance improvement

## Security
See `SECURITY.md` for security reporting process. Never include credentials, tokens, or internal IPs in commits. The pre-commit gitleaks hook will reject commits containing secrets.

## SBOM
This project maintains an SPDX 2.3 SBOM at `sbom/ns-bos-kernel.spdx.json`. Update when adding or updating dependencies:

```bash
python scripts/sbom.py
```

## License
By contributing, you agree that your contributions will be licensed under the Apache 2.0 License. See `LICENSE`.
