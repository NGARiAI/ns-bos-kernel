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
1. Fork the repository (`NGARiAI/ns-bos-kernel`)
2. Create a feature branch from `master` (`git checkout -b feat/my-feature master`)
3. All contributions must pass:
   - The pre-commit and pre-push hooks (see below)
   - CI: the `lint`, `test` (Python 3.10 to 3.13), `security` and `build`
     jobs, summarised by the `ci-ok` check. `CI.md` lists what each one runs.
   - Security review (no new secrets, no eval/exec)
4. Update documentation and `CHANGELOG.md` (`[Unreleased]`) for any change a
   user would notice
5. Open the pull request against `master`, the default branch

## Development Setup
```bash
git clone https://github.com/NGARiAI/ns-bos-kernel.git
cd ns-bos-kernel
make check                     # builds .venv from the hash-pinned locks, then lint and tests
.venv/bin/pre-commit install   # commit and push hooks
python -m core.kernel          # run the kernel
```

Every check is a make target, and CI runs the same targets:

| Target | Runs |
|--------|------|
| `make check` | lint and the test suite: the loop to run before every commit |
| `make ci` | everything CI runs: lint, workflow lint, coverage, sandbox tests, bandit, pip-audit, SBOM check, reproducible build, install smoke test |
| `make fmt` | apply ruff formatting |
| `make sbom` | regenerate the SBOM after a runtime lock change |
| `make help` | list every target |

`CI.md` covers the jobs, the dependency locks and the tests that need
bubblewrap, a software TPM or SoftHSM. `RELEASING.md` covers releases.

## Pre-commit Hooks
`.venv/bin/pre-commit install` sets up two hooks:

- Before each commit: `gitleaks` (no secrets), `ruff` and `ruff format`,
  trailing whitespace, end of file, YAML and large-file checks.
- Before each push: `make check`.

A hook that fails stops the commit or push. Fix the cause; do not skip it.

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
- `build:` Build, packaging and dependency locks
- `ci:` CI workflows and hooks
- `chore:` Maintenance tasks
- `sec:` Security fix
- `perf:` Performance improvement

## Security
See `SECURITY.md` for security reporting process. Never include credentials, tokens, or internal IPs in commits. The pre-commit gitleaks hook will reject commits containing secrets.

## SBOM
This project maintains an SPDX 2.3 SBOM at `sbom/ns-bos-kernel.spdx.json`. To change a runtime dependency, edit `core/kernel/requirements.in`, run the pip-compile command in the header of `core/kernel/requirements.txt`, then regenerate the SBOM and commit all three together:

```bash
make sbom
```

`make ci` fails if the SBOM and the lock disagree.

## License
By contributing, you agree that your contributions will be licensed under the Apache 2.0 License. See `LICENSE`.
