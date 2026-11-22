# CI

Every check is a Makefile target, and `.github/workflows/ci.yml` calls those
same targets, so a check cannot pass locally and fail in CI for a different
reason. `make help` lists the targets.

## Local use

    make check    lint and tests, the fast loop
    make ci       the CI checks on this machine's Python (needs bubblewrap
                  and network access)

CI also runs the tests on Python 3.10 to 3.13 and on arm64, and its build job
runs `make build`, which needs a clean tree and so is not part of `make ci`;
`make repro` checks the same wheel.

The first run builds `.venv` from the hash-pinned locks,
`core/kernel/requirements.txt` and `core/kernel/requirements-dev.txt`. CI
installs the same locks itself and passes `PYTHON=python`.

`.venv/bin/pre-commit install` sets up two git hooks. Before each commit:
gitleaks, ruff, ruff format, whitespace, end of file, YAML and large-file
checks. Before each push: `make check`, so a branch with failing lint or tests
does not leave the machine. `git push --no-verify` skips it; CI runs the same
checks either way.

## Jobs

The workflow runs on pushes and pull requests to `master`, `main` and
`develop`, daily at 06:17 UTC, and on demand from Actions > CI > Run workflow.
The daily run turns a new advisory against a pinned dependency into a red run
even when nobody has pushed. Scheduled runs use the default branch, and GitHub
pauses them in a public repository after 60 days without activity; re-enable
the workflow from the Actions tab.

| Job | Targets | Fails on |
|-----|---------|----------|
| lint | `lint`, `lint-shell`, `lint-workflows` | ruff findings or format drift; shellcheck findings in `install.sh`; actionlint or zizmor findings in `.github/workflows` |
| test (py3.10 to py3.13) | `cov` | a failing test; coverage under `COV_FLOOR` (92); an SBOM that disagrees with the runtime lock; unusable bubblewrap, software TPM or SoftHSM |
| test (py3.12, arm64) | `cov` | the same as test, on an `ubuntu-24.04-arm` runner. Skipped on a private repository, where arm runners are not free; `ci-ok` accepts the skip |
| security | `bandit`, `sbom-check`, `audit` | bandit findings of medium severity or higher; a runtime lock entry without a pin or hash; a known vulnerability in either lock |
| build | `repro`, `build`, `smoke` | two builds of the wheel that differ; files in the wheel outside `core/kernel`; a wheel that does not install or start |
| ci-ok | none | any job above not succeeding |

`ci-ok` runs even when other jobs fail or skip. It is the one check to require
in branch protection. The build job keeps its output as the `ci-dist` artifact
for 14 days, and the release workflow compares its own wheel against it.

## Sandbox and TPM tests

The isolation tests need bubblewrap and unprivileged user namespaces. The test
job installs bubblewrap and sets `kernel.apparmor_restrict_unprivileged_userns=0`,
which Ubuntu 24.04 turns on by default. `NGARI_REQUIRE_BWRAP=1` makes a missing
or unusable bubblewrap a failure; without it those tests skip. `make
test-sandbox` sets it.

The `tpm2` key provider tests run against a software TPM (`swtpm:` TCTI,
a state manufactured by `swtpm_setup` under the test's tmp directory), never
a hardware chip. `swtpm_setup` allocates the sha256 PCR bank and gives each
state its own seed, which a raw `libtpms:` state file does not. The test job
installs `tpm2-tools`, `libtss2-tcti-swtpm0`, `swtpm` and `swtpm-tools`.
`NGARI_REQUIRE_TPM_SIM=1` makes a missing simulator a failure; without it
those tests skip.

The PIV/CAC operator check tests use a SoftHSM token created in the test's
tmp directory in place of a card. The test job installs `softhsm2` and
`opensc` (for `pkcs11-tool`). `NGARI_REQUIRE_PKCS11_SIM=1` makes a missing
SoftHSM a failure.

## Dependencies

Runtime pins live in `core/kernel/requirements.in` and
`core/kernel/requirements.txt`. To change one, edit the `.in` file, run the
`pip-compile` command in the header of `requirements.txt`, run `make sbom`, and
commit the lock changes and the regenerated SBOM together. A Dependabot pull
request that bumps a runtime pin fails the test job until `make sbom` is run on
its branch.

Tool pins live in `core/kernel/requirements-dev.in` and
`core/kernel/requirements-dev.txt`. Edit the `.in` file and run `make lock-dev`
(needs `uv`). The dev lock is compiled against the runtime lock, so a tool
update cannot move a runtime pin, and tools never reach the SBOM or the wheel.
`make audit` scans both locks.

## Workflow checks

`make lint-workflows` runs actionlint and zizmor over `.github/workflows`.
actionlint is downloaded to `.tools/` and checked against a pinned sha256
(Linux only). zizmor runs offline locally and online in CI. Third-party actions
are pinned to a full commit SHA with the tag in a trailing comment; keep that
form when editing a `uses:` line.

## CodeQL

`.github/workflows/codeql.yml` analyses the Python code and the workflow files
on pushes and pull requests to `master` and `main`, and on Wednesdays at 05:41
UTC. Results appear under Security > Code scanning. The job skips itself in a
private repository, where code scanning needs GitHub Code Security. It is not
part of `ci-ok`.

## Scorecard

`.github/workflows/scorecard.yml` runs the OpenSSF Scorecard checks on the
repository's own practices (pinned actions, token permissions, branch
protection, signed releases and others) on pushes to `master` and `main`, when
branch protection changes, and on Mondays at 06:17 UTC. Results go to the
Security tab under Code scanning and, with `publish_results`, to the public
Scorecard API and badge. The job skips itself in a private repository, so it does nothing until
the repository is public. It is not part of `ci-ok`.

## Repository settings

Set these once, as an admin:

- `master`: require a pull request, require review from Code Owners
  (`.github/CODEOWNERS`), require the `ci-ok` status check, and block force
  pushes and deletion.
- Tags matching `v*`: restrict creation, update and deletion to maintainers.
  Pushing a tag publishes a release, so tag access is release access.
- Actions: enable them on the repository, and on any fork that should run CI.
  Every action in use is GitHub-owned (`actions/*`, `github/codeql-action`)
  except `ossf/scorecard-action`, so allowed actions can be limited to those
  created by GitHub plus `ossf/scorecard-action@*`.
