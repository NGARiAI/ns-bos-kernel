# Developer entry points. The CI workflow calls these same targets, so a green
# `make ci` here means the same checks pass on GitHub.
#
#   make check   fast loop: lint and tests
#   make ci      the CI checks on this Python (needs bubblewrap and network)

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

VENV         ?= .venv
PYTHON       ?= $(VENV)/bin/python
SRC          := core/kernel scripts tests setup.py conftest.py
RUNTIME_LOCK := core/kernel/requirements.txt
DEV_LOCK     := core/kernel/requirements-dev.txt
COV_FLOOR    ?= 92
BIN          := $(if $(findstring /,$(PYTHON)),$(dir $(PYTHON)),)
ZIZMOR_FLAGS ?= --offline

# actionlint is a Go binary, so it is fetched from the release page and
# checked against the published sha256 (Linux only).
ACTIONLINT_VERSION      := 1.7.12
ACTIONLINT_SHA256_amd64 := 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ACTIONLINT_SHA256_arm64 := 325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
GO_ARCH                 := $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
ACTIONLINT              := .tools/actionlint-$(ACTIONLINT_VERSION)

# Locally, targets build .venv from the hash-pinned locks on first use. CI
# passes PYTHON=python after installing the same locks itself.
ifeq ($(PYTHON),$(VENV)/bin/python)
ENV := $(VENV)/.locked
endif

.DEFAULT_GOAL := help
.PHONY: help venv check lint lint-workflows lint-shell fmt test cov test-sandbox bandit audit sbom sbom-check \
	build repro smoke verify-release trace ci lock-dev clean

help: ## List the targets
	@awk -F':.*## ' '/^[a-zA-Z_-]+:.*## /{printf "  %-13s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

$(VENV)/.locked: $(RUNTIME_LOCK) $(DEV_LOCK)
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install --quiet --disable-pip-version-check \
	    --require-hashes -r $(RUNTIME_LOCK) -r $(DEV_LOCK)
	@touch $@

venv: $(VENV)/.locked ## Create .venv from the hash-pinned locks

check: lint test ## Lint and run the tests

lint: $(ENV) ## ruff check and format check
	$(PYTHON) -m ruff check $(SRC)
	$(PYTHON) -m ruff format --check $(SRC)

$(ACTIONLINT):
	mkdir -p .tools
	curl -fsSL -o .tools/actionlint.tar.gz https://github.com/rhysd/actionlint/releases/download/v$(ACTIONLINT_VERSION)/actionlint_$(ACTIONLINT_VERSION)_linux_$(GO_ARCH).tar.gz
	echo "$(ACTIONLINT_SHA256_$(GO_ARCH))  .tools/actionlint.tar.gz" | sha256sum -c -
	tar -xzf .tools/actionlint.tar.gz -C .tools actionlint
	mv .tools/actionlint $@
	rm -f .tools/actionlint.tar.gz

lint-shell: ## shellcheck on the shell scripts (needs shellcheck)
	shellcheck -S style install.sh

lint-workflows: $(ENV) $(ACTIONLINT) ## actionlint and zizmor on .github/workflows (Linux)
	$(ACTIONLINT)
	$(BIN)zizmor $(ZIZMOR_FLAGS) .github/workflows

fmt: $(ENV) ## Apply ruff formatting
	$(PYTHON) -m ruff format $(SRC)

test: $(ENV) ## Full test suite
	$(PYTHON) -m pytest tests -q

cov: $(ENV) ## Full test suite with a coverage report and a minimum
	$(PYTHON) -m pytest tests -q --cov=core/kernel \
	    --cov-report=term-missing:skip-covered --cov-fail-under=$(COV_FLOOR)

test-sandbox: $(ENV) ## Isolation tests; fail instead of skip if bubblewrap is unusable
	NGARI_REQUIRE_BWRAP=1 $(PYTHON) -m pytest tests/test_sandbox.py -q

bandit: $(ENV) ## Static security analysis
	$(PYTHON) -m bandit -q -r core/kernel scripts -ll

audit: $(ENV) ## Known-vulnerability scan of the runtime and dev locks (network)
	$(PYTHON) -m pip_audit -r $(RUNTIME_LOCK) -r $(DEV_LOCK)

sbom: $(ENV) ## Regenerate sbom/ns-bos-kernel.spdx.json
	$(PYTHON) scripts/sbom.py

sbom-check: $(ENV) ## Check that the runtime lock is fully pinned with hashes
	$(PYTHON) scripts/sbom.py --verify-requirements

build: $(ENV) ## Wheel, source tarball, SBOM and SHA256SUMS in dist/ (clean tree)
	rm -rf dist
	$(PYTHON) scripts/release.py build --outdir dist $(if $(ALLOW_DIRTY),--allow-dirty)

repro: $(ENV) ## Build the wheel twice and compare hashes
	$(PYTHON) scripts/release.py repro

smoke: $(ENV) ## Install a wheel in a fresh venv and start ns-bos (network; WHEEL=path)
	$(PYTHON) scripts/smoke_wheel.py $(WHEEL)

trace: ## Regenerate docs/validation/TRACE.md from the part11 test markers
	$(PYTHON) scripts/trace.py

verify-release: ## Check a downloaded release against its signed SHA256SUMS (DIR=path KEY=file.pub VERSION=X.Y.Z)
	$(if $(KEY),,$(error KEY= the release public key file is required))
	python3 scripts/release.py verify --dir "$(or $(DIR),.)" --key "$(KEY)" $(if $(VERSION),--version "$(VERSION)")

ci: lint lint-shell lint-workflows cov test-sandbox bandit audit sbom-check repro smoke ## The CI checks, on this Python (not make build)

lock-dev: ## Regenerate the dev tool lock (needs uv)
	uv pip compile --universal --python-version 3.10 --generate-hashes --no-header \
	    -c $(RUNTIME_LOCK) core/kernel/requirements-dev.in -o $(DEV_LOCK)

clean: ## Remove build output
	rm -rf dist build core/kernel/build ns_bos.egg-info core/ns_bos.egg-info
