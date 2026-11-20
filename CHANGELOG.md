# Changelog

All notable changes to the NS-BOS Kernel are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Key providers: the data plane takes its Fernet master key from a
  `KeyProvider` chosen with `NGARI_KEY_PROVIDER`. `file`, the existing
  `master.key`, stays the default. Each is tested against data v0.1.0 wrote
- `tpm2` key provider: the master key sealed to a TPM 2.0 through tpm2-tools
  (`NGARI_TPM_TCTI`, `NGARI_TPM_TIMEOUT`), with transient objects only and no
  NV writes. A sealed key is lost with the chip that sealed it
- Each provider refuses to start beside the other's key file, and each start
  writes a `key_provider` audit entry: the provider's name and whether it
  holds the key in hardware (`docs/KEY_PROVIDERS.md`)
- `keys status` and `keys migrate`. Migrate seals `master.key` into the TPM,
  unseals and compares it, trial-decrypts one stored file, and leaves
  `master.key` in place for the operator to remove
- `keys export-recovery` and `keys restore`: a passphrase-wrapped copy of the
  master key (scrypt N=2^15, r=8, p=1; Fernet), restored into a new TPM after
  a board swap. An unusable old sealed file is renamed, never deleted
- Optional PCR policy for the sealed key: `keys restore --pcrs sha256:7` or
  `NGARI_TPM_PCRS`, only with a recovery bundle in hand; new keys are never
  PCR-bound. A host update can leave the key recoverable only from the bundle
- `keys selftest [--json] [--pcrs SEL]` runs the tpm2 provider's lifecycle
  against a TPM in a scratch directory and prints the TPM's maker, model,
  firmware and PCR banks. It never reads the kernel's data or key
- `keys migrate`, `keys export-recovery` and `keys restore` record
  `key_migrated`, `recovery_exported` and `key_restored` in the audit log.
  No key material, passphrase or PIN is recorded
- Opt-in PIV/CAC operator check (`NGARI_OPERATOR_AUTH=card`) before those
  three commands: the card signs a challenge bound to the command and data
  directory, checked against a certificate pinned in `sovereign/operators/`
- Card settings `NGARI_PKCS11_MODULE`, `NGARI_PKCS11_TOKEN` and
  `NGARI_PKCS11_KEY_ID`. Each pass and refusal is recorded as `operator_auth`.
  Tested against SoftHSM, not yet with a physical card (`docs/PIV_CAC.md`)
- `keys card-check [--out FILE]` tests a card before it is pinned. A
  certificate must hold an EC key on P-256, P-384 or P-521, or an RSA key of
  at least 2048 bits, and be within its dates, or it is refused
- `keys pin-operator --cert FILE --user ID [--name NAME]` pins a certificate
  for a named operator, who is then recorded as the actor of what a gated
  command changes. `--replaces OLD` pins a reissued card as the same person
- Operator roles in `sovereign/roles.json`: once the file exists the card
  gate is required and every gated command needs `admin`. `keys set-roles`
  changes roles and `keys roles` lists them
- Electronic signatures: `records sign FILE --meaning M` has the operator's
  card sign the file's SHA-256 with the meaning, the signer and the UTC time,
  PIN every time, recorded as `esignature` (`docs/ESIGNATURES.md`)
- `records signatures FILE` checks every signature on the file as it is now;
  a changed file or another card's signature does not check. Applications
  get `records_cli.checked_signatures` and `CardAuthenticator.presented()`
- `agents sponsor` signs a manifest for an AI agent with its sponsor's card:
  what it may do and until when, at most a year. `agents list` and `agents
  check` check it; it is not yet enforced (`docs/AGENT_IDENTITY.md`)
- Audit entries carry the previous entry's hash and an HMAC-SHA256 under a
  key derived from the master key (HKDF, info `ngari-audit-v1`). Appends are
  locked and synced (`docs/AUDIT_LOG.md`)
- `audit verify` checks every entry's hash, chain link and MAC. `audit
  anchor` prints the entry count and tail hash to keep off the machine, and
  `audit verify --anchor` checks a later log against it
- `audit show` prints the audit trail, one line per entry or `--json`,
  selected by `--action`, `--actor`, `--since` and `--until`. It checks the
  log first; a log that fails is shown only with `--unverified` and exits 1
- The kernel records its own state changes, actor `kernel`: `kernel_started`,
  `kernel_stopped`, `agent_registered`, `agent_state_changed`, `task_created`,
  `task_state_changed`, `event_published` and `twin_updated`
- Those entries hold ids, names, topics, sizes and state names only, never a
  payload, result, error text, message body or twin value. `get_status()`
  counts them in `kernel.audited_actions`
- PII redaction by pattern: email addresses, phone, SSN and card numbers and
  street addresses are replaced by their kind in every audit entry, and in
  log lines unless `NGARI_REDACT_PII=0`. Best effort (`docs/PII_REDACTION.md`)
- `NGARI_AIR_GAP` air-gap mode: the inference clients call loopback addresses
  only and raise `AirGapError`, without making a request, for any other
  endpoint, and `pull_model` is refused (`docs/AIR_GAP.md`)
- The compliance report gains `key_provider`, `key_file_mode`, `audit_tail`
  and `air_gap`: the setting at call time and the host's network interface
  counters since the data plane started. It measures; it verifies nothing
- `NGARI_ENCRYPT_STATE` (off by default) encrypts the agent registry, the
  task file and inter-agent messages under a key derived from the master
  key. Once encrypted, state stays encrypted with the setting off
- `state status`, `state encrypt` and `state decrypt` show, encrypt and
  decrypt agent state. They refuse while the kernel runs and under another
  master key; `state decrypt` is card-gated (`docs/AGENT_STATE.md`)
- Inter-agent messages are removed after 21 years (7671 days), each sweep
  recorded as `retention_expired`. `NGARI_RETENTION_DAYS` can lengthen that
  or be `never`, not shorten it (`docs/RETENTION.md`)
- `sync/sync.log` is a hash chain checked by `verify_sync_ledger()`. A v0.1.0
  log is kept byte for byte, with its length and SHA-256 recorded in a
  `ledger_chained` entry (`docs/SYNC_LEDGER.md`)
- One `python -m core.kernel` per data directory: it holds a lock on
  `kernel.lock`, and a second one exits with status 2 naming the first one's
  pid. A crash leaves no lock behind
- `ns-bos` and `python -m core.kernel` take the commands `keys`, `audit`,
  `state`, `records` and `agents`, each with `--help`; an unknown command
  exits 2 with the usage. v0.1.0 started the kernel whatever the arguments
- `NGARI_SANDBOX_REQUIRE_BWRAP=1` refuses agent code (`sandbox_unavailable`)
  when bubblewrap is missing. `BwrapSandbox(extra_ro_binds=[(host,
  sandbox_path)])` binds host directories read-only into agent code's view
- `install.sh` clones a ref (`master` by default, or `--ref` a tag or
  branch), creates a virtualenv from the hash-pinned dependencies and checks
  the import. The repository root also installs with `pip install .`
- A Makefile holding every check, a GitHub Actions workflow built on its
  targets (lint, tests on Python 3.10 to 3.13, security, build), CodeQL, and
  hash-pinned locks for the runtime and for the dev and CI tools (`CI.md`)
- Release tooling: the wheel builds byte for byte the same on Python 3.10 to
  3.13 (`make repro`), a smoke test installs and starts it, and a tag
  workflow publishes the wheel, source tarball, checksums and provenance
- `scripts/release.py verify --dir DIR --key KEY.pub` (`make verify-release`)
  checks a downloaded release offline: an OpenSSH signature of `SHA256SUMS`
  by the release key, and each file against its line (`RELEASING.md`)
- `docs/validation/TRACE.md`: each 21 CFR Part 11 clause the kernel
  addresses, how, and the tests that show it, generated by `make trace`. A
  starting point for a buyer's validation, not that validation
- `docs/FIPS.md`: every cryptographic primitive the kernel uses, which
  library or device provides it and its FIPS 140-3 status, kept current by
  a test. No FIPS compliance is claimed

### Changed

- Air-gap mode is on by default; `NGARI_AIR_GAP=0` (or `false`, `no`, `off`)
  turns it off. With it on, a LAN engine URL, `pull_model`, a sync mode other
  than `local_only`, and agent code on a machine without bubblewrap are refused
- Agent code runs under the `restricted` seccomp profile by default, with
  limits on each run and without `/opt` or most of `/etc` in view (see
  Security). `seccomp_level=""` turns the filter off
- Python 3.9 is no longer supported. The package metadata requires 3.10 or
  newer, which the v0.1.0 code already needed, and tests run on 3.10 to 3.13
- beautifulsoup4 is no longer a dependency; nothing in the kernel used it.
  soupsieve and typing-extensions go with it
- The data directory, `logs/`, `sovereign/`, `encrypted/` and `audit/` are
  owner-only (0700), and `kernel.log` and stored files are 0600. Existing
  directories and the log are tightened at start
- The task, message and registry files are written compact, not indented
- Input from agents and models is bounded (`docs/AGENT_RUNTIME.md`):
  payloads, results and messages 256 KiB and 64 levels deep, descriptions
  4 KiB, topics 214 bytes, names, types, ids and actions 256 bytes
- After upgrading, run `python -m core.kernel audit adopt-legacy` once. It
  checks the entries v0.1.0 wrote and appends a keyed `legacy_history` entry;
  until then `audit verify` and the compliance report say not verified
- When encrypted files exist and no key is found, the data plane raises
  `KeyProviderError` instead of creating a new master key, and
  `python -m core.kernel` exits with status 2 and logs the reason
- A digital twin whose checksum does not match is no longer loaded after a
  warning. It is renamed `digital_twin.json.rejected-<UTC time>`, recorded in
  the sync ledger, and the kernel starts with an empty twin
- Module demos run as `python -m core.kernel.<package>`. The data plane's was
  `python core/kernel/data_plane/__init__.py`; the agent runtime's, which
  failed on a relative import, now runs

### Fixed

- `python -m core.kernel`, the documented quick start, failed with "No module
  named core.kernel.__main__". A data directory it cannot use now gives
  `Cannot start:` and exit status 2. An empty `NGARI_DATA_DIR` counts as unset
- SIGTERM, which systemd sends, never ran `stop()`, and Ctrl+C before the
  run loop skipped it and ended in a traceback. Both now shut down through
  `stop()` and exit 0, and a second signal does not cut the shutdown short
- `create_task` and `register_node` always failed (an enum is not JSON
  serializable) and left a truncated `tasks.json` or `fleet.json` that
  stopped every later start. A result that is not JSON is stored as text
- State files were written over in place, and one cut short by a crash
  stopped every later start. Each is written to a temporary file, synced and
  renamed, and an unreadable one is renamed `<name>.corrupt-<UTC time>`
- A twin, UI layout or behavior record with fields of the wrong type was
  saved on import, and then every later update, rendering or start raised.
  Such input is refused, and `import_layout` returns `False` for it
- `register_agent` minted a new id on every call, so each kernel start added
  six more agents to the registry. Registering an existing name now returns
  its id and keeps its state and memory
- Inter-agent messages: two on one topic in the same second overwrote each
  other, and `get_messages("alerts")` also returned `alerts_low`. Each has
  its own file, topics match exactly, and each subscriber gets its own copy
- `TaskPriority`, `SyncMode` and `AgentStateEnum` members are accepted from
  either import path of their modules. An agent set to `INITIALIZING`
  through `core.kernel.agent_runtime` was never started by `start()`
- `store_encrypted` wrote over the old file in place, so a crash mid-write
  could lose the old value; it now writes a synced temporary file and
  renames it. A `delete()` cut short leaves the old value or nothing
- Two kernels starting at once on a new data directory could end up with
  different master keys, and a crash during creation could leave an empty
  `master.key`. The key file is now linked into place complete or not at all
- An empty, cut-short or non-object `telemetry_config.json` stopped the data
  plane from starting. It is renamed aside and replaced with telemetry off,
  and rewrites go through a synced temporary file
- An audit log ending in part of a line or in zero bytes, as a crash or
  power loss leaves, made its readers raise. The next append moves those
  bytes to a file beside the log and records `audit_tail_set_aside`
- `get_audit_log` and `get_sync_history` read the whole log for a few
  entries. Both stream, and a limit of 0 returns nothing. `get_sync_history`
  skips a line cut short or not UTF-8, where it raised
- `uptime_seconds` in `get_status()` counted from construction on the wall
  clock and kept counting after `stop()`. It and the sandbox's
  `elapsed_seconds` use a monotonic clock; uptime is 0 while stopped
- Every sandboxed run failed on x86_64 with "execvp python3: No such file or
  directory" because `/lib64` was not bound. Output that is not UTF-8 no
  longer discards a run's result
- The sandbox rewrote `eval(`, `exec(`, `open(` and `compile(` as text, so
  `re.compile(...)` and `gzip.open(...)` failed while `f = open` went
  through. Only the names are renamed, and calling one raises PermissionError
- `get_capabilities()` reported isolation whenever `bwrap` was on PATH; it
  now runs bubblewrap and a filter and reports `bwrap_probe` and
  `seccomp_probe`. `get_sandbox(timeout=...)` ignored a later timeout
- `generate`, `chat` and `list_models` raised when an engine answered 200
  with a body of another shape or nested too deep. They return the empty
  answer of a failed call, and bad `list_models` entries are skipped
- A tool call written in a model's prose was dropped when a string argument
  held a brace, and calls parsed together shared an id. Calls are read with
  a JSON decoder and ids are random
- A tool dispatcher that fails, or a reply the tool loop cannot read, ends
  the loop with the history of the calls that ran. The manager used to
  report "No available inference engine"
- `InferenceEngineManager` sent llama.cpp the model name as the prompt, sent
  a vLLM tool conversation to Ollama without saying so, and passed `chat`
  options an engine does not take. The last two raise `ValueError`
- A Raspberry Pi or other ARM board was reported as x86_64. The device-tree
  model identifies the board, and an AGX Thor is a Thor
- CPU utilisation read 0% with BusyBox `top` or a decimal-comma locale, and
  the x86 GPU name was wrong when lspci prints a PCI domain. Two thermal
  zones of one type overwrote each other; the second is `<type> (<zone>)`
- Jetson GPU utilisation and power always read 0: tegrastats output was
  discarded and `jtop --json` does not exist. One tegrastats line is read,
  power also from `POM_5V_IN`, and GPU memory is the board's, not 64 GB
- Adapting a generative UI layout to one user's habits reordered the shared
  stored layout for every later user. Adaptation works on a copy
- `LICENSE` holds the full Apache 2.0 text. Documentation and the compliance
  report said AES-256; Fernet uses AES-128-CBC with HMAC-SHA256. `delete()`
  is documented as a best-effort overwrite, not a secure delete

### Security

- In v0.1.0 each audit entry was hashed on its own, so entries could be
  edited, removed or reordered without detection. The log is now a hash
  chain keyed with HMAC-SHA256, checked by `audit verify` and against anchors
- In v0.1.0 the seccomp filter used aarch64 system-call numbers on every
  architecture and had no architecture check, so on x86_64 it blocked the
  wrong calls and let ptrace, bpf and kexec through
- Seccomp numbers now come from each architecture's headers (x86_64 and
  aarch64); other architectures get no filter, as `get_capabilities()`
  reports. Every filter checks the ABI first and refuses x32 calls
- Agent code ran with no seccomp filter by default. It now runs under
  `restricted` unless the caller names another profile, and an unknown
  `seccomp_level` raises `ValueError` instead of running unfiltered
- A seccomp filter that could not be installed was logged and the agent code
  ran anyway. The run now stops before agent code starts, and the result
  says `seccomp_not_installed`
- Under `restricted`, agent code could create a user namespace and hold
  every capability in it. `unshare`, the mount calls, `keyctl`,
  `request_key`, `memfd_create` and `clone` with a namespace flag are refused
- The sandbox bound all of `/etc` and `/opt` and shared the caller's
  terminal, standard input and session keyring. Of `/etc` only `ld.so.cache`
  and `localtime` are bound, `/opt` is not, and a run has its own session
- A sandboxed run had no resource bounds. Output is capped while it is read,
  writable mounts have a size (bubblewrap 0.7.0 or later), and each run has
  memory, file size, process and open file limits (`docs/SANDBOX.md`)
- Without bubblewrap, a timeout killed only the first process and agent code
  could import from the host's `/tmp`. A timeout now kills every process the
  run started, and the run has a private working directory
- Key names, generative UI ids and message topics were used as file names
  unchecked, so `../name` reached files outside `encrypted/`, `ui/` and
  `comm/`. Names that are empty or hold `/` or NUL are refused
- Generative UI HTML rendering put layout text into the page unescaped, so
  an imported layout could inject script. Every value is HTML-escaped, and
  agent-supplied text is escaped in log lines
- `chat_with_tools` dispatched any JSON object with a `"name"` key in a
  model reply as a tool call, declared or not. Only declared tools are
  dispatched, at most `max_tool_calls` (16 by default) over all rounds
- The inference clients followed HTTP redirects and sent loopback calls
  through an environment proxy, either of which could carry a prompt to
  another host. Redirects are not followed and loopback calls go direct
- `master.key` was written with the default mode and tightened afterwards,
  and the data directories were created 0755, stored files 0644. The key is
  created 0600, and the rest is owner-only (see Changed)
- The compliance report returned `data_sovereignty: enforced` and
  `external_telemetry: False` as constants. Both are computed at call time
  from the audit check, the key provider and the telemetry setting
- certifi 2026.10.23 (from 2026.7.22, PYSEC-2026-4320) and urllib3 2.8.0
  (from 2.7.0, PYSEC-2026-4175, -4176 and -4177); pip-audit runs on both
  locks in CI. soupsieve 2.9.1, open to four advisories, is not installed

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
