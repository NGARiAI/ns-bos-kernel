# Known Limitations

What the NS-BOS Kernel does not do today. Each item names the page that
gives the detail. `tests/test_known_limitations.py` checks this page against
the code, so an item that is fixed fails the suite until it is removed here.

## Keys

- **The default key is a plaintext file.** The `file` provider keeps the
  master key in `sovereign/keys/master.key`, mode 0600, beside the data it
  protects. Anyone who can read that file, or who copies the data directory,
  can decrypt it. The `tpm2` provider seals the key to a TPM 2.0 chip and is
  opt-in (`docs/KEY_PROVIDERS.md`).
- **A sealed key has no PCR policy unless one is set.** Without one, any
  local process that can open the TPM can unseal the key.
- **One key, no rotation.** Records are encrypted directly under the master
  key. There is no key-encryption key, no rotation command and no
  passphrase-protected mode for a machine without a TPM.
- **TPM sealing is tested on a software TPM.** It has not been tested on
  Jetson secure storage (firmware TPM or OP-TEE).

## Cryptography

- **No validated cryptographic module as shipped.** No part of the kernel
  runs inside a module validated under FIPS 140-3. The algorithms in use are
  listed in `docs/FIPS.md`. One of them, scrypt, which protects the recovery
  bundle, is not an approved algorithm.
- **Fernet uses AES-128**, in CBC mode with HMAC-SHA256.

## Audit log

- **Entries removed from the end are not detected by the log alone.** They
  are detected against an anchor kept off the machine. Anchors are taken by
  hand with `audit anchor` and are not signed (`docs/AUDIT_LOG.md`).
- **Some entries carry no MAC.** The `keys`, `records` and `agents` commands
  write their entries without one, and nothing keyed covers them until the
  next kernel start.
- **Anyone holding the master key can rewrite the log** with valid hashes
  and MACs. On a `file` install that is anyone who can read `master.key`.
- **The log shares a file system with the kernel** and is not append-only
  at the file system level.

## Operators and agents

- **Card support is tested against SoftHSM**, not yet with a physical
  PIV/CAC card and reader (`docs/PIV_CAC.md`).
- **No certificate chains or revocation.** Trust is the certificate pinned
  on the machine. There is no two-person rule.
- **Roles cover the gated commands and signatures only.** There is no
  access control over the kernel's Python API: code that can import the
  kernel can call it.
- **Agent manifests are not enforced.** The kernel registers an agent that
  has no manifest, does not record actions under the agent's identity, and
  does not enforce the permissions a manifest lists
  (`docs/AGENT_IDENTITY.md`).
- **A signature check cannot show the past.** It cannot show that the
  signer held the role, or that the card was not yet retired, when it
  signed (`docs/ESIGNATURES.md`).

## Sandbox

- **The seccomp filter is a denylist.** It refuses 36 system calls
  (`restricted`) or 54 (`strict`) and allows the rest (`docs/SANDBOX.md`).
- **Without bubblewrap and with air-gap mode off**, agent code runs in a
  subprocess with the filter and limits and no namespaces, unless
  `NGARI_SANDBOX_REQUIRE_BWRAP=1`.
- **Limits are per process.** There is no cgroup and no CPU-time limit, and
  when the kernel runs as root the process limit does not apply.
- **No filter on architectures other than x86_64 and aarch64.**
- **The Python import blocklist is not a boundary.**

## Data at rest

- **Agent state is plaintext by default.** The registry, tasks and messages
  are encrypted only with `NGARI_ENCRYPT_STATE=1`, and file names, sizes and
  times stay visible (`docs/AGENT_STATE.md`).
- **The digital twin and the sync ledger are plaintext.**
- **`delete()` is a best-effort overwrite**, not a secure erase.
- **Key material is not locked in memory.**

## Network and models

- **No sync between machines.** There is no peer discovery, no transport
  and no mesh. The sync modes other than `local_only` send nothing.
- **Inference engines are reached over HTTP without authentication**, on
  loopback. Air-gap mode does not cover the engine's own network traffic
  (`docs/AIR_GAP.md`).
- **Models are not signed or verified** when loaded.

## Runtime

- **The kernel stores tasks and does not run them.** An application runs
  the queue.
- **Linux only**, with Python 3.10 or newer.

## Fixed since v0.1.0

Defects in the v0.1.0 release that are fixed in this tree are listed under
"Security" and "Fixed" in `CHANGELOG.md`.
