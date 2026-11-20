# Key providers

The data plane encrypts everything under `sovereign/encrypted/` with one
44-byte Fernet master key. A key provider decides where that key lives. Two
ship today: `file` (the default, and the only behavior before this change) and
`tpm2` (the key sealed to a TPM 2.0).

A key that cannot be unsealed is data that no longer exists. Every rule below
follows from that.

## Choosing a provider

| Variable | Default | Meaning |
|----------|---------|---------|
| `NGARI_KEY_PROVIDER` | `file` | `file` or `tpm2`. Any other name stops the kernel. |
| `NGARI_TPM_TCTI` | `device:/dev/tpmrm0` | How tpm2-tools reach the TPM. Always explicit. |
| `NGARI_TPM_TIMEOUT` | `30` | Seconds allowed per tpm2-tools call. |
| `NGARI_TPM_PCRS` | unset | PCR selection for `keys restore`, e.g. `sha256:7`. |

There is no fallback between providers. If the selected provider cannot
produce the key, the kernel logs one line and exits with status 2. It never
falls back to a plaintext key, and it never creates a new key while
encrypted files exist.

## Files

All under `$NGARI_DATA_DIR/sovereign/keys/`, directory mode 0700.

| File | Provider | Contents |
|------|----------|----------|
| `master.key` | `file` | The Fernet key in plaintext, mode 0600. |
| `master.key.sealed` | `tpm2` | JSON: format version, parent key name, sealed public and private parts, optional PCR selection. Mode 0600. Holds no key bytes. |
| `master.key.sealed.unusable-<UTC time>` | `tpm2` | A sealed file that no longer unsealed here, set aside by `keys restore`. Never deleted by the kernel. |

New files are written under a temporary name, synced, and linked into place,
so a crash or a second kernel starting at the same moment never leaves a
partial key or two different keys.

## The interface

`core/kernel/data_plane/keys.py` defines `KeyProvider`:

- `name`: the value of `NGARI_KEY_PROVIDER` that selects it.
- `load_or_create(*, may_create=True) -> bytes`: the Fernet key. With
  `may_create=False` (the data plane passes this whenever an `.enc` file
  exists) a missing key raises `KeyNotProvisionedError` instead of being
  created. Every other failure raises `KeyProviderError`.
- `describe() -> dict`: facts measured at call time, never the key. Always
  `provider`, `hardware_bound` and `ok`. The compliance report includes it,
  and every kernel start writes a `key_provider` audit entry with the name,
  `hardware_bound` and `ok`.

A provider is registered by name in `_FACTORIES` with a constructor taking
the keys directory and the environment. `SovereignDataPlane(key_provider=...)`
takes an instance directly.

## The tpm2 provider

It drives the tpm2-tools command line (5.x), so it adds no Python
dependency. Install `tpm2-tools`; on Debian and Ubuntu that pulls in the
device TCTI.

- **Parent**: an ECC P-256 storage key in the owner hierarchy, recreated from
  a pinned template on every use. Nothing is made persistent and nothing is
  written to TPM NV memory. All objects are transient.
- **Sealed object**: a keyedhash data object (`fixedtpm|fixedparent|noda`,
  plus `userwithauth` when there is no PCR policy). The key goes in on
  tpm2_create's stdin and comes out on tpm2_unseal's stdout. It is never in
  argv, a file, a log line or an error message.
- **New keys**: generated, sealed, unsealed and compared before the sealed
  file is published. The provider refuses to create a key when a plaintext
  `master.key` is beside it; use `keys migrate` for that.
- **Resource manager**: use `/dev/tpmrm0` (the kernel's) or tpm2-abrmd. On a
  TCTI without one (`libtpms:`, `swtpm:`, `mssim:`, a raw `/dev/tpm0`) the
  provider flushes every transient object and session after each step, which
  also clears objects other programs left in that TPM.
- **Cost**: about 1.2 s to provision and 1.0 s to unseal on a Nuvoton NPCT
  TPM 2.0 through `/dev/tpmrm0`. The kernel unseals once per start.
- **Device access**: the kernel's user must be able to read and write the
  device. Debian and Ubuntu make `/dev/tpmrm0` group `tss` (tpm-udev), so add
  that user to `tss`; a container sees whatever the host passes through. When
  a `device:` TCTI cannot be opened, the error names the path and, as the TPM
  stack's own message does not, whether it is missing or which owner, group
  and mode keep this user out.

`ok` in `describe()` is true only when the sealed file is mode 0600, it was
unsealed by this process, and no plaintext `master.key` remains beside it.

### Bound to one chip

The sealed key can only be unsealed by the TPM that sealed it, under the
same owner hierarchy. A replaced board, a cleared TPM, or copying the data
directory to another machine all make it unusable on its own. Keep a
recovery bundle (below) somewhere other than the machine.

On a VM or container the TPM belongs to the host. Its owner hierarchy and its
PCRs are the host's, so host maintenance can affect the guest's key.

## Commands

All run as `python -m core.kernel keys <command>` (or `ns-bos keys ...`) and
take `--data-dir`. None of them starts the kernel. With `NGARI_OPERATOR_AUTH=card`,
`migrate`, `export-recovery` and `restore` first need the operator's PIV/CAC card
(PIN from `--pin-file` or the terminal) and record the result, pass or fail, as an
`operator_auth` audit entry; see `PIV_CAC.md`. Either way, a migrate, export or
restore that changes something is recorded in the audit log, keyed like any
other entry; `pin-operator` and `set-roles` record unkeyed `operator_pinned`
and `roles_changed` entries, and `status`, `selftest`, `roles` and
`card-check` never write to it. With a roles file, each gated command needs
the `admin` role and the gate cannot be off.
`AUDIT_LOG.md` lists the entries and covers checking the log.

| Command | Does |
|---------|------|
| `keys status` | Prints what is on disk: selected provider, `master.key` and `master.key.sealed` presence and mode, PCR selection, number of encrypted files. Reads only; does not use the TPM. |
| `keys migrate` | Seals the existing `master.key` into the TPM. Checks first that the key decrypts one stored file, then seals, unseals with a fresh provider and compares. Leaves `master.key` untouched. |
| `keys export-recovery --out FILE` | Writes a passphrase-wrapped copy of the key in use to a new file (mode 0600, never overwritten). |
| `keys restore --bundle FILE [--pcrs SEL]` | Seals the bundle's key into the current TPM, optionally bound to PCRs. |
| `keys selftest [--json] [--pcrs SEL]` | Runs the tpm2 lifecycle against the TPM in a scratch directory: a probe stored under a new file key, `migrate`, the probe read back through the sealed key with `master.key` deleted, `export-recovery`, `restore` into a second store, and a sealed blob with one byte changed refused. With `--pcrs` (default `$NGARI_TPM_PCRS`), also a `restore` bound to those PCRs that must read back; PCRs are only read, never extended. Prints the TPM's maker, model, firmware and allocated PCR banks and one line per step; a selection the TPM has no bank for stops before any step. Never reads the data directory or its key, so it needs no card; exits 1 at the first failed step. |
| `keys pin-operator --cert FILE --user ID [--name NAME] [--replaces OLD]` | Pins a certificate for a named operator (with `--replaces`, the same person as `OLD`, for a reissued card): writes `<user>.pem` and `<user>.json` (user id and printed name, default the certificate's common name) into `sovereign/operators/`, never overwriting, and records `operator_pinned`. With the gate on, needs a pinned operator's card unless none is pinned yet; see `PIV_CAC.md`. |
| `keys roles` | Lists named operators and their roles from `sovereign/roles.json`. Reads only; needs no card. |
| `keys set-roles --user ID --roles LIST` | Replaces a named operator's roles (`admin`, `author`, `reviewer`, `approver`, `sponsor`, comma-separated, or `none`) and records `roles_changed`. Refuses a change that leaves no `admin`. Gated; needs `admin` once a roles file exists; see `PIV_CAC.md`. |
| `keys card-check [--pin-file FILE] [--out FILE]` | Has the PIV/CAC card sign a fresh challenge with the PIN and verifies it against the card's certificate; prints the certificate and whether it is pinned. With `--out`, writes the verified certificate for pinning. Changes nothing; see `PIV_CAC.md`. |

Exit status is 0 on success, 1 on a refused or failed command, 2 on bad
arguments. The passphrase for the last two comes from `--passphrase-file` or
the terminal, never from argv or the environment.

### Moving an existing install to tpm2

Run `keys selftest` first. It proves this TPM seals, unseals, recovers and
refuses a tampered blob, without touching the data.

1. `keys status` and confirm `master.key` is present and the file count is
   what you expect.
2. `NGARI_TPM_TCTI=device:/dev/tpmrm0 python -m core.kernel keys migrate`.
3. `keys export-recovery --out /media/usb/ngari-recovery.json` and store the
   passphrase separately from the file.
4. Start the kernel with `NGARI_KEY_PROVIDER=tpm2` and check the data.
5. Move `master.key` off the machine yourself. Until then the compliance
   report shows the tpm2 provider as not ok, because the key is also on disk
   in plaintext. The kernel never deletes it.

To go back, set `NGARI_KEY_PROVIDER=file` while `master.key` still exists.

### After a board swap, with master.key still on the disk

If `master.key` was never removed, `keys export-recovery` works without the
sealed file: when `master.key.sealed` cannot be unsealed on this TPM and
`master.key` decrypts a stored file, the bundle is made from `master.key` and
the command says so. It still refuses when there is no stored file to prove the
key against, or when `master.key` does not decrypt one. Then `keys restore
--bundle` seals the key into the new TPM as below.

### After a board swap

1. The kernel stops with "sealed under a different TPM owner hierarchy".
2. `keys restore --bundle ngari-recovery.json`. The bundle's key must
   decrypt a stored file. The old sealed file is kept as
   `master.key.sealed.unusable-<time>`; it stays in place until the new one
   is proven and swapped in, so an interrupted restore leaves the store as it
   was.
3. Start the kernel with `NGARI_KEY_PROVIDER=tpm2`.

## Recovery bundle

A JSON file holding the master key encrypted under a key derived from the
passphrase: scrypt with N=2^15, r=8, p=1 (32 MiB of memory, about 0.1 s),
then Fernet. The passphrase must be at least 12 characters. A wrong
passphrase or an edited bundle fails closed. KDF parameters read from a
bundle are bounded (N up to 2^17, r up to 16, p up to 4), so a crafted file
cannot demand unbounded memory.

The bundle also recovers agent state encrypted with `NGARI_ENCRYPT_STATE`:
its key is derived from the master key (`docs/AGENT_STATE.md`).

Anyone holding both the bundle and the passphrase can read every encrypted
file. Store them apart.

## PCR policy

Off by default, and new keys are never PCR-bound. `keys restore --pcrs
sha256:7` (or `NGARI_TPM_PCRS`) seals the key under a PolicyPCR policy with
no auth value, so it unseals only while the selected PCRs keep their current
values. Restore is the only way in, which means the operator already holds a
bundle that opens and matches the data. `--pcrs none` removes the policy.
Some chips leave the sha256 bank unallocated; restore checks for it first and
changes nothing if it is missing, and `keys selftest --pcrs` reports the
allocated banks.

Any firmware, bootloader or kernel update that changes a selected PCR makes
the key fail closed at the next start. It then comes back only through `keys
restore` with the bundle, which can bind it to the new values. On a VM or
container, the PCRs are the host's boot measurements: a host update the
guest never sees can lock the guest's key.

## Testing

`tests/test_tpm.py`, `test_keys_cli.py`, `test_recovery.py` and
`test_pcr_policy.py` run against an in-process software TPM (the `libtpms:`
TCTI with a state file in the test's tmp directory), never a hardware chip.
They skip when tpm2-tools or the TCTI are missing. `NGARI_REQUIRE_TPM_SIM=1`
(set in CI) turns the skip into a failure. Every provider has a same-boot
round trip test and a test that data written by v0.1.0
(`tests/vectors/v0.1.0`) decrypts after the change.

`tests/test_main_tpm.py` runs `python -m core.kernel` itself on the tpm2
provider: two boots share one sealed key and its data. It exits with status 2
and leaves every key file as it was when the TPM is unreachable, when a
plaintext key exists and nothing is sealed, when the sealed key was altered,
and when it was sealed by another TPM.
