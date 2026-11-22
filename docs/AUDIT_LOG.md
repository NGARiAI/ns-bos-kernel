# Audit log

The data plane appends one JSON line per event to
`$NGARI_DATA_DIR/sovereign/audit/sovereign_audit.log` (mode 0600), under an
exclusive lock, with an fsync after each line. Each data plane start writes a
`key_provider` entry (which provider holds the key, whether it is hardware-bound and ok, and whether air-gap mode was on, as `air_gap`), and `store_encrypted` (with the `size` stored, in bytes), `retrieve_decrypted` and `delete`
write one per call. With `NGARI_OPERATOR_AUTH=card`, the `keys` commands add an
`operator_auth` entry (see `PIV_CAC.md`). When they change something,
`keys migrate`, `keys export-recovery` and `keys restore` record
`key_migrated` (`tcti`, the TPM the key went to), `recovery_exported`
(resource the bundle path) and `key_restored` (`pcrs`, the PCR selection;
`rebound`, whether an existing seal was rebound; `set_aside`, the name of a
sealed file set aside, or null), with the operator as the actor when the gate checked one
(the named operator's user id, else the card's fingerprint) and `local`
otherwise. `keys pin-operator` records `operator_pinned` (resource the user
id, details `name` and `fingerprint`, and for a reissued card `replaces` and
`person`; `PIV_CAC.md`) and `keys set-roles` records
`roles_changed` (resource the user id, details `from` and `to`); with roles
set, `operator_auth` also names the `role` checked. `records sign` records
`esignature` and `esignature_refused` (`ESIGNATURES.md`). `agents sponsor` records
`agent_sponsored` (resource the agent's name, the sponsor's user id as the
actor, details `agent_type`, `not_after`, `manifest_sha256`, `fingerprint`
and `replaced`) and `agent_sponsor_refused` (`reason`; `AGENT_IDENTITY.md`).
`state encrypt` and `state decrypt`
record `state_encrypted` and `state_decrypted` per file (`bytes`) and once
for `comm` (`messages`), with the same actors; `state decrypt` is gated like
the key commands. These carry a MAC from the key the
command used. No key material, passphrase or PIN is recorded.

## Kernel entries

The kernel records its own state changes, always with actor `kernel`: the
kernel acting on a request from a caller it does not authenticate, so the
entry shows what was done and not who asked. Each entry is written after the
state it describes is on disk. Nothing is written when nothing changed (an
unchanged re-registration, a state set to the one it has).

| Entry | Resource | Details |
|-------|----------|---------|
| `kernel_started` | the kernel version | `platform`, `agents` |
| `kernel_stopped` | the kernel version | `uptime_seconds` |
| `agent_registered` | the agent id | `name`, `type`, `outcome` (`created` or `updated`) |
| `agent_state_changed` | the agent id | `from`, `to` |
| `task_created` | the task id | `agent_id`, `action`, `priority` |
| `task_state_changed` | the task id | `from`, `to` |
| `event_published` | the topic | `file`, `bytes`, `subscribers` |
| `twin_updated` | the twin key | none |
| `state_encrypted` | `registry.json` or `tasks.json` | `bytes` |
| `retention_expired` | `comm` | `removed`, `retention_days`, `oldest`, `newest` |

Payloads, results, error text, message bodies, agent descriptions, memory,
environments and twin values are never in an entry: ids, names, topics, sizes
and state names only. Subscribing is not recorded, as it changes no state. The
log is keyed, not encrypted: these details stay readable with
`NGARI_ENCRYPT_STATE` on. `state_encrypted` is
written once per file, when a plaintext registry or task file is encrypted in
place because `NGARI_ENCRYPT_STATE` is on (`docs/AGENT_STATE.md`).

A failing append (a full disk) raises to the caller of the operation, after its
state is saved, except in `stop()`, which logs it at ERROR and finishes
shutting down. `get_status()` reports `kernel.audited_actions`, counts of what
this process wrote since it started, and the compliance report's `audit_tail`
is the hash of the last entry, the value `audit anchor` prints, so a status
snapshot can be checked against an anchor kept off the machine. Every
published event costs one synced append, about 4 ms on the development
machine and more on an SD card.

## After a crash

A write cut short by a crash or power loss can leave the log ending in part
of a line, or in zero bytes. The next append, which every data plane start
makes, copies everything after the last whole entry to a new file beside the
log, `sovereign_audit.log.damaged-<UTC time>-<offset>` (mode 0600), cuts it
from the log, and records an `audit_tail_set_aside` entry with its size,
SHA-256 and that file name, chained to the last whole entry. Until then
`audit verify` reports `unreadable entry`. A damaged line with whole entries
after it is not touched, and the check keeps reporting it. If the copy cannot
be written, the log is left as it is and the append fails.

## What an entry holds

| Field | Meaning |
|-------|---------|
| `timestamp` | UTC, ISO 8601 |
| `action`, `actor`, `resource`, `details` | What happened, to what |
| `prev_hash` | `hash` of the entry before it; 64 zeros for the first |
| `mac` | HMAC-SHA256 of the entry without `hash` and `mac` |
| `hash` | SHA-256 of the entry without `hash`, so it covers `mac` |

The MAC key is HKDF-SHA256 of the master key with info `ngari-audit-v1`. It is
separate from the keys Fernet derives for encryption, and it is never written
anywhere. `operator_auth` entries are recorded before the command may read the
key, and `operator_pinned`, `roles_changed`, `esignature`,
`esignature_refused`, `agent_sponsored` and `agent_sponsor_refused` by
commands that never read it, so they carry no MAC; their hash and chain are
still checked, an `esignature` carries the card's own signature, and an
`agent_sponsored` entry names a manifest that carries one. Until a keyed entry follows them, they can be
rewritten without the key (What it cannot see).

## Checking it

    python -m core.kernel audit verify [--anchor FILE]
    python -m core.kernel audit anchor

Both take `--data-dir` (default `$NGARI_DATA_DIR`), read the master key
through the configured provider to derive the MAC key, and append nothing.
Neither starts the kernel. On a `tpm2` install they need the TPM, as the
kernel does.
They read the log under a shared lock, which waits for an entry being
written to be complete; the kernel's appends wait while a check reads, so a
full check of a very large log on a running kernel holds its writes for that
long.

`audit verify` reads every line and stops at the first problem. It prints
`audit log OK: N entries verified` and exits 0, or prints the problem on
stderr and exits 1:

| Message | Cause |
|---------|-------|
| `unreadable entry` | A line that is not a JSON entry with a `hash`, is not UTF-8, or holds a field twice (JSON would keep the last, so the line could show one value and be hashed with another) |
| `broken chain at entry N` | `prev_hash` is not the previous entry's `hash`: an entry was removed, inserted or moved |
| `entry N does not match its hash` | The entry was edited |
| `entry N has a bad MAC` | The entry was rewritten without the master key, or with another key |
| `entry N (key_provider) has no MAC` | A start entry without a MAC; every data plane start writes one |
| `entry N has no MAC after keyed entries` | An entry without a MAC after entries that have one |
| `N unkeyed entries from before the key are not attested; run audit adopt-legacy` | Entries from before the log had a key, with no keyed entry vouching for them (see After an upgrade) |
| `entry N attests history that is not there` | A `legacy_history` entry whose count or tail does not match the unkeyed entries before it, or a second one |

Exit status 2 means bad arguments. A key that cannot be loaded, or an anchor
file that cannot be read, exits 1 with the reason.

## Showing it

    python -m core.kernel audit show [--anchor FILE] [--action A]... [--actor U]
        [--since DATE] [--until DATE] [--json] [--unverified]

prints the audit trail for inspection (21 CFR 11.10(b)): one readable line
per entry, with its number in the log (the N in `audit verify`'s
messages), time, action, actor, resource and details, under a line saying
how many entries were verified and shown. `--json` prints the entries as
stored, one JSON line each, with no header; each parses to exactly the
entry that was hashed and checked. `--action` (repeatable),
`--actor`, `--since` and `--until` select entries; a date (`2026-10-31`)
means the whole UTC day, and a time (`2026-10-31T14:05:09Z`) is exact,
with `--until` showing entries before it.

The log is checked first, as `audit verify` does (with `--anchor` if
given), and only a log that passes is shown, exit 0. The bytes checked are
copied to an unnamed temporary file beside the log while the shared lock
is held, and printed from that copy after it is released, so what is shown
is exactly what was verified and a slow reader never holds up the kernel's
appends. A log that fails is not shown, exit 1, unless `--unverified` is
given: then it is shown whole, under a first line `NOT VERIFIED: <problem>`,
lines that are not entries as `N  unreadable line`, and the exit status is
still 1.

The kernel's compliance report runs the same check: `audit_integrity` is its
result and `audit_entries` the line count, both measured at call time. In one
kernel process, a repeat check hashes the bytes the last passing check
covered, and parses only what was added after them if those bytes are
unchanged; any change to them means a full check. The answer is the same
either way (100,000 entries: 2.4 s for the first check, 0.1 s for the next).

## After an upgrade

A log written before the kernel kept a MAC key (v0.1.0) holds entries with
no MAC. Nothing in the file can show they were there before the key rather
than written yesterday by someone without it, so they verify only once an
operator has vouched for them:

    python -m core.kernel audit adopt-legacy

checks every hash and link, then appends a keyed `legacy_history` entry
naming how many unkeyed entries there are (`entries`) and the hash of the
last one (`tail`).
From then on a rewrite of that history breaks the chain or contradicts the
entry. Until it is run, `audit verify` and the compliance report report the
log as not verified. Run it once, after confirming the old entries are what
you expect; it refuses a log whose hashes or links do not hold, and does
nothing on a log that has no unkeyed entries or is already attested.

## What it cannot see

Removing entries from the end leaves a shorter log that still verifies.
Entries written after the last keyed one can also be edited, reordered or
removed and the chain rebuilt without the key: `keys`, `records` and
`agents` commands write `operator_auth`, `operator_pinned`, `roles_changed`,
`esignature`, `esignature_refused`, `agent_sponsored` and
`agent_sponsor_refused` without a MAC, and nothing keyed
covers them until the next kernel start writes a `key_provider` entry on
top. Anyone holding the master key can also rewrite the whole log with
valid hashes and MACs, and on a `file` install that includes anyone who
can read `master.key`. All of these are caught only against an anchor
kept off the machine; take one after signing or changing operators.

## Keeping an anchor

`audit anchor` verifies the log, then prints the entry count and the hash of
the last entry:

    {"entries": 5, "tail": "4db94a89...c96"}

1. `python -m core.kernel audit anchor > anchor-2026-10-28.json` and copy the
   file off the machine, to another host or removable media.
2. Later, `python -m core.kernel audit verify --anchor anchor-2026-10-28.json`.

The log may have grown since. It fails with `log has N entries, the anchor
recorded M` if it is shorter, and with `entry M is not the one the anchor
recorded` if entry M is no longer the same, which is what a rewrite up to that
point produces. Take a new anchor as often as losing the entries since the
last one would matter.
