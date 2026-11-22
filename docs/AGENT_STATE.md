# Agent state encryption

`NGARI_ENCRYPT_STATE` encrypts the agent registry
(`agents/registry/registry.json`), the task file (`agents/tasks/tasks.json`)
and inter-agent messages (`agents/comm/`). It is off by default, so an
application that reads those files directly keeps working until it is turned
on.

| Variable | Default | Meaning |
|----------|---------|---------|
| `NGARI_ENCRYPT_STATE` | off | `1`, `true`, `yes` or `on` turn it on. Unset, empty, `0`, `false`, `no` and `off` leave it off. Any other value turns it on and logs a warning. |

## The key

The state key is derived from the master key with HKDF-SHA256 (info
`ngari-state-v1`), so it is neither the master key nor the key the data plane
encrypts `sovereign/encrypted/` with, nor the audit MAC key. Whatever holds the
master key holds this one too: with `NGARI_KEY_PROVIDER=tpm2` agent state is
bound to the TPM, and a recovery bundle of the master key recovers agent state.
There is no second key to back up.

## On disk

An encrypted file is one JSON object:

    {"format": "ngari-encrypted-v1", "key_id": "<32 hex>", "token": "<Fernet token>"}

`key_id` names the master key the file belongs to (16 bytes derived with info
`ngari-key-id-v1`); it reveals nothing about the key. The token holds the exact
bytes the plaintext file would have held. Messages written while encryption is
on are named `<topic>_<time>_<hex>.enc.json`; messages written before keep
their names and stay readable where they are.

## Turning it on

At the next start the registry and the task file are encrypted in place, each
by one synced rename, so a crash leaves the plaintext file or the encrypted
one, never neither. Each is recorded once in the audit log as
`state_encrypted` with its plaintext length. A file that cannot be read is set
aside as `<name>.corrupt-<UTC time>` as before, and it keeps its plaintext:
check `agents/` for such files after turning encryption on. Messages already in
`agents/comm/` stay plaintext.

## Once on, it stays on

When any agent state is encrypted, everything the runtime writes is encrypted,
whatever the setting says; turning the setting off logs a warning and changes
nothing on disk. Going back to plaintext is `state decrypt`.

## Commands

    python -m core.kernel state status
    python -m core.kernel state encrypt
    python -m core.kernel state decrypt [--pin-file FILE]

All three take `--data-dir` (default `$NGARI_DATA_DIR`).

`status` prints what is encrypted, the key ids found, any set-aside files
and any temporary files a killed write left behind; both kinds can hold
plaintext, and nothing removes them. It reads no key.

`encrypt` encrypts the registry, the task file and every plaintext message,
including the backlog the kernel leaves alone at start. `decrypt` turns all of
it back into the exact bytes it held before, for an earlier kernel or an
application that reads the files. With `NGARI_OPERATOR_AUTH=card`, `decrypt`
needs the operator's card (see `PIV_CAC.md`); `encrypt` only adds protection
and does not.

Stop the kernel, and any application that builds `NSBOSKernel` or
`AgentRuntime` on this data directory, first: a live one writes its own copy
back from memory, which undoes a decrypt. Both commands refuse while
`python -m core.kernel` runs (it holds `kernel.lock`), but an application that
builds the kernel itself takes no lock, and they cannot see it. Both check
every encrypted file's key id against the master key before changing
anything. Messages are converted in batches: each
new copy is synced, then the directory, and only then are the old files
removed, so a run cut short leaves every message readable once and the next
run finishes it. A file that cannot be read or written is left as it is and
named, the others are converted, and the command exits 1. Each run records `state_encrypted` or `state_decrypted` per
file and once for `comm`. With `NGARI_ENCRYPT_STATE` still on, the next start
encrypts decrypted state again, so unset it first.

## Another key, or no key

A registry or task file encrypted under another master key stops the start
with `Cannot start:`, naming both key ids, before anything is written, and the
command exits 2. The file is never set aside. The start also reads the key id
of one message; a message under another key that it did not read, or a damaged
one, is skipped by the reader with a warning and left in place. With encrypted
state present and no key, no new key is created. A runtime built without the
kernel and given no key (`AgentRuntime("<data dir>/agents")`) refuses encrypted
state with `StateKeyError`. `AgentRuntime()` with no directory uses
`$NGARI_DATA_DIR` itself, not `agents/` below it, so it
does not see the kernel's state at all and writes its own, in plaintext. A registry or task file whose key id matches but whose
token is damaged is set aside like any damaged file.

## What it does not cover

File names, sizes and times, and so how many agents, tasks and messages there
are, their topics, and when they changed.

Copies kept outside `agents/` are not encrypted: the digital twin
(`sync/digital_twin.json`) holds each agent's name, id and type, the sync
ledger (`sync/sync.log`) names the twin keys it updated, among them
`agent.<name>`, and the audit log (`sovereign/audit/`) records agent names and
types, task actions and message topics (docs/AUDIT_LOG.md, Kernel entries).
Descriptions, memory, environments, payloads, results and message bodies are
in none of them. Choose agent names, task actions and topics with that in
mind. A process running as the kernel's user can read the
master key, and with it everything here. `get_status()["agents"]["state_encryption"]`
reports whether encryption is on.
