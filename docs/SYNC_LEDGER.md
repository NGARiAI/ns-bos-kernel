# Sync ledger

`sync/sync.log` records what the digital twin did: one JSON line per update,
chained like the audit log but with no key. This note says what is in it, how
an old log is carried over, what happens to a twin that fails its checksum, and
what the chain cannot see.

## Entries

Every line holds `timestamp`, `action`, `key`, the action's own fields,
`prev_hash` (the `hash` of the line before, 64 zeros for the first) and `hash`
(SHA-256 of the line without its `hash`, JSON with sorted keys, the rule the
audit log uses). Appends take an exclusive lock and are synced.

| Action | Key | Other fields |
|--------|-----|--------------|
| `update` | the twin key | `version`, `checksum` |
| `ledger_chained` | `sync.log` | `prefix_bytes`, `prefix_sha256` |
| `twin_rejected` | the kept file's name | `reason` (`checksum`), `kept_as`, `bytes`, `sha256` |
| `twin_set_aside` | the kept file's name | `reason` (the error's type), `kept_as` |

## A log from v0.1.0

Lines written before the chain have no hash. The file is not rewritten. The
first append after the upgrade adds a `ledger_chained` entry recording the
length and SHA-256 of everything that was there, and the chain starts after it.
A last old line cut short by a crash gets only a newline. `get_sync_history()`
returns old and new lines.

## A twin that fails its checksum

The twin file carries a checksum over its content. A twin that does not match
it was edited or damaged. It is renamed `digital_twin.json.rejected-<UTC time>`
(`-1`, `-2` and so on for another in the same second, so none is overwritten)
with its bytes untouched, a `twin_rejected` entry records its length and
SHA-256, and the kernel starts with an empty twin. Before this, such a twin was
loaded after a warning. A twin that cannot be read at all, or has the wrong
shape, is renamed `digital_twin.json.corrupt-<UTC time>` as before and recorded
as `twin_set_aside`. Nothing is deleted. Moving a rejected twin back does not
bring it back: its checksum still does not match, so it is rejected again,
and `import_twin` refuses it for the same reason. To keep values from it,
check them, then set each one again with `update_twin`, which records each
change in the ledger.

## Checking it

`NetworkSynchronization.verify_sync_ledger()` returns `None`, or the first
problem: `broken chain at entry N`, `entry N does not match its hash`,
`line N is not a ledger entry` (a torn line stays in the file and is reported),
or `the v0.1.0 part of sync.log has changed`.

## What it cannot see

There is no key. Someone who can write the file can rewrite the whole ledger
with valid hashes, and entries cut from the end leave a shorter log that
still verifies. The checksum on the twin has the same limit: it is a plain
SHA-256, so an edit that also recomputes it loads. Binding either to the
master key would go through the kernel's audit chain rather than a second
chain, and is for the maintainer to decide.
