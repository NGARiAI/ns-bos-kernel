# Message retention

Inter-agent messages are kept 21 years and then removed. That is the default
and the minimum: 7671 days, so leap years never make it shorter than 21
calendar years, as records are kept in regulated industries such as
biopharma. `NGARI_RETENTION_DAYS` can keep them longer, or `never` keeps
every message; no setting can shorten the retention.

| Variable | Default | Meaning |
|----------|---------|---------|
| `NGARI_RETENTION_DAYS` | 7671 (21 years) | A whole number of days, 7671 or more, or `never` to keep every message. A value below 7671, or anything else, keeps every message and logs an error naming the floor. |

## What expires

Only message files in `agents/comm/`, the one store that grows without bound
(one file per published message). A message's age is the UTC time `publish`
wrote into its file name, not the file's modification time, which a copy or a
restore from backup changes. Encrypted messages (`.enc.json`) and messages
written by v0.1.0 expire the same way.

Nothing else is ever removed: not the audit log, which is the compliance
record, not the keys or `sovereign/encrypted/`, not the agent registry, tasks,
digital twin or sync ledger, and not files set aside as damaged or rejected.

## When

At kernel start, then once a day while it runs, timed on the monotonic clock
so setting the wall clock does not start a sweep. `python -m core.kernel`
does this itself. An application that builds `NSBOSKernel` gets the start
sweep from `start()`; for the daily one it calls `kernel.tick()` from its own
loop, every minute or so, and `tick()` sweeps at most once a day.

Each sweep that removes anything syncs the directory, then writes one keyed
`retention_expired` entry to the audit log: how many message files (an
encrypted copy and a plaintext copy of one message count as two), the
retention in days, and the oldest and newest time removed. No message names,
topics or content are recorded. If the sync or the entry fails, what was
removed is kept in `.retention-clock.json` and recorded by the next sweep,
so no removal goes unrecorded. A sweep that fails is logged and the kernel
goes on.

## The clock

Retention depends on the system clock, and a board with no real-time clock
and no network time can have it wrong in either direction. The rules are built
so that a wrong clock can only make retention keep more:

- A message is removed a day and a second after it passes the retention, so
  stamps cut to the second and a restart cannot make it go early.
- No message can be older than the code that named it (2026-08-23 for v0.1.0
  names, 2026-10-27 for the current ones). A message dated earlier was written
  while the clock was wrong, at 1970 or an old image date, and is never
  removed by its date. Remove it by hand after checking it.
- The latest time seen is kept in `agents/comm/.retention-clock.json`. While
  the clock is behind it, nothing expires and a warning is logged; publish
  notices too. Once the clock is right again, every message dated before that
  time is aged from the moment it was right, because it may have been written
  while the clock was wrong.
- After the first sweep, the cutoff moves only as fast as time measured on the
  monotonic clock, and by at most a day across a restart, so a clock that
  jumps ahead cannot remove years of messages at once. Time the machine is off
  does not count: a box that is off for a month keeps its messages a month
  longer. The first sweep measures back from the newest message, so an idle
  bus keeps its old messages longer too.

Set the clock before the first start: a clock that is wrong but later than
2026-10-27 at the very first sweep, with no record yet, is the one case these
rules cannot see. `get_status()["kernel"]["retention_days"]` reports the
setting.

## Upgrading

Earlier versions kept every message. From this version the retention is 21
years, so the first start after the upgrade removes any message older than
that, and records it; no message can be that old yet. To keep everything as before, set
`NGARI_RETENTION_DAYS=never` before the upgrade.
