# Agent identity

An AI agent's identity is a manifest: a small file naming the agent and
what it may do, signed with the PIV/CAC card of the named operator who
sponsors it. A person answers for every agent, and the agent itself never
holds a key. This page covers sponsoring and checking manifests; the kernel
does not yet refuse an agent without one or enforce its permissions (What
comes next).

## The manifest

`$NGARI_DATA_DIR/sovereign/agents/<agent>.json`, mode 0600, in a directory
of mode 0700. One JSON object:

| Field | Meaning |
|-------|---------|
| `version` | 1 |
| `agent` | The agent's name: 1 to 64 letters, digits or `.` `_` `-`, starting with a letter or digit; also the file's name |
| `agent_type` | The agent's type, as it registers |
| `permissions` | `tools`, `data`, `publish`, `subscribe` and `tasks_for`, each a list of names: the tools it may call, the data key prefixes it may read and write, the topics it may publish on and subscribe to, the agents it may create tasks for. An empty list allows nothing, and `*` is not taken |
| `not_before`, `not_after` | When the sponsorship holds, UTC; at most 366 days apart, so every agent is reviewed at least once a year |
| `sponsor` | `user`, `name` and `fingerprint`: the named operator and their card's certificate |
| `signed_at`, `nonce` | The card's signing time and 16 random bytes |
| `signature` | The card's signature, hex |

The card signs `ngari-agent-manifest-v1`, a NUL byte, and the manifest's
canonical JSON without `signature` (keys sorted, no spaces, ASCII). Every
field is under the signature, permissions and dates included. The label is
the manifest's own, so a gate signature or an electronic signature from the
same card can never stand in for one.

## Who can sponsor

A pinned operator with a name (`keys pin-operator`). With a roles file, the
operator must also hold the `sponsor` role (`PIV_CAC.md`); `admin` alone is
not enough, so the people who manage operators and the people who vouch for
agents can be different. The card and PIN are needed for every
sponsorship, whatever `NGARI_OPERATOR_AUTH` says.

## Commands

All run as `python -m core.kernel agents <command>` (or `ns-bos agents ...`)
and take `--data-dir`.

| Command | Does |
|---------|------|
| `agents sponsor AGENT --type TYPE` | Signs a manifest for AGENT with the operator's card and files it. `--tool`, `--data`, `--publish`, `--subscribe` and `--task-for` each add one permission and repeat; `--days` sets how long it holds (default 90, at most 366). An existing manifest is renewed only with `--replace`, and the one it replaces is kept under `agents/superseded/`. The request is checked before the PIN is asked for; the new manifest is checked as the kernel will check it before it is filed. |
| `agents list` | Each filed manifest and whether it checks now; exits 1 if any does not. |
| `agents check AGENT` | Checks AGENT's manifest now and prints its sponsor, expiry and permissions; exits 1 if it does not check. |

## When a manifest stops checking

A manifest checks only while its sponsorship holds, so taking any part away
takes the agent's sponsorship away with it. `agents list` and `agents check`
give the reason:

| Reason | Cause |
|--------|-------|
| `missing`, `unreadable`, `malformed` | No manifest, one that cannot be read, or one without the shape above |
| `wrong agent` | A manifest filed under another agent's name |
| `not pinned` | The sponsor's certificate is no longer pinned, for example moved to `operators/retired/` |
| `not the sponsor` | The operator files no longer give that certificate to that user and name |
| `weak key` | The certificate's key is one the kernel no longer accepts |
| `expired`, `not yet valid` | The manifest, or the sponsor's certificate, is outside its dates |
| `signature` | Any field changed after signing |
| `no sponsor role` | The sponsor no longer holds the `sponsor` role |

## Audit entries

`agents sponsor` records `agent_sponsored`, with the sponsor as the actor,
the agent's name as the resource, and the manifest's SHA-256, type, expiry
and certificate fingerprint; a refusal by the card or the role check
records `agent_sponsor_refused` with its reason (`AUDIT_LOG.md`). Both carry
no MAC, as the command never reads the master key; the manifest carries
the card's own signature.

## What comes next

- The kernel refuses to register or run an agent whose manifest does not
  check. A setting lets existing applications keep working while they move
  to manifests, and every start with it on is recorded and warned about.
- Every action an agent takes is recorded under the agent and its sponsor,
  not under `kernel`.
- The kernel enforces the permissions, denying anything not listed.
- Actions outside them go to a queue a person approves with their card.
- A person can suspend an agent with their card at any time.
