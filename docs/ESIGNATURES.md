# Electronic signatures

    python -m core.kernel records sign FILE --meaning approval [--pin-file FILE]
    python -m core.kernel records signatures FILE

`records sign` has the operator's PIV/CAC card sign one file, PIN every
time, and records the signature in the audit chain. `records signatures`
lists every signature on the file as it is now and checks each one. Both
take `--data-dir` (default `$NGARI_DATA_DIR`). The signer must be a named
operator (`PIV_CAC.md`, Named operators); the card settings are the gate's
(`NGARI_PKCS11_MODULE`, `NGARI_PKCS11_TOKEN`, `NGARI_PKCS11_KEY_ID`).
Signing does not depend on `NGARI_OPERATOR_AUTH`: the card is the signature.

## What the card signs

The fields below, joined with NUL bytes, under the label
`ngari-esignature-v1`. The gate signs under `ngari-operator-auth-v1`, so a
signature made to pass the gate can never stand in for one on a record.

| Field | Value |
|-------|-------|
| record | SHA-256 of the file's bytes, hex |
| meaning | `authorship`, `review`, `approval` or `responsibility` |
| user | the signer's user id |
| name | the signer's printed name, from `<user>.json` |
| fingerprint | SHA-256 of the signer's pinned certificate |
| signed_at | UTC, to the second (`2026-10-31T14:05:09Z`) |
| nonce | 16 random bytes, hex |

The card's certificate must be pinned, valid now, named and hold a key the
gate accepts (`PIV_CAC.md`); with a roles file the signer must also hold
the meaning's role. Both are checked before
the card is asked to sign. The signature is then checked against the
pinned certificate before anything is written.

## The entry

`esignature`: actor the user id, resource the record's SHA-256, details
`meaning`, `name`, `fingerprint`, `signed_at`, `nonce`, `signature` (hex),
`file` (the file name, for people; not signed) and, with roles set, `role`.
A refusal is `esignature_refused`: actor the card's fingerprint (or
`unknown`), resource the record's SHA-256, details `meaning` and `reason`
(one of the codes in `PIV_CAC.md`, Refusal reasons). Neither carries a MAC, since signing never
reads the master key; both are hash-chained like every entry, and the
kernel itself cannot write them. No PIN is recorded. Until the next keyed
entry, entries like these can be rewritten without the key
(`AUDIT_LOG.md`, What it cannot see), so keep an `audit anchor` after
signing.

If the card signs and the entry cannot be written, the command says the
signature does not exist and should be made again.

## Checking

`records signatures FILE` hashes the file, finds every `esignature` entry
for that hash, rebuilds what the card signed from the entry and verifies
it with the certificate whose fingerprint the entry names. It prints one
line per signature:

    approval by Jane Doe (jdoe) at 2026-10-31T14:05:09Z: valid

`valid (certificate retired)` when the certificate is in
`operators/retired/`; `INVALID: the signature does not verify` when any
signed field, the signer or the record was changed; `INVALID: certificate
... is not jdoe's (Jane Doe)` when the signature is good but the operator
files do not give that certificate to that user id and printed name, as
when one card signs in another person's name; `INVALID: certificate ...
has ...` when its key is one the gate refuses (a weak RSA key, another
curve, another key type); `INVALID: the entry is malformed`; `not checked: ...` when the certificate is neither pinned nor
retired. A broken operator file stops the check. A changed file has a new hash and so no signatures. Exit status
is 0 only when there is at least one signature and every one is valid.
Lines in the log that are not entries are skipped; `audit verify` is what
checks the chain itself.

## What a check proves

A `valid` line proves that the card holding a certificate pinned or
retired here, which the operator files give to that user id and printed
name, signed exactly those fields over the file's bytes as it is now.

It does not prove when, or under which rules. `signed_at` is the clock of
the machine that signed. The role, and that the certificate was not yet
retired, are checked by `records sign` when it signs and cannot be seen
afterwards. A card signs whatever its holder asks, so a holder who can
write the audit log can sign with `pkcs11-tool` outside the kernel and
append an entry, and it checks as their own signature with any meaning.
Keep write access to the data directory to the people who administer the
machine; an application that signs for operators should run as a system
user they cannot log in as.

## When an operator leaves

Move their `.pem` into `$NGARI_DATA_DIR/sovereign/operators/retired/` and
keep their `.json`. The gate and `records sign` refuse a retired
certificate, and signatures already made with it still check. Their card
still signs, so take away their access to this machine as well (What a
check proves). Keeping the `.json` keeps the user id taken, so it can
never be given to someone else. When the same person gets a new card, pin
it under a new user id with `keys pin-operator --replaces OLD`, so their
signatures from both cards are one person's (`PIV_CAC.md`).

## Part 11 clauses

The tests that show each clause are listed in `docs/validation/TRACE.md`,
generated from markers on the tests.

| Clause | How |
|--------|-----|
| 11.50(a)(1) printed name | `name`, signed |
| 11.50(a)(2) date and time | `signed_at`, UTC, signed |
| 11.50(a)(3) meaning | `meaning`, one of four, signed |
| 11.50(b) same controls, readable form | entry in the hash-chained audit log; `records signatures` prints name, meaning and time |
| 11.70 signature linked to its record | signs the record's SHA-256 |
| 11.100(a) unique to one person, never reassigned | one operator file per user id, one name per certificate; retired ids stay taken; a signature counts only from its signer's own certificate |
| 11.200(a)(1) two components | the card (its private key) and the PIN |
| 11.200(a)(1)(i) and (ii) a series of signings | both components at every signing, stricter than the rule |
| 11.200(a)(3) use by anyone else | a signature counts only from the signer's own card, which needs that card and its PIN |
| 11.300(d) unauthorized use | the card limits PIN tries; a wrong PIN is never retried or recorded; refusals are recorded |
| 11.10(g) authority checks | with roles, `records sign` needs the meaning's role; a later check cannot show it (What a check proves) |

| Meaning | Role needed with a roles file |
|---------|-------------------------------|
| `authorship` | `author` |
| `review` | `reviewer` |
| `approval` | `approver` |
| `responsibility` | `approver` |

## Not covered here

These are the organization's procedures, not the kernel's: checking a
person's identity before their card is issued (11.100(b)), the
certification letter to FDA (11.100(c)), training and written policies
(11.10(i), (j)), and periodic checks of cards and PINs (11.300(b), (e)).
The kernel does not keep the signed files; it checks the file it is given.
