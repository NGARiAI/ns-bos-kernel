# PII redaction

The kernel replaces personal data it can recognise by pattern with the kind of
data it was: email addresses become `[email]`, phone numbers `[phone]`, US
social security numbers `[ssn]`, payment card numbers `[card]` and street
addresses `[address]`. It is best effort: a pattern finds the usual forms and
misses others, such as a phone number written in words, an address with no
street word, or a name. Phone numbers are found in North American form, with
or without `+1` or `1-` (`1-800-555-0199`, `(415) 555-0132`), and in
international form as usually grouped, 8 to 15 digits (`+44 20 7946 0958`,
`+33 1 23 45 67 89`). SSNs are found with dashes or with spaces
(`123-45-6789`, `123 45 6789`).

## Where

Every audit entry, always. The resource and every string in the details are
redacted before the entry is hashed and written, so the chain verifies as
before. The audit log is kept for decades and never deleted, so no setting
turns this off.

The kernel's log lines, the file under `logs/` and the console, messages and
tracebacks alike, unless `NGARI_REDACT_PII` is `0`, `false`, `no` or `off`,
for debugging. An application that builds `NSBOSKernel` itself sets up its own
logging; it can use the same formatter:

    from core.kernel.data_plane.redact import RedactingFormatter
    handler.setFormatter(RedactingFormatter("%(asctime)s %(message)s"))

| Variable | Default | Meaning |
|----------|---------|---------|
| `NGARI_REDACT_PII` | on | `0`, `false`, `no` or `off` keep PII in the kernel's log lines. The audit log is redacted whatever this says. |

## What is not changed

The data itself: stored records, agent state, task payloads and messages keep
what was put in them, and are read back by the names they were given. Only
what the audit log and the log lines say about them is redacted, so an entry
for `store_encrypted("patient 123-45-6789")` names `patient [ssn]` while the
record is still read with its own key. Encrypt agent state
(`docs/AGENT_STATE.md`) to protect what is stored.

Hashes, UUIDs, hex strings and time stamps, which the audit chain depends on,
are never matched: every pattern is bounded so that digits inside one are not
taken for a number of their own. The bounds are letters, digits and dashes;
an underscore is not one, so `patient_123-45-6789` and a message file name
`<topic>_<time>_<hex>.json` lose their PII like any other text. A card number is redacted only when it passes
the Luhn check, so most order numbers and counters stay; a long digit string
that does pass it cannot be told from a card number and is redacted. Every
card in a run of numbers is found, after a short number ("visit 3 4111 ...")
or another card too, and a run of digit groups joined by dashes that is too
long to be a card (a UUID in digits) is left whole.
