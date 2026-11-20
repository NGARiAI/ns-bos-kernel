# PIV/CAC operator authentication

Status: built as designed below (`core/kernel/data_plane/operator_auth.py`),
tested against SoftHSM. Not yet tried with a physical card and reader;
`keys card-check` (below) is the hand test for one.

The kernel can already hold its master key in a TPM (see `KEY_PROVIDERS.md`).
The TPM proves which machine is running. It says nothing about which person
ran `keys restore` or `keys export-recovery`, and those two commands can
hand the master key to whoever runs them. A PIV or CAC card adds that: a
key that never leaves the card, unlocked by a PIN, tied to a certificate the
operator was issued.

## Decision

1. **Build an operator authentication gate first.** Before a gated command
   runs, the operator's card signs a fresh challenge. The kernel checks the
   signature against a certificate pinned on the machine and records the
   result in the audit chain. A failure stops the command.
2. **Do not wrap the master key with the card yet.** A card-wrapped key (ECDH
   with the card's key management key, slot 9D) would make the card a second
   point of permanent loss next to the TPM, and lost or reissued cards are
   routine. Revisit once the gate has run in the field.
3. **No new Python dependency.** The card is driven through `pkcs11-tool`
   from OpenSC, the same way the TPM provider drives tpm2-tools. Signatures
   are verified with `cryptography`, which the kernel already pins.

## What was verified on this machine

OpenSC 0.26.1 and SoftHSM 2.6.1 (Debian 13). Ubuntu 24.04 ships OpenSC
0.25.0 and SoftHSM 2.6.1 as `opensc`, `opensc-pkcs11` and `softhsm2`.

| Check | Result |
|-------|--------|
| PIN through `--pin env:NAME` | Works for login, write and sign. The PIN stays out of argv, where any local user could read it. |
| `env:NAME` with the variable unset and no terminal | Exits after 9 ms with "util_getpass error". No hang. |
| Wrong PIN | `CKR_PIN_INCORRECT (0xa0)`, non-zero exit. |
| Mechanism `ECDSA-SHA256` on SoftHSM | `CKR_MECHANISM_INVALID`. Only raw `ECDSA` is offered, which is also what PIV cards expose. |
| SHA-256 in the kernel, raw `ECDSA` on the token, `--signature-format openssl` | DER signature that `cryptography` verifies over the original challenge. |
| Reading the certificate | `--read-object --type cert` needs no login. |

## The gate

Opt-in with `NGARI_OPERATOR_AUTH=card`. Default `off`, so nothing changes
for existing installs.

Gated commands: `keys migrate`, `keys export-recovery`, `keys restore`,
`state decrypt`, and `keys pin-operator` once one operator is pinned. The card signs for the command by name (`state decrypt`), and
that name is the `resource` of its `operator_auth` entry.
Gating kernel start is possible later but would make an unattended reboot
need a person at the machine, so it is not part of the first version.

Steps for one gated command:

1. Read the certificate from the card (no PIN needed). Its SHA-256
   fingerprint must match a certificate in a file (PEM, which may hold
   several, or DER) in `$NGARI_DATA_DIR/sovereign/operators/`. The pinned file is what gets
   trusted, not the copy on the card. Its validity dates must cover now;
   a refusal gives the dates and this machine's clock. Its key must be EC
   on P-256, P-384 or P-521, or RSA of at least 2048 bits with an exponent
   from 65537 up to below 2^256 (FIPS 186-5; PIV cards use P-256, P-384 and
   RSA-2048; a huge exponent can make any padded message a signature);
   any other is refused with reason `weak key`, before the card signs, and
   `pin-operator` and `card-check` refuse it too. A board without a
   real-time clock or network time needs its clock set before a card can
   pass.
2. Build the challenge: a fixed label (`ngari-operator-auth-v1`), the
   command name, the data directory, the pinned fingerprint and 32 random
   bytes. A signature for one command cannot be replayed for another, or on
   another store.
3. Hash it with SHA-256 and have the card sign the digest with raw ECDSA.
   The PIN reaches `pkcs11-tool` only through `NGARI_CARD_PIN` in the
   child's environment. A value in the kernel's own environment is dropped,
   so it is not a setting.
4. Verify the signature with the pinned certificate's public key.
5. With a roles file, check that the operator is named and holds the role
   the command needs (see Roles).
6. Append an `operator_auth` entry to the audit chain: actor is the named
   operator's user id (see Named operators), or the certificate fingerprint
   for a certificate pinned without a name; resource is the command; details
   are `subject` (the certificate's) and `ok`, plus `name` (the printed name)
   and `fingerprint` for a named operator, and `role` when roles are set.
   What the command then records has the same actor. Failures are recorded
   too, by fingerprint, with `ok` false and a `reason` (Refusal reasons). No
   PIN, no challenge bytes, no signature.

Any failure stops the command before it reads a key. An operator file that
cannot be read or is not valid stops it before the card is asked anything,
so it costs no PIN try. A wrong PIN is never
retried automatically: PIV cards block after a few wrong tries (usually 3),
and unblocking needs the PUK or a reissue.

### Refusal reasons

A refusal recorded as `operator_auth` (by the gate) or `esignature_refused`
(by `records sign`) carries one of these in `reason`. The message printed
with it says more; the entry holds only the code.

| Reason | Refused because |
|--------|-----------------|
| `no pin` | No PIN could be read: no `--pin-file` and no terminal, a file that cannot be read, or a PIN that is not UTF-8 text or holds a NUL byte |
| `pin` | The card says the PIN is wrong, or that it is locked |
| `card` | The card could not be used: `pkcs11-tool` missing, failing or timing out, or no certificate it can read under the key ID |
| `no pinned certificates` | `operators/` holds no certificate |
| `bad pinned certificate` | A certificate file in `operators/` does not parse |
| `bad operator file` | An operator `.json` cannot be read or is not valid (Named operators) |
| `bad roles file` | `roles.json` cannot be read or is not valid (Roles) |
| `not pinned` | The card's certificate is not in `operators/`; a retired one is not |
| `not named` | `records sign`: the card's certificate is pinned without an operator file |
| `not yet valid`, `expired` | The certificate's dates do not cover this machine's clock |
| `weak key` | The key is below the limits in step 1 |
| `unsupported key` | The key is neither EC nor RSA |
| `signature` | The card's signature does not verify against the pinned certificate |
| `role` | Roles are set, and the operator does not hold the role the command or meaning needs, or is not named, or the command has none (Roles) |
| `error` | Anything else; the message gives the exception's type only, never its text |

## Checking a card and pinning it

    python -m core.kernel keys card-check [--pin-file FILE] [--out FILE]

reads the card's certificate, has the card sign a fresh challenge with the
PIN, and verifies the signature against that certificate, which proves the
card holds the private key. It prints the certificate's name, key type,
fingerprint and validity dates, and whether it is pinned on this store. The
challenge names `keys card-check`, so the signature cannot open a gated
command. It needs no pinned certificate and writes no audit entry.

To pin an operator, run it with `--out operator.pem` (mode 0600, never
overwritten), then

    python -m core.kernel keys pin-operator --cert operator.pem --user ID [--name NAME] [--pin-file FILE]

which pins the certificate under a user id and printed name (next section).
Copying the file into `$NGARI_DATA_DIR/sovereign/operators/` still works too;
that operator is recorded by fingerprint, with no name.

## Named operators

21 CFR 11.10(e) asks the audit trail to say which person did what. A named
operator is a pinned certificate plus `<user>.json` beside it:

    {"fingerprint": "<SHA-256 of the certificate, hex>", "name": "Jane Q. Doe", "user": "jdoe", "version": 1}

`keys pin-operator` writes `<user>.pem` and `<user>.json`, both new files,
mode 0600, never overwritten. For a certificate already pinned by copying it
writes only the `.json`. A certificate that already has a name, or a user id
in use, is refused and nothing changes.

| Field | Rule |
|-------|------|
| `user` | 1 to 64 letters, digits, `.`, `_` or `-`, starting with a letter or digit; also the file name |
| `name` | `--name`, else the certificate's common name; 1 to 128 printable characters, no spaces at either end |
| `person` | Only with `--replaces OLD`: the user id this person first had (OLD's `person`, else OLD); the same rule as `user` |

Each must reach the audit log unchanged, and the log masks emails and
anything shaped like a phone, SSN or card number (`PII_REDACTION.md`). A
CAC common name such as `DOE.JANE.Q.1234567890` passes; `jane.doe@example.com`
is refused with a hint to give `--name`.

On a store that has never had an operator (nothing in `operators/`,
`retired/` included, and no `roles.json`), the first operator is pinned
with no card, since nobody can sign for it yet. After that, pinning goes
through the gate like a key command, and the challenge names `keys
pin-operator`. If the last pinned certificate has been retired, nobody can
pin through the gate until an administrator copies a certificate into
`operators/` by hand. A user id that still has roles in `roles.json` is
refused until they are cleared with `keys set-roles --roles none`, so a
new person never inherits an earlier operator's roles. Each pin
writes an `operator_pinned` entry: actor `local` or the operator who signed,
resource the user id, details `name` (the printed name) and `fingerprint`,
and with `--replaces` the earlier user id (`replaces`) and the `person`. It never
reads the key, so it carries no MAC.

The gate reads every `.json` in `operators/` (names starting with a dot are
skipped) and fails closed if one is unreadable, does not hold exactly
`version`, `user`, `name` and `fingerprint` (and `person` or not) with valid
values, is not named after its user, or names a
certificate another file already names. A file whose certificate is not
pinned names nobody who can pass. A reissued card is pinned under a new
user id, since the old one stays taken, with `--replaces OLD`: the new file
then carries `"person"`, the user id this person first had, so an
application can tell one individual from two (`checked_signatures` and
`presented()` report it; it is the user id when there is none). To remove
an operator, move their `.pem`
into `operators/retired/` and keep their `.json`: the certificate can no
longer pass the gate or sign, their signatures still check
(`ESIGNATURES.md`), and the user id stays taken. Past entries keep the user
id and, in `operator_auth`, the printed name.

## Roles

21 CFR 11.10(d) and (g) ask that only authorized people use the system,
and that each action be checked against what that person may do.
`$NGARI_DATA_DIR/sovereign/roles.json` gives named operators roles from a
fixed set:

    {"roles": {"jdoe": ["admin", "reviewer"]}, "version": 1}

| Role | Needed for |
|------|------------|
| `admin` | `keys migrate`, `keys export-recovery`, `keys restore`, `keys pin-operator`, `keys set-roles`, `state decrypt` |
| `author`, `reviewer`, `approver` | Electronic signatures with the meaning authorship, review, approval or responsibility (`ESIGNATURES.md`) |
| `sponsor` | Sponsoring an AI agent: signing its manifest (`AGENT_IDENTITY.md`) |

With no roles file, any pinned operator passes the gate, as before. Once
the file exists, a gated command with `NGARI_OPERATOR_AUTH` off is refused,
since roles nothing checks would read as a control that is not there.
After the card signs, the operator must be named and hold the command's
role. A refusal is recorded as `operator_auth` with reason `role` and the
operator as actor; a pass records the role. A roles file that cannot be
read or is not valid stops the gate before the PIN is read (reason
`bad roles file`).

    python -m core.kernel keys roles
    python -m core.kernel keys set-roles --user ID --roles admin,reviewer [--pin-file FILE]

`keys roles` lists named operators and their roles; it only reads and needs
no card. `keys set-roles` replaces one operator's roles, comma-separated or
`none`, and is gated: while there is no roles file any pinned operator may
set the first roles, and after that it needs `admin`. Roles go only to
named operators, though roles left for a user id whose operator file was
deleted can be cleared with `none`. A change that would leave no `admin`
who can pass the gate (a named operator whose certificate is pinned, not
retired, in date and with a key the gate accepts) is refused, since nobody
could change roles again. The roles in force
are read again once the roles lock is held: if roles were set after this
command's card check, as by another operator setting the first roles at
the same moment, the operator must hold `admin` in them, and with the gate
off the change is refused. Changes are made
under a lock and recorded as `roles_changed` (resource the user id, details
`from` and `to`), with no MAC.

Deleting `roles.json` returns the store to any pinned operator. That takes
write access to the data directory, the same access that pins operators,
and no entry records it; later `operator_auth` entries simply carry no
`role`.

## Reader setup

OpenSC reaches readers through PC/SC: the `pcscd` daemon and its library,
`libpcsclite1` (Debian and Ubuntu: `apt install pcscd`, then `pcsc_scan`
from `pcsc-tools` should list the reader). In a container the reader's USB
device has to be passed through and `pcscd` run inside it. Without these,
OpenSC fails with only `CKR_GENERAL_ERROR`; `card-check` and the gate say
which part is missing: the library, `pcscd`, its socket
(`/run/pcscd/pcscd.comm`, or `PCSCLITE_CSOCK_NAME`), the module, or a card
in the reader.

## Settings

| Variable | Default | Meaning |
|----------|---------|---------|
| `NGARI_OPERATOR_AUTH` | `off` | `card` turns the gate on. |
| `NGARI_PKCS11_MODULE` | OpenSC's `opensc-pkcs11.so` for the running architecture | PKCS#11 module path. |
| `NGARI_PKCS11_TOKEN` | unset (only card present) | Token label, when more than one card is inserted. |
| `NGARI_PKCS11_KEY_ID` | `01` | Object ID. OpenSC maps PIV slot 9A (PIV Authentication) to `01`, 9C to `02`, 9D to `03`, 9E to `04`. |

The PIN comes from the terminal or `--pin-file`, never argv or the
environment of the kernel itself.

## Slot choice

Slot 9A (PIV Authentication) is the right one: it exists for logging a
person in, and it asks for the PIN once per session. Slot 9C (Digital
Signature) asks for the PIN on every signature and implies a signature the
person meant to make on a document. Slot 9E (Card Authentication) needs no
PIN, so it proves the card is present, not that its holder is.

## Not covered

- Certificate chains and revocation. The machines run air-gapped with no CRL
  or OCSP reachable, so trust is the pinned certificate. Removing a person
  means moving their certificate into `operators/retired/`.
- Smart card readers on this development machine. Tests run against SoftHSM
  with a key and certificate imported into a token in the test's tmp
  directory. A real card needs `pcscd` and a reader, and is a hand test.
- Several operators approving one command (two-person rule). The audit entry
  carries enough to add it later.

## Tests

These all pass (`tests/test_operator_auth.py`). Signature from the pinned card's key accepted, for EC and RSA keys. A certificate that is not
pinned, an expired one, a signature over another command or another data
directory, and a wrong PIN all fail closed. The PIN never appears in argv
(checked from inside a fake `pkcs11-tool`), a log line, an exception or the
audit entry. A failed and a successful attempt both appear in the audit
chain. `NGARI_REQUIRE_PKCS11_SIM=1` turns a missing SoftHSM into a failure,
and CI installs `softhsm2` and `opensc`.
