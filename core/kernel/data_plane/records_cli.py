"""ns-bos records: sign records with an operator's card and check signatures.

Electronic signatures (docs/ESIGNATURES.md; 21 CFR 11.50, 11.70, 11.200(a)).
`records sign FILE --meaning M` has the operator's PIV/CAC card sign the
file's SHA-256 with the meaning, the signer's user id and printed name and
the time, PIN every time. The signature goes into the audit chain as an
`esignature` entry. `records signatures FILE` lists every signature on the
file as it is now and checks each against the signer's certificate.
"""

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import append_audit
from .keys import KeyProviderError
from .keys_cli import MigrationError, describe_os_error, read_passphrase, sovereign_dir
from .operator_auth import (
    CardAuthenticator,
    OperatorAuthError,
    esign_message,
    key_problem,
    load_identities,
    load_pinned,
)
from .roles import load_roles

MEANINGS = ("authorship", "review", "approval", "responsibility")
# The role each meaning needs once roles are set.
MEANING_ROLES = {
    "authorship": "author",
    "review": "reviewer",
    "approval": "approver",
    "responsibility": "approver",
}
RETIRED = "retired"  # operators/retired/: certificates that only verify
_SIGNED = ("meaning", "name", "fingerprint", "signed_at", "nonce", "signature")


def record_digest(path: Path) -> str:
    """SHA-256 of the file's bytes, hex, read in 1 MiB pieces."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                digest.update(chunk)
    except OSError as exc:
        raise MigrationError(f"cannot read {path}: {describe_os_error(exc)}") from None
    return digest.hexdigest()


def sign(
    store: Path,
    environ: Mapping[str, str],
    path: Path,
    meaning: str,
    pin_file: str | None,
) -> list[str]:
    """Sign path with meaning on the operator's card and record it. Refusals
    are recorded as esignature_refused."""
    digest = record_digest(path)
    audit_log = store / "audit" / "sovereign_audit.log"
    role = None
    try:
        load_roles(store)  # checked before the PIN, so a broken file costs no try
        try:
            pin = read_passphrase(
                pin_file, confirm=False, prompt="Card PIN: ", option="--pin-file"
            )
        except MigrationError as exc:
            raise OperatorAuthError(str(exc), "no pin") from None
        # Read again: a role taken away while the PIN was typed must count.
        roles = load_roles(store)
        if roles is not None:
            role = MEANING_ROLES[meaning]
        facts = CardAuthenticator.from_env(store / "operators", environ).esign(
            digest, meaning, pin, roles, role
        )
    except OperatorAuthError as exc:
        append_audit(
            audit_log, "esignature_refused", exc.fingerprint, digest,
            {"meaning": meaning, "reason": exc.reason},
        )  # fmt: skip
        raise
    except Exception as exc:  # noqa: BLE001 - refuse and record whatever failed
        append_audit(
            audit_log, "esignature_refused", "unknown", digest,
            {"meaning": meaning, "reason": "error"},
        )  # fmt: skip
        raise OperatorAuthError(
            f"the signature failed with {type(exc).__name__}", "error"
        ) from None
    details = {
        "meaning": meaning,
        "name": facts["name"],
        "fingerprint": facts["fingerprint"],
        "signed_at": facts["signed_at"],
        "nonce": facts["nonce"],
        "signature": facts["signature"],
        "file": path.name,
    }
    if role:
        details["role"] = role
    try:
        append_audit(audit_log, "esignature", facts["user"], digest, details)
    except OSError as exc:
        raise MigrationError(
            f"the card signed, but the signature could not be recorded "
            f"({describe_os_error(exc)}), so it does not exist. Fix the audit log "
            "and sign again."
        ) from None
    by = f"{facts['name']} ({facts['user']}) at {facts['signed_at']}"
    return [f"signed {path}: {meaning} by {by}", f"sha256 {digest}"]


def _entries_in(lines, digest: str):
    """The esignature entries for digest among lines, oldest first. Lines
    that are not entries are skipped: `audit verify` is what checks the
    chain."""
    for line in lines:
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if (
            isinstance(entry, dict)
            and entry.get("action") == "esignature"
            and entry.get("resource") == digest
        ):
            yield entry


def _entries(audit_log: Path, digest: str):
    if not audit_log.exists():
        return
    with open(audit_log, "rb") as f:
        yield from _entries_in(f, digest)


def _status(
    entry: dict, digest: str, pinned: dict, retired: dict, identities: dict
) -> tuple[str, bool]:
    details = entry.get("details")
    try:
        fields = [details[k] for k in _SIGNED]
        if not all(isinstance(v, str) for v in [*fields, entry["actor"]]):
            raise TypeError
        meaning, name, fp, signed_at, nonce, signature = fields
        message = esign_message(
            digest, meaning, entry["actor"], name, fp, signed_at, nonce
        )
        signature = bytes.fromhex(signature)
    except (KeyError, TypeError, ValueError):
        return "INVALID: the entry is malformed", False
    cert = pinned.get(fp) or retired.get(fp)
    if cert is None:
        where = f"neither pinned nor in operators/{RETIRED}/"
        return f"not checked: certificate {fp[:16]} is {where}", False
    problem = key_problem(cert)
    if problem:
        return f"INVALID: certificate {fp[:16]} has {problem}", False
    try:
        CardAuthenticator._verify(cert, signature, message, fp)
    except OperatorAuthError:
        return "INVALID: the signature does not verify", False
    # A card signs whatever its holder asks, so the entry's own claim of who
    # signed counts only if the operator files give that card to that person.
    ident = identities.get(fp) or {}
    if (ident.get("user"), ident.get("name")) != (entry["actor"], name):
        owner = f"{entry['actor']}'s ({name})"
        return f"INVALID: certificate {fp[:16]} is not {owner}", False
    return ("valid" if fp in pinned else "valid (certificate retired)"), True


def checked_signatures(store: Path, path: Path, lines=None) -> tuple[str, list[dict]]:
    """The record's SHA-256 and every signature on it as it is now, oldest
    first, each checked: meaning, user, name and signed_at as the entry gives
    them (None where it gives none), person (who the operator files say the
    signer is across reissued cards; the user id otherwise), valid, and
    status, the words `records signatures` prints after the colon. For
    applications that act on who has signed what. lines, when given, are the
    audit log's lines to read, such as a copy whose chain was just verified
    (data_plane.checked_copy), so the answer covers exactly the entries that
    were checked; by default the log is read as it is."""
    digest = record_digest(path)
    operators = store / "operators"
    pinned = load_pinned(operators)
    retired = load_pinned(operators / RETIRED)
    identities = load_identities(operators)
    found = []
    entries = (
        _entries_in(lines, digest)
        if lines is not None
        else _entries(store / "audit" / "sovereign_audit.log", digest)
    )
    for entry in entries:
        status, good = _status(entry, digest, pinned, retired, identities)
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        found.append(
            {
                "meaning": details.get("meaning"),
                "user": entry.get("actor"),
                "person": (identities.get(details.get("fingerprint")) or {}).get(
                    "person", entry.get("actor")
                )
                if good
                else entry.get("actor"),
                "name": details.get("name"),
                "signed_at": details.get("signed_at"),
                "valid": good,
                "status": status,
            }
        )
    return digest, found


def _shown(value) -> str:
    return "?" if value is None else str(value)


def signatures(store: Path, path: Path) -> tuple[list[str], bool]:
    """A line per signature on path as it is now, and whether there is at
    least one and every one checks."""
    digest, found = checked_signatures(store, path)
    if not found:
        return [f"no signatures on {path} as it is now (sha256 {digest})"], False
    lines = [
        f"{_shown(s['meaning'])} by {_shown(s['name'])} ({_shown(s['user'])}) at "
        f"{_shown(s['signed_at'])}: {s['status']}"
        for s in found
    ]
    return [f"sha256 {digest}", *lines], all(s["valid"] for s in found)


def cli(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(
        prog="ns-bos records", description=__doc__.split("\n")[0]
    )
    parser.add_argument(
        "--data-dir", help="kernel data directory (default $NGARI_DATA_DIR)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    signing = sub.add_parser("sign", help="sign a file with the operator's card")
    signing.add_argument("file", help="the record to sign")
    signing.add_argument("--meaning", required=True, choices=MEANINGS)
    signing.add_argument(
        "--pin-file", help="file holding the card PIN (else the terminal)"
    )
    listing = sub.add_parser(
        "signatures", help="list and check the signatures on a file as it is now"
    )
    listing.add_argument("file", help="the record")
    args = parser.parse_args(argv)
    store = sovereign_dir(env, args.data_dir)
    try:
        if args.command == "sign":
            lines = sign(store, env, Path(args.file), args.meaning, args.pin_file)
            ok = True
        else:
            lines, ok = signatures(store, Path(args.file))
    except (MigrationError, KeyProviderError) as exc:
        print(f"{args.command}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{args.command}: {describe_os_error(exc)}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    return 0 if ok else 1
