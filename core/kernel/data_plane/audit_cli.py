"""ns-bos audit: verify the audit chain, print its anchor and show its entries.

`audit verify` checks the chain with its MACs; `audit anchor` prints the
anchor to keep off the machine; `audit show` prints the entries a check has
just verified, for inspection (21 CFR 11.10(b)). `audit adopt-legacy` vouches
for entries written before the log had a key, and is the only command that
appends to the log. Each derives the MAC key from the master key, read through
the configured provider, and none constructs a data plane.
"""

import argparse
import json
import os
import sys
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

from . import (
    _WS,
    LEGACY_HISTORY,
    append_audit,
    audit_anchor,
    audit_key,
    check_audit_chain,
    checked_copy,
    scan_audit_chain,
)
from .keys import KeyProviderError, provider_from_env, validate_key
from .keys_cli import describe_os_error, sovereign_dir


def _mac_key(store: Path, environ: Mapping[str, str]) -> bytes:
    provider = provider_from_env(store / "keys", environ)
    return audit_key(validate_key(provider.load_or_create(may_create=False)))


def load_anchor(path: str) -> dict:
    try:
        anchor = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read anchor {path}: {exc}") from None
    except RecursionError:
        raise ValueError(f"cannot read anchor {path}: nested too deep") from None
    if not (
        isinstance(anchor, dict)
        and type(anchor.get("entries")) is int
        and anchor["entries"] >= 0
        and isinstance(anchor.get("tail"), str)
        and len(anchor["tail"]) == 64
    ):
        raise ValueError(f"{path} is not an audit anchor")
    return anchor


def adopt_legacy(log: Path, mac_key: bytes) -> int:
    """Append a keyed entry naming the unkeyed history's count and tail hash,
    after checking every hash and link in the log. An operator's decision to
    trust what was there before the key; never done on its own."""
    reason, chain = scan_audit_chain(log, mac_key)
    if reason:
        print(f"audit adopt-legacy: FAILED: {reason}", file=sys.stderr)
        return 1
    if not chain.unkeyed:
        print("audit adopt-legacy: no entries from before the key; nothing to adopt")
        return 0
    if chain.attested:
        print("audit adopt-legacy: the history is already attested; nothing to do")
        return 0
    details = {"entries": chain.unkeyed, "tail": chain.unkeyed_tail}
    append_audit(log, LEGACY_HISTORY, "operator", "audit", details, mac_key)
    print(
        f"adopted {chain.unkeyed} entries written before the key "
        f"(tail {chain.unkeyed_tail[:16]}); the log now verifies"
    )
    return 0


def _iso(value: str) -> datetime:
    """datetime.fromisoformat, with a trailing Z for UTC, which Python takes
    only from 3.11 on; the kernel runs on 3.10."""
    if value[-1:] in ("Z", "z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _day(value: str, end: bool) -> datetime:
    """--since and --until: a UTC date (the whole day) or an ISO 8601 time."""
    try:
        if len(value) == 10:
            day = datetime.combine(datetime.fromisoformat(value), time(), timezone.utc)
            if not end:
                return day
            try:
                return day + timedelta(days=1)
            except OverflowError:  # 9999-12-31: the end of the calendar
                return datetime.max.replace(tzinfo=timezone.utc)
        moment = _iso(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a date (2026-10-31) or a time (2026-10-31T14:05:09Z)"
        ) from None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _value(value) -> str:
    """A string as it is when printable with no space, quote or =; anything
    else as JSON, which escapes control, format and non-ASCII characters.
    So no value an agent wrote can move the cursor, add a line or stop the
    output on a strict UTF-8 terminal."""
    if (
        isinstance(value, str)
        and value
        and value.isprintable()
        and not any(c in value for c in ' "=')
    ):
        return value
    return json.dumps(value, sort_keys=True)


def _readable(number: int, entry: dict) -> str:
    details = entry.get("details")
    if isinstance(details, dict):
        shown = " ".join(f"{_value(k)}={_value(v)}" for k, v in sorted(details.items()))
    else:
        shown = _value(details)
    head = [str(number), entry.get("timestamp"), entry.get("action"),
            entry.get("actor"), entry.get("resource")]  # fmt: skip
    return "  ".join(_value(x) for x in head) + (f"  {shown}" if shown else "")


def _when(entry: dict) -> datetime | None:
    try:
        moment = _iso(entry["timestamp"])
    except (KeyError, TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def show(lines: Iterable[bytes], args) -> tuple[list[str], int, int]:
    """The lines to print for the entries args selects, the number shown
    and the number of entries in the log."""
    out, shown, number = [], 0, 0
    for line in lines:
        if not line.strip(_WS):  # blank exactly as the check counts it
            continue
        number += 1
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise TypeError
        except (ValueError, TypeError, RecursionError):
            out.append(f"{number}  unreadable line")
            continue
        when = _when(entry)
        if (
            (args.action and entry.get("action") not in args.action)
            or (args.actor is not None and entry.get("actor") != args.actor)
            or (args.since and (when is None or when < args.since))
            or (args.until and (when is None or when >= args.until))
        ):
            continue
        shown += 1
        out.append(
            line.decode().rstrip("\n") if args.json else _readable(number, entry)
        )
    return out, shown, number


def cli(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(
        prog="ns-bos audit", description=__doc__.split("\n")[0]
    )
    parser.add_argument(
        "--data-dir", help="kernel data directory (default $NGARI_DATA_DIR)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("verify", help="verify hashes, chain and MACs")
    check.add_argument("--anchor", help="anchor file from an earlier `audit anchor`")
    sub.add_parser("anchor", help="verify, then print the anchor as JSON")
    sub.add_parser(
        "adopt-legacy",
        help="vouch for the entries written before the log had a key (an upgrade)",
    )
    listing = sub.add_parser(
        "show", help="verify, then print the entries for inspection"
    )
    listing.add_argument("--anchor", help="anchor file from an earlier `audit anchor`")
    listing.add_argument(
        "--action", action="append", help="only this action (repeatable)"
    )
    listing.add_argument("--actor", help="only entries by this actor")
    listing.add_argument(
        "--since", type=lambda v: _day(v, False), help="from this UTC date or time"
    )
    listing.add_argument(
        "--until",
        type=lambda v: _day(v, True),
        help="up to this UTC date (inclusive) or time",
    )
    listing.add_argument(
        "--json", action="store_true", help="the entries as stored, one JSON line each"
    )
    listing.add_argument(
        "--unverified",
        action="store_true",
        help="print a log that fails its check, under a NOT VERIFIED line (exit 1)",
    )
    args = parser.parse_args(argv)
    store = sovereign_dir(env, args.data_dir)
    log = store / "audit" / "sovereign_audit.log"

    try:
        mac_key = _mac_key(store, env)
        if args.command == "adopt-legacy":
            return adopt_legacy(log, mac_key)
        if args.command == "show":
            anchor = load_anchor(args.anchor) if args.anchor else None
            reason, copy = checked_copy(log, mac_key, anchor)
            if reason and not args.unverified:
                copy.close()
                print(f"audit show: FAILED: {reason}; nothing shown (--unverified "
                      "shows it anyway)", file=sys.stderr)  # fmt: skip
                return 1
            with copy:
                lines, shown, total = show(copy, args)
            if reason:
                print(f"NOT VERIFIED: {reason}")
            elif not args.json:
                against = " and matches the anchor" if anchor else ""
                print(f"audit log verified: {total} entries{against}; {shown} shown")
            for line in lines:
                print(line)
            return 1 if reason else 0
        anchor = load_anchor(args.anchor) if getattr(args, "anchor", None) else None
        reason = check_audit_chain(log, mac_key, anchor)
    except (KeyProviderError, ValueError) as exc:
        print(f"audit {args.command}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"audit {args.command}: {describe_os_error(exc)}", file=sys.stderr)
        return 1
    if reason:
        print(f"audit {args.command}: FAILED: {reason}", file=sys.stderr)
        return 1
    if args.command == "anchor":
        print(json.dumps(audit_anchor(log)))
    else:
        entries = audit_anchor(log)["entries"]
        against = " and matches the anchor" if anchor else ""
        print(f"audit log OK: {entries} entries verified{against}")
    return 0
