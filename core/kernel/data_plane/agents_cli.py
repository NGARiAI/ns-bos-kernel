"""ns-bos agents: sponsor AI agents with an operator's card, and check them
(docs/AGENT_IDENTITY.md)."""

import argparse
import contextlib
import os
import secrets
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import append_audit
from .agent_manifest import (
    DEFAULT_DAYS,
    MANIFEST_VERSION,
    MAX_DAYS,
    PERMISSIONS,
    SPONSOR_ROLE,
    TIME_FORMAT,
    ManifestError,
    agent_name_problem,
    agents_dir,
    canonical,
    check_agent,
    filed_agents,
    manifest_path,
    manifest_sha256,
    permissions_problem,
    signed_message,
    verify,
)
from .keys import KeyProviderError, _sync_directory, _write_synced, make_private_dir
from .keys_cli import MigrationError, describe_os_error, read_passphrase, sovereign_dir
from .operator_auth import CardAuthenticator, OperatorAuthError
from .roles import load_roles

SUPERSEDED = "superseded"  # earlier manifests of a sponsored agent, kept


def _audit_log(store: Path) -> Path:
    return store / "audit" / "sovereign_audit.log"


def sponsor(
    store: Path,
    environ: Mapping[str, str],
    agent: str,
    agent_type: str,
    permissions: dict,
    days: int,
    pin_file: str | None,
    replace: bool = False,
) -> list[str]:
    """Sign a manifest for agent with the operator's card and file it. The
    request is checked before the PIN is asked for; a card refusal is
    recorded as agent_sponsor_refused, a sponsorship as agent_sponsored."""
    problem = (
        agent_name_problem(agent)
        or permissions_problem(permissions)
        or (None if 1 <= days <= MAX_DAYS else f"--days must be 1 to {MAX_DAYS}")
    )
    if not problem and (not agent_type or not agent_type.isprintable()):
        problem = "--type must be a non-empty printable string"
    if problem:
        raise MigrationError(problem)
    path = manifest_path(store, agent)
    if path.exists() and not replace:
        raise MigrationError(
            f"{agent} already has a manifest ({path}); give --replace to renew it"
        )
    signed = {}

    def message_for(user, name, fp, signed_at, nonce):
        start = datetime.strptime(signed_at, TIME_FORMAT).replace(tzinfo=timezone.utc)
        signed.update(
            version=MANIFEST_VERSION,
            agent=agent,
            agent_type=agent_type,
            permissions=permissions,
            not_before=signed_at,
            not_after=(start + timedelta(days=days)).strftime(TIME_FORMAT),
            sponsor={"user": user, "name": name, "fingerprint": fp},
            signed_at=signed_at,
            nonce=nonce,
        )
        return signed_message(signed)

    audit_log = _audit_log(store)
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
        facts = CardAuthenticator.from_env(store / "operators", environ).sign_named(
            message_for, pin, roles, SPONSOR_ROLE, purpose=f"sponsor agent {agent}"
        )
    except OperatorAuthError as exc:
        append_audit(
            audit_log, "agent_sponsor_refused", exc.fingerprint, agent,
            {"reason": exc.reason},
        )  # fmt: skip
        raise
    except Exception as exc:  # noqa: BLE001 - refuse and record whatever failed
        append_audit(
            audit_log, "agent_sponsor_refused", "unknown", agent, {"reason": "error"}
        )
        raise OperatorAuthError(
            f"the sponsorship failed with {type(exc).__name__}", "error"
        ) from None
    manifest = {**signed, "signature": facts["signature"]}
    verify(manifest, store)  # the check the kernel will make, before it is filed
    replaced = _file(store, agent, canonical(manifest) + b"\n", replace)
    sha = manifest_sha256(manifest)
    try:
        append_audit(
            audit_log, "agent_sponsored", facts["user"], agent,
            {"agent_type": agent_type, "not_after": manifest["not_after"],
             "manifest_sha256": sha, "fingerprint": facts["fingerprint"],
             "replaced": replaced},
        )  # fmt: skip
    except OSError as exc:
        raise MigrationError(
            f"{agent}'s manifest is filed, but the audit entry could not be written "
            f"({describe_os_error(exc)}). Fix the audit log; the sponsorship stands "
            "on the manifest's own signature."
        ) from None
    by = f"{facts['name']} ({facts['user']})"
    return [
        f"{agent} sponsored by {by} until {manifest['not_after']}: {path}",
        f"manifest sha256 {sha}",
    ]


def _file(store: Path, agent: str, data: bytes, replace: bool) -> bool:
    """File a manifest, complete or not at all. A manifest it replaces is
    kept under superseded/. Returns whether one was replaced."""
    folder = agents_dir(store)
    make_private_dir(folder)
    path = manifest_path(store, agent)
    tmp = folder / f".{agent}.json.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_synced(fd, data)
        if not replace:
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise MigrationError(
                    f"{agent} got a manifest meanwhile ({path}); nothing was changed"
                ) from None
            _sync_directory(folder)
            return False
        replaced = path.exists()
        if replaced:
            kept = folder / SUPERSEDED
            make_private_dir(kept)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            os.link(path, kept / f"{agent}.{stamp}.{secrets.token_hex(2)}.json")
            _sync_directory(kept)
        os.replace(tmp, path)
        _sync_directory(folder)
        return replaced
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def check(store: Path, agent: str) -> list[str]:
    facts = check_agent(store, agent)
    return [
        (
            f"{agent} ({facts['agent_type']}): sponsored by {facts['sponsor_name']} "
            f"({facts['sponsor']}) until {facts['not_after']}"
        ),
        *(
            f"  {key}: {', '.join(facts['permissions'][key]) or 'none'}"
            for key in PERMISSIONS
        ),
        f"manifest sha256 {facts['sha256']}",
    ]


def listing(store: Path) -> tuple[list[str], bool]:
    """A line per filed manifest, and whether every one checks now."""
    names = filed_agents(store)
    if not names:
        return [f"no agent manifests in {agents_dir(store)}"], True
    lines, ok = [], True
    for agent in names:
        try:
            facts = check_agent(store, agent)
        except ManifestError as exc:
            lines.append(f"{agent}: NOT SPONSORED ({exc.reason}): {exc}")
            ok = False
            continue
        lines.append(
            f"{agent}: sponsored by {facts['sponsor_name']} ({facts['sponsor']}) "
            f"until {facts['not_after']}"
        )
    return lines, ok


def cli(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(
        prog="ns-bos agents", description=__doc__.split("\n")[0]
    )
    parser.add_argument(
        "--data-dir", help="kernel data directory (default $NGARI_DATA_DIR)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sponsoring = sub.add_parser(
        "sponsor", help="sign an agent's manifest with your card"
    )
    sponsoring.add_argument("agent", help="the agent's name")
    sponsoring.add_argument("--type", required=True, help="the agent's type")
    for key, what in (
        ("tool", "a tool the agent may call"),
        ("data", "a data key prefix the agent may read and write"),
        ("publish", "a topic the agent may publish on"),
        ("subscribe", "a topic the agent may subscribe to"),
        ("task-for", "an agent the agent may create tasks for"),
    ):
        sponsoring.add_argument(
            f"--{key}", action="append", default=[], help=f"{what} (repeat)"
        )
    sponsoring.add_argument(
        "--days", type=int, default=DEFAULT_DAYS,
        help=f"days the sponsorship lasts (default {DEFAULT_DAYS}, at most {MAX_DAYS})",
    )  # fmt: skip
    sponsoring.add_argument(
        "--replace", action="store_true", help="renew an existing manifest"
    )
    sponsoring.add_argument(
        "--pin-file", help="file holding the card PIN (else the terminal)"
    )
    sub.add_parser("list", help="every filed manifest and whether it checks now")
    checking = sub.add_parser("check", help="check one agent's manifest")
    checking.add_argument("agent", help="the agent's name")
    args = parser.parse_args(argv)
    store = sovereign_dir(env, args.data_dir)
    ok = True
    try:
        if args.command == "sponsor":
            permissions = {
                "tools": args.tool,
                "data": args.data,
                "publish": args.publish,
                "subscribe": args.subscribe,
                "tasks_for": args.task_for,
            }
            lines = sponsor(
                store, env, args.agent, args.type, permissions, args.days,
                args.pin_file, args.replace,
            )  # fmt: skip
        elif args.command == "check":
            lines = check(store, args.agent)
        else:
            lines, ok = listing(store)
    except ManifestError as exc:
        print(f"{args.command}: NOT SPONSORED ({exc.reason}): {exc}", file=sys.stderr)
        return 1
    except (MigrationError, KeyProviderError) as exc:
        print(f"{args.command}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{args.command}: {describe_os_error(exc)}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    return 0 if ok else 1
