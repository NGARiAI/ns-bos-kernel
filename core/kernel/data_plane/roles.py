"""Operator roles (docs/PIV_CAC.md; 21 CFR 11.10(d), (g)): which named
operators may run which gated commands.

sovereign/roles.json maps user ids to roles from a fixed set. With no file,
any pinned operator passes the card gate. With one, the card gate is required
and each gated command needs the role COMMAND_ROLES gives it.
"""

import contextlib
import fcntl
import json
import os
from collections.abc import Iterator
from pathlib import Path

from .keys import _sync_directory, _write_synced
from .operator_auth import OperatorAuthError, user_id_problem

ROLES = ("admin", "author", "reviewer", "approver", "sponsor")
ROLES_VERSION = 1
ROLES_FILE = "roles.json"
# The role each gated command needs. A gated command missing here is refused.
COMMAND_ROLES = {
    "keys migrate": "admin",
    "keys export-recovery": "admin",
    "keys restore": "admin",
    "keys pin-operator": "admin",
    "keys set-roles": "admin",
    "state decrypt": "admin",
}


def roles_path(store: Path) -> Path:
    return store / ROLES_FILE


def load_roles(store: Path) -> dict[str, list[str]] | None:
    """Roles by user id, or None when there is no roles file. A file that
    cannot be read or is not valid raises OperatorAuthError, so the gate
    fails closed rather than fall back to no roles."""
    path = roles_path(store)

    def bad(why: str) -> OperatorAuthError:
        return OperatorAuthError(f"{path} {why}", "bad roles file")

    try:
        data = path.read_bytes()
    except FileNotFoundError:
        # A link to a file that is not there (a volume not mounted) is a
        # roles file that cannot be read, not the absence of one.
        if os.path.lexists(path):
            raise bad("is a link to a file that does not exist") from None
        return None
    except OSError as exc:
        raise bad(f"cannot be read ({exc.strerror})") from None
    try:
        record = json.loads(data)
    except (ValueError, RecursionError):
        raise bad("is not JSON") from None
    if not isinstance(record, dict) or set(record) != {"version", "roles"}:
        raise bad("must hold exactly version and roles")
    if type(record["version"]) is not int or record["version"] != ROLES_VERSION:
        raise bad(f"has version {record['version']!r}, not {ROLES_VERSION}")
    if not isinstance(record["roles"], dict):
        raise bad("roles must map user ids to lists of roles")
    roles = {}
    for user, granted in record["roles"].items():
        problem = user_id_problem(user)
        if problem:
            raise bad(f"names user {user!r}: {problem}")
        if (
            not isinstance(granted, list)
            or not all(r in ROLES for r in granted)
            or len(set(granted)) != len(granted)
        ):
            raise bad(
                f"gives {user} {granted!r}; each role once, from {', '.join(ROLES)}"
            )
        roles[user] = sorted(granted)
    return roles


def roles_bytes(roles: dict[str, list[str]]) -> bytes:
    kept = {user: sorted(granted) for user, granted in roles.items() if granted}
    record = {"version": ROLES_VERSION, "roles": kept}
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()


def authorize(roles: dict | None, operator: dict, command: str) -> str | None:
    """The role operator needs for command and holds, or None with no roles
    file. OperatorAuthError (reason "role") when they do not hold it."""
    if roles is None:
        return None
    fp = operator["fingerprint"]
    needed = COMMAND_ROLES.get(command)
    if needed is None:
        raise OperatorAuthError(f"{command} has no role set for it", "role", fp)
    user = operator.get("user")
    if user is None:
        raise OperatorAuthError(
            f"roles are set, and certificate {fp[:16]} has no named operator "
            "(keys pin-operator)",
            "role",
            fp,
        )
    if needed not in roles.get(user, []):
        raise OperatorAuthError(
            f"{user} does not hold the {needed} role that {command} needs", "role", fp
        )
    return needed


def parse_roles(given: str) -> list[str]:
    """A comma-separated list of roles, or "none"; ValueError otherwise."""
    if given.strip().lower() == "none":
        return []
    granted = [r.strip() for r in given.split(",")]
    unknown = [r for r in granted if r not in ROLES]
    if unknown:
        raise ValueError(
            f"unknown role {', '.join(map(repr, unknown))}; roles are "
            f"{', '.join(ROLES)}, comma-separated, or none"
        )
    if len(set(granted)) != len(granted):
        raise ValueError("a role is given twice")
    return sorted(granted)


@contextlib.contextmanager
def roles_lock(store: Path) -> Iterator[None]:
    """Exclusive while roles.json is read and replaced, so two changes made
    at once cannot lose one of them."""
    fd = os.open(store / ".roles.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def write_roles(store: Path, roles: dict[str, list[str]]) -> None:
    """Replace roles.json in one rename, synced, mode 0600."""
    path = roles_path(store)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.new")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        _write_synced(fd, roles_bytes(roles))
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    _sync_directory(store)
