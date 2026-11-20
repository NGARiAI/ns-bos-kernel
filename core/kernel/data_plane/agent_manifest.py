"""Agent manifests (docs/AGENT_IDENTITY.md): an AI agent's identity and what
it may do, signed by the card of the named operator who sponsors it.

A manifest is one JSON object in sovereign/agents/<agent>.json. The
sponsor's card signs MANIFEST_LABEL, a NUL byte and the manifest's
canonical JSON without its signature, so a change to any field, the
permissions and dates included, breaks the signature. A manifest checks
only while its sponsor's certificate is pinned and valid, the operator
files still give that certificate to that person, the sponsor still holds
the sponsor role (when roles are set) and the time is within its dates:
taking any of these away takes the agent's sponsorship away with it.
"""

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .operator_auth import (
    MANIFEST_LABEL,
    CardAuthenticator,
    OperatorAuthError,
    _check_validity,
    key_problem,
    load_identities,
    load_pinned,
    name_problem,
    user_id_problem,
)
from .roles import load_roles

MANIFEST_VERSION = 1
AGENTS_DIR = "agents"
SPONSOR_ROLE = "sponsor"
DEFAULT_DAYS = 90
MAX_DAYS = 366  # a sponsorship is reviewed at least once a year
MAX_BYTES = 64 * 1024  # a manifest file
# What an agent may do, each a list of names; an empty list allows nothing.
PERMISSIONS = ("tools", "data", "publish", "subscribe", "tasks_for")
MAX_ITEMS = 256
ITEM_MAX_BYTES = 256
FIELDS = {
    "version", "agent", "agent_type", "permissions", "not_before", "not_after",
    "sponsor", "signed_at", "nonce", "signature",
}  # fmt: skip
SPONSOR_FIELDS = {"user", "name", "fingerprint"}
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_AGENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", re.ASCII)
_HEX = re.compile(r"(?:[0-9a-f]{2})+", re.ASCII)


class ManifestError(Exception):
    """A manifest that cannot be written or does not check; reason is a short
    fixed word for the audit log and for `agents list`."""

    def __init__(self, message: str, reason: str):
        super().__init__(message)
        self.reason = reason


def agent_name_problem(agent) -> str | None:
    """Why agent cannot name a sponsored agent, or None. The name is also its
    manifest's file name."""
    if not isinstance(agent, str) or not _AGENT.fullmatch(agent):
        return (
            "an agent name is 1 to 64 letters, digits or the characters . _ -, "
            "starting with a letter or digit"
        )
    return None


def permissions_problem(permissions) -> str | None:
    """Why permissions cannot be an agent's permissions, or None: exactly the
    PERMISSIONS keys, each a list of distinct names. '*' is not taken: what an
    agent may do is listed one by one."""
    if not isinstance(permissions, dict) or set(permissions) != set(PERMISSIONS):
        return f"permissions must hold exactly {', '.join(PERMISSIONS)}"
    for key in PERMISSIONS:
        items = permissions[key]
        if not isinstance(items, list) or len(items) > MAX_ITEMS:
            return f"permissions.{key} must be a list of at most {MAX_ITEMS} names"
        if len(set(map(str, items))) != len(items):
            return f"permissions.{key} names an item twice"
        for item in items:
            if not isinstance(item, str) or not item or not item.isprintable():
                return f"permissions.{key} holds an empty or unprintable name"
            if len(item.encode("utf-8", "surrogatepass")) > ITEM_MAX_BYTES:
                return f"permissions.{key} holds a name over {ITEM_MAX_BYTES} bytes"
            if item == "*":
                return f"permissions.{key}: '*' is not taken; list each name"
            if key == "tasks_for" and agent_name_problem(item):
                return f"permissions.tasks_for: {item[:64]!r} is not an agent name"
    return None


def _time(value, field: str) -> datetime:
    try:
        return datetime.strptime(value, TIME_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise ManifestError(
            f"{field} must be a UTC time like 2026-11-14T09:30:00Z", "malformed"
        ) from None


def check_shape(manifest) -> None:
    """ManifestError("malformed") unless manifest has the version 1 shape."""

    def bad(why: str) -> ManifestError:
        return ManifestError(f"the manifest is malformed: {why}", "malformed")

    if not isinstance(manifest, dict) or set(manifest) != FIELDS:
        raise bad(f"it must hold exactly {', '.join(sorted(FIELDS))}")
    if type(manifest["version"]) is not int or manifest["version"] != MANIFEST_VERSION:
        raise bad(f"version {manifest['version']!r} is not {MANIFEST_VERSION}")
    problem = agent_name_problem(manifest["agent"])
    if problem:
        raise bad(problem)
    agent_type = manifest["agent_type"]
    if (
        not isinstance(agent_type, str)
        or not agent_type
        or not agent_type.isprintable()
    ):
        raise bad("agent_type must be a non-empty printable string")
    if len(agent_type.encode("utf-8", "surrogatepass")) > ITEM_MAX_BYTES:
        raise bad(f"agent_type is over {ITEM_MAX_BYTES} bytes")
    problem = permissions_problem(manifest["permissions"])
    if problem:
        raise bad(problem)
    sponsor = manifest["sponsor"]
    if not isinstance(sponsor, dict) or set(sponsor) != SPONSOR_FIELDS:
        raise bad(f"sponsor must hold exactly {', '.join(sorted(SPONSOR_FIELDS))}")
    problem = user_id_problem(sponsor["user"]) or name_problem(sponsor["name"])
    if problem:
        raise bad(f"sponsor: {problem}")
    fp = sponsor["fingerprint"]
    if not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{64}", fp, re.ASCII):
        raise bad("sponsor.fingerprint must be 64 lowercase hex digits")
    start = _time(manifest["not_before"], "not_before")
    end = _time(manifest["not_after"], "not_after")
    _time(manifest["signed_at"], "signed_at")
    if not start < end <= start + timedelta(days=MAX_DAYS):
        raise bad(f"not_after must fall after not_before, by at most {MAX_DAYS} days")
    nonce = manifest["nonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce, re.ASCII):
        raise bad("nonce must be 32 lowercase hex digits")
    signature = manifest["signature"]
    if not isinstance(signature, str) or not _HEX.fullmatch(signature):
        raise bad("signature must be lowercase hex")


def body(manifest: dict) -> dict:
    """The manifest without its signature: what the card signs."""
    return {k: v for k, v in manifest.items() if k != "signature"}


def canonical(value: dict) -> bytes:
    """One byte string per value: keys sorted, no spaces, ASCII only."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def signed_message(manifest_body: dict) -> bytes:
    return MANIFEST_LABEL + b"\0" + canonical(manifest_body)


def manifest_sha256(manifest: dict) -> str:
    """The manifest's identity in the audit log: the SHA-256 of its canonical
    JSON, signature included."""
    return hashlib.sha256(canonical(manifest)).hexdigest()


def agents_dir(store: Path) -> Path:
    return Path(store) / AGENTS_DIR


def manifest_path(store: Path, agent: str) -> Path:
    return agents_dir(store) / f"{agent}.json"


def read_manifest(path: Path) -> dict:
    """The manifest in path, or ManifestError: missing, too large or not JSON.
    Its shape is checked by verify."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_BYTES + 1)
    except FileNotFoundError:
        raise ManifestError(f"no manifest at {path}", "missing") from None
    except OSError as exc:
        raise ManifestError(
            f"{path} cannot be read ({exc.strerror})", "unreadable"
        ) from None
    if len(data) > MAX_BYTES:
        raise ManifestError(f"{path} is over {MAX_BYTES} bytes", "malformed")
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        raise ManifestError(f"{path} is not JSON", "malformed") from None


def verify(manifest, store: Path, now: datetime | None = None) -> dict:
    """Facts about a manifest that checks now, or ManifestError naming the
    first thing that does not: its shape, the sponsor's certificate (pinned,
    given to that person, a key the kernel accepts, valid now), the
    signature, the sponsor role, and the manifest's own dates."""
    check_shape(manifest)
    store = Path(store)
    operators = store / "operators"
    sponsor = manifest["sponsor"]
    user, name, fp = sponsor["user"], sponsor["name"], sponsor["fingerprint"]
    cert = load_pinned(operators).get(fp)
    if cert is None:
        raise ManifestError(
            f"the sponsor's certificate {fp[:16]} is not pinned in {operators}",
            "not pinned",
        )
    identity = load_identities(operators).get(fp) or {}
    if (identity.get("user"), identity.get("name")) != (user, name):
        raise ManifestError(
            f"the operator files do not give certificate {fp[:16]} to {user} ({name})",
            "not the sponsor",
        )
    problem = key_problem(cert)
    if problem:
        raise ManifestError(f"certificate {fp[:16]} has {problem}", "weak key")
    try:
        _check_validity(cert, fp)
        CardAuthenticator._verify(
            cert,
            bytes.fromhex(manifest["signature"]),
            signed_message(body(manifest)),
            fp,
        )
        roles = load_roles(store)
    except OperatorAuthError as exc:
        raise ManifestError(str(exc), exc.reason) from None
    if roles is not None and SPONSOR_ROLE not in roles.get(user, []):
        raise ManifestError(
            f"{user} no longer holds the {SPONSOR_ROLE} role", "no sponsor role"
        )
    now = now or datetime.now(timezone.utc)
    if now < _time(manifest["not_before"], "not_before"):
        raise ManifestError(
            f"the manifest is valid from {manifest['not_before']}", "not yet valid"
        )
    if now > _time(manifest["not_after"], "not_after"):
        raise ManifestError(
            f"the manifest expired at {manifest['not_after']}", "expired"
        )
    return {
        "agent": manifest["agent"],
        "agent_type": manifest["agent_type"],
        "permissions": manifest["permissions"],
        "sponsor": user,
        "sponsor_name": name,
        "fingerprint": fp,
        "not_after": manifest["not_after"],
        "sha256": manifest_sha256(manifest),
    }


def check_agent(store: Path, agent: str, now: datetime | None = None) -> dict:
    """verify() for the manifest filed under agent's name, which must be the
    agent it names: a manifest copied under another name does not check."""
    problem = agent_name_problem(agent)
    if problem:
        raise ManifestError(problem, "malformed")
    manifest = read_manifest(manifest_path(store, agent))
    facts = verify(manifest, store, now)
    if facts["agent"] != agent:
        raise ManifestError(
            f"the manifest filed as {agent} is for {facts['agent']}", "wrong agent"
        )
    return facts


def filed_agents(store: Path) -> list[str]:
    """The names manifests are filed under, sorted."""
    folder = agents_dir(store)
    if not folder.is_dir():
        return []
    return sorted(p.stem for p in folder.glob("*.json") if not p.name.startswith("."))
