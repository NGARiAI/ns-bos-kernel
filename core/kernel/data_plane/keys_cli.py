"""ns-bos keys: manage the master key, operator certificates and roles.

`keys status` reads the key store without loading a key. `keys migrate` seals
an existing plaintext master.key into the TPM: it seals that key, unseals it,
compares, trial-decrypts stored data, and stops. It never deletes or rewrites
master.key; removing the plaintext copy is the operator's decision. `keys
export-recovery` and `keys restore` keep or use a passphrase-wrapped recovery
copy of the key. No command opens the store through a SovereignDataPlane.
"""

import argparse
import getpass
import hmac
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization

from . import append_audit, audit_key, recovery
from .keys import (
    PROVIDER_ENV,
    KeyProviderError,
    make_private_dir,
    publish_new_file,
    validate_key,
)
from .operator_auth import (
    AUTH_ENV,
    CardAuthenticator,
    OperatorAuthError,
    _check_key,
    _check_validity,
    identity_bytes,
    load_identities,
    load_pinned,
    name_problem,
    subject,
    user_id_problem,
)
from .roles import (
    authorize,
    load_roles,
    parse_roles,
    roles_lock,
    roles_path,
    write_roles,
)
from .tpm import PCRS_ENV, TPMKeyProvider, missing_pcr_bank, parse_pcrs


def describe_os_error(exc: OSError) -> str:
    """One line for a file a command could not use."""
    where = f"{exc.filename}: " if exc.filename else ""
    line = f"{where}{exc.strerror or exc}"
    if isinstance(exc, PermissionError):
        line += "; run this as the user that owns the data directory"
    return line


def sovereign_dir(environ: Mapping[str, str], data_dir: str | None = None) -> Path:
    base = (
        data_dir
        or environ.get("NGARI_DATA_DIR")
        or str(Path.home() / ".ngari" / "kernel")
    )
    return Path(base) / "sovereign"


def _mode(path: Path) -> str | None:
    try:
        return oct(path.stat().st_mode & 0o777)
    except OSError:
        return None


def _sealed_pcrs(sealed: Path) -> str | None:
    try:
        value = json.loads(sealed.read_bytes()).get("pcrs")
    except (OSError, ValueError, AttributeError, RecursionError):
        return None
    return value if isinstance(value, str) else None


def status(store: Path, environ: Mapping[str, str]) -> dict:
    """Facts read from disk. No key is loaded and the TPM is not used."""
    keys_dir = store / "keys"
    plain = keys_dir / "master.key"
    sealed = keys_dir / "master.key.sealed"
    enc = sorted((store / "encrypted").glob("*.enc"))
    return {
        "data_directory": str(store),
        "selected_provider": (environ.get(PROVIDER_ENV) or "file").strip().lower(),
        "master_key": {"present": plain.exists(), "mode": _mode(plain)},
        "sealed_key": {
            "present": sealed.exists(),
            "mode": _mode(sealed),
            "pcrs": _sealed_pcrs(sealed),
        },
        "encrypted_files": len(enc),
    }


class MigrationError(Exception):
    pass


def migrate(store: Path, environ: Mapping[str, str], actor: str = "local") -> list[str]:
    """Seal master.key into the TPM. Returns report lines; raises
    MigrationError with nothing changed except a blob this run removed."""
    keys_dir = store / "keys"
    plain = keys_dir / "master.key"
    if not plain.exists():
        raise MigrationError(f"no plaintext key at {plain}; nothing to migrate")
    try:
        key = validate_key(plain.read_bytes())
        provider = TPMKeyProvider.from_env(keys_dir, environ)
    except (OSError, KeyProviderError) as exc:
        raise MigrationError(f"cannot read {plain}: {exc}") from None

    trial = next(iter(sorted((store / "encrypted").glob("*.enc"))), None)
    if trial is not None:
        try:
            Fernet(key).decrypt(trial.read_bytes())
        except InvalidToken:
            raise MigrationError(
                f"{plain} does not decrypt {trial.name}. Refusing to seal a key that "
                "does not open the stored data."
            ) from None

    try:
        in_effect, created = provider.seal(key)
    except KeyProviderError as exc:
        raise MigrationError(f"sealing failed: {exc}") from None
    published = provider.sealed_file.read_bytes() if created else None

    try:
        if not hmac.compare_digest(in_effect, key):
            raise MigrationError(
                f"{provider.sealed_file} already holds a different key than {plain}. "
                "Nothing was changed. Find out which key the data needs first."
            )
        unsealed = TPMKeyProvider.from_env(keys_dir, environ).unseal()
        # Equal to a key that already decrypted the trial file, so no second
        # trial decrypt is needed.
        if not hmac.compare_digest(unsealed, key):
            raise MigrationError("the sealed key did not unseal to master.key")
    except (MigrationError, KeyProviderError) as exc:
        if created and provider.sealed_file.read_bytes() == published:
            provider.sealed_file.unlink()
        if isinstance(exc, MigrationError):
            raise
        raise MigrationError(f"verification failed: {exc}") from None

    checked = f"decrypts {trial.name}" if trial else "no encrypted files to test"
    state = "sealed" if created else "was already sealed"
    if created:  # a second run that finds the key sealed changes nothing
        _record(store, key, "key_migrated", actor, "tpm2", {"tcti": provider.tcti})
    return [
        (
            f"master.key {state} into the TPM at {provider.sealed_file} "
            f"(TCTI {provider.tcti}); unseal matches; {checked}."
        ),
        f"{plain} is unchanged. Start the kernel with {PROVIDER_ENV}=tpm2.",
        (
            "The compliance report shows the tpm2 provider as not ok while the "
            "plaintext copy exists. A sealed key is lost with this TPM: run "
            "`keys export-recovery` and store the bundle off this machine before "
            "removing master.key."
        ),
    ]


def _trial(store: Path) -> Path | None:
    return next(iter(sorted((store / "encrypted").glob("*.enc"))), None)


def current_key(store: Path, environ: Mapping[str, str]) -> bytes:
    """The key the store runs on: the sealed one, else master.key. It must
    decrypt a stored file when there is one."""
    return _current_key(store, environ)[0]


def _current_key(store: Path, environ: Mapping[str, str]) -> tuple[bytes, str | None]:
    """The key, and a note when it had to come from master.key because the
    sealed file cannot be unsealed on this TPM (a replaced board, a reset TPM).
    master.key is used then only if it decrypts a stored file: that is the
    proof it is the key the data needs."""
    keys_dir = store / "keys"
    plain = keys_dir / "master.key"
    provider = TPMKeyProvider.from_env(keys_dir, environ)
    note = None
    if provider.sealed_file.exists():
        try:
            key = provider.unseal()
        except KeyProviderError as exc:
            trial = _trial(store)
            if not plain.exists() or trial is None:
                raise
            candidate = validate_key(plain.read_bytes())
            try:
                Fernet(candidate).decrypt(trial.read_bytes())
            except InvalidToken:
                raise exc from None
            key, note = (
                candidate,
                (
                    f"{provider.sealed_file} cannot be unsealed on this TPM, so the key "
                    f"is master.key, which decrypts {trial.name}."
                ),
            )
        else:
            if plain.exists() and not hmac.compare_digest(
                validate_key(plain.read_bytes()), key
            ):
                raise MigrationError(
                    f"{plain} and {provider.sealed_file} hold different keys. "
                    "Find out which key the data needs first."
                )
    elif plain.exists():
        key = validate_key(plain.read_bytes())
    else:
        raise MigrationError(f"no master key in {keys_dir}")
    trial = _trial(store)
    if trial is not None:
        try:
            Fernet(key).decrypt(trial.read_bytes())
        except InvalidToken:
            raise MigrationError(
                f"the master key does not decrypt {trial.name}"
            ) from None
    return key, note


def export_recovery(
    store: Path,
    environ: Mapping[str, str],
    out: Path,
    passphrase: bytes,
    actor: str = "local",
) -> list[str]:
    recovery.check_passphrase(passphrase)
    key, note = _current_key(store, environ)
    data = recovery.wrap(key, passphrase)
    try:
        created = publish_new_file(out, data)
    except OSError as exc:
        raise MigrationError(f"cannot write {out}: {exc.strerror}") from None
    if not created:
        raise MigrationError(f"{out} already exists; it was not overwritten")
    _record(store, key, "recovery_exported", actor, str(out), {})
    return [
        *([note] if note else []),
        f"recovery bundle written to {out} (mode 0600); it opens with the passphrase.",
        (
            "Move it off this machine and keep the passphrase apart from it. "
            "Anyone with both can read every encrypted file."
        ),
    ]


def restore(
    store: Path,
    environ: Mapping[str, str],
    bundle: Path,
    passphrase: bytes,
    pcrs: str | None = None,
    actor: str = "local",
) -> list[str]:
    """Seal the bundle's key into this TPM, optionally bound to PCRs. An
    unusable old blob is kept under another name, never deleted, and stays
    in place until the new one is proven and swapped in. This is the only
    way to a PCR-bound key: the operator has to hold a bundle that opens and
    matches the data."""
    pcrs = parse_pcrs(pcrs)
    try:
        raw = bundle.read_bytes()
    except OSError as exc:
        raise MigrationError(f"cannot read {bundle}: {exc.strerror}") from None
    key = recovery.unwrap(raw, passphrase)
    trial = _trial(store)
    if trial is not None:
        try:
            Fernet(key).decrypt(trial.read_bytes())
        except InvalidToken:
            raise MigrationError(
                f"the bundle's key does not decrypt {trial.name}. Nothing was changed."
            ) from None
    keys_dir = store / "keys"
    plain = keys_dir / "master.key"
    if plain.exists() and not hmac.compare_digest(
        validate_key(plain.read_bytes()), key
    ):
        raise MigrationError(
            f"{plain} holds a different key than the bundle. Nothing was changed."
        )
    make_private_dir(keys_dir)
    provider = TPMKeyProvider.from_env(keys_dir, environ)
    # Before anything is renamed or sealed: a bank the chip has not allocated
    # would otherwise fail halfway with the TPM tool's own message.
    problem = missing_pcr_bank(pcrs, provider.identity()["pcr_banks"] if pcrs else [])
    if problem:
        raise MigrationError(f"{problem}. Nothing was changed.")
    aside = None
    if provider.sealed_file.exists():
        try:
            sealed = provider.unseal()
        except KeyProviderError:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            aside = provider.sealed_file.with_name(
                f"{provider.sealed_file.name}.unusable-{stamp}"
            )
            # A leftover link from an interrupted run is the same file and is
            # reused; anything else under that name is not touched.
            if aside.exists() and not os.path.samefile(aside, provider.sealed_file):
                raise MigrationError(f"{aside} already exists") from None
            provider.seal_over(key, pcrs, aside)
            lines = [
                (
                    f"key restored and sealed into the TPM at {provider.sealed_file} "
                    f"(TCTI {provider.tcti})."
                ),
            ]
            if pcrs:
                lines.append(_bound(provider, pcrs))
            lines.append(f"the old sealed file did not unseal here; kept as {aside}.")
            lines.append(f"Start the kernel with {PROVIDER_ENV}=tpm2.")
            _record(store, key, "key_restored", actor, "tpm2",
                    {"pcrs": pcrs, "rebound": False, "set_aside": aside.name})  # fmt: skip
            return lines
        else:
            if not hmac.compare_digest(sealed, key):
                raise MigrationError(
                    f"{provider.sealed_file} already holds a different key that "
                    "unseals on this TPM. Nothing was changed."
                )
            if provider.pcrs() == pcrs:
                return [
                    f"{provider.sealed_file} already holds this key. Nothing changed."
                ]
            provider.reseal(key, pcrs)
            _record(store, key, "key_restored", actor, "tpm2",
                    {"pcrs": pcrs, "rebound": True, "set_aside": None})  # fmt: skip
            return [_bound(provider, pcrs)]
    in_effect, _ = provider.seal(key, pcrs)
    if not hmac.compare_digest(in_effect, key):
        raise MigrationError("another process sealed a different key meanwhile")
    lines = [
        (
            f"key restored and sealed into the TPM at {provider.sealed_file} "
            f"(TCTI {provider.tcti})."
        ),
    ]
    if pcrs:
        lines.append(_bound(provider, pcrs))
    lines.append(f"Start the kernel with {PROVIDER_ENV}=tpm2.")
    _record(store, key, "key_restored", actor, "tpm2",
            {"pcrs": pcrs, "rebound": False, "set_aside": None})  # fmt: skip
    return lines


def _record(
    store: Path, key: bytes, action: str, actor: str, resource: str, details: dict
):
    """A keyed audit entry for a key command that changed something. The MAC
    key comes from the key the command just used; no key material is written."""
    try:
        append_audit(
            store / "audit" / "sovereign_audit.log", action, actor, resource, details,
            audit_key(key),
        )  # fmt: skip
    except OSError as exc:
        # The change is made; only its record failed. Say both.
        raise MigrationError(
            f"{action.replace('_', ' ')}: done, but the audit entry could not be "
            f"written ({describe_os_error(exc)}). Fix the audit log, then record it "
            "by hand or keep this output."
        ) from None


def _bound(provider: TPMKeyProvider, pcrs: str | None) -> str:
    if not pcrs:
        return f"{provider.sealed_file} resealed with no PCR policy."
    return (
        f"{provider.sealed_file} is bound to PCRs {pcrs}. If they change (a "
        "firmware, bootloader or kernel update; on a VM or container, the "
        "host's), the key comes back only from the recovery bundle."
    )


def operator_gate(
    command: str,
    store: Path,
    environ: Mapping[str, str],
    pin_file: str | None,
    family: str = "keys",
) -> dict | None:
    """With NGARI_OPERATOR_AUTH=card, the operator's card must sign for this
    command ("<family> <command>") first, and with a roles file the operator
    must hold the role the command needs. Pass and fail both go into the
    audit chain. A roles file with the gate off refuses the command: roles
    that nothing checks would read as a control that is not there."""
    mode = (environ.get(AUTH_ENV) or "off").strip().lower()
    if mode == "off":
        if os.path.lexists(roles_path(store)):
            raise MigrationError(
                f"roles are set in {roles_path(store)}, so {family} {command} "
                f"needs {AUTH_ENV}=card"
            )
        return None
    if mode != "card":
        raise MigrationError(f"{AUTH_ENV} must be off or card, got {mode!r}")
    action = f"{family} {command}"
    audit_log = store / "audit" / "sovereign_audit.log"
    facts = None
    try:
        load_roles(store)  # checked before the PIN, so a broken file costs no try
        try:
            pin = read_passphrase(
                pin_file, confirm=False, prompt="Card PIN: ", option="--pin-file"
            )
        except MigrationError as exc:
            raise OperatorAuthError(str(exc), "no pin") from None
        facts = CardAuthenticator.from_env(store / "operators", environ).authenticate(
            action, store, pin
        )
        # Read again: a PIN prompt can wait any length of time, and a role
        # taken away meanwhile must count.
        role = authorize(load_roles(store), facts, action)
    except OperatorAuthError as exc:
        # A role refusal comes after the card signed: the operator is known.
        actor = operator_actor(facts) if facts else exc.fingerprint
        append_audit(
            audit_log, "operator_auth", actor, action,
            {"ok": False, "reason": exc.reason},
        )  # fmt: skip
        raise
    except Exception as exc:  # noqa: BLE001 - refuse and record whatever failed
        # Anything else is still a refusal, and still recorded. The type is
        # enough: an exception's text can hold what was being decoded.
        append_audit(
            audit_log, "operator_auth", "unknown", action,
            {"ok": False, "reason": "error"},
        )  # fmt: skip
        raise OperatorAuthError(
            f"the operator check failed with {type(exc).__name__}", "error"
        ) from None
    details = {"ok": True, "subject": facts["subject"]}
    if "user" in facts:  # a named operator: the person is the actor
        details.update(name=facts["name"], fingerprint=facts["fingerprint"])
    if role:
        details["role"] = role
    append_audit(audit_log, "operator_auth", operator_actor(facts), action, details)
    return facts


def operator_actor(operator: dict | None) -> str:
    """The audit actor for what a gated command does: the named operator's
    user id, else the card's fingerprint, else `local` with no gate."""
    if not operator:
        return "local"
    return operator.get("user") or operator["fingerprint"]


def operator_line(operator: dict) -> str:
    fp = operator["fingerprint"][:16]
    if "user" in operator:
        return f"operator: {operator['name']} ({operator['user']}, certificate {fp})"
    return f"operator: {operator['subject']} ({fp})"


def _one_certificate(path: Path):
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise MigrationError(f"cannot read {path}: {exc.strerror}") from None
    try:
        certs = (
            x509.load_pem_x509_certificates(data)
            if b"-----BEGIN" in data
            else [x509.load_der_x509_certificate(data)]
        )
    except ValueError:
        raise MigrationError(f"{path} is not a certificate") from None
    if len(certs) != 1:
        raise MigrationError(
            f"{path} holds {len(certs)} certificates; pin one at a time"
        )
    return certs[0]


def _no_operators_yet(store: Path) -> bool:
    """A store that never had an operator: nothing in operators/, retired/
    included, and no roles file. Only there may an operator be pinned with
    no card to sign for it. A store whose last certificate was retired is
    not one: pinning there would hand its roles to whoever came first."""
    if os.path.lexists(roles_path(store)):
        return False
    operators = store / "operators"
    if not os.path.lexists(operators):
        return True
    return not any(not p.name.startswith(".") for p in operators.iterdir())


def pin_operator(
    store: Path,
    cert_file: Path,
    user: str,
    name: str | None,
    actor: str = "local",
    replaces: str | None = None,
) -> list[str]:
    """Pin a certificate for a named operator: <user>.pem (unless the
    certificate is already pinned in another file) and <user>.json with the
    user id and printed name, both new files, mode 0600, never overwritten.
    The printed name defaults to the certificate's common name. replaces
    names the user id of the same person's earlier card: the new id carries
    that person, so applications can tell the two apart from two people."""
    cert = _one_certificate(cert_file)
    fp = cert.fingerprint(hashes.SHA256()).hex()
    _check_validity(cert, fp)
    _check_key(cert, fp)
    problem = user_id_problem(user)
    if problem:
        raise MigrationError(problem)
    name = subject(cert).strip() if name is None else name.strip()
    problem = name_problem(name)
    if problem:
        raise MigrationError(problem)
    operators = store / "operators"
    pinned = load_pinned(operators)
    identities = load_identities(operators)
    person = None
    if replaces is not None:
        if user_id_problem(replaces) or replaces == user:
            raise MigrationError(f"--replaces {replaces!r} is not another user id")
        earlier = [i for i in identities.values() if i["user"] == replaces]
        if not earlier:
            raise MigrationError(
                f"there is no operator {replaces} to replace (their .json must be "
                "kept, retired or not). Nothing was changed."
            )
        person = earlier[0].get("person", replaces)
    named = identities.get(fp)
    if named:
        raise MigrationError(
            f"certificate {fp[:16]} is already pinned for {named['user']} "
            f"({named['name']}). Nothing was changed."
        )
    identity = operators / f"{user}.json"
    if identity.exists():
        raise MigrationError(f"{identity} already exists. Nothing was changed.")
    left = (load_roles(store) or {}).get(user)
    if left:
        raise MigrationError(
            f"{user} still has roles in {roles_path(store)} ({', '.join(left)}) "
            f"from an earlier operator; clear them first (keys set-roles --user "
            f"{user} --roles none). Nothing was changed."
        )
    make_private_dir(operators)
    lines = []
    if fp in pinned:
        lines.append(f"certificate {fp[:16]} was already pinned; adding its operator.")
    else:
        pem = operators / f"{user}.pem"
        if not publish_new_file(pem, cert.public_bytes(serialization.Encoding.PEM)):
            raise MigrationError(f"{pem} already exists. Nothing was changed.")
        lines.append(f"certificate {fp[:16]} pinned as {pem}.")
    if not publish_new_file(identity, identity_bytes(user, name, fp, person)):
        raise MigrationError(
            f"{identity} appeared meanwhile; the certificate is pinned without a name"
        )
    lines.append(f"operator {user}: {name}, recorded in {identity}.")
    try:
        append_audit(
            store / "audit" / "sovereign_audit.log", "operator_pinned", actor, user,
            {"name": name, "fingerprint": fp,
             **({"replaces": replaces, "person": person} if person else {})},
        )  # fmt: skip
    except OSError as exc:
        raise MigrationError(
            f"operator pinned, but the audit entry could not be written "
            f"({describe_os_error(exc)}). Fix the audit log, then record it by "
            "hand or keep this output."
        ) from None
    return lines


def _gate_takes(cert, fp: str) -> bool:
    try:
        _check_validity(cert, fp)
        _check_key(cert, fp)
    except OperatorAuthError:
        return False
    return True


def _shown(granted: list[str]) -> str:
    return ", ".join(granted) if granted else "no roles"


def set_roles(
    store: Path, user: str, given: str, actor: str = "local", *, gated: bool = False
) -> list[str]:
    """Set a named operator's roles (comma-separated, or none) in roles.json,
    recorded with the roles before and after. Refused when it would leave no
    admin, since then nobody could change roles again.

    gated: the command line checked actor at the card gate before this was
    called. The roles in force are read again under the lock, and if roles
    were set meanwhile, actor must hold admin in them."""
    problem = user_id_problem(user)
    if problem:
        raise MigrationError(problem)
    try:
        after = parse_roles(given)
    except ValueError as exc:
        raise MigrationError(str(exc)) from None
    operators = store / "operators"
    identities = load_identities(operators)
    pinned = load_pinned(operators)
    named = {i["user"] for i in identities.values()}
    # Only a named operator whose pinned certificate the gate would take,
    # in date and with a key it accepts, can pass it.
    active = {
        i["user"]
        for fp, i in identities.items()
        if fp in pinned and _gate_takes(pinned[fp], fp)
    }
    with roles_lock(store):
        loaded = load_roles(store)
        if gated and loaded is not None and "admin" not in loaded.get(actor, []):
            if actor == "local":
                raise MigrationError(
                    f"roles were set in {roles_path(store)} while this ran, so keys "
                    f"set-roles needs {AUTH_ENV}=card. Nothing changed."
                )
            raise MigrationError(
                f"roles were set in {roles_path(store)} after the card check, and "
                f"{actor} does not hold admin in them. Nothing changed."
            )
        current = loaded or {}
        before = current.get(user, [])
        if before == after:
            return [f"{user} already has {_shown(after)}. Nothing changed."]
        if after and user not in named:
            raise MigrationError(
                f"{user} is not a named operator; pin them first (keys pin-operator)"
            )
        updated = {**current, user: after}
        if not any("admin" in updated.get(user, []) for user in active):
            raise MigrationError(
                "that would leave no admin who can pass the gate (a named "
                "operator with a pinned certificate that is in date and has a key "
                "the gate accepts), and nobody could change roles again. Nothing "
                "changed."
            )
        write_roles(store, updated)
        try:
            append_audit(
                store / "audit" / "sovereign_audit.log", "roles_changed", actor,
                user, {"from": before, "to": after},
            )  # fmt: skip
        except OSError as exc:
            raise MigrationError(
                f"roles changed, but the audit entry could not be written "
                f"({describe_os_error(exc)}). Fix the audit log, then record it by "
                "hand or keep this output."
            ) from None
    return [f"{user}: {_shown(before)} -> {_shown(after)}."]


def list_roles(store: Path) -> list[str]:
    """Each named operator with their roles, and roles left for a user id
    whose operator file is gone."""
    identities = sorted(
        load_identities(store / "operators").values(), key=lambda i: i["user"]
    )
    roles = load_roles(store)
    lines = []
    if roles is None:
        lines.append(
            f"no roles file ({roles_path(store)}): with {AUTH_ENV}=card any "
            "pinned operator passes the gate."
        )
        roles = {}
    for identity in identities:
        user = identity["user"]
        lines.append(f"{user}: {identity['name']}; {_shown(roles.get(user, []))}")
    for user in sorted(set(roles) - {i["user"] for i in identities}):
        lines.append(f"{user}: no operator file; {_shown(roles[user])}")
    if not identities and not roles:
        lines.append("no named operators.")
    return lines


def _chosen_pcrs(given: str | None, environ: Mapping[str, str]) -> str | None:
    """--pcrs, else NGARI_TPM_PCRS; 'none' in either means no PCR policy."""
    chosen = given if given is not None else environ.get(PCRS_ENV)
    if chosen is not None and chosen.strip().lower() == "none":
        return None
    return chosen


def card_check(
    store: Path, environ: Mapping[str, str], pin_file: str | None, out: str | None
) -> list[str]:
    """The card signs a fresh challenge with the PIN and the signature is
    checked against the card's certificate. With out, the verified
    certificate is written there (mode 0600, never overwritten)."""
    pin = read_passphrase(
        pin_file, confirm=False, prompt="Card PIN: ", option="--pin-file"
    )
    operators = store / "operators"
    facts = CardAuthenticator.from_env(operators, environ).check(store, pin)
    fp = facts["fingerprint"]
    lines = [
        (
            f"card: {facts['subject']} ({facts['key']}), certificate {fp[:16]}, "
            f"valid {facts['not_before'][:10]} to {facts['not_after'][:10]}"
        ),
        (
            "signature: the card signed a fresh challenge with the PIN, and it "
            "verifies against the card's certificate"
        ),
        f"pinned on this store: {'yes' if facts['pinned'] else 'no'} ({operators})",
    ]
    if out:
        try:
            created = publish_new_file(Path(out), facts["pem"])
        except OSError as exc:
            raise MigrationError(f"cannot write {out}: {exc.strerror}") from None
        if not created:
            raise MigrationError(f"{out} already exists; it was not overwritten")
        lines.append(
            f"certificate written to {out}. To pin it: keys pin-operator --cert "
            f"{out} --user ID (or copy it into {operators}/ with mode 0600)."
        )
    elif not facts["pinned"]:
        lines.append(
            f"To pin it, run again with --out FILE and copy the file into {operators}/."
        )
    return lines


def read_passphrase(
    path: str | None,
    *,
    confirm: bool,
    prompt: str = "Recovery passphrase: ",
    option: str = "--passphrase-file",
) -> bytes:
    """From a file (one trailing newline dropped) or the terminal. Never from
    argv or the environment."""
    if path:
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            raise MigrationError(f"cannot read {path}: {exc.strerror}") from None
        return data.removesuffix(b"\n").removesuffix(b"\r")
    if not sys.stdin.isatty():
        what = "PIN" if "PIN" in prompt else "passphrase"
        raise MigrationError(f"no terminal: give the {what} with {option}")
    first = getpass.getpass(prompt).encode()
    if confirm and getpass.getpass("Again: ").encode() != first:
        raise MigrationError("the passphrases did not match")
    return first


def cli(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(
        prog="ns-bos keys", description=__doc__.split("\n")[0]
    )
    parser.add_argument(
        "--data-dir", help="kernel data directory (default $NGARI_DATA_DIR)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show where the master key is held")
    check = sub.add_parser(
        "selftest",
        help="run the tpm2 key lifecycle against the TPM in a scratch directory",
    )
    check.add_argument("--json", action="store_true", help="print the report as JSON")
    check.add_argument(
        "--pcrs",
        default=None,
        help=f"also test a PCR policy, e.g. sha256:7 (default ${PCRS_ENV}; 'none' for no PCR step)",
    )
    card = sub.add_parser(
        "card-check",
        help="prove the PIV/CAC card signs with its certificate's key; changes nothing",
    )
    card.add_argument(
        "--pin-file", help="file holding the card PIN (else the terminal)"
    )
    card.add_argument("--out", help="write the verified certificate here, for pinning")
    pin = sub.add_parser(
        "pin-operator",
        help="pin a certificate for a named operator (user id and printed name)",
    )
    pin.add_argument(
        "--cert", required=True, help="certificate file, as card-check --out writes it"
    )
    pin.add_argument(
        "--user", required=True, help="user id: 1 to 64 letters, digits, . _ -"
    )
    pin.add_argument(
        "--name", help="printed name (default the certificate's common name)"
    )
    pin.add_argument(
        "--replaces",
        help="user id of this person's earlier card (a reissue); the new id is the same person",
    )
    sub.add_parser("roles", help="list named operators and their roles")
    setr = sub.add_parser(
        "set-roles",
        help="set a named operator's roles (admin, author, reviewer, approver, sponsor)",
    )
    setr.add_argument("--user", required=True, help="the operator's user id")
    setr.add_argument("--roles", required=True, help="comma-separated roles, or none")
    migrate_cmd = sub.add_parser(
        "migrate", help="seal master.key into the TPM, keeping it"
    )
    export = sub.add_parser(
        "export-recovery", help="write a passphrase-wrapped copy of the key"
    )
    export.add_argument("--out", required=True, help="bundle file to create")
    export.add_argument("--passphrase-file", help="file holding the passphrase")
    rest = sub.add_parser("restore", help="seal the key from a bundle into this TPM")
    rest.add_argument("--bundle", required=True, help="recovery bundle to read")
    rest.add_argument("--passphrase-file", help="file holding the passphrase")
    rest.add_argument(
        "--pcrs",
        default=None,
        help=f"bind to PCRs, e.g. sha256:7 (default ${PCRS_ENV}; 'none' for no policy)",
    )
    for gated in (pin, setr, migrate_cmd, export, rest):
        gated.add_argument(
            "--pin-file", help=f"card PIN, when {AUTH_ENV}=card (else the terminal)"
        )
    args = parser.parse_args(argv)
    store = sovereign_dir(env, args.data_dir)

    if args.command == "status":
        try:
            facts = status(store, env)
        except OSError as exc:
            print(f"status: {describe_os_error(exc)}", file=sys.stderr)
            return 1
        print(json.dumps(facts, indent=2))
        return 0
    if args.command == "roles":
        try:
            lines = list_roles(store)
        except (MigrationError, KeyProviderError) as exc:
            print(f"roles: {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"roles: {describe_os_error(exc)}", file=sys.stderr)
            return 1
        for line in lines:
            print(line)
        return 0
    if args.command == "card-check":
        # Reads only the card and the list of pinned certificates, so it needs
        # no gate; pinning stays a file an administrator copies.
        try:
            lines = card_check(store, env, args.pin_file, args.out)
        except (MigrationError, KeyProviderError) as exc:
            print(f"card-check: {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"card-check: {describe_os_error(exc)}", file=sys.stderr)
            return 1
        for line in lines:
            print(line)
        return 0
    if args.command == "selftest":
        # Never reads the store or its key, so the operator gate does not apply.
        from .selftest import format_report, run_selftest

        if args.json:
            report = run_selftest(env, _chosen_pcrs(args.pcrs, env))
            print(json.dumps(report, indent=2))
        else:
            # Each line as soon as it is known; the summary at the end.
            report = run_selftest(
                env, _chosen_pcrs(args.pcrs, env), lambda line: print(line, flush=True)
            )
            print(format_report(report)[-1])
        return 0 if report["passed"] else 1
    try:
        # The first operator is pinned with no card to sign for it; after
        # that, pinning another is gated like a key command.
        first = args.command == "pin-operator" and _no_operators_yet(store)
        operator = (
            None if first else operator_gate(args.command, store, env, args.pin_file)
        )
        actor = operator_actor(operator)
        if operator:
            print(operator_line(operator))
        if args.command == "pin-operator":
            lines = pin_operator(
                store, Path(args.cert), args.user, args.name, actor, args.replaces
            )
        elif args.command == "set-roles":
            lines = set_roles(store, args.user, args.roles, actor, gated=True)
        elif args.command == "migrate":
            lines = migrate(store, env, actor)
        elif args.command == "export-recovery":
            secret = read_passphrase(args.passphrase_file, confirm=True)
            lines = export_recovery(store, env, Path(args.out), secret, actor)
        else:
            secret = read_passphrase(args.passphrase_file, confirm=False)
            chosen = _chosen_pcrs(args.pcrs, env)
            lines = restore(store, env, Path(args.bundle), secret, chosen, actor)
    except (MigrationError, KeyProviderError) as exc:
        print(f"{args.command}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{args.command}: {describe_os_error(exc)}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    return 0
