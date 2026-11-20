"""ns-bos state: show, encrypt or decrypt agent state (docs/AGENT_STATE.md).

`status` reads no key. `encrypt` and `decrypt` take the master key the
store runs on, refuse while a kernel holds the data directory, check every
encrypted file's key id before changing anything, and record what they did
in the audit chain. `decrypt` goes through the operator gate.
"""

import argparse
import contextlib
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from agent_runtime import (
    StateKeyError,
    _is_message_name,
    _open_state,
    _read_bytes,
    _seal,
    _sealed_key_id,
    _temp_name,
    _write_durably,
    encrypt_state_enabled,
    sealed_state,
)
from data_plane.keys import KeyProviderError
from data_plane.keys_cli import (
    MigrationError,
    _record,
    current_key,
    describe_os_error,
    operator_actor,
    operator_gate,
    operator_line,
    sovereign_dir,
)
from data_plane.operator_auth import AUTH_ENV
from data_plane.state import StateCipher

# Messages converted between directory syncs. A plaintext file is removed only
# after the directory entry of its encrypted copy is durable, and back.
BATCH = 256
_ENC = ".enc.json"


def _write_synced(path: Path, data: bytes) -> None:
    """Temporary file, fsync, rename. The caller syncs the directory once
    per batch instead of once per file."""
    tmp = _temp_name(path)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)  # umask applies
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _state_files(agents: Path) -> tuple[Path, Path]:
    return agents / "registry" / "registry.json", agents / "tasks" / "tasks.json"


def _messages(comm: Path, encrypted: bool) -> list[Path]:
    if not comm.is_dir():
        return []
    found = []
    with os.scandir(comm) as entries:
        for entry in entries:
            name = entry.name
            if not _is_message_name(name):
                continue  # temporary files, notes, anything publish did not write
            if name.endswith(_ENC) == encrypted:
                found.append(Path(entry.path))
    return sorted(found)


def status(data_dir: Path, environ: Mapping[str, str]) -> dict:
    """What is encrypted under agents/, from file names and first bytes
    only. Set-aside files are listed because they keep their plaintext."""
    agents = data_dir / "agents"
    registry, tasks = _state_files(agents)

    def kind(path: Path) -> str:
        if not path.exists():
            return "absent"
        return "encrypted" if _sealed_key_id(_read_bytes(path)) else "plaintext"

    comm = agents / "comm"
    found = sealed_state(agents)
    return {
        "setting": encrypt_state_enabled(environ),
        "encrypted": found["files"] > 0,
        "registry": kind(registry),
        "tasks": kind(tasks),
        "messages": {
            "plaintext": len(_messages(comm, False)),
            "encrypted": len(_messages(comm, True)),
        },
        "key_ids": sorted(found["key_ids"]),
        "set_aside": sorted(
            p.relative_to(agents).as_posix() for p in agents.rglob("*.corrupt-*")
        ),
        "temp_files": _temp_files(agents),
    }


def _temp_files(agents: Path) -> list[str]:
    """Temporary files a killed write left under agents/. They can hold the
    plaintext of a save that never finished; nothing reads them."""
    return sorted(p.relative_to(agents).as_posix() for p in agents.rglob(".*.tmp"))


def _check_key_ids(agents: Path, cipher) -> None:
    """Every encrypted file must belong to this key before anything changes."""
    registry, tasks = _state_files(agents)
    others = {}
    for path in (registry, tasks, *_messages(agents / "comm", True)):
        key_id = _sealed_key_id(_read_bytes(path))
        if key_id is not None and key_id != cipher.key_id:
            others.setdefault(key_id, []).append(path.name)
    if others:
        names = sum(len(v) for v in others.values())
        raise MigrationError(
            f"{names} encrypted file{'s' if names != 1 else ''} under agents/ belong "
            f"to another master key (key id {', '.join(sorted(others))}; the key in "
            f"use has {cipher.key_id}). Nothing was changed."
        )


def _convert_messages(
    comm: Path, cipher, encrypt: bool, problems: list[str], progress: list[int]
) -> None:
    """Encrypt each plaintext message to <name>.enc.json, or decrypt each
    encrypted one back to <name>.json, in synced batches. A copy left by an
    interrupted run is reused when it holds the same bytes. A message that
    cannot be read or written is named in problems and the run goes on;
    progress[0] counts the messages whose old file is gone, so far."""
    batch = []

    def flush():
        _sync_dir(comm)
        for source in batch:
            source.unlink()
        _sync_dir(comm)
        progress[0] += len(batch)
        batch.clear()

    for source in _messages(comm, not encrypt):
        name = source.name
        try:
            if encrypt:
                raw = source.read_bytes()
                if _sealed_key_id(raw) is not None:
                    problems.append(
                        f"comm/{name}: already encrypted under a plaintext name; left as is"
                    )
                    continue
                if not isinstance(json.loads(raw), dict):
                    raise ValueError("not a message")
                target = comm / f"{name[:-5]}{_ENC}"
            else:
                raw, was_encrypted = _open_state(source, cipher)
                if not was_encrypted:
                    raise ValueError("not encrypted")
                target = comm / f"{name[: -len(_ENC)]}.json"
        except (ValueError, RecursionError, StateKeyError) as exc:
            problems.append(
                f"comm/{name}: cannot be read ({type(exc).__name__}); left as is"
            )
            continue
        except OSError as exc:
            problems.append(f"comm/{name}: {describe_os_error(exc)}; left as is")
            continue
        if target.exists():
            try:
                same = _open_state(target, cipher)[0] == raw
            except (ValueError, StateKeyError):
                same = False
            if not same:
                problems.append(
                    f"comm/{name}: {target.name} exists with other content; both left as they are"
                )
                continue
        else:
            try:
                _write_synced(target, _seal(raw, cipher) if encrypt else raw)
            except OSError as exc:
                problems.append(
                    f"comm/{name}: {target.name} could not be written "
                    f"({describe_os_error(exc)}); left as is"
                )
                continue
        batch.append(source)
        if len(batch) >= BATCH:
            flush()
    if batch:
        flush()


def convert(
    data_dir: Path,
    environ: Mapping[str, str],
    encrypt: bool,
    actor: str = "local",
    hold_lock: Callable | None = None,
    lines: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Encrypt or decrypt all agent state. Returns (lines, problems); a
    problem is a file left as it was. Lines are appended to the given list
    as the run goes, so a caller can still show them when the run stops on
    an error."""
    lines = [] if lines is None else lines
    store = sovereign_dir(environ, str(data_dir))
    agents = data_dir / "agents"
    lock = (hold_lock or _kernel_lock)(data_dir)
    if lock is None:
        raise MigrationError(
            f"a kernel is running on {data_dir}; stop it first, it rewrites agent "
            "state from memory"
        )
    try:
        key = current_key(store, environ)
        cipher = StateCipher(key)
        _check_key_ids(agents, cipher)
        problems = []
        verb, action = (
            ("encrypted", "state_encrypted")
            if encrypt
            else ("decrypted", "state_decrypted")
        )
        files = _state_files(agents)
        # While any agent state is encrypted the kernel keeps all of it
        # encrypted, so a run cut short is finished by running it again.
        for path in files if encrypt else reversed(files):
            if not path.exists():
                continue
            is_sealed = _sealed_key_id(_read_bytes(path)) is not None
            if is_sealed == encrypt:
                lines.append(f"{path.name}: already {verb}")
                continue
            try:
                raw = path.read_bytes() if encrypt else _open_state(path, cipher)[0]
                if encrypt and not isinstance(json.loads(raw), dict):
                    raise ValueError("not a JSON object")
            except (ValueError, RecursionError) as exc:
                problems.append(
                    f"{path.name}: cannot be read ({type(exc).__name__}); left as is, "
                    "and the kernel sets it aside at start"
                )
                continue
            _write_durably(path, _seal(raw, cipher) if encrypt else raw)
            _record(store, key, action, actor, path.name, {"bytes": len(raw)})
            lines.append(f"{path.name}: {verb} ({len(raw)} bytes)")
        progress = [0]
        try:
            _convert_messages(agents / "comm", cipher, encrypt, problems, progress)
        finally:
            # What was done is recorded even when a directory sync stops the run.
            moved = progress[0]
            if moved:
                _record(store, key, action, actor, "comm", {"messages": moved})
            lines.append(f"comm/: {moved} message{'s' if moved != 1 else ''} {verb}")
    finally:
        lock.close()
    leftovers = _temp_files(agents)
    if encrypt and leftovers:
        lines.append(
            f"{len(leftovers)} temporary file{'s' if len(leftovers) != 1 else ''} "
            "left by a write that was cut short may hold plaintext; `state status` "
            "lists them. Check them, then remove them with the kernel stopped."
        )
    setting = encrypt_state_enabled(environ)
    if encrypt and not setting:
        if sealed_state(agents)["files"]:
            lines.append(
                "NGARI_ENCRYPT_STATE is off; agent state stays encrypted anyway "
                "(docs/AGENT_STATE.md)."
            )
        else:
            lines.append(
                "There is no agent state to encrypt yet, and NGARI_ENCRYPT_STATE is "
                "off, so the kernel will write it in the clear; set it to 1."
            )
    if not encrypt and setting:
        lines.append(
            "NGARI_ENCRYPT_STATE is on, so the next start encrypts it again; unset it "
            "first."
        )
    return lines, problems


def _kernel_lock(data_dir: Path):
    from core.kernel import _hold_instance_lock

    return _hold_instance_lock(data_dir)


def _data_dir(environ: Mapping[str, str], given: str | None) -> Path:
    return sovereign_dir(environ, given).parent


def cli(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    hold_lock: Callable | None = None,
) -> int:
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(
        prog="ns-bos state", description=__doc__.split("\n")[0]
    )
    parser.add_argument(
        "--data-dir", help="kernel data directory (default $NGARI_DATA_DIR)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show what agent state is encrypted; reads no key")
    sub.add_parser("encrypt", help="encrypt all agent state, messages included")
    decrypt = sub.add_parser(
        "decrypt", help="decrypt all agent state, for going back to plaintext"
    )
    decrypt.add_argument(
        "--pin-file", help=f"card PIN, when {AUTH_ENV}=card (else the terminal)"
    )
    args = parser.parse_args(argv)
    data_dir = _data_dir(env, args.data_dir)
    if args.command == "status":
        try:
            print(json.dumps(status(data_dir, env), indent=2))
        except OSError as exc:
            print(f"status: {describe_os_error(exc)}", file=sys.stderr)
            return 1
        return 0
    lines: list[str] = []
    try:
        actor = "local"
        if args.command == "decrypt":
            store = sovereign_dir(env, str(data_dir))
            operator = operator_gate(
                "decrypt", store, env, args.pin_file, family="state"
            )
            if operator:
                actor = operator_actor(operator)
                print(operator_line(operator))
        _, problems = convert(
            data_dir, env, args.command == "encrypt", actor, hold_lock, lines
        )
    except (MigrationError, KeyProviderError) as exc:
        for line in lines:
            print(line)
        print(f"{args.command}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        for line in lines:
            print(line)
        print(f"{args.command}: {describe_os_error(exc)}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    for problem in problems:
        print(f"{args.command}: {problem}", file=sys.stderr)
    return 1 if problems else 0
