"""The notes in docs/ have to name what the code actually reads and runs."""

import argparse
import ast
import datetime
import json
import re
import sys
from pathlib import Path

import pytest

from core.kernel.data_plane import keys, recovery, tpm
from core.kernel.data_plane.keys_cli import cli

DOC_DIR = Path(__file__).resolve().parent.parent / "docs"
DOC = (DOC_DIR / "KEY_PROVIDERS.md").read_text()


def test_every_setting_is_documented_with_its_default():
    rows = {
        keys.PROVIDER_ENV: keys.DEFAULT_PROVIDER,
        tpm.TCTI_ENV: tpm.DEFAULT_TCTI,
        tpm.TIMEOUT_ENV: f"{tpm.DEFAULT_TIMEOUT:g}",
        tpm.PCRS_ENV: "unset",
    }
    for name, default in rows.items():
        assert re.search(rf"\| `{name}` \| `?{re.escape(default)}`? \|", DOC), name


def test_every_provider_and_keys_command_is_documented():
    for name in keys._FACTORIES:
        assert f"`{name}`" in DOC
    parser_commands = [
        "status",
        "migrate",
        "export-recovery",
        "restore",
        "selftest",
        "card-check",
    ]
    for command in parser_commands:
        assert f"`keys {command}" in DOC
        try:
            cli([command, "--help"])
        except SystemExit as exc:
            assert exc.code == 0


def test_recovery_parameters_match_the_code():
    assert recovery.SCRYPT_N == 2**15
    assert "N=2^15, r=8, p=1" in DOC
    assert (recovery.SCRYPT_R, recovery.SCRYPT_P) == (8, 1)
    assert f"at least {recovery.MIN_PASSPHRASE} characters" in DOC


def test_the_piv_note_matches_the_code():
    from core.kernel.data_plane import operator_auth as oa

    piv = (DOC_DIR / "PIV_CAC.md").read_text()
    for name in (oa.AUTH_ENV, oa.MODULE_ENV, oa.TOKEN_ENV, oa.OBJECT_ID_ENV):
        assert f"| `{name}` |" in piv, name
    assert f"| `{oa.OBJECT_ID_ENV}` | `{oa.DEFAULT_KEY_ID}` |" in piv
    assert f"(`{oa.CHALLENGE_LABEL.decode()}`)" in piv


def test_the_key_note_describes_the_card_check():
    from core.kernel.data_plane.operator_auth import AUTH_ENV

    assert f"`{AUTH_ENV}=card`" in DOC
    assert "`operator_auth` audit entry" in DOC
    assert "`--pin-file`" in DOC
    assert "writes the audit log." not in DOC


# -- AUDIT_LOG.md ------------------------------------------------------------------

AUDIT_DOC = (DOC_DIR / "AUDIT_LOG.md").read_text()


def _documented_messages():
    part = AUDIT_DOC.split("## Checking it", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| `([^`]+)` \|", part, re.MULTILINE)
    anchor = AUDIT_DOC.split("## Keeping an anchor", 1)[1]
    found = re.findall(r"(?:fails with|and with) `([^`]+)`", anchor)
    rows += [" ".join(message.split()) for message in found]
    return {
        row: re.compile(re.sub(r"\b[NM]\b", r"\\d+", re.escape(row))) for row in rows
    }


@pytest.fixture
def audited(tmp_path):
    from core.kernel.data_plane import SovereignDataPlane

    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    for i in range(3):
        plane.store_encrypted(f"k{i}", {"i": i})
    return tmp_path / "sovereign" / "audit" / "sovereign_audit.log"


def _verify(tmp_path, capsys, *args):
    from core.kernel.data_plane.audit_cli import cli

    code = cli(["verify", *args], {"NGARI_DATA_DIR": str(tmp_path)})
    out = capsys.readouterr()
    return code, (out.out + out.err).strip()


def _rewrite(log, index, change, rehash=True):
    from core.kernel.data_plane import SovereignDataPlane

    lines = log.read_text().splitlines()
    entry = json.loads(lines[index])
    change(entry)
    if rehash:
        entry["hash"] = SovereignDataPlane._entry_hash(entry)
    lines[index] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n")


def _edit_details(entry):
    entry["details"] = {"size": 0}


def _drop_line(log, index):
    lines = log.read_text().splitlines()
    del lines[index]
    log.write_text("\n".join(lines) + "\n")


def _mac_key_of(log):
    from core.kernel.data_plane import audit_key
    from core.kernel.data_plane.keys import validate_key

    return audit_key(
        validate_key((log.parent.parent / "keys" / "master.key").read_bytes())
    )


def _keyless_rewrite(log):
    """What a writer without the key can do: drop the keyed entries, strip
    every MAC and rebuild the hashes and links."""
    from core.kernel.data_plane import SovereignDataPlane

    out, prev = [], "0" * 64
    for line in log.read_text().splitlines():
        entry = json.loads(line)
        if entry["action"] == "key_provider":
            continue
        entry.pop("mac", None)
        entry["prev_hash"] = prev
        entry["hash"] = prev = SovereignDataPlane._entry_hash(entry)
        out.append(json.dumps(entry))
    log.write_text("\n".join(out) + "\n")


def _false_attestation(log):
    from core.kernel.data_plane import LEGACY_HISTORY, append_audit

    details = {"entries": 9, "tail": "f" * 64}
    append_audit(log, LEGACY_HISTORY, "operator", "audit", details, _mac_key_of(log))


DAMAGE = {
    "unreadable": lambda log: log.write_text(log.read_text() + "not json\n"),
    "keyless rewrite": _keyless_rewrite,
    "false attestation": _false_attestation,
    "removed": lambda log: _drop_line(log, 2),
    "edited": lambda log: _rewrite(log, 1, _edit_details, rehash=False),
    "rewritten": lambda log: _rewrite(log, 1, _edit_details),
    "start unkeyed": lambda log: _rewrite(log, 0, lambda e: e.pop("mac")),
    "later unkeyed": lambda log: _rewrite(log, 2, lambda e: e.pop("mac")),
}


def test_every_audit_failure_is_documented_and_every_documented_one_happens(
    audited, tmp_path, capsys
):
    documented = _documented_messages()
    clean = audited.read_text()
    produced = []
    for damage in DAMAGE.values():
        audited.write_text(clean)
        damage(audited)
        code, out = _verify(tmp_path, capsys)
        assert code == 1 and out.startswith("audit verify: FAILED: "), out
        produced.append(out.removeprefix("audit verify: FAILED: "))
    audited.write_text(clean)
    anchor = tmp_path / "anchor.json"
    from core.kernel.data_plane import audit_anchor

    anchor.write_text(json.dumps(audit_anchor(audited)))
    _drop_line(audited, 3)
    produced.append(_verify(tmp_path, capsys, "--anchor", str(anchor))[1])
    audited.write_text(clean)
    anchor.write_text(json.dumps({"entries": 2, "tail": "f" * 64}))
    produced.append(_verify(tmp_path, capsys, "--anchor", str(anchor))[1])
    produced = [p.removeprefix("audit verify: FAILED: ") for p in produced]
    matched = {
        row for p in produced for row, rx in documented.items() if rx.fullmatch(p)
    }
    assert all(any(rx.fullmatch(p) for rx in documented.values()) for p in produced), (
        produced
    )
    assert matched == set(documented)


def test_a_clean_audit_log_reads_as_documented(audited, tmp_path, capsys):
    from core.kernel.data_plane import AUDIT_KEY_INFO, audit_anchor

    assert "`$NGARI_DATA_DIR/sovereign/audit/sovereign_audit.log`" in AUDIT_DOC
    assert f"info `{AUDIT_KEY_INFO.decode()}`" in AUDIT_DOC
    assert "`audit log OK: N entries verified`" in AUDIT_DOC
    assert _verify(tmp_path, capsys) == (0, "audit log OK: 4 entries verified")
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps(audit_anchor(audited)))
    assert _verify(tmp_path, capsys, "--anchor", str(anchor))[0] == 0
    assert set(json.loads(anchor.read_text())) == {"entries", "tail"}
    example = re.search(r'^    (\{"entries".*\})$', AUDIT_DOC, re.MULTILINE).group(1)
    assert set(json.loads(example)) == {"entries", "tail"}
    with pytest.raises(SystemExit) as bad:
        _verify(tmp_path, capsys, "--bogus")
    assert bad.value.code == 2 and "Exit status 2 means bad arguments" in AUDIT_DOC


def test_every_action_written_to_the_audit_log_is_documented():
    source = "\n".join(
        p.read_text()
        for p in (DOC_DIR.parent / "core" / "kernel" / "data_plane").glob("*.py")
    )
    actions = set(re.findall(r'\b_audit\(\s*"([a-z_]+)"', source))
    actions |= set(re.findall(r'append_audit\(\s*audit_log,\s*"([a-z_]+)"', source))
    actions |= set(re.findall(r'_record\(\s*store,\s*key,\s*"([a-z_]+)"', source))
    actions |= set(
        re.findall(
            r'append_audit\(\s*store / "audit" / "sovereign_audit.log",\s*"([a-z_]+)"',
            source,
        )
    )
    from core.kernel.data_plane import TAIL_SET_ASIDE

    actions.add(TAIL_SET_ASIDE)  # written by append_audit itself, after a crash
    assert actions == {"key_provider", "store_encrypted", "retrieve_decrypted", "delete",
                       "operator_auth", "audit_tail_set_aside", "key_migrated",
                       "recovery_exported", "key_restored", "operator_pinned",
                       "roles_changed", "esignature", "esignature_refused",
                       "agent_sponsored", "agent_sponsor_refused"}  # fmt: skip
    assert all(f"`{action}`" in AUDIT_DOC for action in actions)


# -- the Python floor is enforced by the linter -------------------------------------


def test_ruff_targets_the_oldest_supported_python(tmp_path):
    import subprocess
    import sys

    root = DOC_DIR.parent
    floor = re.search(
        r'python_requires=">=3\.(\d+)"',
        (root / "core" / "kernel" / "setup.py").read_text(),
    )
    target = re.search(
        r'^target-version = "py3(\d+)"$', (root / "ruff.toml").read_text(), re.MULTILINE
    )
    assert floor and target and floor.group(1) == target.group(1)
    newer = tmp_path / "newer.py"
    newer.write_text('d = {"k": 1}\nprint(f"{d["k"]}")\n')
    run = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--no-cache", "--config", str(root / "ruff.toml"), str(newer)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert run.returncode != 0
    assert (
        "Cannot reuse outer quote character in f-strings on Python 3.10" in run.stdout
    )


# -- the kernel entries table --------------------------------------------------------


def _kernel_rows():
    part = AUDIT_DOC.split("## Kernel entries", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for name, details in re.findall(
        r"^\| `([a-z_]+)` \| [^|]+ \| ([^|]+) \|$", part, re.MULTILINE
    ):
        rows[name] = (
            set()
            if details.strip() == "none"
            else set(re.findall(r"`([a-z_]+)`", details.split("(")[0]))
        )
    return rows


def test_the_kernel_entries_table_matches_what_the_kernel_writes(tmp_path, monkeypatch):
    import asyncio

    from core.kernel import KERNEL_ACTOR, NSBOSKernel

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(
        "NGARI_RETENTION_DAYS", "never"
    )  # no sweep on the real clock yet
    kernel = NSBOSKernel()
    agent_id = kernel.register_agent("CEO", "strategic", "a description")
    kernel.agent_runtime.scheduler.register_handler("ok", lambda p: 1)
    kernel.create_task(agent_id, "ok", {})
    kernel.publish_event("topic", {"m": 1})
    kernel.start()
    asyncio.run(kernel.agent_runtime.scheduler.process_queue())
    kernel.stop()
    monkeypatch.setenv("NGARI_ENCRYPT_STATE", "1")  # encrypts the plaintext files
    monkeypatch.delenv("NGARI_RETENTION_DAYS")  # 21 years: expires an old message
    comm = tmp_path / "agents" / "comm"
    (comm / "topic_20500101_000000_000000_0a0b0c0d.json").write_text("{}")
    (comm / "topic_20750601_000000_000000_0a0b0c0e.json").write_text("{}")
    kernel = NSBOSKernel()

    class In2075(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2075, 6, 1, 1, tzinfo=tz)

    runtime = sys.modules[type(kernel.agent_runtime.comm).__module__]
    monkeypatch.setattr(runtime, "datetime", In2075)  # the kernel's own copy
    kernel.start()
    kernel.stop()
    seen = {}
    for entry in kernel.data_plane.get_audit_log(10**6):
        if entry["actor"] == KERNEL_ACTOR:
            seen[entry["action"]] = set(entry["details"])
    documented = _kernel_rows()
    assert seen == documented
    assert "`kernel.audited_actions`" in AUDIT_DOC and "`audit_tail`" in AUDIT_DOC


def test_the_readme_lists_every_doc_and_nothing_else():
    import subprocess

    root = DOC_DIR.parent
    tracked = set(
        subprocess.run(
            ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
        ).stdout.split()
    )
    section = (root / "README.md").read_text().split("## Documentation", 1)[1]
    section = section.split("\n## ", 1)[0]
    rows = set(re.findall(r"^\| `([^`]+)` \|", section, re.MULTILINE))
    docs = {
        path for path in tracked if path.startswith("docs/") and path.endswith(".md")
    }
    assert docs - rows == set(), "docs with no row in README's documentation table"
    assert rows - tracked == set(), "rows naming files that are not in the repository"


# -- every command line against its document -----------------------------------------


class _Built(Exception):
    """Carries the parser a command line built out of parse_args."""


def _parser(cli, monkeypatch):
    def caught(self, *args, **kwargs):
        raise _Built(self)

    with monkeypatch.context() as patch:
        patch.setattr(argparse.ArgumentParser, "parse_args", caught)
        with pytest.raises(_Built) as built:
            cli([])
    return built.value.args[0]


@pytest.mark.parametrize("family", ["keys", "audit", "records", "state"])
def test_every_command_and_option_is_in_its_document(family, monkeypatch):
    from core.kernel import USAGE, state_cli
    from core.kernel.data_plane import audit_cli, keys_cli, records_cli

    cli = {"keys": keys_cli.cli, "audit": audit_cli.cli, "records": records_cli.cli,
           "state": state_cli.cli}[family]  # fmt: skip
    doc = re.search(rf"^  {family} .*\(docs/(\w+\.md)\)$", USAGE, re.MULTILINE).group(1)
    text = (DOC_DIR / doc).read_text()

    def named(word):
        return re.search(re.escape(word) + r"(?![\w-])", text) is not None

    def options(parser):
        return [o for a in parser._actions for o in a.option_strings
                if o.startswith("--") and o != "--help"]  # fmt: skip

    parser = _parser(cli, monkeypatch)
    missing = [o for o in options(parser) if not named(o)]
    [commands] = [
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    ]
    for command, sub in commands.choices.items():
        missing += [] if named(f"{family} {command}") else [f"{family} {command}"]
        missing += [f"{family} {command} {o}" for o in options(sub) if not named(o)]
    assert missing == [], f"not in docs/{doc}"


# Phrases shaped like a command that are not one: the line `audit verify`
# prints when the log checks.
_NOT_COMMANDS = {"audit log"}


def test_every_command_line_a_document_shows_exists(monkeypatch):
    import subprocess

    from core.kernel import state_cli
    from core.kernel.data_plane import audit_cli, keys_cli, records_cli

    known = {}
    for family, command_line in (("keys", keys_cli.cli), ("audit", audit_cli.cli),
                                 ("records", records_cli.cli), ("state", state_cli.cli)):  # fmt: skip
        parser = _parser(command_line, monkeypatch)
        top = {o for a in parser._actions for o in a.option_strings}
        [commands] = [
            a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
        ]
        known[family] = {name: top | {o for a in sub._actions for o in a.option_strings}
                         for name, sub in commands.choices.items()}  # fmt: skip
    root = DOC_DIR.parent
    tracked = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    families = "keys|audit|records|state"
    shapes = (rf"(?:python3? -m core\.kernel|ns-bos) ({families}) ([a-z][a-z-]*)([^\n`]*)",
              rf"`({families}) ([a-z][a-z-]*)([^`\n]*)`")  # fmt: skip
    shown, wrong = 0, []
    for name in tracked:
        text = (root / name).read_text()
        for shape in shapes:
            for family, command, rest in re.findall(shape, text):
                if f"{family} {command}" in _NOT_COMMANDS:
                    continue
                shown += 1
                if command not in known[family]:
                    wrong.append(f"{name}: {family} {command}")
                    continue
                for option in re.findall(r"(?<![\w-])--[a-z][a-z-]*", rest):
                    if option not in known[family][command]:
                        wrong.append(f"{name}: {family} {command} {option}")
    assert shown > 100  # the shapes still match how the documents write commands
    assert wrong == []


# -- refusal reasons ------------------------------------------------------------------


def _refusal_reasons():
    """Every reason an OperatorAuthError can carry, read from the code: its
    second argument, or what a variable passed there is assigned from."""
    reasons = set()
    for path in (DOC_DIR.parent / "core").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            assigned = {}
            for node in ast.walk(func):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assigned.setdefault(target.id, []).append(node.value)
            for node in ast.walk(func):
                called = getattr(node, "func", None)
                name = getattr(called, "id", None) or getattr(called, "attr", None)
                if name != "OperatorAuthError" or len(node.args) < 2:
                    continue
                arg = node.args[1]
                sources = (
                    assigned.get(arg.id, []) if isinstance(arg, ast.Name) else [arg]
                )
                assert sources, (
                    f"{path.name}:{node.lineno} passes a reason from elsewhere"
                )
                for source in sources:
                    reasons |= _values(source)
    return reasons


def _values(node):
    """The strings an expression can give: a literal, or either side of a
    conditional expression (not what its condition tests)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _values(node.body) | _values(node.orelse)
    return set()


def test_every_refusal_reason_is_in_the_table():
    piv = (DOC_DIR / "PIV_CAC.md").read_text()
    table = piv.split("### Refusal reasons", 1)[1].split("\n## ", 1)[0]
    documented = set()
    for line in table.splitlines():
        if line.startswith("| `"):
            documented |= set(re.findall(r"`([^`]+)`", line.split(" | ")[0]))
    assert documented == _refusal_reasons()
    signatures = " ".join((DOC_DIR / "ESIGNATURES.md").read_text().split())
    assert "one of the codes in `PIV_CAC.md`, Refusal reasons" in signatures


# -- what each entry holds ------------------------------------------------------------

# The calls that append an entry, with their action and details arguments. The
# kernel's own runtime entries go through its audit hook instead and are
# checked against the Kernel entries table above.
_WRITERS = {"append_audit": (1, 4), "_record": (2, 5), "_audit": (0, 3)}


def _assignments(func):
    """name -> what is assigned to it in func, tuple unpacking included."""
    assigned = {}
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                assigned.setdefault(target.id, []).append(node.value)
            elif isinstance(target, ast.Tuple):
                value = node.value
                for side in (
                    [value.body, value.orelse]
                    if isinstance(value, ast.IfExp)
                    else [value]
                ):
                    if isinstance(side, ast.Tuple):
                        for name, part in zip(target.elts, side.elts):
                            if isinstance(name, ast.Name):
                                assigned.setdefault(name.id, []).append(part)
    return assigned


def _detail_keys(node, assigned, func):
    """The keys details can hold: every dict literal in it, and for a variable
    what it is assigned, details["x"] = ... and details.update(...)."""
    keys = {k.value for d in ast.walk(node) if isinstance(d, ast.Dict)
            for k in d.keys if isinstance(k, ast.Constant)}  # fmt: skip
    if not isinstance(node, ast.Name):
        return keys
    for value in assigned.get(node.id, []):
        keys |= _detail_keys(value, {}, func)
    for n in ast.walk(func):
        for target in n.targets if isinstance(n, ast.Assign) else []:
            if (isinstance(target, ast.Subscript) and getattr(target.value, "id", None) == node.id
                    and isinstance(target.slice, ast.Constant)):  # fmt: skip
                keys.add(target.slice.value)
        called = n.func if isinstance(n, ast.Call) else None
        if (isinstance(called, ast.Attribute) and called.attr == "update"
                and getattr(called.value, "id", None) == node.id):  # fmt: skip
            keys |= {k.arg for k in n.keywords if k.arg}
            for arg in n.args:
                keys |= _detail_keys(arg, {}, func)
    return keys


def _written_entries():
    """action -> the details keys its entries can hold, for every entry the
    data plane and the keys, audit, records and state commands write."""
    trees = {
        path: ast.parse(path.read_text())
        for path in (DOC_DIR.parent / "core").rglob("*.py")
    }
    constants = {}
    for tree in trees.values():
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                constants[node.targets[0].id] = _values(node.value)
    entries = {}
    for path, tree in trees.items():
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = {a.arg for a in func.args.args + func.args.kwonlyargs}
            assigned = _assignments(func)
            for call in ast.walk(func):
                name = getattr(getattr(call, "func", None), "id", None) or getattr(
                    getattr(call, "func", None), "attr", None
                )
                if name not in _WRITERS or (
                    name == "_audit" and path.parent.name != "data_plane"
                ):
                    continue
                at, dt = _WRITERS[name]
                if len(call.args) <= max(at, dt):
                    continue
                action = call.args[at]
                if isinstance(action, ast.Name) and action.id in params:
                    continue  # passes its caller's action on
                if isinstance(action, ast.Name):
                    actions = set().union(
                        *map(_values, assigned.get(action.id, []))
                    ) or (constants.get(action.id, set()))
                else:
                    actions = _values(action)
                assert actions, f"{path.name}:{call.lineno}: action not read"
                for one in actions:
                    entries.setdefault(one, set()).update(
                        _detail_keys(call.args[dt], assigned, func)
                    )
    return entries


def test_every_detail_an_entry_holds_is_named_where_its_action_is():
    entries = _written_entries()
    assert {"operator_auth", "esignature", "key_restored", "legacy_history",
            "state_decrypted", "store_encrypted"} <= set(entries)  # fmt: skip
    paragraphs = [" ".join(part.split()) for doc in DOC_DIR.glob("*.md")
                  for part in re.split(r"\n\s*\n", doc.read_text())]  # fmt: skip
    missing = {}
    for action, held in entries.items():
        about = [p for p in paragraphs if f"`{action}`" in p]
        lost = sorted(k for k in held if not any(f"`{k}`" in p for p in about))
        if not about or lost:
            missing[action] = lost or "named nowhere"
    assert missing == {}


# -- AGENT_RUNTIME.md ----------------------------------------------------------------


def test_the_agent_runtime_page_states_the_limits_the_code_has():
    import inspect

    from core.kernel import agent_runtime, generative_ui, inference

    doc = " ".join((DOC_DIR / "AGENT_RUNTIME.md").read_text().split())
    assert agent_runtime.MAX_PAYLOAD_BYTES == 256 * 1024 and "256 KiB" in doc
    assert agent_runtime.MAX_DESCRIPTION_BYTES == 4 * 1024 and "At most 4 KiB" in doc
    assert agent_runtime.MAX_TEXT_BYTES == 256 and "at most 256 bytes each" in doc
    assert f"at most {agent_runtime.MAX_TOPIC_BYTES} bytes in UTF-8" in doc
    assert f"nested more than {agent_runtime.MAX_RESULT_DEPTH} deep" in doc
    assert json.dumps(agent_runtime.UNSTORABLE_RESULT) in doc
    assert f"{inference.MAX_TOOL_CALLS} by default" in doc
    loop = inspect.signature(inference.OllamaInterface.chat_with_tools).parameters
    assert f"`max_iterations` ({loop['max_iterations'].default} by default)" in doc
    assert loop["max_tool_calls"].default == inference.MAX_TOOL_CALLS
    source = inspect.getsource(inference)
    assert all(marker in source and marker in doc
               for marker in ("[_tool_calls_exceeded]", "[_iterations_exceeded]"))  # fmt: skip
    assert generative_ui._COMPONENT_TYPE.pattern == "[a-z][a-z0-9-]*"
    assert "A lowercase letter, then lowercase letters, digits or `-`" in doc
    assert "cut to 200 characters (500 for an error)" in doc
    assert inspect.signature(agent_runtime._logged).parameters["limit"].default == 200


# -- SANDBOX.md ------------------------------------------------------------------------


def _table(doc: str, header: str) -> dict[str, list[str]]:
    """The rows of the Markdown table under header, keyed by first cell."""
    rows, inside = {}, False
    for line in doc.splitlines():
        if line.startswith(header):
            inside = True
        elif inside and line.startswith("|") and not line.startswith("|--"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            rows[cells[0]] = cells[1:]
        elif inside and not line.startswith("|"):
            break
    return rows


def test_the_sandbox_page_states_what_the_code_does():
    import inspect
    import re

    from core.kernel.sandbox import bwrap, seccomp

    text = (DOC_DIR / "SANDBOX.md").read_text()
    doc = " ".join(text.split())
    # The limits table: each default as the code has it, set with what it says.
    limits = _table(text, "| Limit |")
    params = inspect.signature(bwrap.BwrapSandbox.__init__).parameters
    expected = {
        "Wall time": (f"{bwrap.DEFAULT_TIMEOUT} s", "timeout", bwrap.DEFAULT_TIMEOUT),
        "Output kept": (f"{bwrap.MAX_OUTPUT:,} characters", "max_output", bwrap.MAX_OUTPUT),
        "Address space": (f"{bwrap.MEMORY_LIMIT >> 30} GiB", "memory_limit", bwrap.MEMORY_LIMIT),
        "Largest file written": (f"{bwrap.TMPFS_SIZE >> 20} MiB", "tmpfs_size", bwrap.TMPFS_SIZE),
        "Processes": (str(bwrap.MAX_PROCESSES), "max_processes", bwrap.MAX_PROCESSES),
    }  # fmt: skip
    for start, (value, param, default) in expected.items():
        [row] = [cells for label, cells in limits.items() if label.startswith(start)]
        assert row == [value, f"`{param}`"], start
        assert params[param].default == default, param
    assert limits["Open files, per process"] == [
        str(bwrap.MAX_OPEN_FILES),
        "`MAX_OPEN_FILES`",
    ]
    assert len(limits) == len(expected) + 1  # no limit the code does not have
    # The calls restricted refuses: every one named, none that is not.
    part = doc[
        doc.index("`restricted` refuses with EPERM") : doc.index("It refuses `clone`")
    ]
    named = set(re.findall(r"`([a-z0-9_]+)`", part)) - {"restricted"}
    if "io_uring" in named:  # the page's name for the three io_uring calls
        named = named - {"io_uring"} | {
            n for n in seccomp.DANGEROUS_SYSCALLS if n.startswith("io_uring_")
        }
    assert named == set(seccomp.DANGEROUS_SYSCALLS)
    # The levels, and the default.
    assert (
        bwrap.DEFAULT_SECCOMP_LEVEL == "restricted"
        and "`restricted` is the default" in doc
    )
    assert set(bwrap.SECCOMP_LEVELS) == {"", "restricted", "strict"}
    # Mounts: the writable ones are the tmpfs mounts, the read-only binds are named.
    args = bwrap._build_bwrap_args()
    tmpfs = [args[i + 1] for i, a in enumerate(args) if a == "--tmpfs"]
    assert set(tmpfs) == {"/tmp", "/home", "/mnt", "/root", "/var", "/run", "/dev/shm"}
    assert all(f"`{m}`" in doc for m in tmpfs)
    binds = [
        args[i + 1] for i, a in enumerate(args) if a in ("--ro-bind", "--ro-bind-try")
    ]
    assert all(f"`{b}`" in doc or f"`{b.rsplit('/', 1)[1]}`" in doc for b in binds), (
        binds
    )
    # The error names a result can carry.
    errors = _table(text, "| `error` |")
    assert {"`timeout:<N>s`", "`sandbox_unavailable`", f"`{bwrap.SECCOMP_NOT_INSTALLED}`",
            f"`{bwrap.SANDBOX_NOT_STARTED}`", "anything else"} == set(errors)  # fmt: skip
    assert "sandbox_unavailable" in inspect.getsource(bwrap)


# -- RETENTION.md ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "kept"),
    [(None, 7671), ("", 7671), ("never", None), ("NEVER", None), ("7671", 7671),
     ("9000", 9000), ("7670", None), ("365", None), ("21y", None), ("-1", None)],
)  # fmt: skip
def test_the_retention_page_states_what_the_setting_does(value, kept, caplog):
    import logging
    from datetime import date

    from core.kernel import NSBOSKernel, agent_runtime

    text = (DOC_DIR / "RETENTION.md").read_text()
    doc = " ".join(text.split())
    floor = agent_runtime.RETENTION_FLOOR_DAYS
    assert floor == agent_runtime.RETENTION_DEFAULT_DAYS == 7671 == 21 * 365 + 6
    assert f"the minimum: {floor} days" in doc and f"{floor} or more" in doc
    [row] = _table(text, "| Variable |").values()
    assert _table(text, "| Variable |") == {f"`{agent_runtime.RETENTION_ENV}`": row}
    assert row[0] == f"{floor} (21 years)"
    # The row's meaning, as the code reads the variable.
    caplog.set_level(logging.ERROR)
    env = {} if value is None else {agent_runtime.RETENTION_ENV: value}
    assert agent_runtime.retention_days(env) == kept
    refused = value not in (None, "") and kept is None and value.lower() != "never"
    assert refused == any(str(floor) in r.getMessage() for r in caplog.records)
    # The dates before which a message name says nothing about its age.
    for when in (
        agent_runtime._EARLIEST_V010_NAME,
        agent_runtime._EARLIEST_CURRENT_NAME,
    ):
        assert date.isoformat(when.date()) in doc
    assert NSBOSKernel.SWEEP_SECONDS == 24 * 60 * 60 and "once a day" in doc


# -- PII_REDACTION.md ------------------------------------------------------------------


def test_the_pii_page_examples_are_redacted_as_it_says():
    import inspect
    import re
    import uuid

    import core.kernel as kernel_mod
    from core.kernel.data_plane.redact import redact

    text = (DOC_DIR / "PII_REDACTION.md").read_text()
    doc = " ".join(text.split())
    # Each example the page gives, found as the kind it names.
    for example in (
        "1-800-555-0199",
        "(415) 555-0132",
        "+44 20 7946 0958",
        "+33 1 23 45 67 89",
    ):
        assert (
            f"`{example}`" in doc
            and redact(f"call {example} today") == "call [phone] today"
        )
    for example in ("123-45-6789", "123 45 6789"):
        assert f"`{example}`" in doc and redact(f"id {example}") == "id [ssn]"
    assert '`store_encrypted("patient 123-45-6789")` names `patient [ssn]`' in doc
    assert redact("patient 123-45-6789") == "patient [ssn]"
    assert (
        "`patient_123-45-6789`" in doc
        and redact("patient_123-45-6789") == "patient_[ssn]"
    )
    for kind in ("[email]", "[phone]", "[ssn]", "[card]", "[address]"):
        assert f"`{kind}`" in doc
    assert redact("write to someone@example.org") == "write to [email]"
    # Never matched: what the audit chain depends on.
    for kept in ("0" * 63 + "1", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                 str(uuid.UUID(int=1234567890123456789)), "2026-11-03T12:00:00+00:00"):  # fmt: skip
        assert redact(kept) == kept
    # Cards only when the Luhn check passes; every card in a run is found.
    card = " ".join(["4111"] + ["1111"] * 3)
    assert redact(f"visit 3 {card}") == "visit 3 [card]"
    assert (
        redact(card[:-1] + "2") == card[:-1] + "2"
    )  # fails the check: an order number
    # The variable, its values and the formatter the page shows.
    [row] = _table(text, "| Variable |").values()
    assert (
        set(_table(text, "| Variable |")) == {f"`{kernel_mod.REDACT_ENV}`"}
        and row[0] == "on"
    )
    off = re.findall(r"`(\w+)`", row[1].split("keep")[0])
    assert off == ["0", "false", "no", "off"]
    assert all(f'"{v}"' in inspect.getsource(kernel_mod.main) for v in off)
    assert "from core.kernel.data_plane.redact import RedactingFormatter" in text
