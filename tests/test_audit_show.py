"""`audit show` (docs/AUDIT_LOG.md, 21 CFR 11.10(b)): the audit trail for
inspection, in readable form or as stored, printed only once a check of
exactly those bytes has passed."""

import datetime
import json
import threading
from pathlib import Path

import pytest

from core.kernel.data_plane import (
    SovereignDataPlane,
    append_audit,
    audit_cli,
    audit_key,
    checked_copy,
)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    root = tmp_path / "data" / "sovereign"
    plane = SovereignDataPlane(str(root))  # key_provider
    plane.store_encrypted("report", b"x")  # store_encrypted
    plane.record("agent_registered", "kernel", "a1", {"name": "CEO agent", "type": "x"})
    return root


def _log(store):
    return store / "audit" / "sovereign_audit.log"


def _show(store, capsys, *args):
    env = {"NGARI_DATA_DIR": str(store.parent), "NGARI_KEY_PROVIDER": "file"}
    code = audit_cli.cli(["show", *args], env)
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err


@pytest.mark.part11("11.10(b)")
def test_a_verified_log_is_shown_in_readable_form(store, capsys):
    code, out, err = _show(store, capsys)
    assert code == 0 and err == ""
    entries = [json.loads(x) for x in _log(store).read_text().splitlines()]
    assert out[0] == "audit log verified: 3 entries; 3 shown"
    assert out[1:] == [
        (
            f"1  {entries[0]['timestamp']}  key_provider  system  file  air_gap=true "
            "hardware_bound=false ok=true"
        ),
        f"2  {entries[1]['timestamp']}  store_encrypted  system  report  size=100",
        (
            f"3  {entries[2]['timestamp']}  agent_registered  kernel  a1  "
            'name="CEO agent" type=x'
        ),
    ]


@pytest.mark.part11("11.10(b)")
def test_json_gives_the_entries_exactly_as_stored(store, capsys):
    code, out, _ = _show(store, capsys, "--json")
    assert code == 0
    assert out == _log(store).read_text().splitlines()


def test_details_that_are_not_plain_words_are_quoted(tmp_path):
    entry = {
        "timestamp": "t", "action": "a", "actor": "x y", "resource": "",
        "details": {"nested": {"b": 1, "a": [1, "two"]}, "eq": "a=b", "none": None},
    }  # fmt: skip
    assert audit_cli._readable(7, entry) == (
        '7  t  a  "x y"  ""  eq="a=b" nested={"a": [1, "two"], "b": 1} none=null'
    )
    assert audit_cli._readable(8, {**entry, "details": "plain"}).endswith("  plain")
    assert audit_cli._readable(9, {**entry, "details": {}}).endswith('""')


@pytest.mark.parametrize(
    ("value", "shown"),
    [("Zoë", "Zoë"), ("\x1b[2K", '"\\u001b[2K"'), ("a\rb", '"a\\rb"'),
     ("a\tb", '"a\\tb"'), ("\u202eevil", '"\\u202eevil"'), ("\u200b", '"\\u200b"'),
     ("bad-\udcff", '"bad-\\udcff"'), ("a\x7fb", '"a\\u007fb"')],
    ids=["accent", "escape", "cr", "tab", "bidi", "zero-width", "surrogate", "del"],
)  # fmt: skip
def test_nothing_unprintable_reaches_the_terminal(value, shown):
    assert audit_cli._value(value) == shown


def test_an_agent_cannot_write_terminal_controls_into_the_view(store, capsys, tmp_path):
    from core.kernel.agent_runtime import TaskScheduler

    plane = SovereignDataPlane(str(store))
    tasks = TaskScheduler(
        str(tmp_path / "tasks"), audit=lambda a, r, d: plane.record(a, "kernel", r, d)
    )
    tasks.create_task("a1", "\x1b[1A\x1b[2K\rx", {})  # cursor up, erase line, CR
    code, out, _ = _show(store, capsys)
    assert code == 0
    assert [x for x in out if any(ord(c) < 0x20 or ord(c) == 0x7F for c in x)] == []


def test_a_details_key_cannot_add_a_line(store, capsys):
    fake = "x\n9  2026-10-31T09:00:00+00:00  esignature  qa_lead  batch-42  meaning=approval"
    SovereignDataPlane(str(store)).record(
        "agent_registered", "kernel", "a2", {fake: "y"}
    )
    code, out, _ = _show(store, capsys)
    assert code == 0 and out[0] == "audit log verified: 5 entries; 5 shown"
    assert len(out) == 6


def test_an_entry_that_is_not_utf_8_text_is_shown_on_a_strict_terminal(store):
    import os
    import subprocess
    import sys

    SovereignDataPlane(str(store)).record(
        "state_encrypted", "kernel", "agent-\udcff.json", {"bytes": 1}
    )
    env = {**os.environ, "NGARI_DATA_DIR": str(store.parent), "NGARI_KEY_PROVIDER": "file",
           "PYTHONIOENCODING": "utf-8"}  # fmt: skip
    root = Path(__file__).resolve().parent.parent
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel", "audit", "show"], cwd=root, env=env,
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert run.returncode == 0, run.stderr
    assert '"agent-\\udcff.json"' in run.stdout


def test_filters_by_action_and_actor(store, capsys):
    _, out, _ = _show(store, capsys, "--action", "store_encrypted")
    assert out[0].endswith("; 1 shown") and out[1].startswith("2  ")
    _, out, _ = _show(
        store, capsys, "--action", "store_encrypted", "--action", "key_provider"
    )
    assert [line.split()[0] for line in out[1:]] == ["1", "2"]
    _, out, _ = _show(store, capsys, "--actor", "kernel")
    assert [line.split()[0] for line in out[1:]] == ["3"]
    _, out, _ = _show(store, capsys, "--actor", "nobody")
    assert out == ["audit log verified: 3 entries; 0 shown"]


def _restamp(store, stamps):
    """Give each entry a time and rebuild the chain, as a key holder could."""
    from core.kernel.data_plane import _entry_mac

    key = audit_key((store / "keys" / "master.key").read_bytes())
    lines = [json.loads(x) for x in _log(store).read_text().splitlines()]
    prev = "0" * 64
    for entry, stamp in zip(lines, stamps, strict=True):
        entry["timestamp"], entry["prev_hash"] = stamp, prev
        entry.pop("hash")
        entry.pop("mac", None)
        entry["mac"] = _entry_mac(key, entry)
        entry["hash"] = SovereignDataPlane._entry_hash(entry)
        prev = entry["hash"]
    _log(store).write_text("".join(json.dumps(e) + "\n" for e in lines))


def test_filters_by_date_and_time(store, capsys):
    _restamp(store, ["2026-10-29T23:59:59+00:00", "2026-10-30T12:00:00+00:00",
                     "2026-10-31T00:00:00+00:00"])  # fmt: skip
    _, out, _ = _show(store, capsys, "--since", "2026-10-30")
    assert [x.split()[0] for x in out[1:]] == ["2", "3"]
    _, out, _ = _show(store, capsys, "--until", "2026-10-30")  # the whole day
    assert [x.split()[0] for x in out[1:]] == ["1", "2"]
    _, out, _ = _show(store, capsys, "--since", "2026-10-30", "--until", "2026-10-30")
    assert [x.split()[0] for x in out[1:]] == ["2"]
    _, out, _ = _show(store, capsys, "--since", "2026-10-30T12:00:01Z")
    assert [x.split()[0] for x in out[1:]] == ["3"]
    _, out, _ = _show(
        store, capsys, "--until", "2026-10-30T12:00:00"
    )  # a time: before it
    assert [x.split()[0] for x in out[1:]] == ["1"]


def test_the_last_day_of_the_calendar_is_a_date_like_any(store, capsys):
    code, out, _ = _show(store, capsys, "--until", "9999-12-31")
    assert code == 0 and out[0] == "audit log verified: 3 entries; 3 shown"
    code, out, _ = _show(store, capsys, "--since", "9999-12-31")
    assert code == 0 and out == ["audit log verified: 3 entries; 0 shown"]


class _Py310Datetime(datetime.datetime):
    """fromisoformat as Python 3.10 has it: no trailing Z."""

    @classmethod
    def fromisoformat(cls, value):
        if value.endswith(("Z", "z")):
            raise ValueError(f"Invalid isoformat string: {value!r}")
        return super().fromisoformat(value)


def test_a_utc_z_time_works_on_python_3_10_too(store, capsys, monkeypatch):
    _restamp(store, ["2026-10-29T23:59:59Z", "2026-10-30T12:00:00+00:00",
                     "2026-10-31T00:00:00z"])  # fmt: skip
    monkeypatch.setattr(audit_cli, "datetime", _Py310Datetime)
    _, out, _ = _show(store, capsys, "--since", "2026-10-30T12:00:01Z")
    assert [x.split()[0] for x in out[1:]] == ["3"]
    _, out, _ = _show(store, capsys, "--until", "2026-10-30T12:00:00Z")
    assert [x.split()[0] for x in out[1:]] == ["1"]


def test_an_entry_with_no_readable_time_is_left_out_of_a_date_filter():
    class Args:
        action, actor, json = None, None, False
        since = audit_cli._day("2026-01-01", False)
        until = None

    lines = [b'{"action": "a", "timestamp": "yesterday"}\n', b'{"action": "b"}\n']
    out, shown, total = audit_cli.show(lines, Args)
    assert (out, shown, total) == ([], 0, 2)


@pytest.mark.parametrize("value", ["31/10/2026", "2026-13-01", "soon"])
def test_a_bad_date_is_refused(store, capsys, value):
    env = {"NGARI_DATA_DIR": str(store.parent), "NGARI_KEY_PROVIDER": "file"}
    with pytest.raises(SystemExit) as caught:
        audit_cli.cli(["show", "--since", value], env)
    assert caught.value.code == 2
    assert "is not a date" in capsys.readouterr().err


def _edit(store, number=2):
    lines = _log(store).read_text().splitlines()
    entry = json.loads(lines[number - 1])
    entry["resource"] = "edited"
    lines[number - 1] = json.dumps(entry)
    _log(store).write_text("\n".join(lines) + "\n")


def test_a_log_that_fails_its_check_is_not_shown(store, capsys):
    _edit(store)
    code, out, err = _show(store, capsys)
    assert code == 1 and out == []
    assert "FAILED: entry 2 does not match its hash; nothing shown" in err


def test_unverified_shows_it_under_a_warning_and_still_exits_1(store, capsys):
    _edit(store)
    with open(_log(store), "a") as f:
        f.write("not an entry\n[1, 2]\n")
    code, out, _ = _show(store, capsys, "--unverified")
    assert code == 1
    assert out[0] == "NOT VERIFIED: entry 2 does not match its hash"
    assert [x.split("  ")[0] for x in out[1:]] == ["1", "2", "3", "4", "5"]
    assert "  edited  " in out[2]  # entries after the problem are shown too
    assert out[4:] == ["4  unreadable line", "5  unreadable line"]


def test_blank_lines_do_not_shift_the_numbers(store, capsys):
    lines = _log(store).read_text().splitlines()
    _log(store).write_text(lines[0] + "\n\n" + "\n".join(lines[1:]) + "\n  \n")
    code, out, _ = _show(store, capsys)
    assert code == 0 and out[0] == "audit log verified: 3 entries; 3 shown"
    assert [x.split()[0] for x in out[1:]] == ["1", "2", "3"]


def test_a_line_the_check_finds_unreadable_is_shown_as_one(store, capsys):
    # \x0c and \x0b are whitespace to bytes.strip() but not to JSON.
    lines = _log(store).read_text().splitlines()
    _log(store).write_text(lines[0] + "\n\x0c\n" + "\n".join(lines[1:]) + "\n")
    code, out, _ = _show(store, capsys, "--unverified")
    assert code == 1 and out[0] == "NOT VERIFIED: unreadable entry"
    assert out[2] == "2  unreadable line"
    assert [x.split("  ")[0] for x in out[1:]] == ["1", "2", "3", "4"]


def test_history_from_before_the_key_must_be_vouched_for(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    root = tmp_path / "data" / "sovereign"
    (root / "audit").mkdir(parents=True)
    append_audit(root / "audit" / "sovereign_audit.log", "old", "v0.1.0", "x", {})
    SovereignDataPlane(str(root))  # the first keyed entry
    code, out, err = _show(root, capsys)
    assert code == 1 and out == []
    assert "unkeyed entries from before the key are not attested" in err


def test_unverified_json_has_the_warning_first(store, capsys):
    _edit(store)
    code, out, _ = _show(store, capsys, "--unverified", "--json")
    assert code == 1 and out[0].startswith("NOT VERIFIED: ")
    assert out[1:] == _log(store).read_text().splitlines()


@pytest.mark.parametrize(
    "rewrite",
    [lambda x: x.replace("{", '{"actor": "qa_lead", ', 1),
     lambda x: x.replace('"details": {', '"details": {"name": "x", ', 1),
     lambda x: (x + "\n").encode("utf-16-be")],  # newline too, so it splits as one line
    ids=["field-twice", "nested-field-twice", "utf-16"],
)  # fmt: skip
def test_a_line_that_says_more_than_was_hashed_does_not_verify(store, capsys, rewrite):
    from core.kernel.data_plane import check_audit_chain

    lines = _log(store).read_bytes().splitlines(keepends=True)
    text = lines[2].decode().rstrip("\n")
    changed = rewrite(text)
    lines[2] = changed if isinstance(changed, bytes) else changed.encode() + b"\n"
    _log(store).write_bytes(b"".join(lines))
    key = audit_key((store / "keys" / "master.key").read_bytes())
    assert check_audit_chain(_log(store), key) == "unreadable entry"
    code, out, err = _show(store, capsys, "--json")
    assert code == 1 and out == [] and "unreadable entry" in err


def test_an_anchor_is_checked_first(store, capsys, tmp_path):
    from core.kernel.data_plane import audit_anchor

    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps(audit_anchor(_log(store))))
    code, out, _ = _show(store, capsys, "--anchor", str(anchor))
    assert code == 0 and out[0].endswith("3 entries and matches the anchor; 3 shown")
    lines = _log(store).read_text().splitlines()
    _log(store).write_text("\n".join(lines[:2]) + "\n")  # the tail removed
    code, out, err = _show(store, capsys, "--anchor", str(anchor))
    assert code == 1 and out == []
    assert "log has 2 entries, the anchor recorded 3" in err


def test_no_log_yet_shows_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    root = tmp_path / "data" / "sovereign"
    SovereignDataPlane(str(root))
    _log(root).unlink()
    code, out, _ = _show(root, capsys)
    assert code == 0 and out == ["audit log verified: 0 entries; 0 shown"]


def test_a_key_that_cannot_be_loaded_shows_nothing(store, capsys):
    (store / "keys" / "master.key").write_bytes(b"not a key")
    code, out, err = _show(store, capsys)
    assert code == 1 and out == [] and "audit show:" in err


# -- what is shown is what was checked ---------------------------------------------


def test_the_copy_is_what_was_checked_and_holds_no_lock(store):
    key = audit_key((store / "keys" / "master.key").read_bytes())
    reason, copy = checked_copy(_log(store), key)
    with copy:
        assert reason is None
        done = threading.Event()
        worker = threading.Thread(
            target=lambda: (
                append_audit(_log(store), "later", "x", "y", {}, key),
                done.set(),
            )
        )
        worker.start()
        assert done.wait(5), "an append waited for the copy's reader"
        worker.join()
        shown = copy.read().decode().splitlines()
    assert len(shown) == 3  # the entry appended after the check is not in it
    assert len(_log(store).read_text().splitlines()) == 4
    assert sorted(p.name for p in (store / "audit").iterdir()) == [
        "sovereign_audit.log"
    ]


FORGED = {"timestamp": "2026-10-31T09:00:00+00:00", "action": "esignature",
          "actor": "qa_lead", "resource": "batch-42", "details": {},
          "prev_hash": "0" * 64, "hash": "0" * 64}  # fmt: skip


def test_bytes_written_after_a_passing_check_are_not_shown(store, capsys, monkeypatch):
    # The lock is advisory: a writer without the key that ignores it can add
    # a line once the check has read to the end.
    from core.kernel import data_plane

    real = data_plane._check_entries

    def check_then_append_unlocked(lines, chain, mac_key):
        reason = real(lines, chain, mac_key)
        with open(_log(store), "ab") as f:
            f.write((json.dumps(FORGED) + "\n").encode())
        return reason

    monkeypatch.setattr(data_plane, "_check_entries", check_then_append_unlocked)
    code, out, _ = _show(store, capsys)
    assert code == 0 and out[0] == "audit log verified: 3 entries; 3 shown"
    assert not any("qa_lead" in line for line in out)


def test_a_failed_check_still_copies_the_whole_log(store):
    _edit(store, 1)
    key = audit_key((store / "keys" / "master.key").read_bytes())
    reason, copy = checked_copy(_log(store), key)
    with copy:
        assert reason == "entry 1 does not match its hash"
        assert copy.read() == _log(store).read_bytes()


def test_a_copy_that_fails_midway_is_closed(store, monkeypatch):
    from core.kernel import data_plane

    key = audit_key((store / "keys" / "master.key").read_bytes())
    opened = []
    real = data_plane.tempfile.TemporaryFile

    def tracked(*args, **kwargs):
        f = real(*args, **kwargs)
        opened.append((f, kwargs.get("dir")))
        return f

    def broken(*args):
        raise OSError(5, "Input/output error")

    _edit(store, 1)  # a failed check copies the rest, which here fails
    monkeypatch.setattr(data_plane.tempfile, "TemporaryFile", tracked)
    monkeypatch.setattr(data_plane.shutil, "copyfileobj", broken)
    with pytest.raises(OSError):
        checked_copy(_log(store), key)
    [(copy, where)] = opened
    assert copy.closed
    assert where == store / "audit"  # on the log's disk, not in a RAM /tmp


def test_the_command_line_reaches_show(store, capsys, monkeypatch):
    from core import kernel as kernel_mod

    monkeypatch.setenv("NGARI_DATA_DIR", str(store.parent))
    with pytest.raises(SystemExit) as caught:
        kernel_mod.main(["audit", "show", "--action", "key_provider"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.startswith("audit log verified: 3 entries; 1 shown")


def test_the_doc_shows_the_command():
    doc = (Path(__file__).resolve().parent.parent / "docs" / "AUDIT_LOG.md").read_text()
    assert "python -m core.kernel audit show" in doc
