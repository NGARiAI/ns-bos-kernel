"""A damaged or rejected file is moved aside under <name>.<kind>-<UTC time>
and never over an earlier one: a second file in the same second gets -1,
-2 and so on, with or without hard links. One copy of the helper per
module (the double import), all the same text."""

import datetime
import errno
import inspect
import json
import os

import pytest

from core.kernel import (
    agent_runtime,
    data_plane,
    generative_ui,
    inference,
    network_sync,
)

MODULES = (agent_runtime, data_plane, generative_ui, inference, network_sync)


class Fixed(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 10, 31, 1, 2, 3, tzinfo=tz)


@pytest.fixture
def same_second(monkeypatch):
    for module in MODULES:
        monkeypatch.setattr(module, "datetime", Fixed)


def test_the_copies_are_the_same_text():
    assert len({inspect.getsource(m._keep_aside) for m in MODULES}) == 1


@pytest.mark.parametrize("module", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_a_second_file_in_the_same_second_does_not_overwrite_the_first(
    tmp_path, same_second, module
):
    path = tmp_path / "state.json"
    path.write_text("first")
    first = module._keep_aside(path, "corrupt")
    path.write_text("second")
    second = module._keep_aside(path, "corrupt")
    assert (first.name, second.name) == (
        "state.json.corrupt-20261031T010203Z",
        "state.json.corrupt-20261031T010203Z-1",
    )
    assert (first.read_text(), second.read_text()) == ("first", "second")
    assert not path.exists()


@pytest.mark.parametrize("module", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_without_hard_links_nothing_is_overwritten_either(
    tmp_path, same_second, monkeypatch, module
):
    def no_links(src, dst):
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", no_links)
    path = tmp_path / "state.json"
    for text in ("first", "second"):
        path.write_text(text)
        module._keep_aside(path, "rejected")
    kept = sorted(p.name for p in tmp_path.iterdir())
    assert kept == [
        "state.json.rejected-20261031T010203Z",
        "state.json.rejected-20261031T010203Z-1",
    ]


def test_two_rejected_twins_in_one_second_are_both_kept(tmp_path, same_second):
    sync = network_sync.NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.a", 1)
    good = json.loads((tmp_path / "digital_twin.json").read_text())
    for value in (2, 3):
        edited = dict(good, preferences={"a": value})
        (tmp_path / "digital_twin.json").write_text(json.dumps(edited))
        network_sync.NetworkSynchronization(str(tmp_path))
    kept = sorted(tmp_path.glob("digital_twin.json.rejected-*"))
    assert [json.loads(p.read_text())["preferences"]["a"] for p in kept] == [2, 3]
    entries = [json.loads(x) for x in (tmp_path / "sync.log").read_text().splitlines()]
    assert [e["kept_as"] for e in entries if e["action"] == "twin_rejected"] == [
        p.name for p in kept
    ]


def test_a_deeply_nested_twin_is_set_aside_and_the_kernel_starts(tmp_path, monkeypatch):
    from core.kernel import NSBOSKernel

    (tmp_path / "sync").mkdir()
    (tmp_path / "sync" / "digital_twin.json").write_bytes(b"[" * 100_000)
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    NSBOSKernel()
    assert len(list((tmp_path / "sync").glob("digital_twin.json.corrupt-*"))) == 1


def test_history_skips_a_line_that_is_not_utf8(tmp_path):
    sync = network_sync.NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.a", 1)
    with open(tmp_path / "sync.log", "ab") as f:
        f.write(b'{"key": "\xff\xfe"}\n')
    sync.update_twin("pref.b", 2)
    assert [e["key"] for e in sync.get_sync_history()] == ["pref.a", "pref.b"]
