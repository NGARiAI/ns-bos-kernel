"""telemetry_config.json: telemetry is forced off, and a damaged file
(empty, cut short or not an object) does not stop the data plane or the
kernel from starting."""

import json
import os

import pytest

from core.kernel.data_plane import SovereignDataPlane


@pytest.fixture
def store(tmp_path):
    SovereignDataPlane(str(tmp_path / "sovereign"))
    return tmp_path / "sovereign"


def _config(store):
    return store / "telemetry_config.json"


@pytest.mark.parametrize(
    "damage",
    [b"", b'{"external_tele', b"[true]", b"42", b"\0" * 64, b"[" * 100_000],
    ids=["empty", "torn", "a list", "a number", "zero bytes", "nested too deep"],
)  # fmt: skip
def test_a_damaged_config_is_set_aside_and_replaced(store, damage):
    _config(store).write_bytes(damage)
    plane = SovereignDataPlane(str(store))
    [aside] = store.glob("telemetry_config.json.corrupt-*")
    assert aside.read_bytes() == damage
    assert json.loads(_config(store).read_text()) == {"external_telemetry": False}
    assert plane.export_compliance_report()["external_telemetry"] is False


def test_the_kernel_starts_with_an_empty_config(tmp_path):
    from core.kernel import NSBOSKernel

    SovereignDataPlane(str(tmp_path / "sovereign"))
    (tmp_path / "sovereign" / "telemetry_config.json").write_bytes(b"")
    assert (
        NSBOSKernel(str(tmp_path)).get_status()["data_sovereignty"][
            "external_telemetry"
        ]
        is False
    )


def test_telemetry_is_switched_off_and_other_settings_kept(store):
    _config(store).write_text(json.dumps({"external_telemetry": True, "endpoint": "x"}))
    SovereignDataPlane(str(store))
    assert json.loads(_config(store).read_text()) == {
        "external_telemetry": False,
        "endpoint": "x",
    }
    assert list(store.glob("telemetry_config.json.corrupt-*")) == []
    assert [p.name for p in store.iterdir() if p.name.endswith(".tmp")] == []


def test_a_config_that_is_already_off_is_not_rewritten(store):
    _config(store).write_text('{"external_telemetry": false, "note": "mine"}')
    os.utime(_config(store), (1, 1))
    SovereignDataPlane(str(store))
    assert _config(store).stat().st_mtime == 1
    assert _config(store).read_text() == '{"external_telemetry": false, "note": "mine"}'


def test_no_config_means_none_is_created(store):
    assert not _config(store).exists()
    SovereignDataPlane(str(store))
    assert not _config(store).exists()


def test_damage_after_start_is_reported_as_unknown(store):
    plane = SovereignDataPlane(str(store))
    _config(store).write_bytes(b'{"external_tele')
    report = plane.export_compliance_report()
    assert report["external_telemetry"] is None
    assert report["data_sovereignty"] == "violations_detected"


def test_a_crash_while_rewriting_keeps_the_old_file(store, monkeypatch):
    from core.kernel import data_plane

    original = json.dumps({"external_telemetry": True})
    _config(store).write_text(original)

    def crash(src, dst):
        raise OSError("power lost")

    monkeypatch.setattr(data_plane.os, "replace", crash)
    with pytest.raises(OSError, match="power lost"):
        SovereignDataPlane(str(store))
    assert _config(store).read_text() == original
    assert [p.name for p in store.iterdir() if p.name.endswith(".tmp")] == []
