"""Inter-agent message retention: 21 years by default and at the least
(NGARI_RETENTION_DAYS can keep messages longer, or for ever, never shorter).
Messages older than the retention are removed at start and daily, by the time
in their names, and never sooner: a clock that is behind, ahead, or set back
and forth can only make retention keep more.

The tests run in 2075 with the real floor, so their messages can be more than
21 years old and still dated after the code that names them existed."""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

from core.kernel import NSBOSKernel
from core.kernel.agent_runtime import (
    RETENTION_DEFAULT_DAYS,
    RETENTION_FLOOR_DAYS,
    InterAgentCommunication,
    retention_days,
)

R = RETENTION_FLOOR_DAYS  # 7671: 21 years with six leap days
NOW = datetime(2075, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
EPOCH = datetime(2070, 1, 1, tzinfo=timezone.utc)
BOOT = "test-boot"


@pytest.fixture(autouse=True)
def setting_unset(monkeypatch):
    monkeypatch.delenv("NGARI_RETENTION_DAYS", raising=False)


def _message(directory, when, topic="orders", suffix=".json", hexpart="0a0b0c0d"):
    name = f"{topic}_{when.strftime('%Y%m%d_%H%M%S')}_000000_{hexpart}{suffix}"
    path = directory / name
    path.write_text(
        json.dumps({"topic": topic, "message": {}, "timestamp": when.isoformat()})
    )
    return path


def _ago(days, now=NOW):
    return now - timedelta(days=days)


def _sweep(bus, days, now, boot=BOOT):
    """A sweep at wall time now, with a monotonic clock that agrees with it:
    a machine whose clock is right and has run since EPOCH."""
    return bus.expire(
        days, now=now, monotonic=(now - EPOCH).total_seconds(), boot_id=boot
    )


def _stamp(when):
    return when.strftime("%Y%m%dT%H%M%SZ")


# -- the setting -----------------------------------------------------------------------


@pytest.mark.part11("11.10(c)")
def test_the_floor_and_the_default_are_21_years():
    assert RETENTION_FLOOR_DAYS == RETENTION_DEFAULT_DAYS == 21 * 365 + 6
    # The longest run of leap days: Feb 29 of 2028, 2032, 2036, 2040, 2044, 2048.
    start = datetime(2028, 2, 1, tzinfo=timezone.utc)
    assert start + timedelta(days=R) >= start.replace(year=2049)
    assert start + timedelta(days=R - 1) < start.replace(year=2049)


@pytest.mark.parametrize(
    ("value", "days"),
    [("", R), (str(R), R), (f" {R + 1} ", R + 1), ("10000", 10000), ("never", None),
     (" Never ", None)],
)  # fmt: skip
def test_values_that_are_taken(value, days, caplog):
    """Unset or empty is 21 years; longer is taken; never keeps everything,
    and is a choice, not a mistake: no error for it."""
    assert retention_days({"NGARI_RETENTION_DAYS": value}) == days
    assert "no message is expired" not in caplog.text


@pytest.mark.parametrize(
    "value", [str(R - 1), "2557", "365", "30", "0", "-1", "1y", "1.5", "forever"]
)
def test_no_value_can_shorten_the_retention(value, caplog):
    # Below 21 years, or not a whole number: every message is kept, and the
    # error names the floor.
    assert retention_days({"NGARI_RETENTION_DAYS": value}) is None
    assert "no message is expired" in caplog.text
    assert str(R) in caplog.text


@pytest.mark.parametrize("days", [R - 1, 365, 0, True, str(R), float(R)])
def test_the_floor_holds_in_expire_itself(tmp_path, days):
    bus = InterAgentCommunication(str(tmp_path))
    old = _message(tmp_path, _ago(R + 5000))
    _message(tmp_path, NOW, hexpart="ffffffff")
    with pytest.raises(ValueError, match=f"{R}-day floor"):
        _sweep(bus, days, NOW)
    assert old.exists()


# -- what expires, with a clock that is right ------------------------------------------


def test_age_is_read_from_the_name_not_the_file_time(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    old_name = _message(tmp_path, _ago(R + 35), hexpart="00000001")  # fresh mtime
    new_name = _message(tmp_path, _ago(10), hexpart="00000002")
    ancient = (NOW - timedelta(days=R + 4000)).timestamp()
    os.utime(new_name, (ancient, ancient))  # an old mtime, as after a restore
    record = _sweep(bus, R, NOW)
    assert not old_name.exists() and new_name.exists()
    assert record["removed"] == 1


def test_encrypted_v010_and_paired_copies_expire_alike(tmp_path):
    from cryptography.fernet import Fernet

    from core.kernel.data_plane.state import StateCipher

    bus = InterAgentCommunication(
        str(tmp_path), cipher=StateCipher(Fernet.generate_key())
    )
    v010 = tmp_path / f"orders_{_ago(R + 135).strftime('%Y%m%d_%H%M%S')}.json"
    v010.write_text("{}")
    _message(tmp_path, _ago(R + 235), suffix=".enc.json")
    pair = _message(tmp_path, _ago(R + 335), hexpart="0000000f")
    pair.with_name(pair.name[:-5] + ".enc.json").write_text("{}")
    kept = _message(tmp_path, _ago(1), hexpart="00000009")
    record = _sweep(bus, R, NOW)
    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.startswith(".")) == [
        kept.name
    ]
    assert record["removed"] == 4
    assert (record["oldest"], record["newest"]) == (
        _stamp(_ago(R + 335)),
        _stamp(_ago(R + 135)),
    )


def test_nothing_but_message_files_is_touched(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    stamp = _ago(R + 3000).strftime("%Y%m%d_%H%M%S")
    others = [
        tmp_path / "notes.txt",
        tmp_path / f".orders_{stamp}_000000_0a0b0c0d.json.42.abcd.tmp",
        tmp_path / f"orders_{stamp}.json.corrupt-20200101T000000Z",
    ]
    for path in others:
        path.write_text("x")
    (tmp_path / f"folder_{stamp}.json").mkdir()
    target = _message(tmp_path, _ago(1))
    (tmp_path / f"link_{stamp}.json").symlink_to(target)
    _message(tmp_path, _ago(R + 2000), hexpart="00000003")
    assert _sweep(bus, R, NOW)["removed"] == 1
    assert (
        all(p.exists() for p in others) and (tmp_path / f"folder_{stamp}.json").is_dir()
    )
    assert (tmp_path / f"link_{stamp}.json").is_symlink() and target.exists()


def test_a_message_that_cannot_be_removed_is_left_and_the_rest_go(
    tmp_path, monkeypatch, caplog
):
    bus = InterAgentCommunication(str(tmp_path))
    stuck = _message(tmp_path, _ago(R + 135), hexpart="00000001")
    _message(tmp_path, _ago(R + 235), hexpart="00000002")
    _message(tmp_path, _ago(1), hexpart="00000003")
    real = os.unlink

    def unlink(path, *args, **kwargs):
        if path == stuck.name:
            raise PermissionError(13, "Permission denied")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    assert _sweep(bus, R, NOW)["removed"] == 1
    assert (
        stuck.exists()
        and f"Cannot remove expired message {stuck.name!r}" in caplog.text
    )


def test_a_message_goes_a_day_after_the_retention_never_before(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    inside = _message(tmp_path, _ago(R), hexpart="00000001")
    margin = _message(
        tmp_path, _ago(R + 1), hexpart="00000002"
    )  # within the day of margin
    past = _message(tmp_path, _ago(R + 1) - timedelta(seconds=2), hexpart="00000003")
    _message(tmp_path, NOW, hexpart="ffffffff")
    assert _sweep(bus, R, NOW)["removed"] == 1
    assert inside.exists() and margin.exists() and not past.exists()


def test_the_removal_is_synced_before_it_is_recorded(tmp_path, monkeypatch):
    order = []
    real_fsync, real_unlink = os.fsync, os.unlink

    def fsync(fd):
        if os.path.realpath(os.readlink(f"/proc/self/fd/{fd}")) == os.path.realpath(
            tmp_path
        ):
            order.append("directory synced")
        return real_fsync(fd)

    def unlink(path, *args, **kwargs):
        if "dir_fd" in kwargs:
            order.append("removed")
        return real_unlink(path, *args, **kwargs)

    bus = InterAgentCommunication(
        str(tmp_path), audit=lambda *a: order.append("recorded")
    )
    _message(tmp_path, _ago(R + 435))
    _message(tmp_path, NOW, hexpart="ffffffff")
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "unlink", unlink)
    _sweep(bus, R, NOW)
    removed = len(order) - 1 - order[::-1].index("removed")
    recorded = order.index("recorded")
    assert removed < recorded and "directory synced" in order[removed:recorded]


def test_an_idle_bus_measures_from_its_newest_message_at_the_first_sweep(tmp_path):
    # The first sweep has no record: it measures back from the newest message,
    # so an idle bus keeps its old messages longer, never shorter, and the
    # cutoff then moves with measured time.
    bus = InterAgentCommunication(str(tmp_path))
    old = _message(tmp_path, _ago(R + 435))
    assert _sweep(bus, R, NOW) is None and old.exists()
    _message(tmp_path, NOW, hexpart="ffffffff")
    assert _sweep(bus, R, NOW + timedelta(days=1)) is None
    assert old.exists()  # the cutoff moves one day, not 435
    assert _sweep(bus, R, NOW + timedelta(days=R + 2))["removed"] == 1


def test_a_topic_with_a_newline_expires_like_any_other(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    odd = _message(tmp_path, _ago(R + 435), topic="ops\nalerts")
    plain = _message(tmp_path, _ago(R + 435), topic="ops-alerts")
    _message(tmp_path, NOW, hexpart="ffffffff")
    assert _sweep(bus, R, NOW)["removed"] == 2
    assert not odd.exists() and not plain.exists()


# -- the clock -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["orders_19700101_000000_000000_0a0b0c0d.json", "orders_20000101_000000_000000_0a0b0c0d.json",
     "orders_20261026_235959_000000_0a0b0c0d.json", "orders_20260822_000000.json",
     "orders_19700101_000000.json"],
)  # fmt: skip
def test_a_name_dated_before_its_format_existed_is_never_removed(tmp_path, name):
    # A board with no real-time clock that boots at 1970, at 2000 or at its
    # image date writes these; their dates say nothing about their age.
    bus = InterAgentCommunication(str(tmp_path))
    (tmp_path / name).write_text("{}")
    _message(tmp_path, NOW, hexpart="ffffffff")
    assert _sweep(bus, R, NOW) is None
    assert (tmp_path / name).exists()


def test_messages_written_while_the_clock_was_behind_are_held(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    _message(tmp_path, _ago(10), hexpart="00000001")
    _sweep(bus, R, NOW)  # the clock is right: NOW is seen
    behind = NOW.replace(year=2073)  # then the board boots two years behind
    assert _sweep(bus, R, behind + timedelta(hours=2)) is None  # nothing while behind
    written = [
        _message(tmp_path, behind + timedelta(hours=h), hexpart=f"{h:08x}")
        for h in (3, 4, 5)
    ]
    fixed = NOW + timedelta(days=3)  # the clock is set right three days later
    assert _sweep(bus, R, fixed) is None
    assert all(p.exists() for p in written)  # dated 2073, really three days old
    # They are aged from when the clock is right again, and go 21 years after.
    assert _sweep(bus, R, fixed + timedelta(days=R - 30)) is None
    assert all(p.exists() for p in written)
    # The first sweep measures from a message ten days old, so ten days more.
    end = fixed + timedelta(days=R + 15)
    _message(tmp_path, end, hexpart="fffffffe")  # a live bus
    record = _sweep(bus, R, end)
    assert record is not None and not any(p.exists() for p in written)


def test_publish_notices_a_clock_that_went_back(tmp_path, monkeypatch):
    from core.kernel import agent_runtime

    bus = InterAgentCommunication(str(tmp_path))
    _message(tmp_path, _ago(1))
    _sweep(bus, R, NOW)

    class Behind(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2074, 1, 1, tzinfo=tz)

    monkeypatch.setattr(agent_runtime, "datetime", Behind)
    bus.publish("orders", {"m": 1})
    clock = json.loads((tmp_path / ".retention-clock.json").read_text())
    assert clock["behind"] is True and clock["hold_below"] == NOW.isoformat()


def test_a_leftover_message_from_the_future_does_not_let_a_jump_remove_everything(
    tmp_path,
):
    bus = InterAgentCommunication(str(tmp_path))
    real = [
        _message(tmp_path, _ago(days), hexpart=f"{days:08x}")
        for days in range(1, 300, 10)
    ]
    future = NOW + timedelta(days=R + 3650)
    _message(tmp_path, future, hexpart="ffffffff")  # dated by a mistyped clock
    _sweep(bus, R, NOW)
    # Next boot, the clock jumps 31 years ahead; no new message yet.
    assert _sweep(bus, R, future + timedelta(days=30), boot="next-boot") is None
    assert all(p.exists() for p in real)


def test_the_cutoff_moves_only_as_fast_as_measured_time(tmp_path):
    bus = InterAgentCommunication(str(tmp_path))
    young = [
        _message(tmp_path, _ago(days), hexpart=f"{days:08x}") for days in (30, 100, 300)
    ]
    _sweep(bus, R, NOW)
    jumped = NOW + timedelta(days=R + 3650)
    _message(tmp_path, jumped, hexpart="ffffffff")
    hour_later = (NOW - EPOCH).total_seconds() + 3600
    # Same run: the wall clock moves 31 years, the monotonic clock an hour.
    assert bus.expire(R, now=jumped, monotonic=hour_later, boot_id=BOOT) is None
    # A restart: at most a day counts, however far the wall clock moves.
    assert _sweep(bus, R, jumped + timedelta(days=1), boot="other-boot") is None
    assert all(p.exists() for p in young)


def test_an_unreadable_clock_record_starts_again(tmp_path, caplog):
    bus = InterAgentCommunication(str(tmp_path))
    (tmp_path / ".retention-clock.json").write_text("{not json")
    _message(tmp_path, _ago(R + 435))
    _message(tmp_path, NOW, hexpart="ffffffff")
    assert _sweep(bus, R, NOW)["removed"] == 1
    assert "retention clock record is unreadable" in caplog.text


# -- every removal recorded, in its own directory --------------------------------------


@pytest.mark.parametrize("fails", ["directory sync", "audit append"])
def test_a_removal_that_could_not_be_recorded_is_recorded_next_time(
    tmp_path, monkeypatch, fails
):
    records = []
    bus = InterAgentCommunication(
        str(tmp_path), audit=lambda action, resource, details: records.append(details)
    )
    old = [
        _message(tmp_path, _ago(R + days), hexpart=f"{days:08x}") for days in (435, 535)
    ]
    _message(tmp_path, NOW, hexpart="ffffffff")
    real_fsync = os.fsync

    def failing_fsync(fd):
        ours = os.path.realpath(os.readlink(f"/proc/self/fd/{fd}")) == os.path.realpath(
            tmp_path
        )
        if ours and not any(p.exists() for p in old):  # after the removals
            raise OSError(5, "Input/output error")
        return real_fsync(fd)

    def failing_audit(action, resource, details):
        raise OSError(28, "No space left on device")

    if fails == "directory sync":
        monkeypatch.setattr(os, "fsync", failing_fsync)
    else:
        monkeypatch.setattr(bus, "_audit", failing_audit)
    with pytest.raises(OSError):
        _sweep(bus, R, NOW)
    monkeypatch.undo()
    assert not any(p.exists() for p in old) and records == []
    bus._audit = lambda action, resource, details: records.append(details)
    record = _sweep(bus, R, NOW + timedelta(hours=1))  # nothing new to remove
    assert record["removed"] == 2 and records == [record]
    assert (record["oldest"], record["newest"]) == (
        _stamp(_ago(R + 535)),
        _stamp(_ago(R + 435)),
    )
    assert _sweep(bus, R, NOW + timedelta(hours=2)) is None  # and only once


def test_swapping_comm_for_a_link_mid_sweep_does_not_redirect_it(tmp_path, monkeypatch):
    comm = tmp_path / "comm"
    comm.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    bus = InterAgentCommunication(str(comm))
    victim = _message(comm, _ago(R + 435))
    _message(comm, NOW, hexpart="ffffffff")
    decoy = other / victim.name
    decoy.write_text("not to be touched")
    real = os.scandir

    class Listing(list):  # stands in for scandir's context manager
        def __enter__(self):
            return iter(self)

        def __exit__(self, *exc):
            return False

    def swapping(target):
        listing = Listing(real(target))
        os.rename(comm, tmp_path / "comm-moved")
        os.symlink(other, comm)  # comm/ is a link to the other directory
        return listing

    monkeypatch.setattr(os, "scandir", swapping)
    bus.expire(R, now=NOW, monotonic=0.0, boot_id=BOOT)
    monkeypatch.undo()
    assert decoy.read_text() == "not to be touched"
    assert not (tmp_path / "comm-moved" / victim.name).exists()


# -- through the kernel ----------------------------------------------------------------


@pytest.fixture
def at(monkeypatch):
    """The kernel's own copy of agent_runtime (the flat import) runs at a
    fixed time: NOW, unless another is given."""

    def use(kernel, when=NOW):
        class Fixed(datetime):
            @classmethod
            def now(cls, tz=None):
                return when.astimezone(tz) if tz else when.replace(tzinfo=None)

        module = sys.modules[type(kernel.agent_runtime.comm).__module__]
        monkeypatch.setattr(module, "datetime", Fixed)

    return use


def _kernel(tmp_path, monkeypatch, days):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    if days is not None:
        monkeypatch.setenv("NGARI_RETENTION_DAYS", str(days))
    kernel = NSBOSKernel()
    return kernel, tmp_path / "agents" / "comm"


def _entries(kernel, action):
    return [e for e in kernel.data_plane.get_audit_log(10**6) if e["action"] == action]


@pytest.mark.part11("11.10(c)", "11.10(e)")
def test_unset_keeps_21_years_and_removes_what_is_older(tmp_path, monkeypatch, at):
    kernel, comm = _kernel(tmp_path, monkeypatch, None)
    at(kernel)
    old = _message(comm, _ago(R + 435), topic="secret-topic")
    kept = _message(comm, _ago(R), hexpart="00000001")
    _message(comm, NOW, hexpart="ffffffff")
    elsewhere = [tmp_path / "agents" / "registry" / old.name, tmp_path / "sync" / old.name,
                 tmp_path / "sovereign" / "encrypted" / old.name]  # fmt: skip
    for path in elsewhere:
        path.write_text("{}")
    assert kernel.retention_days == R
    kernel.start()
    assert not old.exists() and kept.exists() and all(p.exists() for p in elsewhere)
    [entry] = _entries(kernel, "retention_expired")
    assert entry["resource"] == "comm" and entry["details"]["removed"] == 1
    assert entry["details"]["retention_days"] == R and "mac" in entry
    assert "secret-topic" not in json.dumps(entry)
    assert kernel.data_plane.verify_audit_integrity()
    assert kernel.get_status()["kernel"]["retention_days"] == R
    kernel.stop()


def test_a_longer_retention_is_taken(tmp_path, monkeypatch, at):
    kernel, comm = _kernel(tmp_path, monkeypatch, R + 1000)
    at(kernel)
    between = _message(comm, _ago(R + 435), hexpart="00000001")
    _message(comm, NOW, hexpart="ffffffff")
    kernel.start()
    assert between.exists() and kernel.retention_days == R + 1000
    kernel.stop()


def test_the_daily_tick_sweeps_once_a_day(tmp_path, monkeypatch, at):
    kernel, comm = _kernel(tmp_path, monkeypatch, None)
    at(kernel)
    _message(comm, NOW, hexpart="ffffffff")
    kernel.start()
    old = _message(comm, _ago(R + 435))
    kernel.tick()  # less than a day since the start sweep
    assert old.exists()
    kernel._last_sweep -= kernel.SWEEP_SECONDS
    kernel.tick()
    assert not old.exists() and len(_entries(kernel, "retention_expired")) == 1
    kernel.stop()


@pytest.mark.parametrize("days", ["never", R - 1, 365])
def test_never_or_below_the_floor_nothing_is_removed(
    tmp_path, monkeypatch, caplog, at, days
):
    kernel, comm = _kernel(tmp_path, monkeypatch, days)
    at(kernel)
    old = _message(comm, _ago(R + 3000))
    _message(comm, NOW, hexpart="ffffffff")
    kernel.start()
    kernel._last_sweep = None
    kernel.tick()
    assert old.exists() and kernel.retention_days is None
    assert _entries(kernel, "retention_expired") == []
    if days != "never":
        assert f"below the {R}-day (21-year) floor" in caplog.text
    kernel.stop()


def test_a_failed_record_is_logged_and_the_kernel_goes_on(
    tmp_path, monkeypatch, caplog, at
):
    kernel, comm = _kernel(tmp_path, monkeypatch, None)
    at(kernel)
    _message(comm, _ago(R + 435))
    _message(comm, NOW, hexpart="ffffffff")

    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(kernel.data_plane, "record", full)
    kernel._expire_messages()
    assert "Message retention sweep failed" in caplog.text


def test_a_refused_retention_does_not_stop_the_kernel(tmp_path, monkeypatch, caplog):
    kernel, _comm = _kernel(tmp_path, monkeypatch, None)
    kernel.retention_days = 365  # set on the object, below the floor
    kernel.start()
    assert kernel.running and "Message retention sweep failed" in caplog.text
    kernel.stop()
