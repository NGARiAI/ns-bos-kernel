"""main(): a started kernel is always stopped, however the run ends."""

import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import core.kernel as kernel_mod

REPO_ROOT = Path(__file__).resolve().parent.parent


INSTANCES = []


class FakeKernel:
    def __init__(self, fail_at=None):
        self.fail_at = fail_at
        self.started = self.stopped = False
        self.running = False
        INSTANCES.append(self)

    def _maybe_fail(self, step):
        if self.fail_at == step:
            raise KeyboardInterrupt

    def start(self):
        self.started = self.running = True
        self._maybe_fail("start")

    def stop(self):
        self.stopped = True
        self.running = False

    def register_agent(self, name, agent_type, description):
        self._maybe_fail("register")
        return name

    def get_status(self):
        self._maybe_fail("status")
        hw = {
            "platform": "x", "cpu": "x", "cpu_cores": 1, "memory_gb": 1, "gpu": "x",
            "gpu_memory_gb": 0, "storage_available_gb": 1.0,
        }  # fmt: skip
        return {
            "hardware": hw,
            "agents": {"agents": 6},
            "fleet": {"total_nodes": 1},
            "data_sovereignty": {"data_sovereignty": "enforced"},
        }


@pytest.fixture
def fake(monkeypatch, tmp_path):
    INSTANCES.clear()
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))

    def use(fail_at=None):
        monkeypatch.setattr(kernel_mod, "NSBOSKernel", lambda: FakeKernel(fail_at))

    return use


@pytest.mark.parametrize("step", ["start", "register", "status"])
def test_an_interrupt_after_start_still_stops_the_kernel(fake, step):
    fake(step)
    kernel_mod.main([])
    [kernel] = INSTANCES
    assert kernel.started and kernel.stopped


def test_an_interrupt_in_the_run_loop_stops_the_kernel(fake, monkeypatch):
    fake()

    def sleep(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(kernel_mod.time, "sleep", sleep)
    kernel_mod.main([])
    assert INSTANCES[0].stopped


def test_an_interrupt_during_construction_exits_130(monkeypatch, tmp_path):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))

    def interrupted():
        raise KeyboardInterrupt

    monkeypatch.setattr(kernel_mod, "NSBOSKernel", interrupted)
    with pytest.raises(SystemExit) as caught:
        kernel_mod.main([])
    assert caught.value.code == 130


def test_the_sigterm_handler_is_put_back(fake):
    fake("register")

    def mine(signum, frame):
        pass

    previous = signal.signal(signal.SIGTERM, mine)
    try:
        kernel_mod.main([])
        assert signal.getsignal(signal.SIGTERM) is mine
    finally:
        signal.signal(signal.SIGTERM, previous)


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_right_after_start_shuts_down_cleanly(tmp_path, sig):
    env = {**os.environ, "NGARI_DATA_DIR": str(tmp_path), "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "core.kernel"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines = queue.Queue()
    reader = threading.Thread(
        target=lambda: [lines.put(line) for line in proc.stdout], daemon=True
    )
    reader.start()
    # Logged inside start(), before the agents register: a signal here must
    # still reach stop().
    started = f"{kernel_mod.KERNEL_FULL_NAME} v{kernel_mod.VERSION} started"
    seen = []
    try:
        deadline = time.monotonic() + 60
        while True:
            line = lines.get(timeout=max(0.1, deadline - time.monotonic()))
            seen.append(line)
            if line.rstrip().endswith(started):
                proc.send_signal(sig)
                break
        proc.wait(timeout=60)
    except (queue.Empty, subprocess.TimeoutExpired):
        pytest.fail("kernel did not start and stop in time:\n" + "".join(seen))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    reader.join(timeout=10)
    while not lines.empty():
        seen.append(lines.get())
    output = "".join(seen)
    assert proc.returncode == 0, output
    assert "Traceback" not in output
    assert output.rstrip().splitlines()[-1].endswith("Kernel stopped"), output


# -- a data directory the kernel cannot use ------------------------------------------


def _start(env_extra, prefix=()):
    env = {**os.environ, "PYTHONUNBUFFERED": "1", **env_extra}
    run = subprocess.run(
        [*prefix, sys.executable, "-m", "core.kernel"], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    return run.returncode, run.stdout + run.stderr


HINT = "Check that NGARI_DATA_DIR is a directory this user owns, on a disk that is writable and not full"


def test_a_data_dir_that_is_a_file_stops_with_a_reason(tmp_path):
    data = tmp_path / "data"
    data.write_text("not a directory")
    code, output = _start({"NGARI_DATA_DIR": str(data)})
    assert code == 2, output
    assert f"Cannot start: {data}: File exists. {HINT}" in output  # the file in the way
    assert "Traceback" not in output


def test_a_store_that_cannot_be_created_stops_with_a_reason(tmp_path):
    (tmp_path / "sovereign").write_text("in the way")
    code, output = _start({"NGARI_DATA_DIR": str(tmp_path)})
    assert code == 2, output
    assert f"Cannot start: {tmp_path / 'sovereign'}: File exists. {HINT}" in output
    assert "Traceback" not in output


def test_a_data_dir_this_user_cannot_write_stops_with_a_reason(tmp_path):
    import shutil as sh

    data = tmp_path / "data"
    data.mkdir()
    if os.geteuid() == 0:
        if sh.which("setpriv") is None:
            pytest.skip("running as root without setpriv")
        prefix = ("setpriv", "--reuid=65534", "--regid=65534", "--clear-groups")
    else:
        data.chmod(0o500)
        prefix = ()
    code, output = _start({"NGARI_DATA_DIR": str(data), "HOME": str(tmp_path)}, prefix)
    assert code == 2, output
    assert "Cannot start: " in output and "Permission denied" in output
    assert "Traceback" not in output


def test_the_reason_names_the_file_when_there_is_one():
    assert kernel_mod._unusable(OSError(28, "No space left on device", "/d/logs")) == (
        f"/d/logs: No space left on device. {HINT}"
    )
    assert kernel_mod._unusable(OSError(30, "Read-only file system")) == (
        f"Read-only file system. {HINT}"
    )


# -- arguments main does not know -----------------------------------------------------


@pytest.mark.parametrize(
    "args", [["stat"], ["sate", "decrypt"], ["--data-dir", "/x"], ["key", "restore"]]
)
def test_an_unknown_command_is_refused_and_never_starts_the_kernel(
    tmp_path, monkeypatch, capsys, args
):
    built = []
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(kernel_mod, "NSBOSKernel", lambda: built.append(1))
    with pytest.raises(SystemExit) as caught:
        kernel_mod.main(args)
    assert caught.value.code == 2
    err = capsys.readouterr().err
    assert f"ns-bos: unknown command {args[0]!r}" in err and "usage: ns-bos" in err
    assert built == [] and not (tmp_path / "data").exists()  # no log, no lock, nothing


@pytest.mark.parametrize("flag", ["-h", "--help", "help"])
def test_help_prints_the_usage_and_starts_nothing(tmp_path, monkeypatch, capsys, flag):
    built = []
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(kernel_mod, "NSBOSKernel", lambda: built.append(1))
    with pytest.raises(SystemExit) as caught:
        kernel_mod.main([flag])
    assert caught.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("usage: ns-bos [keys | audit | state | records | agents]")
    assert built == [] and not (tmp_path / "data").exists()


def test_the_usage_names_every_command_main_runs():
    source = Path(kernel_mod.__file__).read_text()
    import re

    dispatched = re.findall(r'if args\[:1\] == \["(\w+)"\]:', source)
    assert sorted(dispatched) == ["agents", "audit", "keys", "records", "state"]
    for command in dispatched:
        assert f"\n  {command} " in kernel_mod.USAGE


def test_the_command_line_refuses_a_typo_with_exit_2(tmp_path):
    env = {**os.environ, "NGARI_DATA_DIR": str(tmp_path)}
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel", "sate", "decrypt"], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert run.returncode == 2 and "unknown command 'sate'" in run.stderr
    assert list(tmp_path.iterdir()) == []


# -- the data directory, its modes, start and stop -------------------------------------


@pytest.fixture
def kernel_env(tmp_path, monkeypatch):
    monkeypatch.delenv("NGARI_KEY_PROVIDER", raising=False)
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path / "data"))
    return tmp_path / "data"


def test_an_empty_data_dir_variable_names_one_directory_everywhere(
    tmp_path, monkeypatch
):
    # "" is unset: the kernel and the keys, audit, state and records commands
    # all use ~/.ngari/kernel, so there is one key, one log and one lock.
    from core.kernel.data_plane import SovereignDataPlane
    from core.kernel.data_plane.keys_cli import sovereign_dir

    monkeypatch.delenv("NGARI_KEY_PROVIDER", raising=False)
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("NGARI_DATA_DIR", "")
    kernel = kernel_mod.NSBOSKernel()
    expected = sovereign_dir(os.environ)
    assert expected == tmp_path / "home" / ".ngari" / "kernel" / "sovereign"
    assert kernel.data_plane.data_dir == expected
    assert SovereignDataPlane().data_dir == expected.parent  # its own default
    assert not (tmp_path / "cwd" / "sovereign").exists()


@pytest.mark.parametrize(
    "make",
    [
        "agent_runtime.AgentRegistry", "agent_runtime.TaskScheduler",
        "agent_runtime.InterAgentCommunication", "agent_runtime.AgentRuntime",
        "generative_ui.GenerativeUIEngine", "inference.ModelRegistry",
        "network_sync.NetworkSynchronization",
    ],
)  # fmt: skip
def test_an_empty_data_dir_variable_is_not_the_current_directory_for_a_component(
    tmp_path, monkeypatch, make
):
    # A component built without a directory takes "" as unset, not as the
    # current directory (systemd's is /).
    import importlib

    module, name = make.split(".")
    cls = getattr(importlib.import_module(f"core.kernel.{module}"), name)
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("NGARI_DATA_DIR", "")
    built = cls()
    parts = (
        [built.registry, built.scheduler, built.comm]
        if name == "AgentRuntime"
        else [built]
    )
    dirs = [v for part in parts for k, v in vars(part).items() if k.endswith("_dir")]
    assert dirs and all(
        Path(d).is_relative_to(tmp_path / "home" / ".ngari") for d in dirs
    ), dirs
    assert list((tmp_path / "cwd").iterdir()) == []


def _main_until_the_kernel(monkeypatch, root_dir):
    """Run main() up to building the kernel, then stop as Ctrl+C would, and
    take its log handler off again."""
    import logging

    def interrupted():
        raise KeyboardInterrupt

    monkeypatch.setattr(kernel_mod, "NSBOSKernel", interrupted)
    try:
        with pytest.raises(SystemExit):
            kernel_mod.main([])
    finally:
        root = logging.getLogger()
        for handler in list(root.handlers):
            if (
                isinstance(handler, logging.FileHandler)
                and str(root_dir) in handler.baseFilename
            ):
                root.removeHandler(handler)
                handler.close()


def test_main_takes_an_empty_data_dir_variable_as_unset(tmp_path, monkeypatch):
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("NGARI_DATA_DIR", "")
    _main_until_the_kernel(monkeypatch, tmp_path)
    assert (tmp_path / "home" / ".ngari" / "kernel" / "logs" / "kernel.log").exists()
    assert not (tmp_path / "cwd" / "logs").exists()


def test_the_kernel_data_directory_is_owner_only(kernel_env):
    # 0700 whatever the umask: tasks.json (task payloads), the messages, the
    # registry and the twin are not readable by other local users.
    old = os.umask(0o022)
    try:
        kernel = kernel_mod.NSBOSKernel()
        agent = kernel.register_agent("A", "t")
        kernel.create_task(agent, "act", {"customer": "x"})
    finally:
        os.umask(old)
    assert kernel_env.stat().st_mode & 0o777 == 0o700


def test_an_open_data_directory_is_closed_at_start(kernel_env):
    kernel_env.mkdir(mode=0o755)
    kernel_env.chmod(0o755)
    kernel_mod.NSBOSKernel()
    assert kernel_env.stat().st_mode & 0o777 == 0o700


def test_the_kernel_log_is_owner_only(kernel_env, monkeypatch):
    old = os.umask(0o022)
    try:
        _main_until_the_kernel(monkeypatch, kernel_env)
    finally:
        os.umask(old)
    log = kernel_env / "logs" / "kernel.log"
    modes = [oct(p.stat().st_mode & 0o777) for p in (kernel_env, log.parent, log)]
    assert modes == ["0o700", "0o700", "0o600"]


def test_a_log_left_open_is_closed_at_start(kernel_env, monkeypatch):
    (kernel_env / "logs").mkdir(parents=True)
    (kernel_env / "logs").chmod(0o755)
    (kernel_env / "logs" / "kernel.log").write_text("old line\n")
    (kernel_env / "logs" / "kernel.log").chmod(0o644)
    _main_until_the_kernel(monkeypatch, kernel_env)
    log = kernel_env / "logs" / "kernel.log"
    assert oct(log.stat().st_mode & 0o777) == "0o600"
    assert oct(log.parent.stat().st_mode & 0o777) == "0o700"
    assert log.read_text().startswith("old line\n")  # appended to, not replaced


def test_a_second_start_is_not_recorded_as_another_boot(kernel_env):
    kernel = kernel_mod.NSBOSKernel()
    kernel.start()
    since = kernel._running_since
    kernel.start()
    starts = [e for e in kernel.data_plane.get_audit_log(10**6)
              if e["action"] == "kernel_started"]  # fmt: skip
    assert len(starts) == 1 and kernel._running_since == since
    kernel.stop()
    kernel.start()  # after a stop, a start is one again
    assert [e["action"] for e in kernel.data_plane.get_audit_log(10**6)].count(
        "kernel_started"
    ) == 2
    kernel.stop()


def test_a_start_whose_boot_entry_failed_can_be_retried(kernel_env, monkeypatch):
    # A start whose kernel_started append fails leaves the kernel stopped, so
    # the retry does the whole start: entry, runtime and twin status.
    kernel = kernel_mod.NSBOSKernel()
    record = kernel.data_plane.record
    failures = [OSError(28, "No space left on device")]

    def flaky(*args, **kwargs):
        if failures:
            raise failures.pop()
        return record(*args, **kwargs)

    monkeypatch.setattr(kernel.data_plane, "record", flaky)
    with pytest.raises(OSError):
        kernel.start()
    assert (kernel.running, kernel._running_since) == (False, None)
    assert kernel.get_status()["kernel"]["status"] == "stopped"
    kernel.start()  # the disk has room again
    try:
        actions = [e["action"] for e in kernel.data_plane.get_audit_log(10**6)]
        assert actions.count("kernel_started") == 1
        assert kernel.agent_runtime.running
        assert kernel.network_sync.get_twin_value("kernel.status") == "running"
    finally:
        kernel.stop()


@pytest.mark.parametrize("second", [signal.SIGTERM, signal.SIGINT])
def test_a_second_signal_during_stop_still_records_the_stop(
    kernel_env, monkeypatch, second
):
    made = []

    class Kernel(kernel_mod.NSBOSKernel):
        def _twin(self, key, value):
            if (key, value) == ("kernel.status", "stopped"):
                os.kill(os.getpid(), second)  # the second signal, mid-stop
            super()._twin(key, value)

    def build():
        made.append(Kernel())
        return made[-1]

    def first_ctrl_c(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(kernel_mod, "NSBOSKernel", build)
    monkeypatch.setattr(kernel_mod.time, "sleep", first_ctrl_c)

    def mine(signum, frame):
        pass

    before_int = signal.getsignal(signal.SIGINT)
    previous = signal.signal(signal.SIGTERM, mine)
    try:
        kernel_mod.main([])  # no KeyboardInterrupt leaves main
        restored = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
    finally:
        signal.signal(signal.SIGTERM, previous)
        signal.signal(signal.SIGINT, before_int)
        import logging

        root = logging.getLogger()
        for handler in list(root.handlers):
            if (
                isinstance(handler, logging.FileHandler)
                and str(kernel_env) in handler.baseFilename
            ):
                root.removeHandler(handler)
                handler.close()
    assert restored == (mine, before_int)
    assert made[0].data_plane.get_audit_log(1)[0]["action"] == "kernel_stopped"


# -- a second signal as the shutdown begins --------------------------------------------


@pytest.mark.parametrize("first", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize("second", [signal.SIGINT, signal.SIGTERM])
def test_a_second_signal_as_the_shutdown_begins_still_records_the_stop(
    kernel_env, monkeypatch, first, second
):
    # A second signal between entering main's finally and its SIG_IGN must
    # not surface as KeyboardInterrupt: stop() runs and the stop is recorded.
    made = []
    Kernel = kernel_mod.NSBOSKernel

    def build():
        made.append(Kernel())
        return made[-1]

    def signalled(seconds):
        os.kill(os.getpid(), first)

    real = signal.signal
    sent = []

    def second_as_finally_begins(signum, handler):
        # main's own SIG_IGN, as its finally begins; not the handler's
        if (
            handler is signal.SIG_IGN
            and not sent
            and sys._getframe(1).f_code.co_name == "main"
        ):
            sent.append(1)
            os.kill(os.getpid(), second)
        return real(signum, handler)

    def mine(signum, frame):
        pass

    monkeypatch.setattr(kernel_mod, "NSBOSKernel", build)
    monkeypatch.setattr(kernel_mod.time, "sleep", signalled)
    before_int = real(signal.SIGINT, mine)
    before_term = real(signal.SIGTERM, mine)
    monkeypatch.setattr(kernel_mod.signal, "signal", second_as_finally_begins)
    try:
        kernel_mod.main([])
        restored = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))
    finally:
        real(signal.SIGINT, before_int)
        real(signal.SIGTERM, before_term)
        import logging

        root = logging.getLogger()
        for handler in list(root.handlers):
            if (
                isinstance(handler, logging.FileHandler)
                and str(kernel_env) in handler.baseFilename
            ):
                root.removeHandler(handler)
                handler.close()
    assert sent
    assert restored == (mine, mine)
    assert made[0].data_plane.get_audit_log(1)[0]["action"] == "kernel_stopped"


# -- a first signal as a shutdown begins another way -----------------------------------


def test_a_first_signal_as_a_normal_shutdown_begins_still_records_the_stop(
    kernel_env, monkeypatch
):
    # A first signal that arrives as a shutdown begun another way enters
    # main's finally must not surface as KeyboardInterrupt.
    made = []
    Kernel = kernel_mod.NSBOSKernel

    def build():
        kernel = Kernel()

        def tick():
            raise RuntimeError("a tick that fails")  # the loop ends, not by a signal

        kernel.tick = tick
        made.append(kernel)
        return kernel

    real = signal.signal
    sent = []

    def first_as_finally_begins(signum, handler):
        if (
            handler is signal.SIG_IGN
            and not sent
            and sys._getframe(1).f_code.co_name == "main"
        ):
            sent.append(1)
            os.kill(os.getpid(), signal.SIGTERM)
        return real(signum, handler)

    def mine(signum, frame):
        pass

    monkeypatch.setattr(kernel_mod, "NSBOSKernel", build)
    monkeypatch.setattr(kernel_mod.time, "sleep", lambda seconds: None)
    before_int = real(signal.SIGINT, mine)
    before_term = real(signal.SIGTERM, mine)
    monkeypatch.setattr(kernel_mod.signal, "signal", first_as_finally_begins)
    escaped = None
    try:
        try:
            kernel_mod.main([])
        except KeyboardInterrupt as exc:
            escaped = exc
        except RuntimeError:
            pass  # the tick's own error, after the stop
    finally:
        real(signal.SIGINT, before_int)
        real(signal.SIGTERM, before_term)
        import logging

        root = logging.getLogger()
        for handler in list(root.handlers):
            if (
                isinstance(handler, logging.FileHandler)
                and str(kernel_env) in handler.baseFilename
            ):
                root.removeHandler(handler)
                handler.close()
    assert sent
    assert escaped is None, "KeyboardInterrupt must not leave main's finally"
    assert made[0].data_plane.get_audit_log(1)[0]["action"] == "kernel_stopped"


# -- a signal as the handlers are installed --------------------------------------------


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_a_signal_as_the_handlers_are_installed_is_a_clean_stop(
    kernel_env, monkeypatch, sig
):
    # A signal between main's two signal.signal calls is handled inside its
    # try: no KeyboardInterrupt leaves main, and the caller's handlers are
    # put back.
    real = signal.signal
    sent = []

    def signal_after_the_first(signum, handler):
        old = real(signum, handler)
        if signum == sig and handler is kernel_mod._interrupt and not sent:
            sent.append(1)
            os.kill(os.getpid(), sig)
        return old

    def mine(signum, frame):
        pass

    started = []
    Kernel = kernel_mod.NSBOSKernel

    def build():
        kernel = Kernel()
        real_start = kernel.start
        kernel.start = lambda: started.append(1) or real_start()
        return kernel

    monkeypatch.setattr(kernel_mod, "NSBOSKernel", build)
    before_int = real(signal.SIGINT, mine)
    before_term = real(signal.SIGTERM, mine)
    monkeypatch.setattr(kernel_mod.signal, "signal", signal_after_the_first)
    try:
        kernel_mod.main([])
        restored = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))
    finally:
        real(signal.SIGINT, before_int)
        real(signal.SIGTERM, before_term)
        import logging

        root = logging.getLogger()
        for handler in list(root.handlers):
            if (
                isinstance(handler, logging.FileHandler)
                and str(kernel_env) in handler.baseFilename
            ):
                root.removeHandler(handler)
                handler.close()
    assert sent and restored == (mine, mine)
    assert started == []  # stopped before it started: nothing to record
