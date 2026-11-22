"""HAL against a fake /proc and /sys tree and fake top, lspci and tegrastats
on PATH. Nothing here reads the machine the tests run on."""

import os
from pathlib import Path

import pytest

from core.kernel import hal
from core.kernel.hal import X86HAL, JetsonHAL, PlatformType, create_hal, detect_platform

MEMINFO = (
    "MemTotal:        7999536 kB\nMemFree:  1000000 kB\nMemAvailable:    1999884 kB\n"
)
TOP = (
    "top - 18:00:00 up 1 day,  1 user,  load average: 0.10, 0.20, 0.30\n"
    "Tasks: 100 total,   1 running,  99 sleeping,   0 stopped,   0 zombie\n"
    "%Cpu(s):  1.6 us,  0.8 sy,  0.0 ni, 87.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n"
)


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def machine(tmp_path, monkeypatch):
    proc, sys_ = tmp_path / "proc", tmp_path / "sys"
    _write(proc / "meminfo", MEMINFO)
    _write(proc / "cpuinfo", "processor\t: 0\nmodel name\t: Test CPU 3000\n")
    for n, (kind, milli) in enumerate([("x86_pkg_temp", "45500"), ("acpitz", "27800")]):
        _write(sys_ / "class" / "thermal" / f"thermal_zone{n}" / "type", kind + "\n")
        _write(sys_ / "class" / "thermal" / f"thermal_zone{n}" / "temp", milli + "\n")
    _write(sys_ / "class" / "thermal" / "cooling_device0" / "type", "fan\n")
    for iface in ("lo", "eth0", "wlan0"):
        (sys_ / "class" / "net" / iface).mkdir(parents=True)
    monkeypatch.setattr(hal, "PROC", str(proc))
    monkeypatch.setattr(hal, "SYS", str(sys_))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")

    class Machine:
        def tool(self, name, script):
            path = bin_dir / name
            path.write_text("#!/bin/sh\n" + script + "\n")
            path.chmod(0o755)

        def file(self, rel, text):
            _write(tmp_path / rel, text)

    m = Machine()
    m.tool("top", f"cat <<'EOF2'\n{TOP}EOF2")
    m.tool(
        "lspci",
        "echo '00:02.0 VGA compatible controller: Intel Corporation HD Graphics 630 (rev 04)'",
    )
    return m


def test_x86_hardware_info(machine):
    info = X86HAL().get_hardware_info()
    assert info.platform is PlatformType.X86_64
    assert info.cpu_model == "Test CPU 3000"
    assert info.cpu_cores == (os.cpu_count() or 0)
    assert info.total_memory_gb == 7.63
    assert info.gpu_model == "Intel Corporation HD Graphics 630 (rev 04)"
    assert sorted(info.network_interfaces) == ["eth0", "wlan0"]
    assert info.storage_total_gb >= info.storage_available_gb > 0


@pytest.mark.parametrize(
    "hal_cls", [X86HAL, lambda: JetsonHAL(PlatformType.JETSON_NANO)]
)
def test_memory_cpu_and_temperature(machine, hal_cls):
    h = hal_cls()
    assert h.get_memory_utilization() == pytest.approx(75.0, abs=0.01)
    assert h.get_cpu_utilization() == pytest.approx(12.5)
    assert h.get_temperature() == {"x86_pkg_temp": 45.5, "acpitz": 27.8}


def test_missing_sources_read_as_zero_not_errors(machine, tmp_path, monkeypatch):
    monkeypatch.setattr(hal, "PROC", str(tmp_path / "nothing"))
    monkeypatch.setattr(hal, "SYS", str(tmp_path / "nothing"))
    machine.tool("top", "exit 1")
    machine.tool("lspci", "exit 1")
    h = X86HAL()
    assert h.get_memory_utilization() == 0.0
    assert h.get_cpu_utilization() == 0.0
    assert h.get_temperature() == {}
    info = h.get_hardware_info()
    assert (info.cpu_model, info.total_memory_gb, info.gpu_model) == (
        "Unknown x86_64 CPU",
        0.0,
        "Unknown GPU",
    )
    assert info.network_interfaces == []


def test_x86_has_no_gpu_or_power_readings(machine):
    assert X86HAL().get_gpu_utilization() == 0.0
    assert X86HAL().get_power_consumption() == 0.0


def test_jetson_hardware_info(machine):
    machine.file("proc/cpuinfo", "Hardware\t: NVIDIA Tegra\n")
    info = JetsonHAL(PlatformType.JETSON_NANO).get_hardware_info()
    assert info.platform is PlatformType.JETSON_NANO
    assert info.cpu_model == "NVIDIA Tegra"
    assert info.gpu_model == "NVIDIA Jetson GPU"
    assert sorted(info.network_interfaces) == ["eth0", "wlan0"]


def test_jetson_hal_does_not_run_jtop(machine, tmp_path):
    # jtop has no --json option (jetson-stats 7.2.2); the HAL reads tegrastats.
    log = tmp_path / "jtop-ran"
    machine.tool("jtop", f"touch {log}; exit 0")
    jetson = JetsonHAL(PlatformType.JETSON_NANO)
    jetson.get_gpu_utilization()
    assert not log.exists()


@pytest.mark.parametrize(
    ("model", "cpuinfo", "release", "machine_arch", "expected"),
    [
        ("NVIDIA Jetson AGX Orin Developer Kit", "", "5.15.136-tegra", "aarch64",
         PlatformType.JETSON_AGX_ORIN),
        ("NVIDIA Jetson Nano Developer Kit", "", "4.9.337-tegra", "aarch64",
         PlatformType.JETSON_NANO),
        ("NVIDIA Jetson Thor", "", "6.8-tegra", "aarch64", PlatformType.JETSON_THOR),
        ("Raspberry Pi 5 Model B Rev 1.0", "model : raspberry pi 5", "6.6.31", "aarch64",
         PlatformType.RASPBERRY_PI),
        ("", "model name : test cpu", "6.1.0", "x86_64", PlatformType.X86_64),
        ("", "", "6.1.0", "aarch64", PlatformType.ARM64),
        ("", "", "6.1.0", "riscv64", PlatformType.UNKNOWN),
    ],
)  # fmt: skip
def test_platform_detection(
    machine, monkeypatch, model, cpuinfo, release, machine_arch, expected
):
    machine.file("proc/cpuinfo", cpuinfo)
    if model:
        machine.file("proc/device-tree/model", model + "\x00")
    monkeypatch.setattr(hal.platform, "release", lambda: release)
    monkeypatch.setattr(hal.platform, "machine", lambda: machine_arch)
    assert detect_platform() is expected


def test_create_hal_picks_the_class_for_the_platform(machine, monkeypatch):
    monkeypatch.setattr(hal, "detect_platform", lambda: PlatformType.JETSON_AGX_ORIN)
    assert isinstance(create_hal(), JetsonHAL)
    for kind in (PlatformType.X86_64, PlatformType.RASPBERRY_PI, PlatformType.UNKNOWN):
        monkeypatch.setattr(hal, "detect_platform", lambda kind=kind: kind)
        assert isinstance(create_hal(), X86HAL)


ORIN = (
    "10-27-2026 18:00:00 RAM 2448/7620MB (lfb 2x4MB) SWAP 0/3810MB CPU [2%@729,1%@729] "
    "GR3D_FREQ 37%@[305,305] VDD_IN 4583mW/4583mW VDD_SOC 1395mW/1395mW"
)
NANO = (
    "RAM 1902/3956MB (lfb 85x4MB) SWAP 0/1978MB CPU [3%@1479,1%@1479] "
    "GR3D_FREQ 12%@921 POM_5V_IN 2441/2441 POM_5V_GPU 0/0 POM_5V_CPU 371/371"
)


def _streaming_tegrastats(machine, line):
    machine.tool("tegrastats", f"while true; do echo '{line}'; sleep 1; done")


@pytest.mark.parametrize(
    ("line", "gpu", "watts"), [(ORIN, 37.0, 4.583), (NANO, 12.0, 2.441)]
)
def test_tegrastats_readings_from_a_streaming_tool(machine, line, gpu, watts):
    _streaming_tegrastats(machine, line)
    jetson = JetsonHAL(PlatformType.JETSON_AGX_ORIN)
    assert jetson.get_gpu_utilization() == gpu
    assert jetson.get_power_consumption() == pytest.approx(watts)


def test_tegrastats_that_prints_nothing_times_out_quickly(machine, monkeypatch):
    import time

    machine.tool("tegrastats", "exec sleep 30")
    monkeypatch.setattr(hal, "TEGRASTATS_TIMEOUT", 0.3)
    start = time.monotonic()
    assert JetsonHAL(PlatformType.JETSON_NANO).get_power_consumption() == 0.0
    assert time.monotonic() - start < 5


def test_no_tegrastats_reads_zero(machine, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    jetson = JetsonHAL(PlatformType.JETSON_NANO)
    assert jetson.get_gpu_utilization() == 0.0
    assert jetson.get_power_consumption() == 0.0


def test_tegrastats_is_stopped_after_reading(machine, tmp_path):
    pidfile = tmp_path / "pid"
    machine.tool(
        "tegrastats",
        f"echo $$ > {pidfile}; while true; do echo '{ORIN}'; sleep 1; done",
    )
    JetsonHAL(PlatformType.JETSON_AGX_ORIN).get_power_consumption()
    pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.parametrize(
    "model",
    [PlatformType.JETSON_NANO, PlatformType.JETSON_AGX_ORIN, PlatformType.JETSON_THOR],
)
def test_jetson_gpu_memory_is_the_shared_system_memory(machine, model):
    # An 8 GB Orin Nano is detected as AGX Orin; it must not report 64 GB.
    assert JetsonHAL(model).get_hardware_info().gpu_memory_gb == 7.63


@pytest.mark.parametrize(
    ("lspci", "name"),
    [
        ("0000:00:02.0 VGA compatible controller: Intel Corporation UHD Graphics 630",
         "Intel Corporation UHD Graphics 630"),
        ("01:00.0 3D controller: NVIDIA Corporation GA102GL [A10] (rev a1)",
         "NVIDIA Corporation GA102GL [A10] (rev a1)"),
        (("00:1f.3 Audio device: Intel Corporation 3D Sound: Device 1234\n"
          "00:02.0 VGA compatible controller: Matrox G200eR2"),
         "Matrox G200eR2"),
    ],
)  # fmt: skip
def test_gpu_name_from_lspci(machine, lspci, name):
    machine.tool("lspci", f"cat <<'EOF2'\n{lspci}\nEOF2")
    assert X86HAL().get_hardware_info().gpu_model == name


@pytest.mark.parametrize(
    ("output", "busy"),
    [
        (TOP, 12.5),
        ("Mem: 1G used\nCPU:   2% usr   1% sys   0% nic  96% idle   0% io   0% irq\n", 4.0),
        ("%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa\n", 0.0),
        ("Tasks: 3 total\n%Cpu0  :  10.0 us, 5.0 sy, 0.0 ni, 85.0 id\n", 15.0),
        ("no cpu line here\n", None),
        # A process line mentioning "cpu" must not be read as the CPU summary.
        ("  123 root  20 0 cpu_hog idle 50.0\n", None),
    ],
)  # fmt: skip
def test_cpu_busy_from_procps_and_busybox_top(output, busy):
    assert hal._cpu_busy_from_top(output) == busy


def test_busybox_top_is_read_by_both_hals(machine):
    machine.tool("top", "echo 'CPU:  10% usr   5% sys   0% nic  85% idle   0% io'")
    assert X86HAL().get_cpu_utilization() == 15.0
    assert JetsonHAL(PlatformType.JETSON_NANO).get_cpu_utilization() == 15.0


def _counting_tegrastats(machine, tmp_path, line):
    count = tmp_path / "tegrastats-runs"
    machine.tool(
        "tegrastats", f"echo x >> {count}; while true; do echo '{line}'; sleep 1; done"
    )
    return lambda: len(count.read_text().splitlines()) if count.exists() else 0


def test_gpu_and_power_share_one_tegrastats_run(machine, tmp_path):
    runs = _counting_tegrastats(machine, tmp_path, ORIN)
    jetson = JetsonHAL(PlatformType.JETSON_AGX_ORIN)
    assert (jetson.get_gpu_utilization(), jetson.get_power_consumption()) == (
        37.0,
        4.583,
    )
    assert runs() == 1


def test_a_tegrastats_line_past_its_age_is_read_again(machine, tmp_path, monkeypatch):
    runs = _counting_tegrastats(machine, tmp_path, ORIN)
    monkeypatch.setattr(hal, "TEGRASTATS_MAX_AGE", 0.0)
    jetson = JetsonHAL(PlatformType.JETSON_AGX_ORIN)
    jetson.get_gpu_utilization()
    jetson.get_power_consumption()
    assert runs() == 2


def test_an_empty_read_is_not_kept(machine, monkeypatch):
    import time

    machine.tool("tegrastats", "exec sleep 30")
    monkeypatch.setattr(hal, "TEGRASTATS_TIMEOUT", 0.2)
    jetson = JetsonHAL(PlatformType.JETSON_NANO)
    start = time.monotonic()
    assert jetson.get_gpu_utilization() == 0.0
    assert jetson.get_power_consumption() == 0.0
    elapsed = time.monotonic() - start
    assert 0.3 < elapsed < 2.0  # two 0.2 s waits: the timeout is read at call time


def test_without_top_or_statvfs_the_readings_are_zero(machine, tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))  # no top at all

    def no_statvfs(path):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(hal.os, "statvfs", no_statvfs)
    for h in (X86HAL(), JetsonHAL(PlatformType.JETSON_NANO)):
        assert h.get_cpu_utilization() == 0.0
    info = X86HAL().get_hardware_info()
    assert (info.storage_total_gb, info.storage_available_gb) == (0.0, 0.0)
    assert (
        JetsonHAL(PlatformType.JETSON_NANO).get_hardware_info().storage_total_gb == 0.0
    )


def test_without_cpuinfo_the_jetson_cpu_is_unknown_and_detection_goes_by_arch(
    machine, tmp_path, monkeypatch
):
    (tmp_path / "proc" / "cpuinfo").unlink()
    info = JetsonHAL(PlatformType.JETSON_NANO).get_hardware_info()
    assert info.cpu_model == "Unknown"
    monkeypatch.setattr(hal.platform, "release", lambda: "6.1.0")
    monkeypatch.setattr(hal.platform, "machine", lambda: "x86_64")
    assert detect_platform() is PlatformType.X86_64


# -- the board each platform reports ---------------------------------------------------

# Raspberry Pi 5 on Raspberry Pi OS (has the downstream Model line), and any
# arm64 board on a mainline kernel (no Model or Hardware line).
PI5_CPUINFO = (
    "processor\t: 0\nBogoMIPS\t: 108.00\nCPU implementer\t: 0x41\n\n"
    "Revision\t: d04170\nModel\t\t: Raspberry Pi 5 Model B Rev 1.0\n"
)
MAINLINE_ARM64_CPUINFO = "processor\t: 0\nBogoMIPS\t: 108.00\nCPU implementer\t: 0x41\n"


@pytest.mark.parametrize(
    ("cpuinfo", "model", "release", "expected", "cpu"),
    [(PI5_CPUINFO, "Raspberry Pi 5 Model B Rev 1.0", "6.6.51+rpt-rpi-2712",
      PlatformType.RASPBERRY_PI, "Raspberry Pi 5 Model B Rev 1.0"),
     (MAINLINE_ARM64_CPUINFO, None, "6.12.48+deb13-arm64", PlatformType.ARM64,
      "Unknown CPU"),
     ("processor\t: 0\nHardware\t: BCM2835\n", None, "6.1.0", PlatformType.RASPBERRY_PI,
      "BCM2835"),
     ("processor\t: 0\nModel\t\t: \nHardware\t: BCM2711\n", None, "6.1.0",
      PlatformType.RASPBERRY_PI, "BCM2711")],
    ids=["pi5", "arm64", "older-pi", "empty-model"],
)  # fmt: skip
def test_an_arm_board_is_not_reported_as_x86_64(
    machine, monkeypatch, cpuinfo, model, release, expected, cpu
):
    # The generic HAL serves every board but a Jetson, under the board's name.
    machine.file("proc/cpuinfo", cpuinfo)
    if model:
        machine.file("proc/device-tree/model", model + "\x00")
    monkeypatch.setattr(hal.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(hal.platform, "release", lambda: release)
    assert detect_platform() is expected
    info = create_hal().get_hardware_info()
    assert (info.platform, info.cpu_model) == (expected, cpu)


def test_a_pi_kernel_records_its_own_platform(machine, monkeypatch, tmp_path):
    import sys

    flat = sys.modules["hal"]  # the kernel imports its siblings flat
    monkeypatch.setattr(flat, "PROC", hal.PROC)
    monkeypatch.setattr(flat, "SYS", hal.SYS)
    monkeypatch.setattr(flat.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(flat.platform, "release", lambda: "6.6.51+rpt-rpi-2712")
    machine.file("proc/cpuinfo", PI5_CPUINFO)
    machine.file("proc/device-tree/model", "Raspberry Pi 5 Model B Rev 1.0\x00")
    monkeypatch.delenv("NGARI_KEY_PROVIDER", raising=False)
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path / "data"))
    from core.kernel import NSBOSKernel

    kernel = NSBOSKernel()
    kernel.start()
    kernel.stop()
    [started] = [e for e in kernel.data_plane.get_audit_log(10**6)
                 if e["action"] == "kernel_started"]  # fmt: skip
    # The keyed entry is kept for decades, so it must name the real platform.
    assert started["details"]["platform"] == "raspberry_pi"


@pytest.mark.parametrize(
    ("model", "expected"),
    [("NVIDIA Jetson AGX Orin Developer Kit", PlatformType.JETSON_AGX_ORIN),
     ("NVIDIA Jetson Nano Developer Kit", PlatformType.JETSON_NANO),
     ("NVIDIA Jetson Orin Nano Developer Kit", PlatformType.JETSON_AGX_ORIN),
     ("Raspberry Pi 5 Model B Rev 1.0", PlatformType.RASPBERRY_PI),
     ("Raspberry Pi 4 Model B Rev 1.5", PlatformType.RASPBERRY_PI)],
    ids=["agx-orin", "nano", "orin-nano", "pi5", "pi4"],
)  # fmt: skip
def test_the_device_tree_model_alone_identifies_the_board(
    machine, monkeypatch, model, expected
):
    # A mainline (Debian) kernel: no "-tegra" in the release, no Model or
    # Hardware line in cpuinfo. The device-tree model is matched in lowercase,
    # for "nvidia" and for "raspberry".
    machine.file("proc/cpuinfo", MAINLINE_ARM64_CPUINFO)
    machine.file("proc/device-tree/model", model + "\x00")
    monkeypatch.setattr(hal.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(hal.platform, "release", lambda: "6.12.48+deb13-arm64")
    assert detect_platform() is expected


@pytest.mark.parametrize(
    "model", ["NVIDIA Jetson AGX Thor Developer Kit", "NVIDIA Jetson Thor"]
)
def test_jetson_agx_thor_is_thor(machine, monkeypatch, model):
    machine.file("proc/device-tree/model", model + "\x00")
    monkeypatch.setattr(hal.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(hal.platform, "release", lambda: "6.8.12-tegra")
    assert detect_platform() is PlatformType.JETSON_THOR


def test_a_tegrastats_line_cut_short_does_not_outlast_the_timeout(machine, monkeypatch):
    import time

    # A partial line, then a hang: the read gives up at the 0.5 s timeout.
    machine.tool(
        "tegrastats", "printf 'RAM 1902/3956MB (lfb 85x4MB) GR3D_FREQ 1'; exec sleep 8"
    )
    monkeypatch.setattr(hal, "TEGRASTATS_TIMEOUT", 0.5)
    start = time.monotonic()
    assert hal._tegrastats_line() == ""
    assert time.monotonic() - start < 2


def test_a_line_a_tool_ends_without_a_newline_is_read(machine):
    machine.tool(
        "tegrastats", "printf 'RAM 1/2MB GR3D_FREQ 7%%@[1] VDD_IN 900mW/900mW'"
    )
    assert hal._tegrastats_line() == "RAM 1/2MB GR3D_FREQ 7%@[1] VDD_IN 900mW/900mW"


def test_a_tegrastats_line_is_read_whole_across_reads(machine):
    # The line arrives in two writes: the first byte is not the whole line.
    machine.tool(
        "tegrastats",
        "printf 'RAM 1/2MB GR3D_FREQ '; sleep 0.2; printf '37%%@[1] VDD_IN 4583mW/4583mW\\n'; "
        "exec sleep 8",
    )
    assert hal._tegrastats_line() == "RAM 1/2MB GR3D_FREQ 37%@[1] VDD_IN 4583mW/4583mW"


def test_an_endless_line_is_cut_and_the_reader_stops(machine):
    machine.tool("tegrastats", "exec yes x | tr -d '\\n'")
    line = hal._tegrastats_line()
    assert len(line.encode()) <= hal._TEGRASTATS_LINE_MAX and set(line) == {"x"}


def test_a_line_that_dribbles_in_is_given_up_at_the_deadline(machine, monkeypatch):
    import time

    # A byte every 0.2 s and never a newline: each read comes in time, the
    # whole line does not, and the deadline is the whole call's.
    machine.tool("tegrastats", "while true; do printf x; sleep 0.2; done")
    monkeypatch.setattr(hal, "TEGRASTATS_TIMEOUT", 0.5)
    start = time.monotonic()
    assert hal._tegrastats_line() == ""
    assert time.monotonic() - start < 1.5


def test_top_in_a_decimal_comma_locale_is_read_right(machine, monkeypatch):
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_NUMERIC", "de_DE.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)
    # Fake procps: a comma unless the C locale wins, as real top behaves.
    machine.tool(
        "top",
        'case "${LC_ALL:-${LC_NUMERIC:-$LANG}}" in C|C.*|POSIX) s=.;; *) s=,;; esac\n'
        'echo "%Cpu(s):  2${s}3 us,  0${s}7 sy,  0${s}0 ni, 96${s}9 id,  0${s}0 wa,'
        '  0${s}0 hi,  0${s}1 si,  0${s}0 st"',
    )
    assert X86HAL().get_cpu_utilization() == pytest.approx(3.1, abs=0.05)


def test_two_thermal_zones_of_one_type_are_both_reported(machine, tmp_path):
    import shutil

    shutil.rmtree(tmp_path / "sys" / "class" / "thermal")
    for n, (kind, milli) in {10: ("acpitz", "31000"), 0: ("acpitz", "27800"),
                             2: ("acpitz", "29800"), 1: ("cpu", "40000")}.items():  # fmt: skip
        machine.file(f"sys/class/thermal/thermal_zone{n}/type", kind + "\n")
        machine.file(f"sys/class/thermal/thermal_zone{n}/temp", milli + "\n")
    assert X86HAL().get_temperature() == {
        "acpitz": 27.8, "cpu": 40.0, "acpitz (thermal_zone2)": 29.8,
        "acpitz (thermal_zone10)": 31.0,
    }  # fmt: skip


def test_the_lowest_numbered_zone_keeps_the_plain_name_and_bad_ones_are_left_out(
    machine, tmp_path
):
    import shutil

    shutil.rmtree(tmp_path / "sys" / "class" / "thermal")
    for n, (kind, milli) in {10: ("acpitz", "31000"), 2: ("acpitz", "29800"),
                             3: ("acpitz", "not a number")}.items():  # fmt: skip
        machine.file(f"sys/class/thermal/thermal_zone{n}/type", kind + "\n")
        machine.file(f"sys/class/thermal/thermal_zone{n}/temp", milli + "\n")
    assert X86HAL().get_temperature() == {
        "acpitz": 29.8,
        "acpitz (thermal_zone10)": 31.0,
    }
