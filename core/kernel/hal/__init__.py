"""
NS-BOS Kernel - Hardware Abstraction Layer
Device-agnostic hardware interface for NGARi Sovereign Business Operating System.

Supports:
- NVIDIA Jetson (Nano, AGX Orin, Thor)
- x86_64 (Intel, AMD)
- ARM (Raspberry Pi, cloud ARM)
- Cloud VMs (AWS, GCP, Azure)
"""

import logging
import os
import platform
import re
import select
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# Roots of the kernel's pseudo-filesystems; tests point these at a fake tree.
PROC = "/proc"
SYS = "/sys"


class PlatformType(Enum):
    JETSON_NANO = "jetson_nano"
    JETSON_AGX_ORIN = "jetson_agx_orin"
    JETSON_THOR = "jetson_thor"
    X86_64 = "x86_64"
    ARM64 = "arm64"
    RASPBERRY_PI = "raspberry_pi"
    CLOUD_VM = "cloud_vm"
    UNKNOWN = "unknown"


@dataclass
class HardwareInfo:
    platform: PlatformType
    cpu_model: str
    cpu_cores: int
    total_memory_gb: float
    gpu_model: str
    gpu_memory_gb: float
    storage_total_gb: float
    storage_available_gb: float
    network_interfaces: list
    os_name: str
    os_version: str
    kernel_version: str
    hostname: str


# procps: "%Cpu(s):  1.6 us,  0.8 sy, ... 87.5 id, ..."
# BusyBox: "CPU:   2% usr   1% sys   0% nic  96% idle   0% io ..."
_TOP_IDLE = re.compile(r"(\d+(?:\.\d+)?)\s*%?\s*id(?:le)?\b")


def _cpu_busy_from_top(output: str) -> float | None:
    """CPU busy percentage from one `top -bn1` run, or None if no CPU line."""
    for line in output.splitlines():
        if re.match(r"\s*(%Cpu|CPU)", line):
            match = _TOP_IDLE.search(line)
            if match:
                return round(100.0 - float(match.group(1)), 1)
    return None


def _cpu_utilization() -> float:
    """CPU busy percentage from one `top -bn1` run (0.0 if unavailable)."""
    try:
        # The C locale: in a decimal-comma one top prints "96,9 id", which
        # reads as 9% idle.
        result = subprocess.run(
            ["top", "-bn1"], capture_output=True, text=True, timeout=5, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        logger.debug("HAL: failed running top")
        return 0.0
    busy = _cpu_busy_from_top(result.stdout)
    return 0.0 if busy is None else busy


def _memory_utilization() -> float:
    """Percentage of memory in use, from /proc/meminfo (0.0 if unreadable)."""
    try:
        with open(f"{PROC}/meminfo", "r") as f:
            lines = f.readlines()
        total = available = 0
        for line in lines:
            if line.startswith("MemTotal:"):
                total = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                available = int(line.split()[1])
        if total > 0:
            return ((total - available) / total) * 100
    except (OSError, ValueError):
        logger.debug("HAL: failed reading /proc/meminfo")
    return 0.0


def _memory_total_gb() -> float:
    """Total memory in GB, from /proc/meminfo (0.0 if unreadable)."""
    try:
        with open(f"{PROC}/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return round(int(line.split()[1]) / (1024 * 1024), 2)
    except (OSError, ValueError):
        logger.debug("HAL: failed reading /proc/meminfo")
    return 0.0


def _temperatures() -> dict:
    """Thermal zone readings in degrees C, keyed by zone type. Zones are
    read in their numeric order; a second zone of a type already seen (two
    acpitz zones, say) is keyed "<type> (<zone>)", so none is lost and the
    keys do not depend on directory order."""
    temps = {}
    try:
        zones = os.listdir(f"{SYS}/class/thermal/")
    except OSError:
        logger.debug("HAL: failed listing thermal zones")
        return temps
    numbered = [z for z in zones if z.startswith("thermal_zone")]
    for zone in sorted(numbered, key=lambda z: (len(z), z)):  # 2 before 10
        zone_path = f"{SYS}/class/thermal/{zone}"
        try:
            with open(f"{zone_path}/type", "r") as f:
                temp_type = f.read().strip()
            with open(f"{zone_path}/temp", "r") as f:
                reading = int(f.read().strip()) / 1000.0
        except (OSError, ValueError):
            logger.debug("HAL: failed reading thermal zone file")
            continue
        key = temp_type if temp_type not in temps else f"{temp_type} ({zone})"
        temps[key] = reading
    return temps


def _storage_gb() -> tuple[float, float]:
    """(total, available) GB of the root filesystem (0.0, 0.0 if unreadable)."""
    try:
        st = os.statvfs("/")
    except OSError:
        logger.debug("HAL: failed reading filesystem stats")
        return 0.0, 0.0
    return (
        round((st.f_frsize * st.f_blocks) / (1024**3), 2),
        round((st.f_frsize * st.f_bavail) / (1024**3), 2),
    )


def _network_interfaces() -> list:
    """Network interface names except lo."""
    try:
        return [iface for iface in os.listdir(f"{SYS}/class/net/") if iface != "lo"]
    except OSError:
        logger.debug("HAL: failed listing network interfaces")
        return []


class HardwareAbstractionLayer(ABC):
    """Base class for hardware abstraction"""

    @abstractmethod
    def get_hardware_info(self) -> HardwareInfo:
        """Get hardware information"""

    @abstractmethod
    def get_gpu_utilization(self) -> float:
        """Get GPU utilization percentage"""

    @abstractmethod
    def get_memory_utilization(self) -> float:
        """Get memory utilization percentage"""

    @abstractmethod
    def get_cpu_utilization(self) -> float:
        """Get CPU utilization percentage"""

    @abstractmethod
    def get_temperature(self) -> dict:
        """Get temperature readings"""

    @abstractmethod
    def get_power_consumption(self) -> float:
        """Get power consumption in watts"""


TEGRASTATS_TIMEOUT = 3.0
# GPU and power come from the same tegrastats line; a line this recent is
# reused instead of starting tegrastats and waiting an interval again.
TEGRASTATS_MAX_AGE = 2.0
_GR3D = re.compile(r"GR3D_FREQ (\d+(?:\.\d+)?)%")
# VDD_IN 4583mW/4583mW on Orin and Xavier; POM_5V_IN 2441/2441 on the Nano.
_POWER_IN = re.compile(r"(?:VDD_IN|POM_5V_IN) (\d+)(?:mW)?/")


_TEGRASTATS_LINE_MAX = 65536  # bytes; a real line is a few hundred


def _tegrastats_line(timeout: float | None = None) -> str:
    """One line of tegrastats output, or "". tegrastats prints a line per
    interval until it is killed, so it is read, not waited for."""
    if timeout is None:
        timeout = TEGRASTATS_TIMEOUT
    try:
        proc = subprocess.Popen(
            ["tegrastats"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
    except OSError:
        return ""
    # Read by hand against the deadline: select() says only that the first
    # byte is there, and readline() would then wait for the newline with no
    # limit, so a line cut short would hold the caller indefinitely.
    deadline = time.monotonic() + timeout
    fd, data = proc.stdout.fileno(), b""
    try:
        while b"\n" not in data and len(data) < _TEGRASTATS_LINE_MAX:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                return ""  # no whole line in time
            chunk = os.read(fd, 4096)
            if not chunk:
                break  # the tool ended; what it printed is the line
            data += chunk
        return data.split(b"\n", 1)[0][:_TEGRASTATS_LINE_MAX].decode("utf-8", "replace")
    finally:
        proc.kill()
        proc.wait()
        proc.stdout.close()


class JetsonHAL(HardwareAbstractionLayer):
    """Hardware abstraction for NVIDIA Jetson platforms"""

    def __init__(self, model: PlatformType):
        self.model = model
        self._tegra_line = ""
        self._tegra_at = 0.0

    def _tegrastats(self) -> str:
        """A tegrastats line no older than TEGRASTATS_MAX_AGE seconds."""
        now = time.monotonic()
        if self._tegra_line and now - self._tegra_at < TEGRASTATS_MAX_AGE:
            return self._tegra_line
        line = _tegrastats_line()
        if line:
            self._tegra_line, self._tegra_at = line, now
        return line

    def get_hardware_info(self) -> HardwareInfo:
        """Get Jetson hardware information"""
        cpu_info = self._get_cpu_info()
        memory_info = self._get_memory_info()
        gpu_info = self._get_gpu_info()
        storage_info = self._get_storage_info()

        return HardwareInfo(
            platform=self.model,
            cpu_model=cpu_info.get("model", "Unknown"),
            cpu_cores=cpu_info.get("cores", 0),
            total_memory_gb=memory_info.get("total_gb", 0),
            gpu_model=gpu_info.get("model", "NVIDIA Jetson GPU"),
            gpu_memory_gb=gpu_info.get("memory_gb", 0),
            storage_total_gb=storage_info.get("total_gb", 0),
            storage_available_gb=storage_info.get("available_gb", 0),
            network_interfaces=self._get_network_interfaces(),
            os_name=platform.system(),
            os_version=platform.release(),
            kernel_version=platform.version(),
            hostname=platform.node(),
        )

    def get_gpu_utilization(self) -> float:
        """GPU utilization from tegrastats, which ships with JetPack."""
        match = _GR3D.search(self._tegrastats())
        if match:
            return float(match.group(1))
        logger.debug("HAL: no GR3D_FREQ in tegrastats output")
        return 0.0

    def get_memory_utilization(self) -> float:
        """Get memory utilization percentage"""
        return _memory_utilization()

    def get_cpu_utilization(self) -> float:
        """Get CPU utilization percentage"""
        return _cpu_utilization()

    def get_temperature(self) -> dict:
        """Get temperature readings from thermal zones"""
        return _temperatures()

    def get_power_consumption(self) -> float:
        """Get power consumption in watts (Jetson specific)"""
        match = _POWER_IN.search(self._tegrastats())
        if match:
            return int(match.group(1)) / 1000.0
        logger.debug("HAL: no input power rail in tegrastats output")
        return 0.0

    def _get_cpu_info(self) -> dict:
        """Get CPU information"""
        info = {"model": "Unknown", "cores": 0}
        try:
            with open(f"{PROC}/cpuinfo", "r") as f:
                content = f.read()

            for line in content.split("\n"):
                if line.startswith(("Hardware", "model name")):
                    info["model"] = line.split(":")[1].strip()
                    break

            info["cores"] = os.cpu_count() or 0
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading /proc/cpuinfo")

        return info

    def _get_memory_info(self) -> dict:
        """Get memory information"""
        return {"total_gb": _memory_total_gb()}

    def _get_gpu_info(self) -> dict:
        """GPU information. Jetson GPUs have no memory of their own: they
        share system RAM, so the GPU's memory is what the board has, read
        from /proc/meminfo rather than assumed from the model name."""
        return {
            "model": "NVIDIA Jetson GPU",
            "memory_gb": self._get_memory_info().get("total_gb", 0),
        }

    def _get_storage_info(self) -> dict:
        """Get storage information"""
        total, available = _storage_gb()
        return {"total_gb": total, "available_gb": available}

    def _get_network_interfaces(self) -> list:
        """Get network interfaces"""
        return _network_interfaces()


class X86HAL(HardwareAbstractionLayer):
    """Hardware abstraction for x86_64, and for every board that is not a
    Jetson (Raspberry Pi, other ARM64, cloud VMs): the generic /proc and
    /sys readings. It reports the platform it was made for, the one
    detect_platform() found."""

    def __init__(self, platform_type: PlatformType = PlatformType.X86_64):
        self.platform_type = platform_type

    def get_hardware_info(self) -> HardwareInfo:
        """Get hardware information"""
        return HardwareInfo(
            platform=self.platform_type,
            cpu_model=self._get_cpu_model(),
            cpu_cores=os.cpu_count() or 0,
            total_memory_gb=self._get_memory_gb(),
            gpu_model=self._get_gpu_model(),
            gpu_memory_gb=0,
            storage_total_gb=self._get_storage_total(),
            storage_available_gb=self._get_storage_available(),
            network_interfaces=self._get_network_interfaces(),
            os_name=platform.system(),
            os_version=platform.release(),
            kernel_version=platform.version(),
            hostname=platform.node(),
        )

    def get_gpu_utilization(self) -> float:
        """Get GPU utilization (placeholder)"""
        return 0.0

    def get_memory_utilization(self) -> float:
        """Get memory utilization percentage"""
        return _memory_utilization()

    def get_cpu_utilization(self) -> float:
        """Get CPU utilization percentage"""
        return _cpu_utilization()

    def get_temperature(self) -> dict:
        """Get temperature readings from thermal zones"""
        return _temperatures()

    def get_power_consumption(self) -> float:
        """Get power consumption (not available on x86)"""
        return 0.0

    def _get_cpu_model(self) -> str:
        """Get CPU model"""
        # x86 names the CPU in "model name"; ARM kernels give the board in
        # "Model" (Raspberry Pi OS) or the SoC in "Hardware".
        found = {}
        try:
            with open(f"{PROC}/cpuinfo", "r") as f:
                for line in f:
                    field, colon, value = line.partition(":")
                    if colon and value.strip():
                        found.setdefault(field.strip().lower(), value.strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading CPU model")
        for field in ("model name", "model", "hardware"):
            if field in found:
                return found[field]
        if self.platform_type is PlatformType.X86_64:
            return "Unknown x86_64 CPU"
        return "Unknown CPU"

    def _get_memory_gb(self) -> float:
        """Get total memory in GB"""
        return _memory_total_gb()

    def _get_gpu_model(self) -> str:
        """Get GPU model"""
        try:
            result = subprocess.run(
                ["lspci"], capture_output=True, text=True, timeout=5, check=False
            )
            for line in result.stdout.split("\n"):
                # "[dddd:]bb:dd.f Class name: Device", and the domain is
                # printed on machines with more than one PCI domain.
                _, _, rest = line.partition(" ")
                kind, sep, device = rest.partition(": ")
                if sep and ("VGA" in kind or "3D" in kind):
                    return device.strip()
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed querying GPU model")

        return "Unknown GPU"

    def _get_storage_total(self) -> float:
        """Get total storage in GB"""
        return _storage_gb()[0]

    def _get_storage_available(self) -> float:
        """Get available storage in GB"""
        return _storage_gb()[1]

    def _get_network_interfaces(self) -> list:
        """Get network interfaces"""
        return _network_interfaces()


def detect_platform() -> PlatformType:
    """Auto-detect the current platform"""
    machine = platform.machine().lower()
    cpu_info = ""
    kernel_release = platform.release().lower()
    device_model = ""

    try:
        with open(f"{PROC}/cpuinfo", "r") as f:
            cpu_info = f.read().lower()
    except (OSError, ValueError, subprocess.SubprocessError):
        logger.debug("HAL: failed reading /proc/cpuinfo for platform detection")

    try:
        with open(f"{PROC}/device-tree/model", "r") as f:
            # "NVIDIA Jetson AGX Orin Developer Kit", "Raspberry Pi 5 Model B":
            # matched in lower case like everything else here.
            device_model = f.read().strip().rstrip("\x00").lower()
    except (OSError, ValueError, subprocess.SubprocessError):
        logger.debug("HAL: failed reading device-tree model")

    if (
        "tegra" in device_model
        or "tegra" in kernel_release
        or "tegra" in cpu_info
        or "nvidia" in cpu_info
        or "nvidia" in device_model
    ):
        model_lower = (device_model + cpu_info).lower()
        # Thor first: the AGX Thor developer kit has "agx" in its name too.
        if "thor" in model_lower:
            return PlatformType.JETSON_THOR
        elif "agx" in model_lower or "orin" in model_lower:
            return PlatformType.JETSON_AGX_ORIN
        else:
            return PlatformType.JETSON_NANO

    # Check for Raspberry Pi: the device tree names the board on any kernel;
    # cpuinfo only on Raspberry Pi OS's own.
    if "raspberry pi" in device_model or "raspberry" in cpu_info or "bcm" in cpu_info:
        return PlatformType.RASPBERRY_PI

    if machine in ("x86_64", "amd64"):
        return PlatformType.X86_64
    elif machine in ("aarch64", "arm64"):
        return PlatformType.ARM64

    return PlatformType.UNKNOWN


def create_hal() -> HardwareAbstractionLayer:
    """Factory function to create the appropriate HAL instance"""
    platform_type = detect_platform()

    if platform_type in (
        PlatformType.JETSON_NANO,
        PlatformType.JETSON_AGX_ORIN,
        PlatformType.JETSON_THOR,
    ):
        return JetsonHAL(platform_type)
    # Every other board gets the generic readings, under its own name.
    return X86HAL(platform_type)


if __name__ == "__main__":
    hal = create_hal()
    info = hal.get_hardware_info()

    print(f"Platform: {info.platform.value}")
    print(f"CPU: {info.cpu_model} ({info.cpu_cores} cores)")
    print(f"Memory: {info.total_memory_gb} GB")
    print(f"GPU: {info.gpu_model} ({info.gpu_memory_gb} GB)")
    print(
        f"Storage: {info.storage_available_gb:.1f} GB available of {info.storage_total_gb:.1f} GB"
    )
    print(f"OS: {info.os_name} {info.os_version}")
    print(f"Hostname: {info.hostname}")
    print(f"Network: {', '.join(info.network_interfaces)}")

    print(f"\nGPU Utilization: {hal.get_gpu_utilization():.1f}%")
    print(f"Memory Utilization: {hal.get_memory_utilization():.1f}%")
    print(f"CPU Utilization: {hal.get_cpu_utilization():.1f}%")
    print(f"Temperature: {hal.get_temperature()}")
    print(f"Power: {hal.get_power_consumption():.1f}W")
