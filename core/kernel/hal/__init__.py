"""
NS-BOS Kernel - Hardware Abstraction Layer
Device-agnostic hardware interface for NGARi Sovereign Business Operating System.

Supports:
- NVIDIA Jetson (Nano, AGX Orin, Thor)
- x86_64 (Intel, AMD)
- ARM (Raspberry Pi, cloud ARM)
- Cloud VMs (AWS, GCP, Azure)
"""

import json
import logging
import os
import platform
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


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


class JetsonHAL(HardwareAbstractionLayer):
    """Hardware abstraction for NVIDIA Jetson platforms"""

    def __init__(self, model: PlatformType):
        self.model = model
        self._jetson_stats = self._detect_jetson_stats()

    def _detect_jetson_stats(self) -> bool:
        """Check if jetson-stats is available"""
        try:
            result = subprocess.run(
                ["jtop", "--json"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

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
            hostname=platform.node()
        )

    def get_gpu_utilization(self) -> float:
        """Get GPU utilization from jtop or tegrastats"""
        if self._jetson_stats:
            try:
                result = subprocess.run(
                    ["jtop", "--json"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False
                )
                data = json.loads(result.stdout)
                return data.get("gpu", {}).get("status", 0)
            except (OSError, ValueError, subprocess.SubprocessError):
                logger.debug("HAL: GPU util via jtop failed")


        # Fallback to tegrastats
        try:
            result = subprocess.run(
                ["tegrastats"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False
            )
            # Parse GPU utilization from tegrastats output
            output = result.stdout
            if "GR3D_FREQ" in output:
                freq = output.split("GR3D_FREQ ")[1].split("%")[0]
                return float(freq)
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: GPU util via tegrastats failed")


        return 0.0

    def get_memory_utilization(self) -> float:
        """Get memory utilization percentage"""
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()

            total = available = 0
            for line in lines:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    available = int(line.split()[1])

            if total > 0:
                return ((total - available) / total) * 100
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading /proc/meminfo")


        return 0.0

    def get_cpu_utilization(self) -> float:
        """Get CPU utilization percentage"""
        try:
            result = subprocess.run(
                ["top", "-bn1"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            for line in result.stdout.split("\n"):
                if "%Cpu" in line or "cpu" in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if "id" in part.lower():
                            idle = float(parts[i - 1])
                            return 100.0 - idle
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed parsing CPU from top")


        return 0.0

    def get_temperature(self) -> dict:
        """Get temperature readings from thermal zones"""
        temps = {}
        try:
            for zone in os.listdir("/sys/class/thermal/"):
                if zone.startswith("thermal_zone"):
                    zone_path = f"/sys/class/thermal/{zone}"
                    try:
                        with open(f"{zone_path}/type", "r") as f:
                            temp_type = f.read().strip()
                        with open(f"{zone_path}/temp", "r") as f:
                            temp_value = int(f.read().strip()) / 1000.0
                        temps[temp_type] = temp_value
                    except (OSError, ValueError, subprocess.SubprocessError):
                        logger.debug("HAL: failed reading thermal zone file")

        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed listing thermal zones")


        return temps

    def get_power_consumption(self) -> float:
        """Get power consumption in watts (Jetson specific)"""
        try:
            result = subprocess.run(
                ["tegrastats"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False
            )
            output = result.stdout
            if "VDD_IN" in output:
                # Parse power from tegrastats
                parts = output.split("VDD_IN ")
                if len(parts) > 1:
                    power_str = parts[1].split("mW")[0].strip()
                    return float(power_str) / 1000.0
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading power from tegrastats")


        return 0.0

    def _get_cpu_info(self) -> dict:
        """Get CPU information"""
        info = {"model": "Unknown", "cores": 0}
        try:
            with open("/proc/cpuinfo", "r") as f:
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
        info = {"total_gb": 0}
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total_kb = int(line.split()[1])
                        info["total_gb"] = round(total_kb / (1024 * 1024), 2)
                        break
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed parsing /proc/meminfo")


        return info

    def _get_gpu_info(self) -> dict:
        """Get GPU information"""
        info = {"model": "NVIDIA Jetson GPU", "memory_gb": 0}

        # Map Jetson models to GPU memory
        gpu_memory_map = {
            PlatformType.JETSON_NANO: 4,
            PlatformType.JETSON_AGX_ORIN: 64,
            PlatformType.JETSON_THOR: 128,
        }

        info["memory_gb"] = gpu_memory_map.get(self.model, 0)
        return info

    def _get_storage_info(self) -> dict:
        """Get storage information"""
        info = {"total_gb": 0, "available_gb": 0}
        try:
            statvfs = os.statvfs("/")
            info["total_gb"] = round(
                (statvfs.f_frsize * statvfs.f_blocks) / (1024 ** 3), 2
            )
            info["available_gb"] = round(
                (statvfs.f_frsize * statvfs.f_bavail) / (1024 ** 3), 2
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading filesystem stats")


        return info

    def _get_network_interfaces(self) -> list:
        """Get network interface information"""
        interfaces = []
        try:
            for iface in os.listdir("/sys/class/net/"):
                if iface != "lo":
                    interfaces.append(iface)
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed listing network interfaces")


        return interfaces


class X86HAL(HardwareAbstractionLayer):
    """Hardware abstraction for x86_64 platforms"""

    def get_hardware_info(self) -> HardwareInfo:
        """Get x86_64 hardware information"""
        return HardwareInfo(
            platform=PlatformType.X86_64,
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
            hostname=platform.node()
        )

    def get_gpu_utilization(self) -> float:
        """Get GPU utilization (placeholder)"""
        return 0.0

    def get_memory_utilization(self) -> float:
        """Get memory utilization percentage"""
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()

            total = available = 0
            for line in lines:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    available = int(line.split()[1])

            if total > 0:
                return ((total - available) / total) * 100
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading /proc/meminfo")


        return 0.0

    def get_cpu_utilization(self) -> float:
        """Get CPU utilization percentage"""
        try:
            result = subprocess.run(
                ["top", "-bn1"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            for line in result.stdout.split("\n"):
                if "%Cpu" in line or "cpu" in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if "id" in part.lower():
                            idle = float(parts[i - 1])
                            return 100.0 - idle
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed parsing CPU from top")


        return 0.0

    def get_temperature(self) -> dict:
        """Get temperature readings"""
        temps = {}
        try:
            for zone in os.listdir("/sys/class/thermal/"):
                if zone.startswith("thermal_zone"):
                    zone_path = f"/sys/class/thermal/{zone}"
                    try:
                        with open(f"{zone_path}/type", "r") as f:
                            temp_type = f.read().strip()
                        with open(f"{zone_path}/temp", "r") as f:
                            temp_value = int(f.read().strip()) / 1000.0
                        temps[temp_type] = temp_value
                    except (OSError, ValueError, subprocess.SubprocessError):
                        logger.debug("HAL: failed reading thermal zone file")

        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed listing thermal zones")


        return temps

    def get_power_consumption(self) -> float:
        """Get power consumption (not available on x86)"""
        return 0.0

    def _get_cpu_model(self) -> str:
        """Get CPU model"""
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.startswith("model name"):
                        return line.split(":")[1].strip()
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading CPU model")

        return "Unknown x86_64 CPU"

    def _get_memory_gb(self) -> float:
        """Get total memory in GB"""
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total_kb = int(line.split()[1])
                        return round(total_kb / (1024 * 1024), 2)
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading /proc/meminfo")

        return 0.0

    def _get_gpu_model(self) -> str:
        """Get GPU model"""
        try:
            result = subprocess.run(
                ["lspci"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            for line in result.stdout.split("\n"):
                if "VGA" in line or "3D" in line:
                    return line.split(":")[2].strip()
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed querying GPU model")

        return "Unknown GPU"

    def _get_storage_total(self) -> float:
        """Get total storage in GB"""
        try:
            statvfs = os.statvfs("/")
            return round((statvfs.f_frsize * statvfs.f_blocks) / (1024 ** 3), 2)
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading filesystem stats")

        return 0.0

    def _get_storage_available(self) -> float:
        """Get available storage in GB"""
        try:
            statvfs = os.statvfs("/")
            return round((statvfs.f_frsize * statvfs.f_bavail) / (1024 ** 3), 2)
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed reading filesystem stats")

        return 0.0

    def _get_network_interfaces(self) -> list:
        """Get network interfaces"""
        interfaces = []
        try:
            for iface in os.listdir("/sys/class/net/"):
                if iface != "lo":
                    interfaces.append(iface)
        except (OSError, ValueError, subprocess.SubprocessError):
            logger.debug("HAL: failed listing network interfaces")

        return interfaces


def detect_platform() -> PlatformType:
    """Auto-detect the current platform"""
    machine = platform.machine().lower()
    cpu_info = ""
    kernel_release = platform.release().lower()
    device_model = ""

    try:
        with open("/proc/cpuinfo", "r") as f:
            cpu_info = f.read().lower()
    except (OSError, ValueError, subprocess.SubprocessError):
        logger.debug("HAL: failed reading /proc/cpuinfo for platform detection")


    try:
        with open("/proc/device-tree/model", "r") as f:
            device_model = f.read().strip().rstrip("\x00")
    except (OSError, ValueError, subprocess.SubprocessError):
        logger.debug("HAL: failed reading device-tree model")


    if "tegra" in device_model or "tegra" in kernel_release or "tegra" in cpu_info or "nvidia" in cpu_info or "nvidia" in device_model:
        model_lower = (device_model + cpu_info).lower()
        if "agx" in model_lower or "orin" in model_lower:
            return PlatformType.JETSON_AGX_ORIN
        elif "thor" in model_lower:
            return PlatformType.JETSON_THOR
        else:
            return PlatformType.JETSON_NANO

    # Check for Raspberry Pi
    if "raspberry" in cpu_info or "bcm" in cpu_info:
        return PlatformType.RASPBERRY_PI

    # Check architecture
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
    elif platform_type in (
        PlatformType.X86_64,
        PlatformType.ARM64,
        PlatformType.RASPBERRY_PI,
        PlatformType.CLOUD_VM,
    ):
        return X86HAL()
    else:
        return X86HAL()  # Fallback


if __name__ == "__main__":
    hal = create_hal()
    info = hal.get_hardware_info()

    print(f"Platform: {info.platform.value}")
    print(f"CPU: {info.cpu_model} ({info.cpu_cores} cores)")
    print(f"Memory: {info.total_memory_gb} GB")
    print(f"GPU: {info.gpu_model} ({info.gpu_memory_gb} GB)")
    print(f"Storage: {info.storage_available_gb:.1f} GB available of {info.storage_total_gb:.1f} GB")
    print(f"OS: {info.os_name} {info.os_version}")
    print(f"Hostname: {info.hostname}")
    print(f"Network: {', '.join(info.network_interfaces)}")

    print(f"\nGPU Utilization: {hal.get_gpu_utilization():.1f}%")
    print(f"Memory Utilization: {hal.get_memory_utilization():.1f}%")
    print(f"CPU Utilization: {hal.get_cpu_utilization():.1f}%")
    print(f"Temperature: {hal.get_temperature()}")
    print(f"Power: {hal.get_power_consumption():.1f}W")
