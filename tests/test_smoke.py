"""Hermetic smoke tests for the NS-BOS kernel core modules.

No network, no Ollama, no server dependencies — exercises the pure
logic paths (registry round-trips, tool-call parsing, platform/HAL
detection, sandbox result model).
"""

import importlib
import json

from core.kernel.hal import (
    HardwareInfo,
    PlatformType,
    create_hal,
    detect_platform,
)
from core.kernel.inference import (
    InferenceEngine,
    ModelInfo,
    ModelRegistry,
    OllamaInterface,
)
from core.kernel.sandbox.bwrap import SandboxResult


def test_all_kernel_modules_import():
    for name in (
        "core.kernel.agent_runtime",
        "core.kernel.data_plane",
        "core.kernel.generative_ui",
        "core.kernel.hal",
        "core.kernel.inference",
        "core.kernel.network_sync",
        "core.kernel.sandbox",
        "core.kernel.sandbox.bwrap",
        "core.kernel.sandbox.seccomp",
    ):
        assert importlib.import_module(name) is not None


def test_detect_platform_returns_enum():
    plat = detect_platform()
    assert isinstance(plat, PlatformType)


def test_create_hal_hardware_info():
    instance = create_hal()
    info = instance.get_hardware_info()
    assert isinstance(info, HardwareInfo)
    assert isinstance(info.cpu_model, str) and info.cpu_model
    assert isinstance(info.cpu_cores, int) and info.cpu_cores > 0
    assert isinstance(info.total_memory_gb, float)
    assert isinstance(info.os_name, str) and info.os_name
    assert isinstance(info.hostname, str) and info.hostname
    assert isinstance(info.network_interfaces, list)
    assert isinstance(instance.get_memory_utilization(), float)
    assert isinstance(instance.get_cpu_utilization(), float)


def test_sandboxresult_dict():
    r = SandboxResult(
        stdout="out", stderr="err", exit_code=7, elapsed_seconds=1.2345, truncated=True
    )
    d = r.to_dict()
    assert d["stdout"] == "out" and d["stderr"] == "err"
    assert d["exit_code"] == 7 and d["truncated"] is True
    assert d["elapsed_seconds"] == 1.23


def test_model_registry_roundtrip(tmp_path):
    registry = ModelRegistry(registry_dir=str(tmp_path))
    model = ModelInfo(
        name="test-model:latest",
        engine=InferenceEngine.OLLAMA,
        size_gb=1.0,
        parameters="1b",
        context_length=4096,
        quantization="q4",
        status="available",
        last_used="2026-01-01T00:00:00Z",
    )
    registry.register_model(model)
    loaded = ModelRegistry(registry_dir=str(tmp_path))
    found = loaded.get_model("test-model:latest")
    assert found is not None
    assert found.engine == InferenceEngine.OLLAMA
    assert found.size_gb == 1.0
    assert loaded.remove_model("test-model:latest") is True
    assert loaded.remove_model("missing") is False


def test_tool_call_extraction_json_and_codeblock():
    oi = OllamaInterface.__new__(OllamaInterface)
    result = oi._extract_tool_calls_from_content(
        '{"name":"get_weather","arguments":{"city":"NYC"}}'
    )
    assert result and result[0]["function"]["name"] == "get_weather"
    assert result[0]["function"]["arguments"] == {"city": "NYC"}

    fenced = '```json\n{"name":"get_weather","arguments":{"city":"SF"}}\n```'
    result = oi._extract_tool_calls_from_content(fenced)
    assert result and result[0]["function"]["name"] == "get_weather"

    embedded = 'I will call: {"name":"get_weather","arguments":{"city":"LA"}}'
    result = oi._extract_tool_calls_from_content(embedded)
    assert result and result[0]["function"]["name"] == "get_weather"

    assert oi._extract_tool_calls_from_content("just a normal answer") is None


def test_tool_call_extraction_bad_json_does_not_crash():
    oi = OllamaInterface.__new__(OllamaInterface)
    assert oi._extract_tool_calls_from_content("{not json at all") is None


def test_factory_registry_json_serializable():
    registry = ModelRegistry(registry_dir="/tmp/ngari-kernel-test-registry")
    registry.models.clear()
    data = {"models": len(registry.models), "files": [str(registry.registry_file)]}
    assert json.dumps(data) is not None
