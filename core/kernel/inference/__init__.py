"""
NS-BOS Kernel - Local Inference Engine Interface
Supports Ollama, llama.cpp, and vLLM interfaces.
Model registry and management.
"""

import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)


class InferenceEngine(Enum):
    OLLAMA = "ollama"
    LLAMA_CPP = "llama_cpp"
    VLLM = "vllm"


@dataclass
class ModelInfo:
    name: str
    engine: InferenceEngine
    size_gb: float
    parameters: str
    context_length: int
    quantization: str
    status: str  # available, loading, loaded, error
    last_used: str = ""


class OllamaInterface:
    """Interface to Ollama local inference engine"""

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.available = self._check_availability()

    def _check_availability(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def list_models(self) -> list[ModelInfo]:
        """List available Ollama models"""
        if not self.available:
            return []

        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                data = response.json()
                models = []
                for model in data.get("models", []):
                    models.append(ModelInfo(
                        name=model["name"],
                        engine=InferenceEngine.OLLAMA,
                        size_gb=round(model.get("size", 0) / (1024**3), 2),
                        parameters="unknown",
                        context_length=4096,
                        quantization="unknown",
                        status="available",
                        last_used=model.get("modified_at", "")
                    ))
                return models
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"Failed to list Ollama models: {e}")

        return []

    def generate(self, model: str, prompt: str, stream: bool = False) -> str:
        """Generate text using Ollama"""
        if not self.available:
            raise RuntimeError("Ollama is not available")

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": stream
                },
                timeout=120
            )
            if response.status_code == 200:
                if stream:
                    full_response = ""
                    for line in response.iter_lines():
                        if line:
                            data = json.loads(line)
                            full_response += data.get("response", "")
                            if data.get("done", False):
                                break
                    return full_response
                else:
                    return response.json().get("response", "")
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"Ollama generation failed: {e}")

        return ""

    def chat(self, model: str, messages: list[dict], stream: bool = False,
             images: list[str] | None = None,
             tools: list[dict] | None = None,
             format: str | None = None,
             temperature: float | None = None) -> str:
        """Chat with Ollama using chat format"""
        if not self.available:
            raise RuntimeError("Ollama is not available")

        msgs = messages
        if images:
            msgs = list(messages)
            if msgs and msgs[-1]["role"] == "user":
                msgs[-1] = {**msgs[-1], "images": images}
        body: dict[str, Any] = {
            "model": model,
            "messages": msgs,
            "stream": stream
        }
        if tools:
            body["tools"] = tools
        if format:
            body["format"] = format
        if temperature is not None:
            body["options"] = {**body.get("options", {}), "temperature": temperature}

        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=body,
                timeout=120
            )
            if response.status_code == 200:
                if stream:
                    full_response = ""
                    for line in response.iter_lines():
                        if line:
                            data = json.loads(line)
                            full_response += data.get("message", {}).get("content", "")
                            if data.get("done", False):
                                break
                    return full_response
                else:
                    return response.json().get("message", {}).get("content", "")
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"Ollama chat failed: {e}")

        return ""

    def chat_stream(self, model: str, messages: list[dict],
                    images: list[str] | None = None,
                    tools: list[dict] | None = None,
                    format: str | None = None,
                    temperature: float | None = None):
        """Stream chat tokens from Ollama. Yields (token, done) tuples."""
        if not self.available:
            raise RuntimeError("Ollama is not available")

        msgs = messages
        if images:
            msgs = list(messages)
            if msgs and msgs[-1]["role"] == "user":
                msgs[-1] = {**msgs[-1], "images": images}

        body: dict[str, Any] = {
            "model": model,
            "messages": msgs,
            "stream": True,
        }
        if tools:
            body["tools"] = tools
        if format:
            body["format"] = format
        if temperature is not None:
            body["options"] = {**body.get("options", {}), "temperature": temperature}

        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=body,
                timeout=300,
                stream=True,
            )
            if response.status_code != 200:
                logger.error(f"Ollama chat_stream HTTP {response.status_code}: {response.text[:200]}")
                yield ("", True)
                return

            for line in response.iter_lines():
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                token = data.get("message", {}).get("content", "")
                done = data.get("done", False)
                yield (token, done)
                if done:
                    return
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama chat_stream failed: {e}")
            yield ("", True)

    @staticmethod
    def _extract_tool_calls_from_content(content: str) -> list[dict] | None:
        """Parse JSON tool calls from model text content.

        Models may return tool calls as pure JSON or embedded in markdown:
          {"name":"get_weather","arguments":{"city":"NYC"}}
          ```json\n{"name":"get_weather","arguments":{"city":"NYC"}}\n```
          I'll call get_weather: {"name":"get_weather","arguments":{"city":"NYC"}}

        Returns Ollama-format tool_calls list or None.
        """
        # Try finding JSON in markdown code block first
        m = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
        if m:
            candidate = m.group(1).strip()
        else:
            candidate = content.strip()

        # Try parsing as JSON directly
        for text in [candidate, content.strip()]:
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and "name" in parsed:
                    args = parsed.get("arguments", {})
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            pass
                    return [{
                        "id": f"call_{int(time.time()*1000)}",
                        "function": {
                            "name": parsed["name"],
                            "arguments": args if isinstance(args, dict) else str(args),
                        },
                    }]
                if isinstance(parsed, list):
                    result = []
                    for item in parsed:
                        if isinstance(item, dict) and "name" in item:
                            args = item.get("arguments", {})
                            if isinstance(args, str):
                                try:
                                    args = json.loads(args)
                                except json.JSONDecodeError:
                                    pass
                            result.append({
                                "id": f"call_{int(time.time()*1000)}_{len(result)}",
                                "function": {
                                    "name": item["name"],
                                    "arguments": args if isinstance(args, dict) else str(args),
                                },
                            })
                    if result:
                        return result
            except (json.JSONDecodeError, TypeError):
                pass

        # Fallback: scan for {"name":  pattern anywhere in content
        m = re.search(r'\{\s*"name"\s*:\s*"[^"]+"', content)
        if m:
            start = m.start()
            brace_count = 0
            for i in range(start, len(content)):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        try:
                            parsed = json.loads(content[start:i+1])
                            if isinstance(parsed, dict) and "name" in parsed:
                                args = parsed.get("arguments", {})
                                if isinstance(args, str):
                                    try:
                                        args = json.loads(args)
                                    except json.JSONDecodeError:
                                        pass
                                return [{
                                    "id": f"call_{int(time.time()*1000)}",
                                    "function": {
                                        "name": parsed["name"],
                                        "arguments": args if isinstance(args, dict) else str(args),
                                    },
                                }]
                        except json.JSONDecodeError:
                            pass
                        break

        return None

    def chat_with_tools(self, model: str, messages: list[dict],
                        tools: list[dict],
                        max_iterations: int = 4,
                        images: list[str] | None = None) -> dict[str, Any]:
        """Chat with tool-calling loop: call → dispatch → re-call until done.

        Handles both native Ollama tool_calls and JSON text-format tool calls.
        Uses the tool registry from core.tools to dispatch tool calls.
        Returns dict with content, tool_calls_history (list of {name, arguments, result}).
        """
        if not self.available:
            raise RuntimeError("Ollama is not available")

        msgs = list(messages)
        iteration = 0
        tool_calls_history = []

        while iteration < max_iterations:
            iteration += 1

            body: dict[str, Any] = {
                "model": model,
                "messages": msgs,
                "tools": tools,
                "stream": False,
            }
            if images and msgs and msgs[-1].get("role") == "user":
                msgs[-1] = {**msgs[-1], "images": images}

            try:
                resp = requests.post(
                    f"{self.base_url}/api/chat",
                    json=body,
                    timeout=300,
                )
                if resp.status_code != 200:
                    logger.error(f"Ollama chat_with_tools HTTP {resp.status_code}: {resp.text[:200]}")
                    return {"content": "", "tool_calls": []}
                data = resp.json()
            except (requests.exceptions.RequestException, ValueError) as e:
                logger.error(f"Ollama chat_with_tools failed: {e}")
                return {"content": "", "tool_calls": []}

            msg = data.get("message", {})
            content = msg.get("content", "")
            tool_calls = msg.get("tool_calls")

            # Fallback: extract JSON tool calls from text content
            if not tool_calls:
                extracted = self._extract_tool_calls_from_content(content)
                if extracted:
                    tool_calls = extracted
                    logger.info(f"chat_with_tools: extracted {len(tool_calls)} tool call(s) from content")

            msgs.append({"role": "assistant", "content": content})
            if tool_calls:
                msgs[-1]["tool_calls"] = tool_calls

            if not tool_calls:
                return {"content": content, "tool_calls": tool_calls_history}

            from core.tools.dispatch import dispatch_tool_calls
            tool_results = dispatch_tool_calls(tool_calls)
            for tc, tr in zip(tool_calls, tool_results):
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args_raw = fn.get("arguments", {})
                if isinstance(args_raw, str):
                    try:
                        args_raw = json.loads(args_raw)
                    except json.JSONDecodeError:
                        pass
                result_content = tr.get("content", "")
                try:
                    result_content = json.loads(result_content) if isinstance(result_content, str) else result_content
                except (json.JSONDecodeError, TypeError):
                    pass
                tool_calls_history.append({
                    "name": name,
                    "arguments": args_raw,
                    "result": result_content,
                })
            msgs.extend(tool_results)

        logger.warning(f"chat_with_tools exceeded {max_iterations} iterations")
        return {"content": content + "\n\n[_iterations_exceeded]", "tool_calls": tool_calls_history}

    def pull_model(self, model: str) -> bool:
        """Pull a model from Ollama registry"""
        if not self.available:
            raise RuntimeError("Ollama is not available")

        try:
            response = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": model, "stream": False},
                timeout=3600
            )
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to pull model {model}: {e}")
            return False

    def delete_model(self, model: str) -> bool:
        """Delete a local model"""
        if not self.available:
            raise RuntimeError("Ollama is not available")

        try:
            response = requests.delete(
                f"{self.base_url}/api/delete",
                json={"name": model},
                timeout=30
            )
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to delete model {model}: {e}")
            return False

    def get_model_info(self, model: str) -> ModelInfo | None:
        """Get detailed model information"""
        models = self.list_models()
        for m in models:
            if m.name == model:
                return m
        return None


class LlamaCppInterface:
    """Interface to llama.cpp inference engine"""

    def __init__(self, server_url: str = "http://localhost:8080"):
        self.server_url = server_url
        self.available = self._check_availability()

    def _check_availability(self) -> bool:
        """Check if llama.cpp server is running"""
        try:
            response = requests.get(f"{self.server_url}/health", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def generate(self, prompt: str, max_tokens: int = 256,
                 temperature: float = 0.7) -> str:
        """Generate text using llama.cpp"""
        if not self.available:
            raise RuntimeError("llama.cpp server is not available")

        try:
            response = requests.post(
                f"{self.server_url}/completion",
                json={
                    "prompt": prompt,
                    "n_predict": max_tokens,
                    "temperature": temperature
                },
                timeout=120
            )
            if response.status_code == 200:
                return response.json().get("content", "")
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"llama.cpp generation failed: {e}")

        return ""


class VLLMInterface:
    """Interface to vLLM inference engine"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.available = self._check_availability()

    def _check_availability(self) -> bool:
        """Check if vLLM server is running"""
        try:
            response = requests.get(f"{self.base_url}/v1/models", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def list_models(self) -> list[str]:
        """List available vLLM models"""
        if not self.available:
            return []

        try:
            response = requests.get(f"{self.base_url}/v1/models", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return [m["id"] for m in data.get("data", [])]
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"Failed to list vLLM models: {e}")

        return []

    def generate(self, model: str, prompt: str, max_tokens: int = 256,
                 temperature: float = 0.7) -> str:
        """Generate text using vLLM OpenAI-compatible API"""
        if not self.available:
            raise RuntimeError("vLLM server is not available")

        try:
            response = requests.post(
                f"{self.base_url}/v1/completions",
                json={
                    "model": model,
                    "prompt": prompt,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                },
                timeout=120
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("choices", [{}])[0].get("text", "")
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"vLLM generation failed: {e}")

        return ""

    def chat(self, model: str, messages: list[dict],
             max_tokens: int = 256, temperature: float = 0.7) -> str:
        """Chat using vLLM OpenAI-compatible chat API"""
        if not self.available:
            raise RuntimeError("vLLM server is not available")

        try:
            response = requests.post(
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                },
                timeout=120
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error(f"vLLM chat failed: {e}")

        return ""


class ModelRegistry:
    """Central model registry for all inference engines"""

    def __init__(self, registry_dir: str | None = None):
        registry_dir = registry_dir or os.environ.get("NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel" / "models"))
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = self.registry_dir / "registry.json"
        self.models: dict[str, ModelInfo] = {}
        self._load_registry()

    def _load_registry(self):
        """Load model registry"""
        if self.registry_file.exists():
            with open(self.registry_file, "r") as f:
                data = json.load(f)
                for name, model_data in data.items():
                    if isinstance(model_data.get('engine'), str):
                        model_data['engine'] = InferenceEngine(model_data['engine'])
                    self.models[name] = ModelInfo(**model_data)

    def save_registry(self):
        """Save model registry"""
        data = {}
        for name, model in self.models.items():
            d = asdict(model)
            d['engine'] = d['engine'].value if hasattr(d['engine'], 'value') else d['engine']
            data[name] = d
        with open(self.registry_file, "w") as f:
            json.dump(data, f, indent=2)

    def register_model(self, model: ModelInfo):
        """Register a model"""
        self.models[model.name] = model
        self.save_registry()

    def get_model(self, name: str) -> ModelInfo | None:
        """Get model by name"""
        return self.models.get(name)

    def list_models(self) -> list[ModelInfo]:
        """List all registered models"""
        return list(self.models.values())

    def remove_model(self, name: str) -> bool:
        """Remove a model from registry"""
        if name in self.models:
            del self.models[name]
            self.save_registry()
            return True
        return False


class InferenceEngineManager:
    """
    Manages multiple inference engines and provides a unified interface.
    Automatically selects the best available engine for a given model.
    """

    def __init__(self):
        self.engines: dict[InferenceEngine, Any] = {}
        self.registry = ModelRegistry()

        # Initialize available engines
        self._init_engines()

    def _init_engines(self):
        """Initialize available inference engines"""
        # Ollama
        ollama = OllamaInterface()
        if ollama.available:
            self.engines[InferenceEngine.OLLAMA] = ollama
            logger.info("Ollama engine available")

            # Register Ollama models
            for model in ollama.list_models():
                self.registry.register_model(model)

        # llama.cpp
        llamacpp = LlamaCppInterface()
        if llamacpp.available:
            self.engines[InferenceEngine.LLAMA_CPP] = llamacpp
            logger.info("llama.cpp engine available")

        # vLLM
        vllm = VLLMInterface()
        if vllm.available:
            self.engines[InferenceEngine.VLLM] = vllm
            logger.info("vLLM engine available")

        logger.info(f"Initialized {len(self.engines)} inference engines")

    def get_available_engines(self) -> list[InferenceEngine]:
        """Get list of available engines"""
        return list(self.engines.keys())

    def generate(self, model: str, prompt: str,
                 engine: InferenceEngine | None = None) -> str:
        """Generate text using the specified or best available engine"""
        if engine and engine in self.engines:
            eng = self.engines[engine]
            if hasattr(eng, 'generate'):
                return eng.generate(model, prompt)

        # Try engines in order of preference
        for eng_type in [InferenceEngine.OLLAMA, InferenceEngine.VLLM, InferenceEngine.LLAMA_CPP]:
            if eng_type in self.engines:
                eng = self.engines[eng_type]
                if hasattr(eng, 'generate'):
                    try:
                        return eng.generate(model, prompt)
                    except Exception as e:  # noqa: BLE001 - last-resort engine boundary, fall through to next
                        logger.warning(f"Engine {eng_type.value} failed: {e}")
                        continue

        raise RuntimeError("No available inference engine")

    def chat(self, model: str, messages: list[dict],
             engine: InferenceEngine | None = None,
             images: list[str] | None = None,
             tools: list[dict] | None = None,
             format: str | None = None,
             temperature: float | None = None) -> str:
        """Chat using the specified or best available engine"""
        kwargs = {}
        if images is not None:
            kwargs["images"] = images
        if tools is not None:
            kwargs["tools"] = tools
        if format is not None:
            kwargs["format"] = format
        if temperature is not None:
            kwargs["temperature"] = temperature

        if engine and engine in self.engines:
            eng = self.engines[engine]
            if hasattr(eng, 'chat'):
                return eng.chat(model, messages, **kwargs)

        for eng_type in [InferenceEngine.OLLAMA, InferenceEngine.VLLM]:
            if eng_type in self.engines:
                eng = self.engines[eng_type]
                if hasattr(eng, 'chat'):
                    try:
                        return eng.chat(model, messages, **kwargs)
                    except Exception as e:  # noqa: BLE001 - last-resort engine boundary, fall through to next
                        logger.warning(f"Engine {eng_type.value} failed: {e}")
                        continue

        raise RuntimeError("No available inference engine with chat support")

    def chat_with_tools(self, model: str, messages: list[dict],
                        tools: list[dict],
                        max_iterations: int = 4,
                        engine: InferenceEngine | None = None,
                        images: list[str] | None = None) -> dict[str, Any]:
        """Chat with tool-calling loop through the best available engine."""
        if engine and engine in self.engines:
            eng = self.engines[engine]
            if hasattr(eng, 'chat_with_tools'):
                return eng.chat_with_tools(
                    model, messages, tools,
                    max_iterations=max_iterations, images=images
                )

        for eng_type in [InferenceEngine.OLLAMA]:
            if eng_type in self.engines:
                eng = self.engines[eng_type]
                if hasattr(eng, 'chat_with_tools'):
                    try:
                        return eng.chat_with_tools(
                            model, messages, tools,
                            max_iterations=max_iterations, images=images
                        )
                    except Exception as e:  # noqa: BLE001 - last-resort engine boundary, fall through to next
                        logger.warning(f"Engine {eng_type.value} chat_with_tools failed: {e}")
                        continue

        raise RuntimeError("No available inference engine with chat_with_tools")

    def get_status(self) -> dict:
        """Get inference engine status"""
        return {
            "available_engines": [e.value for e in self.engines],
            "registered_models": len(self.registry.models),
            "models": [asdict(m) for m in self.registry.list_models()]
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    manager = InferenceEngineManager()

    # Show status
    status = manager.get_status()
    print(f"Available engines: {status['available_engines']}")
    print(f"Registered models: {status['registered_models']}")

    # Test generation if Ollama is available
    if InferenceEngine.OLLAMA in manager.engines:
        print("\nOllama is available - testing generation...")
        try:
            response = manager.generate(
                "qwen3:32b",
                "What is the NS-BOS kernel?",
                engine=InferenceEngine.OLLAMA
            )
            print(f"Response: {response[:200]}...")
        except Exception as e:  # noqa: BLE001 - CLI smoke test
            print(f"Generation test failed: {e}")
