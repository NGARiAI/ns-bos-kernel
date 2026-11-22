"""
NS-BOS Kernel - Local Inference Engine Interface
Supports Ollama, llama.cpp, and vLLM interfaces.
Model registry and management.
"""

import contextlib
import errno
import inspect
import ipaddress
import json
import logging
import os
import re
import secrets
import urllib.parse
import uuid
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import requests
import urllib3

logger = logging.getLogger(__name__)

_tool_dispatcher: Any | None = None


def set_tool_dispatcher(dispatcher: Any) -> None:
    """Register an application-level tool dispatcher for chat_with_tools.

    The kernel stays independent of application tool registries; applications
    (e.g. the NGARi agent suite) call this to wire in their dispatcher, which
    must accept a list of tool_calls and return a list of result dicts.
    Falls back to the legacy core.tools.dispatch import when available.
    """
    global _tool_dispatcher
    _tool_dispatcher = dispatcher


# Tool calls one chat_with_tools call may dispatch in all, whatever the
# replies ask for: one reply could otherwise carry a thousand calls, each a
# side effect a prompt-injected document chose.
MAX_TOOL_CALLS = 16


def _tool_names(tools: list[dict]) -> set[str]:
    names = set()
    for tool in tools or []:
        if isinstance(tool, dict):
            fn = tool.get("function", tool)
            if isinstance(fn, dict) and isinstance(fn.get("name"), str):
                names.add(fn["name"])
    return names


def _declared_calls(tool_calls: list, tools: list[dict]) -> list:
    """Only calls to tools the caller declared. Any JSON with a "name" key in
    a reply can be parsed as a call, so model output (or text injected into
    it) could otherwise reach the dispatcher with any tool name."""
    allowed = _tool_names(tools)
    kept, ignored = [], []
    for call in tool_calls:
        fn = call.get("function", {}) if isinstance(call, dict) else {}
        name = fn.get("name") if isinstance(fn, dict) else None
        if isinstance(name, str) and name in allowed:
            kept.append(call)
        else:
            ignored.append(name)
    if ignored:
        # One line, the names cut short: a model chooses them.
        shown = ", ".join(repr(str(name)[:64]) for name in ignored[:3])
        logger.warning(
            "chat_with_tools: ignoring %d call(s) to undeclared tools: %s%s",
            len(ignored), shown, ", ..." if len(ignored) > 3 else "",
        )  # fmt: skip
    return kept


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


def _text(data: Any, *path: str | int) -> str:
    """The string at path in a decoded reply, or "" if the reply has another shape.

    path steps are dict keys (str) or list indexes (int). A server that answers
    200 with an unexpected body gives empty text, the same as a failed call.
    """
    for step in path:
        if isinstance(step, int):
            if not isinstance(data, list) or step >= len(data):
                return ""
        elif not isinstance(data, dict):
            return ""
        data = data[step] if isinstance(step, int) else data.get(step)
    return data if isinstance(data, str) else ""


# What reading an engine's reply can raise: the request failing, a body that
# is not JSON, or one nested too deep for the decoder. A reply is untrusted:
# each gives the empty answer a failed call does, never an exception.
_REPLY_ERRORS = (requests.exceptions.RequestException, ValueError, RecursionError)


def _stream_lines(response) -> Iterator[dict]:
    """The decoded objects of a streamed reply, one per line. A line that is
    not a JSON object, or is nested too deep, is skipped, so it costs that
    line and not the text before or after it."""
    for line in response.iter_lines():
        if not line:
            continue
        try:
            data = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(data, dict):
            yield data


def _entries(data: Any, key: str) -> list:
    """The list at data[key], or [] if the reply has another shape.

    Items are not checked here; callers read each one through _text.
    """
    items = data.get(key) if isinstance(data, dict) else None
    return items if isinstance(items, list) else []


def _done(data: Any) -> bool:
    """Whether a decoded stream line marks the end of the stream."""
    return isinstance(data, dict) and bool(data.get("done", False))


def _text_tool_call(item: Any) -> dict | None:
    """One Ollama-format tool call from a decoded {"name", "arguments"} object.

    Arguments given as a JSON string are decoded; anything that is still not
    an object is passed on as its string form. Returns None if item is not a
    call.
    """
    if not isinstance(item, dict) or "name" not in item:
        return None
    args = item.get("arguments", {})
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (ValueError, RecursionError):  # also too deep, or too many digits
            pass
    return {
        "id": f"call_{uuid.uuid4().hex}",
        "function": {
            "name": item["name"],
            "arguments": args if isinstance(args, dict) else str(args),
        },
    }


AIR_GAP_ENV = "NGARI_AIR_GAP"
_AIR_GAP_OFF = frozenset({"0", "false", "no", "off"})
_AIR_GAP_ON = frozenset({"", "1", "true", "yes", "on"})


def air_gap_enabled(environ=None) -> bool:
    """On unless NGARI_AIR_GAP is 0, false, no or off (case and whitespace
    ignored). Any other value keeps it on and logs one warning naming the
    accepted values."""
    env = os.environ if environ is None else environ
    raw = (env.get(AIR_GAP_ENV) or "").strip().lower()
    if raw in _AIR_GAP_OFF:
        return False
    if raw not in _AIR_GAP_ON:
        logger.warning(
            "%s=%r is not a known value; air gap stays on (0, false, no or off turn it off)",
            AIR_GAP_ENV,
            raw[:32],
        )
    return True


class AirGapError(RuntimeError):
    """A call refused because air-gap mode is on."""


# Explicit None values survive requests' merge with HTTP_PROXY and ALL_PROXY
# and are then dropped, so a loopback call is never sent through a proxy.
_DIRECT = {"http": None, "https": None, "all": None}


def loopback_problem(url: str) -> str | None:
    """Why url may not be called in air-gap mode, or None. Nothing is resolved."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError:
        return "not a URL"
    if parts.scheme not in ("http", "https"):
        return f"scheme {parts.scheme!r} is not http or https"
    if not host:
        return "no host"
    connects_to = _connection_host(url)
    if connects_to is None:
        return "not a URL the HTTP library can use"
    if connects_to != host:
        # A backslash, for one, ends the authority for urllib3 and not for
        # urlsplit: http://203.0.113.7\\@127.0.0.1/ reads as 127.0.0.1 here and
        # connects to 203.0.113.7.
        return (
            f"host reads as {host!r} here but the HTTP library would connect "
            f"to {connects_to!r}"
        )
    if host == "localhost":
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return (
            f"host {host!r} is a name, not a loopback address, and would need a lookup"
        )
    # Older CPython patch releases do not call ::ffff:127.0.0.1 loopback; the
    # gate decides it so every supported Python agrees.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return None if ip.is_loopback else f"host {host} is not a loopback address"


def _direct_for(url: str) -> dict:
    """Proxies that send a loopback call direct. requests looks up a proxy for
    "<scheme>://<host>" and "all://<host>" before "<scheme>" and "all", and
    reads those keys from variables such as all://127.0.0.1_proxy, so they
    are cleared as well; None keeps the environment's value out."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    return {**_DIRECT, f"{parts.scheme}://{host}": None, f"all://{host}": None}


def _connection_host(url: str) -> str | None:
    """The host requests would connect to for url, read the way requests
    reads it (its own URL preparation, then urllib3's parser), lowercased and
    without brackets; None if requests would refuse the URL."""
    try:
        prepared = requests.models.PreparedRequest()
        prepared.prepare_url(url, None)
        host = urllib3.util.parse_url(prepared.url).host
    except (requests.exceptions.RequestException, ValueError, UnicodeError):
        return None
    return host.strip("[]").lower() if host else None


def _endpoint(url: str) -> str:
    """scheme://host:port only: a URL can carry user:password@, and no secret
    goes into a log line, an exception or an audit entry."""
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return "an unparsable URL"
    if not host:
        return f"{parts.scheme}:// with no host"
    shown = f"[{host}]" if ":" in host else host  # IPv6 keeps its brackets
    return f"{parts.scheme}://{shown}" + (f":{port}" if port else "")


class _Engine:
    """What the three inference clients share: the air-gap gate and the one
    place the kernel makes an HTTP call."""

    label = "engine"
    _url_attr = "base_url"

    def _attach(self, url: str, air_gap: bool | None) -> None:
        wanted = air_gap_enabled()
        self.air_gap = wanted if air_gap is None else bool(air_gap)
        if wanted and not self.air_gap:
            logger.warning(
                "air gap: %s client for %s built with air_gap=False while %s says on; "
                "this client is not gated",
                self.label, _endpoint(url), AIR_GAP_ENV,
            )  # fmt: skip
        self.refused = loopback_problem(url) if self.air_gap else None
        if self.refused:
            logger.error(
                "air gap: refusing %s endpoint %s (%s); set %s=0 to allow it",
                self.label, _endpoint(url), self.refused, AIR_GAP_ENV,
            )  # fmt: skip
            self.available = False
        else:
            self.available = self._check_availability()

    def _refusal(self, problem: str) -> AirGapError:
        return AirGapError(
            f"{self.label} endpoint {_endpoint(getattr(self, self._url_attr))} refused "
            f"in air-gap mode: {problem}; {AIR_GAP_ENV}=0 allows it"
        )

    def _raise_if_refused(self) -> None:
        if self.refused:
            raise self._refusal(self.refused)

    def _require_available(self) -> None:
        self._raise_if_refused()
        if not self.available:
            raise RuntimeError(f"{self.label} is not available")

    def _http(self, method: str, url: str, **kwargs):
        """The one place the kernel makes an HTTP call. Checked on every call,
        so a base_url changed after construction cannot leave loopback.

        Redirects are never followed, in either mode: requests would send the
        request, body included, to whatever a Location names without the
        check above seeing it, and through an environment proxy, since its
        redirect handling puts the proxies back. A process listening on an
        engine's port could move every prompt off the machine that way. A
        redirect reaches the caller as the non-200 reply it is."""
        problem = loopback_problem(url)
        if self.air_gap and problem:
            raise self._refusal(problem)
        if problem is None:
            kwargs.setdefault("proxies", _direct_for(url))
        kwargs["allow_redirects"] = False
        try:
            response = getattr(requests, method)(url, **kwargs)
        except requests.exceptions.RequestException as exc:
            # requests puts the whole URL, user and password included, in its
            # messages, and the clients log them; this keeps scheme://host:port.
            raise type(exc)(
                f"{type(exc).__name__} from {self.label} at {_endpoint(url)}"
            ) from None
        if getattr(response, "is_redirect", False):
            logger.warning(
                "%s endpoint %s answered with a redirect; it is not followed",
                self.label,
                _endpoint(url),
            )
        return response


class OllamaInterface(_Engine):
    """Interface to Ollama local inference engine"""

    label = "Ollama"

    def __init__(
        self, base_url: str = "http://localhost:11434", air_gap: bool | None = None
    ):
        self.base_url = base_url
        self._attach(base_url, air_gap)

    def _check_availability(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = self._http("get", f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def list_models(self) -> list[ModelInfo]:
        """List available Ollama models"""
        self._raise_if_refused()
        if not self.available:
            return []

        try:
            response = self._http("get", f"{self.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                models = []
                for model in _entries(response.json(), "models"):
                    if not _text(model, "name"):
                        continue
                    size = model.get("size", 0)
                    if not isinstance(size, (int, float)):
                        size = 0
                    models.append(
                        ModelInfo(
                            name=model["name"],
                            engine=InferenceEngine.OLLAMA,
                            size_gb=round(size / (1024**3), 2),
                            parameters="unknown",
                            context_length=4096,
                            quantization="unknown",
                            status="available",
                            last_used=_text(model, "modified_at"),
                        )
                    )
                return models
        except _REPLY_ERRORS as e:
            logger.error(f"Failed to list Ollama models: {e}")

        return []

    def generate(self, model: str, prompt: str, stream: bool = False) -> str:
        """Generate text using Ollama"""
        self._require_available()

        try:
            response = self._http(
                "post",
                f"{self.base_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": stream},
                timeout=120,
            )
            if response.status_code == 200:
                if stream:
                    full_response = ""
                    for data in _stream_lines(response):
                        full_response += _text(data, "response")
                        if _done(data):
                            break
                    return full_response
                else:
                    return _text(response.json(), "response")
        except _REPLY_ERRORS as e:
            logger.error(f"Ollama generation failed: {e}")

        return ""

    def chat(
        self,
        model: str,
        messages: list[dict],
        stream: bool = False,
        images: list[str] | None = None,
        tools: list[dict] | None = None,
        format: str | None = None,
        temperature: float | None = None,
    ) -> str:
        """Chat with Ollama using chat format"""
        self._require_available()

        msgs = messages
        if images:
            msgs = list(messages)
            if msgs and msgs[-1]["role"] == "user":
                msgs[-1] = {**msgs[-1], "images": images}
        body: dict[str, Any] = {"model": model, "messages": msgs, "stream": stream}
        if tools:
            body["tools"] = tools
        if format:
            body["format"] = format
        if temperature is not None:
            body["options"] = {**body.get("options", {}), "temperature": temperature}

        try:
            response = self._http(
                "post", f"{self.base_url}/api/chat", json=body, timeout=120
            )
            if response.status_code == 200:
                if stream:
                    full_response = ""
                    for data in _stream_lines(response):
                        full_response += _text(data, "message", "content")
                        if _done(data):
                            break
                    return full_response
                else:
                    return _text(response.json(), "message", "content")
        except _REPLY_ERRORS as e:
            logger.error(f"Ollama chat failed: {e}")

        return ""

    def chat_stream(
        self,
        model: str,
        messages: list[dict],
        images: list[str] | None = None,
        tools: list[dict] | None = None,
        format: str | None = None,
        temperature: float | None = None,
    ):
        """Stream chat tokens from Ollama. Yields (token, done) tuples. A
        client refused by the air gap raises here, at the call, as every other
        method does, not at the first token."""
        self._raise_if_refused()
        return self._chat_stream(model, messages, images, tools, format, temperature)

    def _chat_stream(self, model, messages, images, tools, format, temperature):
        self._require_available()

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
            response = self._http(
                "post",
                f"{self.base_url}/api/chat",
                json=body,
                timeout=300,
                stream=True,
            )
            if response.status_code != 200:
                logger.error(
                    f"Ollama chat_stream HTTP {response.status_code}: {response.text[:200]}"
                )
                yield ("", True)
                return

            for data in _stream_lines(response):
                token = _text(data, "message", "content")
                done = _done(data)
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
        # JSON in a markdown code block is tried first. Two finds, not a
        # regex: a lazy match between fences takes time quadratic in a run
        # of whitespace after an unclosed fence, on every final answer.
        start = content.find("```")
        end = content.find("```", start + 3) if start != -1 else -1
        if end != -1:
            candidate = content[start + 3 : end].removeprefix("json").strip()
        else:
            candidate = content.strip()

        # Try parsing as JSON directly
        for text in [candidate, content.strip()]:
            try:
                parsed = json.loads(text)
            except (ValueError, RecursionError):  # a reply is untrusted text
                continue
            items = parsed if isinstance(parsed, list) else [parsed]
            calls = [c for c in map(_text_tool_call, items) if c]
            if calls:
                return calls

        # Fallback: decode the object that starts at the first {"name": ...
        # raw_decode reads strings properly, so braces inside an argument
        # value do not end the object early.
        m = re.search(r'\{\s*"name"\s*:\s*"[^"]+"', content)
        if m:
            try:
                parsed, _ = json.JSONDecoder().raw_decode(content, m.start())
            except (ValueError, RecursionError):
                return None
            # The regex matched {"name": "...", so this always decodes to a call.
            return [_text_tool_call(parsed)]

        return None

    def chat_with_tools(
        self,
        model: str,
        messages: list[dict],
        tools: list[dict],
        max_iterations: int = 4,
        images: list[str] | None = None,
        max_tool_calls: int = MAX_TOOL_CALLS,
    ) -> dict[str, Any]:
        """Chat with a tool-calling loop: call, dispatch, call again until done.

        Handles both native Ollama tool_calls and JSON text-format tool calls.
        Tool dispatch is supplied by the application via set_tool_dispatcher
        (or the legacy core.tools.dispatch import when present). At most
        max_tool_calls are dispatched in all; calls past it are dropped, and
        a reply asking for more once none are left ends the loop.
        Returns a dict of content and tool_calls, a list of {name, arguments, result}.
        """
        self._require_available()

        msgs = list(messages)
        iteration = 0
        tool_calls_history = []
        dispatched = 0

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
                resp = self._http(
                    "post",
                    f"{self.base_url}/api/chat",
                    json=body,
                    timeout=300,
                )
                if resp.status_code != 200:
                    logger.error(
                        f"Ollama chat_with_tools HTTP {resp.status_code}: {resp.text[:200]}"
                    )
                    return {"content": "", "tool_calls": tool_calls_history}
                data = resp.json()
            except (
                requests.exceptions.RequestException, ValueError, RecursionError
            ) as e:  # fmt: skip
                logger.error(f"Ollama chat_with_tools failed: {type(e).__name__}")
                return {"content": "", "tool_calls": tool_calls_history}

            msg = data.get("message") if isinstance(data, dict) else None
            if not isinstance(msg, dict):
                msg = {}
            content = _text(msg, "content")
            tool_calls = msg.get("tool_calls")
            if not isinstance(tool_calls, list):
                tool_calls = None

            # Fallback: extract JSON tool calls from text content
            if not tool_calls:
                extracted = self._extract_tool_calls_from_content(content)
                if extracted:
                    tool_calls = extracted
                    logger.info(
                        f"chat_with_tools: extracted {len(tool_calls)} tool call(s) from content"
                    )

            if tool_calls:
                tool_calls = _declared_calls(tool_calls, tools)
            left = max_tool_calls - dispatched
            if tool_calls and len(tool_calls) > left:
                logger.warning(
                    "chat_with_tools: dropping %d of %d tool calls (at most %d in all)",
                    len(tool_calls) - max(left, 0), len(tool_calls), max_tool_calls,
                )  # fmt: skip
                if left <= 0:
                    return {
                        "content": content + "\n\n[_tool_calls_exceeded]",
                        "tool_calls": tool_calls_history,
                    }
                tool_calls = tool_calls[:left]

            msgs.append({"role": "assistant", "content": content})
            if tool_calls:
                msgs[-1]["tool_calls"] = tool_calls

            if not tool_calls:
                return {"content": content, "tool_calls": tool_calls_history}

            if _tool_dispatcher is None:
                try:
                    from core.tools.dispatch import dispatch_tool_calls
                except ImportError:
                    logger.warning(
                        "chat_with_tools: no tool dispatcher available; returning call history"
                    )
                    return {"content": content, "tool_calls": tool_calls_history}
            else:
                dispatch_tool_calls = _tool_dispatcher
            try:
                tool_results = dispatch_tool_calls(tool_calls)
                if not isinstance(tool_results, list) or not all(
                    isinstance(r, dict) for r in tool_results
                ):
                    raise TypeError("the dispatcher did not return a list of messages")
            except Exception as exc:  # noqa: BLE001 - the application's tools
                # Earlier rounds' tools have run: the caller gets their history,
                # not an error that reads as "no engine" and invites a retry.
                logger.error(
                    "chat_with_tools: tool dispatch failed: %s", type(exc).__name__
                )
                return {
                    "content": content + "\n\n[_tool_dispatch_failed]",
                    "tool_calls": tool_calls_history,
                }
            dispatched += len(tool_calls)
            for tc, tr in zip(tool_calls, tool_results):
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args_raw = fn.get("arguments", {})
                if isinstance(args_raw, str):
                    try:
                        args_raw = json.loads(args_raw)
                    except (ValueError, RecursionError):
                        pass
                result_content = tr.get("content", "")
                # The tools have run by now: whatever their output holds, the
                # caller gets the history of what ran.
                try:
                    result_content = (
                        json.loads(result_content)
                        if isinstance(result_content, str)
                        else result_content
                    )
                except (ValueError, RecursionError, TypeError):
                    pass
                tool_calls_history.append(
                    {
                        "name": name,
                        "arguments": args_raw,
                        "result": result_content,
                    }
                )
            msgs.extend(tool_results)

        logger.warning(f"chat_with_tools exceeded {max_iterations} iterations")
        return {
            "content": content + "\n\n[_iterations_exceeded]",
            "tool_calls": tool_calls_history,
        }

    def pull_model(self, model: str) -> bool:
        """Pull a model from Ollama registry"""
        if self.air_gap:
            raise AirGapError(
                "pull_model asks Ollama to fetch a model from its registry; refused "
                f"in air-gap mode ({AIR_GAP_ENV}=0 allows it)"
            )
        self._require_available()

        try:
            response = self._http(
                "post",
                f"{self.base_url}/api/pull",
                json={"name": model, "stream": False},
                timeout=3600,
            )
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to pull model {model}: {e}")
            return False

    def delete_model(self, model: str) -> bool:
        """Delete a local model"""
        self._require_available()

        try:
            response = self._http(
                "delete",
                f"{self.base_url}/api/delete",
                json={"name": model},
                timeout=30,
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


class LlamaCppInterface(_Engine):
    """Interface to llama.cpp inference engine"""

    label = "llama.cpp server"
    _url_attr = "server_url"

    def __init__(
        self, server_url: str = "http://localhost:8080", air_gap: bool | None = None
    ):
        self.server_url = server_url
        self._attach(server_url, air_gap)

    def _check_availability(self) -> bool:
        """Check if llama.cpp server is running"""
        try:
            response = self._http("get", f"{self.server_url}/health", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def generate(
        self, prompt: str, max_tokens: int = 256, temperature: float = 0.7
    ) -> str:
        """Generate text using llama.cpp"""
        self._require_available()

        try:
            response = self._http(
                "post",
                f"{self.server_url}/completion",
                json={
                    "prompt": prompt,
                    "n_predict": max_tokens,
                    "temperature": temperature,
                },
                timeout=120,
            )
            if response.status_code == 200:
                return _text(response.json(), "content")
        except _REPLY_ERRORS as e:
            logger.error(f"llama.cpp generation failed: {e}")

        return ""


class VLLMInterface(_Engine):
    """Interface to vLLM inference engine"""

    label = "vLLM server"

    def __init__(
        self, base_url: str = "http://localhost:8000", air_gap: bool | None = None
    ):
        self.base_url = base_url
        self._attach(base_url, air_gap)

    def _check_availability(self) -> bool:
        """Check if vLLM server is running"""
        try:
            response = self._http("get", f"{self.base_url}/v1/models", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def list_models(self) -> list[str]:
        """List available vLLM models"""
        self._raise_if_refused()
        if not self.available:
            return []

        try:
            response = self._http("get", f"{self.base_url}/v1/models", timeout=10)
            if response.status_code == 200:
                entries = _entries(response.json(), "data")
                return [m["id"] for m in entries if _text(m, "id")]
        except _REPLY_ERRORS as e:
            logger.error(f"Failed to list vLLM models: {e}")

        return []

    def generate(
        self, model: str, prompt: str, max_tokens: int = 256, temperature: float = 0.7
    ) -> str:
        """Generate text using vLLM OpenAI-compatible API"""
        self._require_available()

        try:
            response = self._http(
                "post",
                f"{self.base_url}/v1/completions",
                json={
                    "model": model,
                    "prompt": prompt,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
                timeout=120,
            )
            if response.status_code == 200:
                return _text(response.json(), "choices", 0, "text")
        except _REPLY_ERRORS as e:
            logger.error(f"vLLM generation failed: {e}")

        return ""

    def chat(
        self,
        model: str,
        messages: list[dict],
        max_tokens: int = 256,
        temperature: float = 0.7,
    ) -> str:
        """Chat using vLLM OpenAI-compatible chat API"""
        self._require_available()

        try:
            response = self._http(
                "post",
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
                timeout=120,
            )
            if response.status_code == 200:
                return _text(response.json(), "choices", 0, "message", "content")
        except _REPLY_ERRORS as e:
            logger.error(f"vLLM chat failed: {e}")

        return ""


def _write_json(path: Path, data, **dump_kwargs) -> None:
    """Write data as JSON, complete or not at all, and durably: a synced
    temporary file renamed over the old one, then the directory synced, so
    a crash or power loss leaves the old file or the new one, never an empty
    one. Each call has its own temporary name, so threads do not collide."""
    _write_durably(path, json.dumps(data, indent=2, **dump_kwargs).encode())


def _write_durably(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner only
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


# errno values for a filesystem that has no hard links (vfat, some FUSE mounts).
_NO_LINKS = frozenset({errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS})


def _keep_aside(path: Path, kind: str) -> Path:
    """Move path to <name>.<kind>-<UTC time>, never over an existing file: a
    second file kept aside in the same second gets -1, -2 and so on, so no
    earlier copy is lost. A hard link takes the new name or fails, so no
    other process can race it; where the filesystem has no hard links, the
    name is checked first."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for n in range(1000):
        aside = path.with_name(f"{path.name}.{kind}-{stamp}" + (f"-{n}" if n else ""))
        try:
            os.link(path, aside)
        except FileExistsError:
            continue
        except OSError as exc:
            if exc.errno not in _NO_LINKS:
                raise
            if os.path.lexists(aside):
                continue
            os.replace(path, aside)
            return aside
        os.unlink(path)
        return aside
    raise FileExistsError(f"no free name to keep {path.name} aside")


def _set_aside(path: Path, exc: Exception, what: str) -> None:
    """Rename an unreadable file to <name>.corrupt-<UTC time>, never delete
    it, and carry on without it."""
    aside = _keep_aside(path, "corrupt")
    logger.error(
        "%s unreadable (%s); kept as %s, skipped", what, type(exc).__name__, aside.name
    )


class ModelRegistry:
    """Central model registry for all inference engines"""

    def __init__(self, registry_dir: str | None = None):
        registry_dir = registry_dir or (
            os.environ.get("NGARI_DATA_DIR")
            or str(Path.home() / ".ngari" / "kernel" / "models")
        )
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = self.registry_dir / "registry.json"
        self.models: dict[str, ModelInfo] = {}
        self._load_registry()

    def _load_registry(self):
        """Load model registry. An unreadable file is set aside and the
        registry starts empty."""
        if not self.registry_file.exists():
            return
        try:
            data = json.loads(self.registry_file.read_text())
            models = {}
            for name, model_data in data.items():
                model_data = dict(model_data)
                if isinstance(model_data.get("engine"), str):
                    model_data["engine"] = InferenceEngine(model_data["engine"])
                models[name] = ModelInfo(**model_data)
            # Kept only if it can be saved again: asdict gives up long before
            # the decoder does, and every later change saves the registry.
            json.dumps(self._registry_data(models))
        except (ValueError, TypeError, AttributeError, RecursionError) as exc:
            _set_aside(self.registry_file, exc, "Model registry")
            return
        self.models.update(models)

    def save_registry(self):
        """Save model registry"""
        _write_json(self.registry_file, self._registry_data(self.models))

    @staticmethod
    def _registry_data(models: dict) -> dict:
        """models as registry.json holds them."""
        data = {}
        for name, model in models.items():
            d = asdict(model)
            d["engine"] = (
                d["engine"].value if hasattr(d["engine"], "value") else d["engine"]
            )
            data[name] = d
        return data

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


def _unsupported(method, kwargs: dict) -> list[str]:
    """Options in kwargs that method cannot take, sorted."""
    params = inspect.signature(method).parameters
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return []
    return sorted(name for name in kwargs if name not in params)


class InferenceEngineManager:
    """
    Manages multiple inference engines and provides a unified interface.
    Automatically selects the best available engine for a given model.
    """

    def __init__(self):
        self.engines: dict[InferenceEngine, Any] = {}
        self.air_gap = air_gap_enabled()
        self.refused_endpoints: list[str] = []
        self.registry = ModelRegistry()

        self._init_engines()

    def _init_engines(self):
        """Initialize available inference engines"""
        # Ollama
        ollama = OllamaInterface()
        if ollama.refused:
            self.refused_endpoints.append(_endpoint(ollama.base_url))
        if ollama.available:
            self.engines[InferenceEngine.OLLAMA] = ollama
            logger.info("Ollama engine available")

            for model in ollama.list_models():
                self.registry.register_model(model)

        # llama.cpp
        llamacpp = LlamaCppInterface()
        if llamacpp.refused:
            self.refused_endpoints.append(_endpoint(llamacpp.server_url))
        if llamacpp.available:
            self.engines[InferenceEngine.LLAMA_CPP] = llamacpp
            logger.info("llama.cpp engine available")

        # vLLM
        vllm = VLLMInterface()
        if vllm.refused:
            self.refused_endpoints.append(_endpoint(vllm.base_url))
        if vllm.available:
            self.engines[InferenceEngine.VLLM] = vllm
            logger.info("vLLM engine available")

        logger.info(f"Initialized {len(self.engines)} inference engines")

    def get_available_engines(self) -> list[InferenceEngine]:
        """Get list of available engines"""
        return list(self.engines.keys())

    def generate(
        self, model: str, prompt: str, engine: InferenceEngine | None = None
    ) -> str:
        """Generate text using the specified or best available engine"""
        if engine and engine in self.engines:
            return self._generate_with(engine, model, prompt)

        # Try engines in order of preference
        for eng_type in [
            InferenceEngine.OLLAMA,
            InferenceEngine.VLLM,
            InferenceEngine.LLAMA_CPP,
        ]:
            if eng_type in self.engines:
                try:
                    return self._generate_with(eng_type, model, prompt)
                except Exception as e:  # noqa: BLE001 - engine boundary, try the next
                    logger.warning(f"Engine {eng_type.value} failed: {e}")
                    continue

        raise RuntimeError("No available inference engine")

    def _generate_with(self, engine: InferenceEngine, model: str, prompt: str) -> str:
        eng = self.engines[engine]
        if engine is InferenceEngine.LLAMA_CPP:
            # A llama.cpp server serves the one model it was started with.
            return eng.generate(prompt)
        return eng.generate(model, prompt)

    def chat(
        self,
        model: str,
        messages: list[dict],
        engine: InferenceEngine | None = None,
        images: list[str] | None = None,
        tools: list[dict] | None = None,
        format: str | None = None,
        temperature: float | None = None,
    ) -> str:
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
            missing = _unsupported(eng.chat, kwargs)
            if missing:
                raise ValueError(
                    f"{engine.value} chat does not support: {', '.join(missing)}"
                )
            return eng.chat(model, messages, **kwargs)

        skipped = []
        for eng_type in [InferenceEngine.OLLAMA, InferenceEngine.VLLM]:
            if eng_type in self.engines:
                eng = self.engines[eng_type]
                if _unsupported(eng.chat, kwargs):
                    skipped.append(eng_type.value)
                    continue
                try:
                    return eng.chat(model, messages, **kwargs)
                except Exception as e:  # noqa: BLE001 - engine boundary, try the next
                    logger.warning(f"Engine {eng_type.value} failed: {e}")
                    continue

        if skipped:
            raise RuntimeError(
                f"No available inference engine supports chat with "
                f"{', '.join(sorted(kwargs))} (skipped: {', '.join(skipped)})"
            )
        raise RuntimeError("No available inference engine with chat support")

    def chat_with_tools(
        self,
        model: str,
        messages: list[dict],
        tools: list[dict],
        max_iterations: int = 4,
        engine: InferenceEngine | None = None,
        images: list[str] | None = None,
        max_tool_calls: int = MAX_TOOL_CALLS,
    ) -> dict[str, Any]:
        """Chat with tool-calling loop through the named engine, else Ollama.

        A named engine that is running but has no tool loop raises ValueError,
        as chat does for an unsupported option; the call is not sent elsewhere.
        A named engine that is not running falls back to Ollama.
        """
        if engine and engine in self.engines:
            eng = self.engines[engine]
            if not hasattr(eng, "chat_with_tools"):
                raise ValueError(f"{engine.value} does not support chat_with_tools")
            return eng.chat_with_tools(
                model, messages, tools, max_iterations=max_iterations, images=images,
                max_tool_calls=max_tool_calls,
            )  # fmt: skip

        error = None
        ollama = self.engines.get(InferenceEngine.OLLAMA)
        if ollama is not None:
            try:
                return ollama.chat_with_tools(
                    model, messages, tools, max_iterations=max_iterations,
                    images=images, max_tool_calls=max_tool_calls,
                )  # fmt: skip
            except Exception as e:  # noqa: BLE001 - last-resort engine boundary
                logger.warning(f"Engine ollama chat_with_tools failed: {e}")
                error = e
        raise RuntimeError(
            "No available inference engine with chat_with_tools"
        ) from error

    def get_status(self) -> dict:
        """Get inference engine status"""
        return {
            "available_engines": [e.value for e in self.engines],
            "registered_models": len(self.registry.models),
            "models": [asdict(m) for m in self.registry.list_models()],
            "air_gap": self.air_gap,
            "refused_endpoints": list(self.refused_endpoints),
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    manager = InferenceEngineManager()

    status = manager.get_status()
    print(f"Available engines: {status['available_engines']}")
    print(f"Registered models: {status['registered_models']}")

    if InferenceEngine.OLLAMA in manager.engines:
        print("\nOllama is available - testing generation...")
        try:
            response = manager.generate(
                "qwen3:32b", "What is the NS-BOS kernel?", engine=InferenceEngine.OLLAMA
            )
            print(f"Response: {response[:200]}...")
        except Exception as e:  # noqa: BLE001 - CLI smoke test
            print(f"Generation test failed: {e}")
