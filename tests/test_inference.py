"""Inference clients against a fake HTTP layer: no engine, no network."""

import json

import pytest
import requests

from core.kernel import inference
from core.kernel.inference import (
    InferenceEngine,
    InferenceEngineManager,
    LlamaCppInterface,
    ModelInfo,
    ModelRegistry,
    OllamaInterface,
    VLLMInterface,
)


class Response:
    def __init__(self, status=200, body=None, lines=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self._lines = lines or []
        self.text = "" if isinstance(self._body, Exception) else json.dumps(self._body)

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body

    def iter_lines(self):
        yield from (
            json.dumps(x).encode() if not isinstance(x, bytes) else x
            for x in self._lines
        )


@pytest.fixture
def http(monkeypatch, tmp_path):
    """routes: {(METHOD, path): Response | callable(json) -> Response}."""
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    calls, routes = [], {}

    def handler(method):
        def call(url, json=None, **kwargs):
            path = "/" + url.split("/", 3)[3]
            calls.append((method, path, json))
            route = routes.get((method, path))
            if route is None:
                raise requests.ConnectionError(f"nothing at {url}")
            return route(json) if callable(route) else route

        return call

    for method in ("get", "post", "delete"):
        monkeypatch.setattr(inference.requests, method, handler(method.upper()))

    class HTTP:
        def __init__(self):
            self.calls, self.routes = calls, routes

        def ollama_up(self, models=()):
            routes[("GET", "/api/tags")] = Response(body={"models": list(models)})

    return HTTP()


def test_nothing_running_means_nothing_available(http):
    assert not OllamaInterface().available
    assert not LlamaCppInterface().available
    assert not VLLMInterface().available
    manager = InferenceEngineManager()
    assert manager.get_available_engines() == []
    with pytest.raises(RuntimeError, match="No available inference engine"):
        manager.generate("m", "hi")
    with pytest.raises(RuntimeError, match="Ollama is not available"):
        OllamaInterface().chat("m", [])


def test_ollama_models_are_listed_and_registered(http):
    http.ollama_up(
        [{"name": "qwen3:8b", "size": 5 * 1024**3, "modified_at": "2026-10-01"}]
    )
    models = OllamaInterface().list_models()
    assert [(m.name, m.size_gb, m.engine) for m in models] == [
        ("qwen3:8b", 5.0, InferenceEngine.OLLAMA)
    ]
    manager = InferenceEngineManager()
    assert manager.get_available_engines() == [InferenceEngine.OLLAMA]
    assert manager.get_status()["registered_models"] == 1
    assert manager.registry.get_model("qwen3:8b").last_used == "2026-10-01"
    assert OllamaInterface().get_model_info("qwen3:8b").name == "qwen3:8b"
    assert OllamaInterface().get_model_info("missing") is None


def test_ollama_generate_and_chat(http):
    http.ollama_up()
    http.routes[("POST", "/api/generate")] = Response(body={"response": "hello"})
    http.routes[("POST", "/api/chat")] = lambda body: Response(
        body={"message": {"content": f"{len(body['messages'])} msgs"}}
    )
    ollama = OllamaInterface()
    assert ollama.generate("m", "hi") == "hello"
    msgs = [{"role": "user", "content": "describe"}]
    assert ollama.chat("m", msgs, images=["b64"], tools=[{"t": 1}], format="json",
                       temperature=0.2) == "1 msgs"  # fmt: skip
    body = http.calls[-1][2]
    assert body["messages"][-1]["images"] == ["b64"]
    assert "images" not in msgs[-1]  # the caller's list is not modified
    assert (body["tools"], body["format"], body["options"]) == (
        [{"t": 1}],
        "json",
        {"temperature": 0.2},
    )


def test_ollama_streaming_joins_chunks(http):
    http.ollama_up()
    chunks = [{"response": "a"}, {"response": "b", "done": True}, {"response": "never"}]
    http.routes[("POST", "/api/generate")] = Response(lines=chunks)
    assert OllamaInterface().generate("m", "hi", stream=True) == "ab"
    http.routes[("POST", "/api/chat")] = Response(lines=[
        {"message": {"content": "x"}}, b"", b"not json", {"message": {"content": "y"}, "done": True},
    ])  # fmt: skip
    assert list(OllamaInterface().chat_stream("m", [])) == [("x", False), ("y", True)]


def test_ollama_failures_return_empty_text(http):
    http.ollama_up()
    http.routes[("POST", "/api/generate")] = Response(status=500)
    http.routes[("POST", "/api/chat")] = Response(status=503)
    ollama = OllamaInterface()
    assert ollama.generate("m", "hi") == ""
    assert ollama.chat("m", []) == ""
    assert list(ollama.chat_stream("m", [])) == [("", True)]


def test_pull_and_delete_report_the_status(http, monkeypatch):
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    http.ollama_up()
    http.routes[("POST", "/api/pull")] = Response(status=200)
    http.routes[("DELETE", "/api/delete")] = Response(status=404)
    ollama = OllamaInterface()
    assert ollama.pull_model("m") is True
    assert ollama.delete_model("m") is False


def test_pull_is_refused_under_the_air_gap_even_on_loopback(http, monkeypatch):
    monkeypatch.delenv("NGARI_AIR_GAP", raising=False)
    http.ollama_up()
    http.routes[("POST", "/api/pull")] = Response(status=200)
    with pytest.raises(inference.AirGapError, match="pull_model"):
        OllamaInterface().pull_model("m")
    assert [c for c in http.calls if c[1] == "/api/pull"] == []


def test_vllm_and_llamacpp_clients(http):
    http.routes[("GET", "/v1/models")] = Response(body={"data": [{"id": "llama-3"}]})
    http.routes[("POST", "/v1/completions")] = Response(
        body={"choices": [{"text": "v"}]}
    )
    http.routes[("POST", "/v1/chat/completions")] = Response(
        body={"choices": [{"message": {"content": "vc"}}]}
    )
    vllm = VLLMInterface()
    assert vllm.list_models() == ["llama-3"]
    assert (vllm.generate("llama-3", "p"), vllm.chat("llama-3", [])) == ("v", "vc")

    http.routes[("GET", "/health")] = Response()
    http.routes[("POST", "/completion")] = Response(body={"content": "lc"})
    assert LlamaCppInterface().generate("p", max_tokens=8) == "lc"
    assert http.calls[-1][2] == {"prompt": "p", "n_predict": 8, "temperature": 0.7}


def test_the_manager_falls_back_to_the_next_engine(http):
    http.ollama_up()
    http.routes[("POST", "/api/chat")] = Response(body=ValueError("bad json"))
    http.routes[("GET", "/v1/models")] = Response(body={"data": []})
    http.routes[("POST", "/v1/chat/completions")] = Response(
        body={"choices": [{"message": {"content": "from vllm"}}]}
    )
    manager = InferenceEngineManager()
    # Ollama answers with unreadable JSON and returns "", which counts as an answer.
    assert manager.chat("m", []) == ""
    assert manager.chat("m", [], engine=InferenceEngine.VLLM) == "from vllm"


def test_model_registry_round_trip(tmp_path):
    registry = ModelRegistry(str(tmp_path))
    model = ModelInfo("m", InferenceEngine.VLLM, 1.5, "7B", 8192, "q4", "available")
    registry.register_model(model)
    again = ModelRegistry(str(tmp_path))
    assert again.get_model("m") == model
    assert again.remove_model("m") is True
    assert again.remove_model("m") is False
    assert ModelRegistry(str(tmp_path)).list_models() == []


def test_tool_calls_are_read_from_json_text():
    extract = OllamaInterface._extract_tool_calls_from_content
    plain = extract('{"name": "get_weather", "arguments": {"city": "NYC"}}')
    assert plain[0]["function"] == {"name": "get_weather", "arguments": {"city": "NYC"}}
    fenced = extract('Sure.\n```json\n{"name": "t", "arguments": "{\\"a\\": 1}"}\n```')
    assert fenced[0]["function"] == {"name": "t", "arguments": {"a": 1}}
    embedded = extract('I will call {"name": "t", "arguments": {"x": {"y": 1}}} now')
    assert embedded[0]["function"]["arguments"] == {"x": {"y": 1}}
    several = extract('[{"name": "a"}, {"name": "b", "arguments": {}}]')
    assert [c["function"]["name"] for c in several] == ["a", "b"]
    assert extract("no tools here") is None


def test_braces_inside_string_arguments_do_not_cut_the_call_short():
    extract = OllamaInterface._extract_tool_calls_from_content
    for text in ("a } b", "a { b", 'say "}"'):
        content = "Calling: " + json.dumps(
            {"name": "write", "arguments": {"text": text}}
        )
        calls = extract(content + " done")
        assert calls[0]["function"] == {"name": "write", "arguments": {"text": text}}
    assert extract('Calling: {"name": "write", "arguments": {"text": "open') is None


def test_tool_call_arguments_of_every_shape():
    extract = OllamaInterface._extract_tool_calls_from_content

    def args_of(content):
        return [c["function"]["arguments"] for c in extract(content)]

    assert args_of('{"name": "t"}') == [{}]
    assert args_of('{"name": "t", "arguments": "not json"}') == ["not json"]
    assert args_of('{"name": "t", "arguments": [1, 2]}') == ["[1, 2]"]
    assert args_of('{"name": "t", "arguments": "[1]"}') == ["[1]"]
    assert args_of('[{"name": "a", "arguments": "{\\"x\\": 1}"}, 3, {"no": 1}]') == [
        {"x": 1}
    ]
    assert args_of('so: {"name": "t", "arguments": "{\\"x\\": 2}"}') == [{"x": 2}]
    assert args_of('so: {"name": "t", "arguments": "bad"}') == ["bad"]
    calls = extract('[{"name": "a"}, {"name": "b"}]')
    assert len({c["id"] for c in calls}) == 2
    assert all(c["id"].startswith("call_") for c in calls)


def test_text_that_is_not_a_call_gives_none():
    extract = OllamaInterface._extract_tool_calls_from_content
    for content in ("[]", "[1, 2]", '{"tool": "t"}', "42", '"text"', '[{"no": 1}]'):
        assert extract(content) is None, content


def test_chat_with_tools_runs_the_loop(http):
    http.ollama_up()
    replies = iter([
        {"message": {"content": "", "tool_calls": [
            {"function": {"name": "add", "arguments": {"a": 1, "b": 2}}}]}},
        {"message": {"content": "the answer is 3"}},
    ])  # fmt: skip
    http.routes[("POST", "/api/chat")] = lambda body: Response(body=next(replies))
    seen = []

    def dispatcher(calls):
        seen.append(calls)
        return [{"role": "tool", "content": json.dumps({"sum": 3})}]

    inference.set_tool_dispatcher(dispatcher)
    try:
        tools = [{"type": "function", "function": {"name": "add"}}]
        result = OllamaInterface().chat_with_tools(
            "m", [{"role": "user", "content": "1+2"}], tools
        )
    finally:
        inference.set_tool_dispatcher(None)
    assert result == {"content": "the answer is 3",
                      "tool_calls": [{"name": "add", "arguments": {"a": 1, "b": 2},
                                      "result": {"sum": 3}}]}  # fmt: skip
    assert len(seen) == 1


@pytest.mark.parametrize(
    "reply",
    [
        {"message": {"content": '{"name": "Alice", "age": 30}'}},
        {"message": {"content": 'Done. {"name": "delete_everything", "arguments": {}}'}},
        {"message": {"content": "", "tool_calls": [
            {"function": {"name": "delete_everything", "arguments": {}}}]}},
    ],
    ids=["data-with-a-name-key", "injected-text", "native-undeclared"],
)  # fmt: skip
def test_only_declared_tools_reach_the_dispatcher(http, reply, caplog):
    http.ollama_up()
    http.routes[("POST", "/api/chat")] = Response(body=reply)
    dispatched = []
    inference.set_tool_dispatcher(lambda calls: dispatched.append(calls) or [])
    try:
        tools = [{"type": "function", "function": {"name": "add"}}]
        result = OllamaInterface().chat_with_tools(
            "m", [{"role": "user", "content": "x"}], tools
        )
    finally:
        inference.set_tool_dispatcher(None)
    assert dispatched == []
    assert result == {"content": reply["message"]["content"], "tool_calls": []}
    assert "undeclared tool" in caplog.text


def test_a_declared_call_in_text_is_still_dispatched(http):
    http.ollama_up()
    replies = iter(
        [
            {"message": {"content": '{"name": "add", "arguments": {"a": 1}}'}},
            {"message": {"content": "ok"}},
        ]
    )
    http.routes[("POST", "/api/chat")] = lambda body: Response(body=next(replies))
    dispatched = []
    inference.set_tool_dispatcher(
        lambda calls: dispatched.append(calls) or [{"role": "tool", "content": "1"}]
    )
    try:
        tools = [{"name": "add"}]  # bare form is accepted too
        OllamaInterface().chat_with_tools(
            "m", [{"role": "user", "content": "x"}], tools
        )
    finally:
        inference.set_tool_dispatcher(None)
    assert [c[0]["function"]["name"] for c in dispatched] == ["add"]


@pytest.mark.parametrize("explicit", [True, False])
def test_the_manager_sends_llamacpp_the_prompt(http, explicit):
    http.routes[("GET", "/health")] = Response()
    http.routes[("POST", "/completion")] = lambda body: Response(
        body={"content": f"echo:{body['prompt']}"}
    )
    manager = InferenceEngineManager()
    assert manager.get_available_engines() == [InferenceEngine.LLAMA_CPP]
    engine = InferenceEngine.LLAMA_CPP if explicit else None
    assert manager.generate("some-model", "the real prompt", engine=engine) == (
        "echo:the real prompt"
    )
    body = http.calls[-1][2]
    assert body["n_predict"] == 256


def test_the_manager_sends_ollama_the_model(http):
    http.ollama_up()
    http.routes[("POST", "/api/generate")] = lambda body: Response(
        body={"response": f"{body['model']}:{body['prompt']}"}
    )
    assert InferenceEngineManager().generate("qwen3:8b", "hi") == "qwen3:8b:hi"


def test_an_unreadable_model_registry_is_set_aside(tmp_path, caplog):
    (tmp_path / "registry.json").write_text('{"m": {"name": "m", "engine": "nope"}}')
    registry = ModelRegistry(str(tmp_path))
    assert registry.models == {}
    assert len(list(tmp_path.glob("registry.json.corrupt-*"))) == 1
    assert "Model registry unreadable" in caplog.text
    registry.register_model(
        ModelInfo("m", InferenceEngine.OLLAMA, 1, "p", 1, "q", "ok")
    )
    assert ModelRegistry(str(tmp_path)).get_model("m").engine is InferenceEngine.OLLAMA


def _vllm_only(http):
    http.routes[("GET", "/v1/models")] = Response(body={"data": []})
    http.routes[("POST", "/v1/chat/completions")] = lambda body: Response(
        body={"choices": [{"message": {"content": f"t={body['temperature']}"}}]}
    )
    return InferenceEngineManager()


def test_chat_options_vllm_cannot_take_are_named(http):
    manager = _vllm_only(http)
    with pytest.raises(ValueError, match="vllm chat does not support: format, images"):
        manager.chat(
            "m", [], engine=InferenceEngine.VLLM, images=["b64"], format="json"
        )
    with pytest.raises(
        RuntimeError, match=r"supports chat with images, tools \(skipped: vllm\)"
    ):
        manager.chat("m", [], images=["b64"], tools=[{}])


def test_options_vllm_can_take_still_reach_it(http):
    manager = _vllm_only(http)
    assert manager.chat("m", [], temperature=0.3) == "t=0.3"
    assert (
        manager.chat("m", [], engine=InferenceEngine.VLLM, temperature=0.1) == "t=0.1"
    )


def test_tool_call_ids_are_unique():
    extract = OllamaInterface._extract_tool_calls_from_content
    ids = [c["id"] for c in extract('[{"name": "a"}, {"name": "b"}, {"name": "c"}]')]
    ids += [extract('{"name": "a"}')[0]["id"] for _ in range(50)]
    assert len(set(ids)) == len(ids)
    assert all(i.startswith("call_") for i in ids)


# -- chat_with_tools edges ---------------------------------------------------------

ADD = [{"type": "function", "function": {"name": "add"}}]


def _call(args):
    return {
        "message": {
            "content": "",
            "tool_calls": [{"function": {"name": "add", "arguments": args}}],
        }
    }


def _with_dispatcher(results):
    seen = []

    def dispatcher(calls):
        seen.append(calls)
        return results(calls)

    return seen, dispatcher


@pytest.mark.parametrize(
    "route",
    [
        Response(status=500),
        lambda body: (_ for _ in ()).throw(requests.ConnectionError("down")),
    ],
    ids=["http-500", "connection-error"],
)
def test_a_failed_chat_round_returns_nothing(http, route):
    http.ollama_up()
    http.routes[("POST", "/api/chat")] = route
    result = OllamaInterface().chat_with_tools(
        "m", [{"role": "user", "content": "x"}], ADD
    )
    assert result == {"content": "", "tool_calls": []}


def test_the_loop_stops_after_max_iterations(http):
    http.ollama_up()
    http.routes[("POST", "/api/chat")] = Response(body=_call({"a": 1}))
    seen, dispatcher = _with_dispatcher(
        lambda calls: [{"role": "tool", "content": "1"}]
    )
    inference.set_tool_dispatcher(dispatcher)
    try:
        result = OllamaInterface().chat_with_tools(
            "m", [{"role": "user", "content": "x"}], ADD, max_iterations=3
        )
    finally:
        inference.set_tool_dispatcher(None)
    assert len(seen) == 3
    assert result["content"].endswith("[_iterations_exceeded]")
    assert [c["result"] for c in result["tool_calls"]] == [1, 1, 1]


def test_without_a_dispatcher_the_calls_are_not_run(http, monkeypatch):
    import builtins

    http.ollama_up()
    http.routes[("POST", "/api/chat")] = Response(body=_call({"a": 1}))
    real_import = builtins.__import__

    def no_core_tools(name, *args, **kwargs):
        if name.startswith("core.tools"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_core_tools)
    result = OllamaInterface().chat_with_tools(
        "m", [{"role": "user", "content": "x"}], ADD
    )
    assert result == {"content": "", "tool_calls": []}


def test_images_ride_on_the_users_message_and_string_arguments_are_parsed(http):
    http.ollama_up()
    bodies, replies = (
        [],
        iter([_call('{"a": 1, "b": 2}'), {"message": {"content": "done"}}]),
    )
    http.routes[("POST", "/api/chat")] = lambda body: (
        bodies.append(body) or Response(body=next(replies))
    )
    _, dispatcher = _with_dispatcher(
        lambda calls: [{"role": "tool", "content": "plain text"}]
    )
    inference.set_tool_dispatcher(dispatcher)
    try:
        messages = [{"role": "user", "content": "look"}]
        result = OllamaInterface().chat_with_tools("m", messages, ADD, images=["b64"])
    finally:
        inference.set_tool_dispatcher(None)
    assert bodies[0]["messages"][0]["images"] == ["b64"]
    assert "images" not in messages[0]  # the caller's list is not changed
    assert result["tool_calls"] == [
        {"name": "add", "arguments": {"a": 1, "b": 2}, "result": "plain text"}
    ]
    assert result["content"] == "done"


MALFORMED = [[1], "x", None, 3, {"choices": []}, {"choices": None}, {"choices": [None]},
             {"response": 7}, {"message": None}, {"message": {"content": ["a"]}},
             {"content": {"a": 1}}]  # fmt: skip


@pytest.mark.parametrize("body", MALFORMED, ids=repr)
def test_a_malformed_reply_gives_empty_text_not_a_crash(http, body):
    http.ollama_up()
    http.routes[("GET", "/health")] = Response()
    http.routes[("GET", "/v1/models")] = Response(body={"data": []})
    for path in ("/api/generate", "/api/chat", "/completion", "/v1/completions",
                 "/v1/chat/completions"):  # fmt: skip
        http.routes[("POST", path)] = Response(body=body)
    ollama, vllm = OllamaInterface(), VLLMInterface()
    assert ollama.generate("m", "p") == ""
    assert ollama.chat("m", []) == ""
    assert LlamaCppInterface().generate("p") == ""
    assert vllm.generate("m", "p") == ""
    assert vllm.chat("m", []) == ""


def test_well_formed_replies_still_give_their_text(http):
    http.routes[("GET", "/health")] = Response()
    http.routes[("GET", "/v1/models")] = Response(body={"data": []})
    http.routes[("POST", "/completion")] = Response(body={"content": "llama"})
    http.routes[("POST", "/v1/completions")] = Response(
        body={"choices": [{"text": "gen"}, {"text": "second"}]}
    )
    http.routes[("POST", "/v1/chat/completions")] = Response(
        body={"choices": [{"message": {"content": "chat"}}]}
    )
    assert LlamaCppInterface().generate("p") == "llama"
    assert VLLMInterface().generate("m", "p") == "gen"
    assert VLLMInterface().chat("m", []) == "chat"


def test_stream_lines_of_the_wrong_shape_are_skipped(http):
    http.ollama_up()
    lines = [[1], "x", {"message": None}, {"response": 5, "message": {"content": 5}},
             {"response": "a", "message": {"content": "a"}}, {"done": "yes"},
             {"response": "b", "message": {"content": "b"}, "done": True},
             {"response": "c", "message": {"content": "c"}}]  # fmt: skip
    for path in ("/api/generate", "/api/chat"):
        http.routes[("POST", path)] = Response(lines=lines)
    ollama = OllamaInterface()
    assert ollama.generate("m", "p", stream=True) == "a"
    assert ollama.chat("m", [], stream=True) == "a"
    tokens = list(ollama.chat_stream("m", []))
    # [1] and "x" are not objects and are skipped; "done": "yes" ends it.
    assert tokens == [("", False), ("", False), ("a", False), ("", True)]


def test_model_lists_skip_entries_of_the_wrong_shape(http):
    http.ollama_up(
        [{"size": 1}, 3, None, {"name": 5}, {"name": "big", "size": "huge"},
         {"name": "ok", "size": 2 * 1024**3, "modified_at": 5}, {"name": "bare"}]
    )  # fmt: skip
    models = OllamaInterface().list_models()
    assert [(m.name, m.size_gb, m.last_used) for m in models] == [
        ("big", 0.0, ""), ("ok", 2.0, ""), ("bare", 0.0, "")
    ]  # fmt: skip
    http.routes[("GET", "/v1/models")] = Response(
        body={"data": [{}, 3, {"id": 7}, {"id": "llama-3"}, None]}
    )
    assert VLLMInterface().list_models() == ["llama-3"]


@pytest.mark.parametrize(
    "body",
    [[1], None, 3, {"models": None}, {"models": 5}, {"data": None}, {"data": 5}],
    ids=repr,
)
def test_a_malformed_model_list_is_empty(http, body):
    http.routes[("GET", "/api/tags")] = Response()
    http.routes[("GET", "/v1/models")] = Response()
    ollama, vllm = OllamaInterface(), VLLMInterface()
    http.routes[("GET", "/api/tags")] = Response(body=body)
    http.routes[("GET", "/v1/models")] = Response(body=body)
    assert ollama.list_models() == []
    assert vllm.list_models() == []


@pytest.mark.parametrize(
    "body",
    [[1], None, 3, {"message": None}, {"message": "x"}, {"message": {"content": None}},
     {"message": {"content": 5}}],
    ids=repr,
)  # fmt: skip
def test_a_malformed_tool_chat_reply_ends_with_no_content(http, body):
    http.ollama_up()
    http.routes[("POST", "/api/chat")] = Response(body=body)
    tools = [{"type": "function", "function": {"name": "t"}}]
    result = OllamaInterface().chat_with_tools(
        "m", [{"role": "user", "content": "hi"}], tools
    )
    assert result == {"content": "", "tool_calls": []}


def test_null_content_beside_native_tool_calls_still_dispatches(http):
    http.ollama_up()
    replies = iter([
        {"message": {"content": None, "tool_calls": [
            {"function": {"name": "t", "arguments": {"a": 1}}}]}},
        {"message": {"content": "done"}},
    ])  # fmt: skip
    http.routes[("POST", "/api/chat")] = lambda body: Response(body=next(replies))
    inference.set_tool_dispatcher(
        lambda calls: [{"role": "tool", "content": "{}"} for _ in calls]
    )
    try:
        tools = [{"type": "function", "function": {"name": "t"}}]
        result = OllamaInterface().chat_with_tools("m", [], tools)
    finally:
        inference.set_tool_dispatcher(None)
    assert result == {
        "content": "done",
        "tool_calls": [{"name": "t", "arguments": {"a": 1}, "result": {}}],
    }


# -- InferenceEngineManager.chat_with_tools ------------------------------------------

TOOLS = [{"type": "function", "function": {"name": "t"}}]


def test_manager_tool_chat_goes_to_ollama(http):
    http.ollama_up()
    http.routes[("POST", "/api/chat")] = Response(body={"message": {"content": "hi"}})
    manager = InferenceEngineManager()
    expected = {"content": "hi", "tool_calls": []}
    assert manager.chat_with_tools("m", [], TOOLS) == expected
    assert manager.chat_with_tools("m", [], TOOLS, engine=InferenceEngine.OLLAMA) == (
        expected
    )
    sent = [body for method, path, body in http.calls if path == "/api/chat"]
    assert [b["tools"] for b in sent] == [TOOLS, TOOLS]


def test_manager_tool_chat_refuses_a_named_engine_without_tool_support(http):
    http.ollama_up()
    http.routes[("GET", "/v1/models")] = Response(body={"data": []})
    http.routes[("POST", "/api/chat")] = Response(body={"message": {"content": "x"}})
    manager = InferenceEngineManager()
    with pytest.raises(ValueError, match="vllm does not support chat_with_tools"):
        manager.chat_with_tools("m", [], TOOLS, engine=InferenceEngine.VLLM)
    assert not [c for c in http.calls if c[1] == "/api/chat"]


def test_manager_tool_chat_needs_ollama(http):
    http.routes[("GET", "/v1/models")] = Response(body={"data": []})
    manager = InferenceEngineManager()
    with pytest.raises(RuntimeError, match="No available inference engine") as err:
        manager.chat_with_tools("m", [], TOOLS)
    assert err.value.__cause__ is None
    # A named engine that is not running falls back to the default order.
    with pytest.raises(RuntimeError, match="No available inference engine"):
        manager.chat_with_tools("m", [], TOOLS, engine=InferenceEngine.OLLAMA)


def test_manager_tool_chat_reports_an_ollama_failure(http):
    http.ollama_up()
    manager = InferenceEngineManager()
    manager.engines[InferenceEngine.OLLAMA].available = False
    with pytest.raises(RuntimeError, match="No available inference engine") as err:
        manager.chat_with_tools("m", [], TOOLS)
    assert "Ollama is not available" in str(err.value.__cause__)


# -- hostile replies -------------------------------------------------------------------

USER = [{"role": "user", "content": "summarise the attached document"}]


@pytest.fixture
def ollama(http):
    http.ollama_up()
    yield http
    inference.set_tool_dispatcher(None)


def _replies(http, *bodies):
    it = iter(bodies)
    http.routes[("POST", "/api/chat")] = lambda body: Response(body=next(it))


@pytest.mark.parametrize(
    "result", ["1" * 5000, "[" * 100000], ids=["long-number", "deep-nesting"]
)
def test_an_odd_tool_result_keeps_the_history_of_what_ran(ollama, result):
    # The result of a tool that has already run. Text json cannot decode
    # (over 4300 digits, deep nesting) is kept as text, so the caller
    # still gets the history of what ran.
    _replies(ollama, _call({}), {"message": {"content": "done"}})
    inference.set_tool_dispatcher(lambda calls: [{"role": "tool", "content": result}])
    out = OllamaInterface().chat_with_tools("m", USER, ADD)
    assert [c["name"] for c in out["tool_calls"]] == ["add"]
    assert out["tool_calls"][0]["result"] == result  # kept as text


@pytest.mark.parametrize(
    "reply",
    [{"message": {"content": "[" * 100000}},
     {"message": {"content": '{"name": "add", "arguments": {"a": ' + "1" * 5000 + "}}"}},
     {"message": {"content": '{"name": "add", "arguments": "' + "1" * 5000 + '"}'}},
     {"message": {"content": "", "tool_calls": 5}},
     {"message": {"content": "", "tool_calls": [{"function": {"name": ["add"]}}]}},
     {"message": {"content": "", "tool_calls": [{"function": {"name": {"a": 1}}}]}}],
    ids=["deep-text", "long-int-text", "long-int-string-args", "tool_calls-int",
         "list-name", "dict-name"],
)  # fmt: skip
def test_a_hostile_reply_ends_the_loop_without_raising(ollama, reply):
    seen = []
    inference.set_tool_dispatcher(lambda calls: seen.append(calls) or [])
    _replies(ollama, reply, {"message": {"content": "done"}})
    out = OllamaInterface().chat_with_tools("m", USER, ADD)
    assert isinstance(out, dict)
    # The string-argument call is still a call to a declared tool, with its
    # arguments kept as text; nothing else is dispatched.
    assert all(c[0]["function"]["name"] == "add" for c in seen)


def test_a_reply_body_nested_too_deep_ends_the_loop(ollama):
    class Deep(Response):
        def json(self):
            raise RecursionError("maximum recursion depth exceeded")

    ollama.routes[("POST", "/api/chat")] = Deep()
    assert OllamaInterface().chat_with_tools("m", USER, ADD) == {
        "content": "", "tool_calls": []
    }  # fmt: skip


def test_the_manager_does_not_report_a_hostile_reply_as_no_engine(ollama):
    ollama.routes[("POST", "/api/chat")] = Response(
        body={"message": {"content": "[" * 100000}}
    )
    out = inference.InferenceEngineManager().chat_with_tools("m", USER, ADD)
    assert out == {"content": "[" * 100000, "tool_calls": []}


def test_a_failed_later_round_keeps_the_history_of_what_ran(ollama):
    rounds = iter([Response(body=_call({"a": 1})), Response(status=500)])
    ollama.routes[("POST", "/api/chat")] = lambda body: next(rounds)
    inference.set_tool_dispatcher(lambda calls: [{"role": "tool", "content": "2"}])
    out = OllamaInterface().chat_with_tools("m", USER, ADD)
    assert out["tool_calls"] == [{"name": "add", "arguments": {"a": 1}, "result": 2}]


def test_arguments_too_long_to_read_are_kept_as_text_in_the_history(ollama):
    digits = "1" * 5000
    _replies(ollama, _call(digits), {"message": {"content": "done"}})
    inference.set_tool_dispatcher(lambda calls: [{"role": "tool", "content": "ok"}])
    out = OllamaInterface().chat_with_tools("m", USER, ADD)
    assert out["tool_calls"] == [{"name": "add", "arguments": digits, "result": "ok"}]


@pytest.mark.parametrize(
    "content", ["```\n" + "\n" * 100_000, "```json" + " \n" * 50_000 + "x"]
)
def test_an_unclosed_fence_is_read_in_linear_time(ollama, content):
    # The reply is parsed after the HTTP timeout has ended, so an unclosed
    # fence followed by many newlines must not cost quadratic time.
    import time

    ollama.routes[("POST", "/api/chat")] = Response(
        body={"message": {"content": content}}
    )
    start = time.perf_counter()
    OllamaInterface().chat_with_tools("m", USER, ADD)
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize(
    "content",
    ['```json\n{"name": "add", "arguments": {"a": 1}}\n```',
     '```\n  {"name": "add", "arguments": {"a": 1}}  \n```',
     'I will call it: ```json{"name": "add", "arguments": {"a": 1}}``` now'],
)  # fmt: skip
def test_a_fenced_call_is_still_read(content):
    [call] = OllamaInterface._extract_tool_calls_from_content(content)
    assert call["function"] == {"name": "add", "arguments": {"a": 1}}


def test_a_fenced_list_of_calls_is_read_whole():
    content = '```json\n[{"name": "add", "arguments": {}}, {"name": "add", "arguments": {"b": 2}}]\n```'
    calls = OllamaInterface._extract_tool_calls_from_content(content)
    assert [c["function"]["arguments"] for c in calls] == [{}, {"b": 2}]


# -- how many calls one loop dispatches ------------------------------------------------


@pytest.mark.parametrize("where", ["native", "text"])
def test_one_reply_cannot_dispatch_more_than_the_limit(ollama, where):
    if where == "native":
        calls = [
            {"function": {"name": "add", "arguments": {"a": i}}} for i in range(1000)
        ]
        reply = {"message": {"content": "", "tool_calls": calls}}
    else:
        text = json.dumps([{"name": "add", "arguments": {"a": i}} for i in range(1000)])
        reply = {"message": {"content": text}}
    _replies(ollama, reply, {"message": {"content": "done"}})
    seen = []
    inference.set_tool_dispatcher(lambda calls: seen.extend(calls) or [])
    out = OllamaInterface().chat_with_tools("m", USER, ADD, max_iterations=1)
    # The first MAX_TOOL_CALLS, in order, and that is a small number.
    assert inference.MAX_TOOL_CALLS <= 64
    assert [c["function"]["arguments"]["a"] for c in seen] == list(
        range(inference.MAX_TOOL_CALLS)
    )
    assert isinstance(out, dict)


def test_the_limit_counts_across_rounds_and_ends_the_loop(ollama):
    rounds = [{"message": {"content": "", "tool_calls": [
        {"function": {"name": "add", "arguments": {"r": r, "i": i}}} for i in range(3)]}}
        for r in range(4)]  # fmt: skip
    _replies(ollama, *rounds)
    seen = []
    inference.set_tool_dispatcher(lambda calls: seen.extend(calls) or [])
    out = OllamaInterface().chat_with_tools("m", USER, ADD, max_tool_calls=5)
    assert [(c["function"]["arguments"]["r"], c["function"]["arguments"]["i"])
            for c in seen] == [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1)]  # fmt: skip
    assert out["content"].endswith("[_tool_calls_exceeded]")  # round 3 asked for more


def test_the_manager_passes_the_limit_on(ollama):
    _replies(ollama, _call({"a": 1}), {"message": {"content": "done"}})
    seen = []
    inference.set_tool_dispatcher(lambda calls: seen.extend(calls) or [])
    out = inference.InferenceEngineManager().chat_with_tools(
        "m", USER, ADD, max_tool_calls=0
    )
    assert seen == [] and out["content"].endswith("[_tool_calls_exceeded]")


def test_undeclared_tool_names_are_logged_once_and_cut_short(ollama, caplog):
    calls = [{"function": {"name": "x" * 1_000_000, "arguments": {}}}]
    calls += [{"function": {"name": f"y{i}", "arguments": {}}} for i in range(999)]
    ollama.routes[("POST", "/api/chat")] = Response(
        body={"message": {"content": "", "tool_calls": calls}}
    )
    OllamaInterface().chat_with_tools("m", USER, ADD)
    ignored = [r for r in caplog.records if "undeclared" in r.getMessage()]
    assert len(ignored) == 1
    message = ignored[0].getMessage()
    assert (
        len(message) < 400 and "1000 call(s)" in message and message.endswith(", ...")
    )
    assert ("'" + "x" * 64 + "'") in message


# -- a tool that fails in a later round ------------------------------------------------


@pytest.mark.parametrize(
    "second_round",
    [TypeError("to must be one address"), "not a list", ["not a message"]],
    ids=["raises", "not-a-list", "not-messages"],
)
@pytest.mark.parametrize("through", ["ollama", "manager"])
def test_a_tool_that_fails_in_a_later_round_returns_the_history(
    http, through, second_round
):
    # A dispatcher failure ends the loop with round one's history; the
    # manager does not report it as "No available inference engine".
    http.ollama_up()
    replies = iter([_call({"a": 1}), _call({"a": 2})])
    http.routes[("POST", "/api/chat")] = lambda body: Response(body=next(replies))

    def results(calls):
        if calls[0]["function"]["arguments"]["a"] == 1:
            return [{"role": "tool", "content": "1"}]
        if isinstance(second_round, Exception):
            raise second_round
        return second_round

    seen, dispatcher = _with_dispatcher(results)
    inference.set_tool_dispatcher(dispatcher)
    try:
        if through == "ollama":
            engine = OllamaInterface()
        else:
            engine = inference.InferenceEngineManager()
        result = engine.chat_with_tools("m", [{"role": "user", "content": "x"}], ADD)
    finally:
        inference.set_tool_dispatcher(None)
    assert len(seen) == 2
    assert result["content"].endswith("[_tool_dispatch_failed]")
    assert result["tool_calls"] == [{"name": "add", "arguments": {"a": 1}, "result": 1}]


# -- a reply nested too deep, a stream line that cannot be read ------------------------

_DEEP = b"[" * 100_000 + b"]" * 100_000


def _real(body: bytes = b"", lines=None):
    """A requests.Response, so .json() decodes as it does against a server."""
    response = requests.models.Response()
    response.status_code, response._content = 200, body
    if lines is not None:
        response.iter_lines = lambda: iter(lines)
    return response


_CALLS = {
    "ollama generate": ("POST", "/api/generate", lambda: OllamaInterface().generate("m", "p"), ""),
    "ollama chat": ("POST", "/api/chat", lambda: OllamaInterface().chat("m", []), ""),
    "ollama list_models": ("GET", "/api/tags", lambda: OllamaInterface().list_models(), []),
    "llama.cpp generate": ("POST", "/completion", lambda: LlamaCppInterface().generate("p"), ""),
    "vLLM generate": ("POST", "/v1/completions", lambda: VLLMInterface().generate("m", "p"), ""),
    "vLLM chat": ("POST", "/v1/chat/completions", lambda: VLLMInterface().chat("m", []), ""),
    "vLLM list_models": ("GET", "/v1/models", lambda: VLLMInterface().list_models(), []),
}  # fmt: skip


@pytest.mark.parametrize("call", sorted(_CALLS))
def test_a_reply_nested_too_deep_is_an_empty_answer(http, call):
    # Every call handles RecursionError from the decoder, as the tool loop does.
    method, path, run, empty = _CALLS[call]
    for up in (("GET", "/api/tags"), ("GET", "/health"), ("GET", "/v1/models")):
        http.routes[up] = _real(b"{}")
    http.routes[(method, path)] = _real(_DEEP)
    assert run() == empty


@pytest.mark.parametrize(
    "bad", [_DEEP, b"{not json", b"[1, 2]"], ids=["deep", "not-json", "not-object"]
)
@pytest.mark.parametrize("call", ["generate", "chat", "chat_stream"])
def test_a_stream_line_that_cannot_be_read_costs_only_that_line(http, call, bad):
    # generate and chat with stream=True and chat_stream all skip the bad
    # line and keep the text on either side of it.
    http.ollama_up()
    lines = [
        json.dumps({"response": "a", "message": {"content": "a"}}).encode(),
        bad,
        json.dumps(
            {"response": "b", "message": {"content": "b"}, "done": True}
        ).encode(),
    ]
    http.routes[("POST", "/api/generate")] = _real(lines=lines)
    http.routes[("POST", "/api/chat")] = _real(lines=lines)
    ollama = OllamaInterface()
    if call == "generate":
        text = ollama.generate("m", "p", stream=True)
    elif call == "chat":
        text = ollama.chat("m", [], stream=True)
    else:
        text = "".join(token for token, _ in ollama.chat_stream("m", []))
    assert text == "ab"
