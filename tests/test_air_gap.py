"""NGARI_AIR_GAP, inference half: with the gap on (the default) the three
inference clients call loopback addresses only, a refused client raises
AirGapError from every method and makes no request, environment proxies
never carry a loopback call, and pull_model is refused."""

import contextlib
import http.server
import inspect
import socket
import threading
from pathlib import Path

import pytest
import requests

from core.kernel import inference
from core.kernel.inference import (
    AirGapError,
    InferenceEngineManager,
    LlamaCppInterface,
    OllamaInterface,
    VLLMInterface,
    air_gap_enabled,
    loopback_problem,
)

REMOTE = "http://203.0.113.7:11434"
REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def gap_default(monkeypatch):
    monkeypatch.delenv("NGARI_AIR_GAP", raising=False)


class _Response:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body if body is not None else {}

    def json(self):
        return self._body


@pytest.fixture
def calls(monkeypatch):
    seen = []

    def record(method):
        def call(url, **kwargs):
            seen.append((method, url, kwargs))
            return _Response(body={"models": [], "data": []})

        return call

    for method in ("get", "post", "delete"):
        monkeypatch.setattr(inference.requests, method, record(method))
    return seen


# -- the setting ------------------------------------------------------------------


@pytest.mark.parametrize("value", ["0", "false", "no", "off", " Off ", "FALSE"])
def test_these_values_turn_it_off(value):
    assert air_gap_enabled({"NGARI_AIR_GAP": value}) is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "", " ON "])
def test_these_values_keep_it_on(value, caplog):
    assert air_gap_enabled({"NGARI_AIR_GAP": value}) is True
    assert "NGARI_AIR_GAP" not in caplog.text


def test_unset_is_on_and_a_misspelling_stays_on_with_a_warning(caplog):
    assert air_gap_enabled({}) is True
    assert air_gap_enabled({"NGARI_AIR_GAP": "flase"}) is True
    assert "'flase' is not a known value; air gap stays on" in caplog.text


_ALL_COPIES = ("data_plane", "inference", "network_sync", "sandbox.bwrap")


@pytest.mark.parametrize(
    ("value", "on", "warned"),
    [(None, True, False), ("", True, False), ("1", True, False), ("true", True, False),
     ("yes", True, False), ("on", True, False), (" ON ", True, False),
     ("0", False, False), ("false", False, False), ("no", False, False),
     ("off", False, False), (" Off ", False, False), ("FALSE", False, False),
     ("flase", True, True), ("2", True, True), ("disabled", True, True)],
)  # fmt: skip
def test_every_copy_of_the_setting_reads_it_the_same_way(value, on, warned, caplog):
    # The double import keeps helpers per module, so four modules each have
    # their own; one reading a value another way would have the data plane
    # audit the gap as on while a gate let traffic out.
    import importlib
    import logging

    env = {} if value is None else {"NGARI_AIR_GAP": value}
    for name in _ALL_COPIES:
        module = importlib.import_module(f"core.kernel.{name}")
        caplog.clear()
        caplog.set_level(logging.WARNING)
        assert module.air_gap_enabled(env) is on, name
        said = (
            "is not a known value; air gap stays on (0, false, no or off turn it off)"
        )
        assert (said in caplog.text) is warned, name


# -- which URLs ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["http://localhost:11434", "http://LOCALHOST:1", "https://localhost/x", "http://127.0.0.1",
     "http://127.255.255.254:8080/api", "http://[::1]:11434", "http://[::ffff:127.0.0.1]:1",
     "http://user:pw@127.0.0.1:11434"],
)  # fmt: skip
def test_loopback_urls_are_allowed(url):
    assert loopback_problem(url) is None


@pytest.mark.parametrize(
    "url",
    ["http://0.0.0.0:11434", "http://198.51.100.4:11434", REMOTE, "http://127.1:11434",
     "http://ollama.local:11434", "http://localhost.:11434", "http://localhost.localdomain",
     "http://x.localhost", "ftp://127.0.0.1", "", "http://[::1", "http://[::ffff:198.51.100.4]:1"],
)  # fmt: skip
def test_everything_else_is_refused(url):
    assert loopback_problem(url)


# -- a refused client -----------------------------------------------------------------


def test_the_default_is_on_and_a_remote_endpoint_is_refused(calls, caplog):
    client = OllamaInterface(base_url=REMOTE)
    assert client.available is False
    assert "203.0.113.7" in client.refused
    assert calls == []
    assert "refusing Ollama endpoint http://203.0.113.7:11434" in caplog.text
    assert "set NGARI_AIR_GAP=0 to allow it" in caplog.text


def test_every_method_of_a_refused_client_raises_air_gap_error(calls):
    ollama = OllamaInterface(base_url=REMOTE)
    for call in (
        ollama.list_models, lambda: ollama.get_model_info("m"), lambda: ollama.generate("m", "p"),
        lambda: ollama.chat("m", []), lambda: next(ollama.chat_stream("m", [])),
        lambda: ollama.chat_with_tools("m", [], []), lambda: ollama.pull_model("m"),
        lambda: ollama.delete_model("m"),
    ):  # fmt: skip
        with pytest.raises(AirGapError, match="refused in air-gap mode"):
            call()
    with pytest.raises(AirGapError):
        LlamaCppInterface(server_url=REMOTE).generate("p")
    vllm = VLLMInterface(base_url=REMOTE)
    with pytest.raises(AirGapError):
        vllm.generate("m", "p")
    with pytest.raises(AirGapError):
        vllm.list_models()
    assert calls == []
    assert issubclass(AirGapError, RuntimeError)


def test_an_unavailable_loopback_client_still_returns_empty(calls, monkeypatch):
    def down(url, **kwargs):
        raise inference.requests.ConnectionError("down")

    monkeypatch.setattr(inference.requests, "get", down)
    client = OllamaInterface()
    assert (client.available, client.refused) == (False, None)
    assert client.list_models() == [] and client.get_model_info("m") is None
    with pytest.raises(RuntimeError, match="Ollama is not available"):
        client.generate("m", "p")


def test_an_explicit_argument_beats_the_environment(calls, monkeypatch, caplog):
    remote = OllamaInterface(base_url=REMOTE, air_gap=False)
    assert remote.refused is None and [c[1] for c in calls] == [f"{REMOTE}/api/tags"]
    assert "built with air_gap=False while NGARI_AIR_GAP says on" in caplog.text
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    assert OllamaInterface(base_url=REMOTE, air_gap=True).refused


def test_a_base_url_changed_after_construction_is_still_refused(calls):
    client = OllamaInterface()
    calls.clear()
    client.base_url = REMOTE
    with pytest.raises(AirGapError):
        client.generate("m", "p")
    assert calls == []


def test_messages_never_carry_credentials(calls, caplog):
    client = OllamaInterface(base_url="http://user:hunter2@203.0.113.7:11434")
    with pytest.raises(AirGapError) as caught:
        client.generate("m", "p")
    assert "hunter2" not in caplog.text + str(caught.value) + client.refused
    assert "http://203.0.113.7:11434" in str(caught.value)


def test_pull_is_refused_on_loopback_and_allowed_with_the_gap_off(calls, monkeypatch):
    with pytest.raises(AirGapError, match="pull_model"):
        OllamaInterface().pull_model("m")
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    OllamaInterface().pull_model("m")
    assert [c[0] for c in calls if c[1].endswith("/api/pull")] == ["post"]


def test_with_the_gap_off_a_remote_client_is_allowed(calls, monkeypatch):
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    client = OllamaInterface(base_url=REMOTE)
    assert client.refused is None
    _method, url, kwargs = calls[0]
    assert (
        url == f"{REMOTE}/api/tags" and "proxies" not in kwargs
    )  # environment proxies apply


def test_the_manager_reports_the_setting(calls, monkeypatch, tmp_path):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    status = InferenceEngineManager().get_status()
    assert (status["air_gap"], status["refused_endpoints"]) == (True, [])
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    assert InferenceEngineManager().get_status()["air_gap"] is False


# -- no lookup, and no proxy for loopback ----------------------------------------------


def test_the_gate_runs_before_any_lookup_or_call(monkeypatch):
    lookups, requests_made = [], []
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda host, *a, **k: lookups.append(host) or []
    )
    monkeypatch.setattr(
        inference.requests, "get", lambda *a, **k: requests_made.append(a)
    )
    client = OllamaInterface(base_url="http://inference.example.com:11434")
    assert (client.available, lookups, requests_made) == (False, [], [])


class _Tags(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"models": []}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.mark.parametrize("gap", ["1", "0"])
def test_environment_proxies_never_carry_a_loopback_call(monkeypatch, gap):
    server = http.server.HTTPServer(("127.0.0.1", 0), _Tags)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))  # a proxy address nothing listens on
        proxy = f"http://127.0.0.1:{dead.getsockname()[1]}"
        for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(var, proxy)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.setenv("NGARI_AIR_GAP", gap)
        hosts = []
        real = socket.getaddrinfo
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda h, *a, **k: hosts.append(h) or real(h, *a, **k),
        )
        client = OllamaInterface(
            base_url=f"http://127.0.0.1:{server.server_address[1]}"
        )
        assert client.available is True  # it reached the server, not the dead proxy
        assert set(hosts) <= {"127.0.0.1"}
        dead.close()
    finally:
        server.shutdown()


def test_the_proxy_rule_is_what_makes_that_pass(monkeypatch):
    monkeypatch.setattr(inference, "_DIRECT", {})
    server = http.server.HTTPServer(("127.0.0.1", 0), _Tags)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{dead.getsockname()[1]}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        client = OllamaInterface(
            base_url=f"http://127.0.0.1:{server.server_address[1]}"
        )
        assert client.available is False
        dead.close()
    finally:
        server.shutdown()


# -- the data plane records and reports the setting ------------------------------------

NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 99999 10 0 0 0 0 0 0 99999 10 0 0 0 0 0 0
  eth0: {rx} 20 0 0 0 0 0 0 {tx} 15 0 0 0 0 0 0
 wlan0: 5 1 0 0 0 0 0 0 7 1 0 0 0 0 0 0
"""


@pytest.fixture
def net(tmp_path, monkeypatch):
    from core.kernel import data_plane

    dev = tmp_path / "net-dev"
    dev.write_text(NET_DEV.format(rx=2000, tx=100))
    monkeypatch.setattr(data_plane, "PROC_NET_DEV", dev)
    return dev


def _plane(tmp_path):
    from core.kernel.data_plane import SovereignDataPlane

    return SovereignDataPlane(str(tmp_path / "sovereign"))


def test_the_start_entry_records_the_setting_and_stays_keyed(tmp_path, monkeypatch):
    plane = _plane(tmp_path)
    [entry] = plane.get_audit_log(10)
    assert entry["details"] == {"hardware_bound": False, "ok": True, "air_gap": True}
    assert "mac" in entry and plane.verify_audit_integrity()
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    second = [
        e for e in _plane(tmp_path).get_audit_log(10) if e["action"] == "key_provider"
    ][-1]
    assert second["details"]["air_gap"] is False


def test_the_report_measures_the_setting_at_call_time(tmp_path, monkeypatch):
    plane = _plane(tmp_path)
    assert plane.export_compliance_report()["air_gap"]["on"] is True
    assert plane.export_compliance_report()["air_gap"]["source"] == "default"
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    section = plane.export_compliance_report()["air_gap"]
    assert (section["on"], section["source"]) == (False, "environment")
    # The sovereignty verdict is about the data, not this setting.
    assert plane.export_compliance_report()["data_sovereignty"] == "enforced"


def test_host_interfaces_are_parsed_without_loopback(net):
    from core.kernel import data_plane

    assert data_plane._host_interfaces() == {
        "eth0": {"rx_bytes": 2000, "tx_bytes": 100},
        "wlan0": {"rx_bytes": 5, "tx_bytes": 7},
    }


@pytest.mark.parametrize(
    "content", [None, "", "header\nheader\nnot an interface line", "h\nh\n eth0: x y\n"]
)
def test_an_unusable_proc_file_gives_none(tmp_path, monkeypatch, content):
    from core.kernel import data_plane

    dev = tmp_path / "dev"
    if content is not None:
        dev.write_text(content)
    monkeypatch.setattr(data_plane, "PROC_NET_DEV", dev)
    assert data_plane._host_interfaces() in (None, {})
    if content in (None, "h\nh\n eth0: x y\n"):
        assert data_plane._host_interfaces() is None


def test_since_start_counts_what_moved(tmp_path, net):
    plane = _plane(tmp_path)
    net.write_text(NET_DEV.format(rx=2000, tx=1600))
    assert plane.export_compliance_report()["air_gap"]["since_start"] == {
        "eth0": {"rx_bytes": 0, "tx_bytes": 1500},
        "wlan0": {"rx_bytes": 0, "tx_bytes": 0},
    }
    net.write_text(
        NET_DEV.format(rx=2000, tx=1600) + "  usb0: 40 1 0 0 0 0 0 0 60 1 0 0 0 0 0 0\n"
    )
    assert plane.export_compliance_report()["air_gap"]["since_start"]["usb0"] == {
        "rx_bytes": 40,
        "tx_bytes": 60,
    }
    net.unlink()
    assert plane.export_compliance_report()["air_gap"]["since_start"] is None


def test_the_kernel_says_which_mode_it_started_in(tmp_path, monkeypatch, caplog):
    from core.kernel import NSBOSKernel

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    caplog.set_level("INFO")
    kernel = NSBOSKernel()
    assert "Air gap: on" in caplog.text
    assert kernel.get_status()["data_sovereignty"]["air_gap"]["on"] is True
    caplog.clear()
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    NSBOSKernel()
    assert "Air gap: OFF" in caplog.text


def test_the_off_warning_names_every_gate_that_opens(
    tmp_path, monkeypatch, calls, caplog
):
    # Each phrase in the warning is a gate that is shut with the gap on and
    # open with it off; the doc says the same list.
    from core.kernel import AIR_GAP_OFF_ALLOWS, NSBOSKernel
    from core.kernel import network_sync as ns
    from core.kernel.sandbox import bwrap

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    monkeypatch.delenv(bwrap.REQUIRE_BWRAP_ENV, raising=False)

    def gates():
        sync = ns.NetworkSynchronization(str(tmp_path / "sync-check"))
        try:
            sync.set_sync_mode(ns.SyncMode.HYBRID)
            sync_open = True
        except ns.AirGapError:
            sync_open = False
        client = OllamaInterface(base_url=REMOTE)
        try:
            client.pull_model("m")
            pull_open = True
        except AirGapError:
            pull_open = False
        return {
            "inference endpoints outside loopback": client.refused is None,
            "environment proxies for those calls": client.refused is None,
            "model pulls": pull_open,
            "sync modes other than local_only": sync_open,
            "plain subprocess with the host's network when bubblewrap is missing": (
                not bwrap.BwrapSandbox().require_bwrap
            ),
        }

    assert set(gates().values()) == {False}
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    assert set(gates().values()) == {True}
    caplog.clear()
    NSBOSKernel()
    doc = " ".join(
        (REPO_ROOT / "docs" / "AIR_GAP.md").read_text().replace("`", "").split()
    )
    for phrase in gates():
        assert phrase in AIR_GAP_OFF_ALLOWS and phrase in caplog.text, phrase
    for phrase in (
        "inference endpoints outside loopback",
        "model pulls",
        "sync modes other than local_only",
        "when bubblewrap is missing",
    ):
        assert phrase in doc, phrase


# -- the sandbox -----------------------------------------------------------------------


@pytest.fixture
def no_bwrap(monkeypatch):
    from core.kernel.sandbox import bwrap

    monkeypatch.setattr(bwrap, "_BWRAP_PATH", None)
    ran = []
    monkeypatch.setattr(bwrap.subprocess, "run", lambda *a, **k: ran.append(a))
    monkeypatch.setattr(bwrap.subprocess, "Popen", lambda *a, **k: ran.append(a))
    return ran


def test_the_gap_requires_bubblewrap_and_the_code_never_runs_without_it(
    no_bwrap, caplog
):
    from core.kernel.sandbox import bwrap

    # The autouse fixture leaves NGARI_AIR_GAP unset: on.
    sandbox = bwrap.BwrapSandbox()
    assert (sandbox.require_bwrap, sandbox.air_gap) == (True, True)
    assert "air-gap mode is on: agent code will not run" in caplog.text
    result = sandbox.execute_python("print('ran')")
    assert result.error == "sandbox_unavailable"
    assert "or air-gap mode is on" in result.stderr
    assert no_bwrap == []
    assert sandbox.get_capabilities()["air_gap"] is True


def test_an_explicit_false_still_falls_back_with_a_second_warning(no_bwrap, caplog):
    from core.kernel.sandbox import bwrap

    sandbox = bwrap.BwrapSandbox(require_bwrap=False)
    assert sandbox.require_bwrap is False
    assert "air gap is on and bubblewrap is not available" in caplog.text
    sandbox.execute_python("print(1)")
    assert len(no_bwrap) == 1


def test_with_the_gap_off_bubblewrap_is_not_required(no_bwrap, monkeypatch, caplog):
    from core.kernel.sandbox import bwrap

    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    sandbox = bwrap.BwrapSandbox()
    assert (sandbox.require_bwrap, sandbox.air_gap) == (False, False)
    assert "air gap is on" not in caplog.text
    monkeypatch.setenv(bwrap.REQUIRE_BWRAP_ENV, "1")
    assert bwrap.BwrapSandbox().require_bwrap is True


# -- the sync modes --------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["PEER_TO_PEER", "CLOUD_SYNC", "HYBRID"])
def test_only_local_sync_is_allowed_under_the_gap(tmp_path, monkeypatch, mode):
    from core.kernel import network_sync as ns

    sync = ns.NetworkSynchronization(str(tmp_path))
    with pytest.raises(ns.AirGapError, match="would send data off this machine"):
        sync.set_sync_mode(ns.SyncMode[mode])
    assert sync.sync_mode is ns.SyncMode.LOCAL_ONLY
    with pytest.raises(ns.AirGapError):
        sync.set_sync_mode(ns.SyncMode[mode].value)  # plain values too
    sync.set_sync_mode(ns.SyncMode.LOCAL_ONLY)
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    sync.set_sync_mode(ns.SyncMode[mode])
    assert sync.sync_mode is ns.SyncMode[mode]


def test_the_package_sync_class_is_matched_by_value(tmp_path, monkeypatch):
    # The kernel imports the module flat, so its SyncMode is another class.
    import sys

    from core.kernel import NSBOSKernel

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    flat = sys.modules[type(kernel.network_sync).__module__]
    with pytest.raises(flat.AirGapError):
        kernel.network_sync.set_sync_mode(flat.SyncMode.HYBRID)


def test_the_parsers_in_all_four_modules_are_the_same_text():
    from core.kernel import data_plane, network_sync
    from core.kernel.sandbox import bwrap

    modules = (inference, data_plane, network_sync, bwrap)
    assert len({inspect.getsource(m.air_gap_enabled) for m in modules}) == 1
    assert len({(m.AIR_GAP_ENV, m._AIR_GAP_OFF, m._AIR_GAP_ON) for m in modules}) == 1


# -- redirects are never followed ------------------------------------------------------


def _is_loopback(host):
    """The test's own reading of loopback, independent of the gate's."""
    import ipaddress

    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


@pytest.fixture
def reached(monkeypatch):
    """Every host a connection is attempted to; anything not loopback is
    refused here, so nothing in these tests can leave the machine."""
    hosts = []
    real = socket.getaddrinfo

    def guarded(host, *args, **kwargs):
        hosts.append(host)
        if not _is_loopback(str(host)):
            raise OSError(f"test guard: {host} is not loopback")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded)
    return hosts


def _redirecting_server(status, location):
    class Redirect(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if self.path in ("/api/tags", "/health", "/v1/models"):
                body = b'{"models": [], "data": []}'
                self.send_response(200)
            else:
                body = b""
                self.send_response(status)
                self.send_header("Location", location)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _answer

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_off_loopback_is_never_followed(reached, caplog, status):
    server = _redirecting_server(status, "http://203.0.113.7:11434/api/chat")
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        ollama = OllamaInterface(base_url=url)
        assert ollama.available is True
        assert ollama.chat("m", [{"role": "user", "content": "SECRET PROMPT"}]) == ""
        assert ollama.generate("m", "SECRET PROMPT") == ""
        assert list(ollama.chat_stream("m", [{"role": "user", "content": "x"}])) == [
            ("", True)
        ]
        assert LlamaCppInterface(server_url=url).generate("SECRET PROMPT") == ""
        assert VLLMInterface(base_url=url).generate("m", "SECRET PROMPT") == ""
        assert set(reached) == {"127.0.0.1"}  # 203.0.113.7 is never tried
        assert "answered with a redirect; it is not followed" in caplog.text
    finally:
        server.shutdown()


def test_a_redirect_between_loopback_ports_does_not_reach_the_proxy(
    reached, monkeypatch
):
    target = http.server.HTTPServer(("127.0.0.1", 0), _Tags)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    server = _redirecting_server(
        307, f"http://127.0.0.1:{target.server_address[1]}/api/tags"
    )
    try:
        monkeypatch.setenv("HTTP_PROXY", "http://203.0.113.9:3128")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        ollama = OllamaInterface(
            base_url=f"http://127.0.0.1:{server.server_address[1]}"
        )
        assert ollama.chat("m", [{"role": "user", "content": "SECRET PROMPT"}]) == ""
        assert "203.0.113.9" not in reached
    finally:
        server.shutdown()
        target.shutdown()


def test_every_call_is_made_without_following_redirects(calls):
    client = OllamaInterface()
    client.generate("m", "p")
    client.chat("m", [])
    assert calls and all(
        kwargs.get("allow_redirects") is False for _, _, kwargs in calls
    )


# -- the gate reads the host the way the connection does ------------------------------

TRICKY = [
    "http://203.0.113.7\\@127.0.0.1/", "http://203.0.113.7:80\\@127.0.0.1:11434",
    "http://203.0.113.7\\@[::1]/", "http://ollama.example\\@localhost:11434",
    "http://127.0.0.1:80@203.0.113.7/", "http://203.0.113.7@127.0.0.1/",
    "http://127.0.0.1#@203.0.113.7/", "http://127.0.0.1?@203.0.113.7/",
    "http://127.0.0.1%2f@203.0.113.7/", "http://127.0.0.1\\t@203.0.113.7/",
    " http://127.0.0.1/", "HTTP://LOCALHOST:11434/", "http://127.0.0.1./",
    "http://2130706433/", "http://0177.0.0.1/", "http://0x7f.1/", "http://127.1/",
    "http://[::ffff:7f00:1]/", "http://[::1%25eth0]/", "http://user:pw@127.0.0.1:11434",
    "http://localhost:11434", "http://[::1]:11434", "http://[::ffff:127.0.0.1]:1",
]  # fmt: skip


@pytest.mark.parametrize("url", TRICKY)
def test_whatever_the_gate_allows_connects_to_loopback_only(reached, url):
    # The oracle is a real request: every host requests tries to reach is
    # recorded by the socket guard, and none may be off loopback.
    from core.kernel.inference import _DIRECT

    if loopback_problem(url) is not None:
        return
    with contextlib.suppress(requests.exceptions.RequestException, ValueError):
        requests.get(url, proxies=dict(_DIRECT), allow_redirects=False, timeout=0.5)
    off = [h for h in reached if not _is_loopback(str(h))]
    assert off == []


def test_a_backslash_url_is_refused_before_any_connection(reached, caplog):
    client = OllamaInterface(base_url="http://203.0.113.7\\@127.0.0.1:11434")
    assert (
        client.available is False and "would connect to '203.0.113.7'" in client.refused
    )
    with pytest.raises(AirGapError):
        client.chat("m", [{"role": "user", "content": "SECRET PROMPT"}])
    assert reached == []


@pytest.mark.parametrize(
    "variable", ["all://127.0.0.1_proxy", "http://127.0.0.1_proxy"]
)
def test_a_proxy_named_for_the_loopback_host_is_not_used(
    reached, monkeypatch, variable
):
    server = http.server.HTTPServer(("127.0.0.1", 0), _Tags)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv(variable, "http://203.0.113.9:3128")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        client = OllamaInterface(
            base_url=f"http://127.0.0.1:{server.server_address[1]}"
        )
        assert client.available is True  # reached the server, not the proxy
        assert "203.0.113.9" not in reached
    finally:
        server.shutdown()


@pytest.mark.parametrize(
    ("url", "shown"),
    [("http://203.0.113.7:11434/x", "http://203.0.113.7:11434"), ("https://localhost/x", "https://localhost"),
     ("http://[::1]:11434", "http://[::1]:11434"), ("http://user:pw@[::1]/", "http://[::1]"),
     ("http:///nohost", "http:// with no host")],
)  # fmt: skip
def test_endpoints_are_shown_without_credentials_and_with_brackets(url, shown):
    from core.kernel.inference import _endpoint

    assert _endpoint(url) == shown


def test_a_failure_with_the_gap_off_logs_no_credentials(calls, monkeypatch, caplog):
    monkeypatch.setenv("NGARI_AIR_GAP", "0")
    client = OllamaInterface(base_url="http://user:hunter2@203.0.113.7:11434")
    assert client.available is True  # the fake engine answers the probe

    def failing(url, **kwargs):
        # what requests does: the whole URL, credentials included, in the message
        raise requests.exceptions.InvalidURL(f"Failed to parse: {url}")

    monkeypatch.setattr(inference.requests, "post", failing)
    assert client.generate("m", "p") == ""
    assert "hunter2" not in caplog.text
    assert "InvalidURL from Ollama at http://203.0.113.7:11434" in caplog.text


def test_a_refused_stream_refuses_at_the_call(calls):
    stream_call = OllamaInterface(base_url=REMOTE).chat_stream
    with pytest.raises(AirGapError):
        stream_call("m", [])  # no next() needed
    assert calls == []


def test_an_interface_gone_since_start_is_listed_not_dropped(tmp_path, net):
    plane = _plane(tmp_path)
    net.write_text(
        NET_DEV.format(rx=2000, tx=100).replace(
            " wlan0: 5 1 0 0 0 0 0 0 7 1 0 0 0 0 0 0\n", ""
        )
    )
    since = plane.export_compliance_report()["air_gap"]["since_start"]
    assert since["wlan0"] == {"gone": True}
    assert since["eth0"] == {"rx_bytes": 0, "tx_bytes": 0}


def test_a_counter_that_went_down_is_a_reset_not_a_negative(tmp_path, net):
    plane = _plane(tmp_path)  # baseline eth0: rx 2000, tx 100
    net.write_text(NET_DEV.format(rx=10, tx=600))
    eth0 = plane.export_compliance_report()["air_gap"]["since_start"]["eth0"]
    assert eth0 == {"reset": True, "rx_bytes": 10, "tx_bytes": 500}


def test_one_malformed_line_does_not_hide_the_others(tmp_path, net):
    from core.kernel import data_plane

    net.write_text(
        NET_DEV.format(rx=2000, tx=100) + "  bad0 no colon here\n  ppp0: 1 2\n"
    )
    assert set(data_plane._host_interfaces()) == {"eth0", "wlan0"}
