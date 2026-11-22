"""SECURITY.md against the code: one test, or more, for each claim that can
be checked, so the page cannot drift from the kernel."""

import ast
import itertools
import json
import re
from pathlib import Path

import pytest
import requests
from cryptography.fernet import Fernet

from core.kernel.data_plane import SovereignDataPlane

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "core" / "kernel"
SOURCES = sorted(
    p for p in KERNEL.rglob("*.py") if "build" not in p.parts and "tests" not in p.parts
)


def _source(path=None) -> str:
    return "\n".join(p.read_text() for p in ([path] if path else SOURCES))


def _calls(name_test):
    found = []
    for path in SOURCES:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and name_test(node.func):
                found.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    return found


DOC = " ".join((ROOT / "SECURITY.md").read_text().split())
# The claims the tests below check, as the page words them.
CLAIMS = [
    "No external telemetry",
    "encrypted at rest (AES-128-CBC + HMAC-SHA256 via Fernet)",
    "Keyed, hash-chained audit logging",
    "Role-based access control for operators",
    "interface counters measured from `/proc/net/dev`",
    "pinned to exact versions with sha256 hashes",
    "every subprocess call passes an argument list",
    "No eval/exec of caller-provided code outside the sandbox",
    "running as `nobody` (uid 65534)",
    "inference clients default to loopback addresses",
    "never auto-loads models",
    "each entry holds the SHA-256 of the previous one",
    "PII redaction by pattern",
    "kept 21 years by default",
    "The kernel listens on no network port",
    "No external DNS resolution in air-gap mode",
    "SBOM generated at build time (SPDX 2.3)",
    "gitleaks pre-commit hook",
]


@pytest.mark.parametrize("claim", CLAIMS)
def test_the_page_makes_each_claim_tested_here(claim):
    assert claim in DOC


# -- Security Properties ---------------------------------------------------------------


def test_external_telemetry_flag_is_switched_off(tmp_path):
    (tmp_path / "telemetry_config.json").write_text('{"external_telemetry": true}')
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    config = json.loads((tmp_path / "telemetry_config.json").read_text())
    assert config["external_telemetry"] is False
    assert plane.export_compliance_report()["external_telemetry"] is False


def test_only_the_inference_clients_import_an_http_library():
    importers = set()
    for path in SOURCES:
        for node in ast.walk(ast.parse(path.read_text())):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(
                n.split(".")[0]
                in ("requests", "urllib", "http", "socket", "httpx", "aiohttp")
                for n in names
            ):
                importers.add(str(path.relative_to(KERNEL)))
    assert importers == {"inference/__init__.py"}


def test_data_at_rest_is_a_fernet_token(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    path = Path(plane.store_encrypted("note", {"secret": "sovereign-plaintext"}))
    raw = path.read_bytes()
    assert b"sovereign-plaintext" not in raw
    assert raw.startswith(b"gAAAAA")  # Fernet version byte 0x80, base64
    assert plane.fernet.decrypt(raw)


def test_each_audit_entry_holds_the_previous_hash(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    for i in range(3):
        plane.store_encrypted(f"k{i}", i)
    entries = plane.get_audit_log(limit=100)
    for before, after in itertools.pairwise(entries):
        assert after["prev_hash"] == before["hash"]
        assert re.fullmatch(r"[0-9a-f]{64}", after["prev_hash"])


def test_operator_roles_gate_the_commands_the_page_names():
    from core.kernel.data_plane.operator_auth import OperatorAuthError
    from core.kernel.data_plane.roles import COMMAND_ROLES, ROLES, authorize

    assert set(ROLES) == {"admin", "author", "reviewer", "approver", "sponsor"}
    assert all(f"`{role}`" in DOC for role in ROLES)
    assert set(COMMAND_ROLES.values()) <= set(ROLES)
    operator = {"user": "jdoe", "fingerprint": "0" * 64}
    assert authorize({"jdoe": ["admin"]}, operator, "keys migrate") == "admin"
    with pytest.raises(OperatorAuthError, match="role"):
        authorize({"jdoe": ["author"]}, operator, "keys migrate")


NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 99999 10 0 0 0 0 0 0 99999 10 0 0 0 0 0 0
  eth0: 2000 20 0 0 0 0 0 0 {tx} 15 0 0 0 0 0 0
"""


def test_air_gap_is_measured_from_proc_net_dev(tmp_path, monkeypatch):
    # The report holds interface counters read from /proc/net/dev at call time
    # and what they moved by since start. It measures; nothing is "verified".
    from core.kernel import data_plane

    dev = tmp_path / "dev"
    dev.write_text(NET_DEV.format(tx=100))
    monkeypatch.setattr(data_plane, "PROC_NET_DEV", dev)
    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    dev.write_text(NET_DEV.format(tx=1600))
    section = plane.export_compliance_report()["air_gap"]
    assert section["since_start"] == {"eth0": {"rx_bytes": 0, "tx_bytes": 1500}}
    assert "/proc/net/dev" in _source()


# -- Code Level ------------------------------------------------------------------------


def test_runtime_dependencies_are_pinned_with_hashes():
    lock = (KERNEL / "requirements.txt").read_text()
    blocks = re.split(r"\n(?=[A-Za-z0-9])", lock.split("\n", 1)[1])
    packages = [b for b in blocks if re.match(r"[A-Za-z0-9]", b)]
    assert packages
    for block in packages:
        assert re.match(r"[A-Za-z0-9_.\-\[\]]+==\S+", block), block.splitlines()[0]
        assert "--hash=sha256:" in block, block.splitlines()[0]


def test_no_shell_anywhere():
    shells = _calls(
        lambda f: (
            isinstance(f, ast.Attribute)
            and f.attr in ("system", "popen")
            and isinstance(f.value, ast.Name)
            and f.value.id == "os"
        )
    )
    assert shells == []
    for path in SOURCES:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert not (
                    isinstance(node.value, ast.Constant) and node.value.value
                ), path


def test_subprocess_commands_are_argument_lists():
    """Every subprocess call passes a list literal or a variable built as a
    list, so no string is ever parsed by a shell. Which commands may run is
    not centrally allow-listed."""
    bad = []
    for path in SOURCES:
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr
                in ("run", "Popen", "call", "check_output", "check_call")
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.args
                and not isinstance(node.args[0], (ast.List, ast.Name))
            ):
                bad.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert bad == []


def test_no_eval_or_exec_outside_the_sandbox_strings():
    assert _calls(lambda f: isinstance(f, ast.Name) and f.id in ("eval", "exec")) == []


# -- Sandbox Level ---------------------------------------------------------------------


def _profiles():
    from core.kernel.sandbox.seccomp import (
        DANGEROUS_SYSCALLS,
        NETWORK_SYSCALLS,
        PROCESS_SYSCALLS,
    )

    return (
        set(DANGEROUS_SYSCALLS),
        set(DANGEROUS_SYSCALLS + NETWORK_SYSCALLS + PROCESS_SYSCALLS),
    )


def test_the_profiles_block_the_documented_number_of_system_calls():
    restricted, strict = _profiles()
    assert f"block {len(restricted)} system calls (`restricted`, the default)" in DOC
    assert f"or {len(strict)} including network and process creation (`strict`)" in DOC
    threat_model = " ".join((ROOT / "THREAT_MODEL.md").read_text().split())
    assert f"{len(restricted)} system calls refused by `restricted`" in threat_model
    assert f"{len(strict)} by `strict`" in threat_model


def test_import_blocklist_timeout_and_output_cap():
    from core.kernel.sandbox import bwrap

    assert {"subprocess", "multiprocessing", "ctypes", "pickle", "fcntl", "shelve",
            "crypt", "cffi"} <= bwrap.BLOCKED_MODULES  # fmt: skip
    assert bwrap.DEFAULT_TIMEOUT == 30
    assert bwrap.MAX_OUTPUT == 10_000


def test_sandbox_runs_as_nobody_with_no_network():
    from core.kernel.sandbox.bwrap import _build_bwrap_args

    args = _build_bwrap_args()
    assert args[args.index("--uid") + 1] == "65534"
    assert args[args.index("--gid") + 1] == "65534"
    for flag in ("--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc",
                 "--unshare-uts"):  # fmt: skip
        assert flag in args
    assert "--bind" not in args  # only read-only binds and tmpfs


# -- Inference -------------------------------------------------------------------------


def test_inference_clients_default_to_loopback(monkeypatch):
    from core.kernel import inference

    monkeypatch.setattr(inference.requests, "get", _refuse)
    for cls in (inference.OllamaInterface, inference.LlamaCppInterface,
                inference.VLLMInterface):  # fmt: skip
        client = cls()
        url = getattr(client, "base_url", None) or client.server_url
        assert re.match(r"http://(localhost|127\.0\.0\.1):\d+$", url), url


def _refuse(*args, **kwargs):
    raise requests.ConnectionError("no network in tests")


def test_a_remote_inference_url_is_refused(monkeypatch):
    from core.kernel import inference

    monkeypatch.delenv("NGARI_AIR_GAP", raising=False)
    calls = []
    monkeypatch.setattr(
        inference.requests, "get", lambda url, **k: calls.append(url) or _refuse()
    )
    inference.OllamaInterface(base_url="http://203.0.113.7:11434")
    assert calls == []


def test_the_manager_never_loads_or_pulls_a_model(monkeypatch):
    from core.kernel import inference

    posted = []

    class Tags:
        status_code = 200

        @staticmethod
        def json():
            return {"models": [{"name": "m:latest", "size": 1, "details": {}}]}

    monkeypatch.setattr(inference.requests, "get", lambda *a, **k: Tags())
    monkeypatch.setattr(inference.requests, "post", lambda url, **k: posted.append(url))
    monkeypatch.setattr(
        inference.requests, "delete", lambda url, **k: posted.append(url)
    )
    inference.InferenceEngineManager()
    assert posted == []


# -- Data and Network Level ------------------------------------------------------------


def test_pii_redaction(tmp_path):
    # Email, phone, SSN, card and street address, by pattern, in every audit
    # entry and in the kernel's log lines (tests/test_redact.py for the rest).
    from core.kernel.data_plane.redact import redact

    text = "a@b.co (415) 555-0132 123-45-6789 4111 1111 1111 1111 10 Downing St"
    assert redact(text) == "[email] [phone] [ssn] [card] [address]"
    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    plane.store_encrypted("a@b.co", {"v": 1})
    assert "a@b.co" not in plane.audit_log.read_text()


def test_data_retention(tmp_path):
    # Configurable (NGARI_RETENTION_DAYS, 21 years by default and at the least)
    # and automated (at start and daily): a message older than it is removed.
    from datetime import datetime, timezone

    from core.kernel.agent_runtime import (
        RETENTION_FLOOR_DAYS,
        InterAgentCommunication,
        retention_days,
    )

    assert retention_days({"NGARI_RETENTION_DAYS": "9000"}) == 9000
    assert retention_days({}) == RETENTION_FLOOR_DAYS
    bus = InterAgentCommunication(str(tmp_path))
    old = tmp_path / "orders_20500101_000000_000000_0a0b0c0d.json"
    old.write_text('{"topic": "orders"}')
    (tmp_path / "orders_20750601_000000_000000_0a0b0c0e.json").write_text(
        '{"topic": "orders"}'
    )
    bus.expire(RETENTION_FLOOR_DAYS, now=datetime(2075, 6, 1, 1, tzinfo=timezone.utc))
    assert not old.exists()
    assert len(bus.get_messages("orders")) == 1


def test_the_kernel_offers_no_network_service():
    # No listening socket, so no CORS policy, API tokens or peer discovery.
    assert not re.search(
        r"cors|Access-Control-Allow-Origin|def (verify|issue|create)_token|mdns|zeroconf",
        _source(), re.IGNORECASE,
    )  # fmt: skip
    for path in SOURCES:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in ("listen", "serve_forever"), path


def test_air_gap_blocks_dns(monkeypatch):
    # A name that is not a loopback literal is refused before any lookup or call.
    import socket

    from core.kernel import inference

    monkeypatch.delenv("NGARI_AIR_GAP", raising=False)
    lookups, calls = [], []

    def lookup(host, *args, **kwargs):
        lookups.append(host)
        raise OSError("no lookups in this test")

    def get(url, **kwargs):
        calls.append(url)
        raise OSError("no calls in this test")

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    monkeypatch.setattr(inference.requests, "get", get)
    client = inference.OllamaInterface(base_url="http://inference.example.com:11434")
    assert (client.available, lookups, calls) == (False, [], [])
    assert "NGARI_AIR_GAP" in _source()


# -- Build Level -----------------------------------------------------------------------


def test_sbom_is_spdx_2_3():
    sboms = list((ROOT / "sbom").glob("*.spdx.json"))
    assert sboms
    for path in sboms:
        assert json.loads(path.read_text())["spdxVersion"] == "SPDX-2.3"


def test_gitleaks_runs_before_every_commit():
    config = (ROOT / ".pre-commit-config.yaml").read_text()
    assert "gitleaks/gitleaks" in config
    assert re.search(r"id:\s*gitleaks\b", config)


def test_fernet_tokens_from_another_key_do_not_open(tmp_path):
    plane = SovereignDataPlane(data_dir=str(tmp_path))
    foreign = Fernet(Fernet.generate_key()).encrypt(b'{"x": 1}')
    (plane.encrypted_dir / "foreign.enc").write_bytes(foreign)
    assert plane.retrieve_decrypted("foreign") is None
