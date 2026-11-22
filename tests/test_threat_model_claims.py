"""THREAT_MODEL.md and README.md against the code. Each claim is found by a
quoted phrase, and the first test checks that each phrase is still in its
document, so rewording one fails that test and the claim is checked again."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "core" / "kernel"
THREAT = (ROOT / "THREAT_MODEL.md").read_text()
README = (ROOT / "README.md").read_text()

QUOTED = {
    "THREAT_MODEL.md": [
        "| Agent registry, tasks and messages | Medium | `agents/`, plaintext by default; encrypted with `NGARI_ENCRYPT_STATE=1` |",
        "| Audit log | High | `sovereign/audit/`, plaintext, hash-chained and keyed |",
        "The sync ledger is\n  hash-chained, and a digital twin that fails its checksum is not loaded.",
        "in air-gap mode the inference clients reach loopback only",
        "`keys/master.key` (file provider) or sealed to the TPM in `keys/master.key.sealed`",
        "`scripts/sbom.py --verify-requirements`\n  fails CI",
        "CI runs `pip-audit` and `bandit`",
        "**Verification**: `tests/test_sandbox.py`",
        "The kernel does not yet refuse an agent without a manifest",
    ],
    "README.md": [
        "**Auditable**: every kernel action is recorded in a keyed, hash-chained audit log",
        "**Accountable**: operators are named people with PIV/CAC cards and roles",
        "Requires **Linux** and **Python >= 3.10**",
    ],
}


def _source() -> str:
    return "\n".join(
        p.read_text() for p in KERNEL.rglob("*.py") if "build" not in p.parts
    )


def test_every_quoted_claim_is_still_in_its_document():
    docs = {"THREAT_MODEL.md": THREAT, "README.md": README}
    missing = [
        (doc, q) for doc, quotes in QUOTED.items() for q in quotes if q not in docs[doc]
    ]
    assert missing == []


def test_every_document_in_docs_is_listed_in_the_readme_and_every_listed_one_exists():
    listed = re.findall(
        r"^\| `([^`]+)` \|", README.split("## Documentation", 1)[1], re.MULTILINE
    )
    assert all((ROOT / name).exists() for name in listed), listed
    on_disk = {f"docs/{p.name}" for p in (ROOT / "docs").glob("*.md")}
    assert on_disk <= set(listed)


# -- claims that hold --------------------------------------------------------------


def test_the_master_key_files_are_where_the_assets_table_says(tmp_path):
    from core.kernel.data_plane import SovereignDataPlane, tpm

    SovereignDataPlane(str(tmp_path))
    assert (tmp_path / "keys" / "master.key").is_file()
    assert tpm.SEALED_NAME == "master.key.sealed"


def test_the_supply_chain_checks_t6_names_run_in_ci():
    makefile = (ROOT / "Makefile").read_text()
    ci_targets = re.search(r"^ci: (.*?) ##", makefile, re.MULTILINE).group(1).split()
    assert {"sbom-check", "audit", "bandit"} <= set(ci_targets)
    assert "scripts/sbom.py --verify-requirements" in makefile
    assert "-m pip_audit -r $(RUNTIME_LOCK)" in makefile
    assert (ROOT / "tests" / "test_sbom.py").is_file()
    assert (ROOT / "tests" / "test_sandbox.py").is_file()


def test_the_python_floor_matches_the_package():
    setup = (KERNEL / "setup.py").read_text()
    assert 'python_requires=">=3.10"' in setup


# -- claims about state at rest, the ledger, air-gap mode and the audit log ----------


def test_agent_memory_is_plaintext_by_default_as_the_assets_table_says(tmp_path):
    from core.kernel.agent_runtime import AgentConfig, AgentRuntime

    runtime = AgentRuntime(str(tmp_path))
    agent_id = runtime.register_agent(AgentConfig("CEO", "core"))
    runtime.registry.get_agent(agent_id).memory["note"] = "memory-in-the-clear"
    runtime.registry.save_registry()
    assert (
        "memory-in-the-clear" in (tmp_path / "registry" / "registry.json").read_text()
    )


def test_inter_agent_messages_are_plaintext_by_default_as_the_assets_table_says(
    tmp_path,
):
    from core.kernel.agent_runtime import InterAgentCommunication

    bus = InterAgentCommunication(str(tmp_path))
    bus.publish("orders", {"secret": "message-in-the-clear"})
    stored = "".join(p.read_text() for p in tmp_path.glob("orders_*.json"))
    assert "message-in-the-clear" in stored


def test_the_sync_ledger_is_hash_chained(tmp_path):
    from core.kernel.network_sync import NetworkSynchronization

    sync = NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.a", 1)
    sync.update_twin("pref.b", 2)
    entries = [
        json.loads(line) for line in (tmp_path / "sync.log").read_text().splitlines()
    ]
    assert all("prev_hash" in entry for entry in entries)


def test_a_twin_that_fails_its_checksum_is_not_loaded(tmp_path):
    from core.kernel.network_sync import NetworkSynchronization

    sync = NetworkSynchronization(str(tmp_path))
    sync.update_twin("pref.theme", "kemet")
    twin = json.loads((tmp_path / "digital_twin.json").read_text())
    twin["preferences"]["theme"] = "edited"
    (tmp_path / "digital_twin.json").write_text(json.dumps(twin))
    assert (
        NetworkSynchronization(str(tmp_path)).get_twin_value("pref.theme") != "edited"
    )


def test_there_is_an_air_gap_mode(monkeypatch):
    from core.kernel import inference

    monkeypatch.delenv("NGARI_AIR_GAP", raising=False)
    calls = []
    monkeypatch.setattr(inference.requests, "get", lambda url, **k: calls.append(url))
    client = inference.OllamaInterface(base_url="http://203.0.113.7:11434")
    assert (client.available, calls) == (False, [])
    assert "NGARI_AIR_GAP" in _source()


def test_every_kernel_action_is_audited(tmp_path):
    from core.kernel import NSBOSKernel

    kernel = NSBOSKernel(str(tmp_path))
    log = tmp_path / "sovereign" / "audit" / "sovereign_audit.log"
    before = len(log.read_text().splitlines())
    agent_id = kernel.register_agent("CEO", "core")
    kernel.create_task(agent_id, "report", {})
    kernel.publish_event("orders", {"n": 1})
    assert len(log.read_text().splitlines()) >= before + 3
