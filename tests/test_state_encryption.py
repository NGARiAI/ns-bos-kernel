"""NGARI_ENCRYPT_STATE: agent state (registry, tasks, messages) encrypted
under a key derived from the master key. Off by default. Once state is
encrypted it stays encrypted. State under another key, or seen without a key,
stops the start and is never touched. v0.1.0 state loads and is encrypted in
place with its exact bytes inside."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken

from core.kernel import NSBOSKernel
from core.kernel.agent_runtime import (
    AgentConfig,
    AgentRegistry,
    AgentRuntime,
    InterAgentCommunication,
    StateKeyError,
    TaskScheduler,
    encrypt_state_enabled,
    sealed_state,
)
from core.kernel.data_plane import audit_key
from core.kernel.data_plane.state import StateCipher

REPO_ROOT = Path(__file__).resolve().parent.parent
V010 = Path(__file__).parent / "vectors" / "v0.1.0"
ON = {"NGARI_ENCRYPT_STATE": "1"}
SECRETS = ("memory-in-the-clear", "task-payload-in-the-clear", "message-in-the-clear")


@pytest.fixture(autouse=True)
def setting_unset(monkeypatch):
    monkeypatch.delenv("NGARI_ENCRYPT_STATE", raising=False)


def _boot(tmp_path, monkeypatch, on=True):
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    if on:
        monkeypatch.setenv("NGARI_ENCRYPT_STATE", "1")
    else:
        monkeypatch.delenv("NGARI_ENCRYPT_STATE", raising=False)
    return NSBOSKernel()


def _fill(kernel):
    agent_id = kernel.register_agent("CEO", "strategic")
    agent = kernel.agent_runtime.registry.get_agent(agent_id)
    agent.memory["note"] = SECRETS[0]
    kernel.agent_runtime.registry.save_registry()
    task_id = kernel.create_task(agent_id, "report", {"q": SECRETS[1]})
    kernel.publish_event("orders", {"m": SECRETS[2]})
    return agent_id, task_id


def _agent_files(tmp_path):
    return {
        p.relative_to(tmp_path).as_posix(): p.read_bytes()
        for p in sorted((tmp_path / "agents").rglob("*"))
        if p.is_file()
    }


def _envelope(path):
    data = json.loads(path.read_bytes())
    assert list(data) == ["format", "key_id", "token"]
    assert data["format"] == "ngari-encrypted-v1"
    return data


def _master_key(tmp_path):
    return (tmp_path / "sovereign" / "keys" / "master.key").read_bytes()


def _entries(tmp_path, action):
    log = tmp_path / "sovereign" / "audit" / "sovereign_audit.log"
    return [
        e
        for e in (json.loads(x) for x in log.read_text().splitlines())
        if e["action"] == action
    ]


def _kernel_key_error():
    """The KeyProviderError class the kernel raises: it imports data_plane
    flat, so it is not core.kernel.data_plane's."""
    return sys.modules["data_plane"].KeyProviderError


def _install_v010(tmp_path):
    keys = tmp_path / "sovereign" / "keys"
    keys.mkdir(parents=True)
    shutil.copyfile(V010 / "master.key", keys / "master.key")
    (keys / "master.key").chmod(0o600)
    (tmp_path / "sovereign" / "encrypted").mkdir()
    shutil.copyfile(
        V010 / "greeting.enc", tmp_path / "sovereign" / "encrypted" / "greeting.enc"
    )
    shutil.copytree(V010 / "agents", tmp_path / "agents")


# -- the setting --------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", " OFF "])
def test_these_values_leave_it_off(value):
    assert encrypt_state_enabled({"NGARI_ENCRYPT_STATE": value}) is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", " On "])
def test_these_values_turn_it_on(value, caplog):
    assert encrypt_state_enabled({"NGARI_ENCRYPT_STATE": value}) is True
    assert "not a known value" not in caplog.text


def test_unset_is_off_and_a_misspelling_turns_it_on_with_a_warning(caplog):
    assert encrypt_state_enabled({}) is False
    assert encrypt_state_enabled({"NGARI_ENCRYPT_STATE": "ture"}) is True
    assert "'ture' is not a known value; agent state is encrypted" in caplog.text


# -- on -------------------------------------------------------------------------------


def test_with_the_setting_on_nothing_under_agents_is_readable(tmp_path, monkeypatch):
    kernel = _boot(tmp_path, monkeypatch)
    agent_id, task_id = _fill(kernel)
    files = _agent_files(tmp_path)
    assert not [
        name for name, raw in files.items() for s in SECRETS if s.encode() in raw
    ]
    registry = _envelope(tmp_path / "agents" / "registry" / "registry.json")
    _envelope(tmp_path / "agents" / "tasks" / "tasks.json")
    [message] = (tmp_path / "agents" / "comm").glob("orders_*")
    assert message.name.endswith(".enc.json")
    cipher = StateCipher(_master_key(tmp_path))
    assert registry["key_id"] == cipher.key_id
    assert SECRETS[0].encode() in cipher.decrypt(registry["token"])
    # The runtime reads all of it back.
    again = _boot(tmp_path, monkeypatch)
    runtime = again.agent_runtime
    assert runtime.registry.get_agent(agent_id).memory == {"note": SECRETS[0]}
    assert runtime.scheduler.tasks[task_id].payload == {"q": SECRETS[1]}
    assert runtime.comm.get_messages("orders")[0]["message"] == {"m": SECRETS[2]}
    assert again.get_status()["agents"]["state_encryption"] is True


def test_the_documented_claims_hold_with_the_setting_on(tmp_path, monkeypatch):
    # The default is plaintext; with the setting on, state is encrypted.
    kernel = _boot(tmp_path, monkeypatch)
    _fill(kernel)
    registry = (tmp_path / "agents" / "registry" / "registry.json").read_text()
    tasks = (tmp_path / "agents" / "tasks" / "tasks.json").read_text()
    messages = "".join(p.read_text() for p in (tmp_path / "agents" / "comm").iterdir())
    assert set(json.loads(registry)) == {"format", "key_id", "token"}  # agent state
    assert SECRETS[0] not in registry  # agent memory
    assert SECRETS[1] not in tasks  # task state
    assert SECRETS[2] not in messages  # inter-agent messages


def test_with_the_setting_off_state_is_plaintext(tmp_path, monkeypatch):
    kernel = _boot(tmp_path, monkeypatch, on=False)
    _fill(kernel)
    registry = json.loads(
        (tmp_path / "agents" / "registry" / "registry.json").read_text()
    )
    assert "format" not in registry and len(registry) == 1
    assert not list((tmp_path / "agents" / "comm").glob("*.enc.json"))
    assert kernel.get_status()["agents"]["state_encryption"] is False
    assert _entries(tmp_path, "state_encrypted") == []


# -- v0.1.0 state -------------------------------------------------------------------


def test_v010_state_is_encrypted_in_place_with_its_exact_bytes(
    tmp_path, monkeypatch, caplog
):
    _install_v010(tmp_path)
    original = (V010 / "agents" / "registry" / "registry.json").read_bytes()
    [old_message] = (V010 / "agents" / "comm").iterdir()
    kernel = _boot(tmp_path, monkeypatch)
    cipher = StateCipher((V010 / "master.key").read_bytes())
    sealed = _envelope(tmp_path / "agents" / "registry" / "registry.json")
    assert cipher.decrypt(sealed["token"]) == original
    [agent] = kernel.agent_runtime.registry.list_agents()
    assert agent.config.description == "v0.1.0 agent"
    assert agent.memory == {"note": "memory written by v0.1.0"}
    # The v0.1.0 task file is truncated: it is set aside with its bytes kept.
    [kept] = (tmp_path / "agents" / "tasks").glob("tasks.json.corrupt-*")
    assert kept.read_bytes() == (V010 / "agents" / "tasks" / "tasks.json").read_bytes()
    # Old messages stay where they are, readable; nothing rewrites the backlog.
    assert (
        tmp_path / "agents" / "comm" / old_message.name
    ).read_bytes() == old_message.read_bytes()
    assert kernel.agent_runtime.comm.get_messages("orders")[0]["message"] == {
        "m": "message written by v0.1.0"
    }
    [entry] = _entries(tmp_path, "state_encrypted")
    assert (entry["resource"], entry["details"]) == (
        "registry.json",
        {"bytes": len(original)},
    )
    assert "mac" in entry and kernel.data_plane.verify_audit_integrity()
    # The v0.1.0 data plane file still opens: same master key, nothing new.
    assert kernel.data_plane.retrieve_decrypted("greeting") is not None
    _boot(tmp_path, monkeypatch)
    assert len(_entries(tmp_path, "state_encrypted")) == 1  # a second start writes none


def test_a_failed_sync_while_encrypting_leaves_the_plaintext(tmp_path, monkeypatch):
    shutil.copytree(V010 / "agents" / "registry", tmp_path / "registry")
    before = (tmp_path / "registry" / "registry.json").read_bytes()

    def full(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full)
    cipher = StateCipher((V010 / "master.key").read_bytes())
    with pytest.raises(OSError):
        AgentRegistry(str(tmp_path / "registry"), cipher=cipher, encrypt=True)
    monkeypatch.undo()
    assert (tmp_path / "registry" / "registry.json").read_bytes() == before
    assert sorted(p.name for p in (tmp_path / "registry").iterdir()) == [
        "registry.json"
    ]


def test_nothing_is_written_unless_it_decrypts_back(tmp_path):
    class Broken:
        key_id = "0" * 32

        def encrypt(self, data):
            return "token"

        def decrypt(self, token):
            return b"something else"

    registry = AgentRegistry(str(tmp_path), cipher=Broken(), encrypt=True)
    with pytest.raises(RuntimeError, match="did not decrypt"):
        registry.register_agent(AgentConfig("CEO", "strategic"))
    assert list(tmp_path.iterdir()) == []


# -- once encrypted, it stays encrypted ------------------------------------------------


def test_turning_the_setting_off_does_not_decrypt_anything(
    tmp_path, monkeypatch, caplog
):
    _fill(_boot(tmp_path, monkeypatch))
    kernel = _boot(tmp_path, monkeypatch, on=False)
    assert (
        "NGARI_ENCRYPT_STATE is off, but agent state is already encrypted"
        in caplog.text
    )
    kernel.register_agent("CFO", "finance")
    kernel.create_task(kernel.register_agent("COO", "ops"), "x", {})
    kernel.publish_event("orders", {"m": 2})
    _envelope(tmp_path / "agents" / "registry" / "registry.json")
    _envelope(tmp_path / "agents" / "tasks" / "tasks.json")
    assert all(
        p.name.endswith(".enc.json") for p in (tmp_path / "agents" / "comm").iterdir()
    )
    assert kernel.get_status()["agents"]["state_encryption"] is True


# -- another key, or no key ------------------------------------------------------------


def test_another_master_key_stops_the_start_before_anything_is_written(
    tmp_path, monkeypatch
):
    _fill(_boot(tmp_path, monkeypatch))
    old_id = StateCipher(_master_key(tmp_path)).key_id
    other = Fernet.generate_key()
    (tmp_path / "sovereign" / "keys" / "master.key").write_bytes(other)
    agents = _agent_files(tmp_path)
    log = (tmp_path / "sovereign" / "audit" / "sovereign_audit.log").read_bytes()
    with pytest.raises(_kernel_key_error()) as caught:
        _boot(tmp_path, monkeypatch)
    message = str(caught.value)
    assert old_id in message and StateCipher(other).key_id in message
    assert "Refusing to start" in message
    assert _agent_files(tmp_path) == agents
    assert (
        tmp_path / "sovereign" / "audit" / "sovereign_audit.log"
    ).read_bytes() == log


def test_a_lost_master_key_is_not_replaced_over_encrypted_state(tmp_path, monkeypatch):
    _fill(_boot(tmp_path, monkeypatch))
    (tmp_path / "sovereign" / "keys" / "master.key").unlink()
    for stored in (tmp_path / "sovereign" / "encrypted").iterdir():
        stored.unlink()  # only the agent state is left to protect
    with pytest.raises(_kernel_key_error(), match="Refusing to create a new key"):
        _boot(tmp_path, monkeypatch)
    assert not (tmp_path / "sovereign" / "keys" / "master.key").exists()


def test_without_a_key_encrypted_state_is_refused_and_untouched(tmp_path, monkeypatch):
    _fill(_boot(tmp_path, monkeypatch))
    agents = _agent_files(tmp_path)
    with pytest.raises(StateKeyError, match="this runtime was given no key"):
        AgentRuntime(str(tmp_path / "agents"))
    with pytest.raises(StateKeyError, match="is encrypted"):
        AgentRegistry(str(tmp_path / "agents" / "registry"))
    with pytest.raises(StateKeyError):
        TaskScheduler(str(tmp_path / "agents" / "tasks"))
    other = StateCipher(Fernet.generate_key())
    with pytest.raises(StateKeyError, match="under another master key"):
        AgentRegistry(str(tmp_path / "agents" / "registry"), cipher=other)
    with pytest.raises(StateKeyError, match="under another master key"):
        TaskScheduler(str(tmp_path / "agents" / "tasks"), cipher=other)
    assert _agent_files(tmp_path) == agents  # nothing set aside, nothing rewritten


def test_the_kernel_command_exits_2_on_another_key(tmp_path, monkeypatch):
    _fill(_boot(tmp_path, monkeypatch))
    (tmp_path / "sovereign" / "keys" / "master.key").write_bytes(Fernet.generate_key())
    env = {**os.environ, "NGARI_DATA_DIR": str(tmp_path), "NGARI_ENCRYPT_STATE": "1"}
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel"], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    output = run.stdout + run.stderr
    assert run.returncode == 2
    assert "Cannot start: agent state was encrypted under another master key" in output
    assert "Traceback" not in output


# -- damage under this key -------------------------------------------------------------


def _sealed_registry(tmp_path):
    cipher = StateCipher(Fernet.generate_key())
    registry = AgentRegistry(str(tmp_path), cipher=cipher, encrypt=True)
    registry.register_agent(AgentConfig("CEO", "strategic"))
    return cipher, tmp_path / "registry.json"


@pytest.mark.parametrize("damage", ["token", "truncated"])
def test_damage_under_this_key_is_set_aside_like_any_damaged_file(tmp_path, damage):
    cipher, path = _sealed_registry(tmp_path)
    raw = path.read_bytes()
    damaged = (
        raw.replace(b'"token": "g', b'"token": "X') if damage == "token" else raw[:120]
    )
    assert damaged != raw
    path.write_bytes(damaged)
    registry = AgentRegistry(str(tmp_path), cipher=cipher)
    assert registry.list_agents() == []
    [kept] = tmp_path.glob("registry.json.corrupt-*")
    assert kept.read_bytes() == damaged


def test_a_truncated_file_under_another_key_is_still_refused(tmp_path):
    _, path = _sealed_registry(tmp_path)
    path.write_bytes(path.read_bytes()[:120])
    before = path.read_bytes()
    with pytest.raises(StateKeyError):
        AgentRegistry(str(tmp_path), cipher=StateCipher(Fernet.generate_key()))
    assert path.read_bytes() == before and not list(tmp_path.glob("*.corrupt-*"))


# -- messages --------------------------------------------------------------------------


def test_messages_mix_old_plaintext_and_new_encrypted_in_order(tmp_path, caplog):
    cipher = StateCipher(Fernet.generate_key())
    shutil.copytree(V010 / "agents" / "comm", tmp_path, dirs_exist_ok=True)
    bus = InterAgentCommunication(str(tmp_path), cipher=cipher, encrypt=True)
    bus.publish("orders", {"m": "new"})
    assert [m["message"]["m"] for m in bus.get_messages("orders")] == [
        "new",
        "message written by v0.1.0",
    ]
    # A bus with no key, or another key, skips what it cannot open and says so.
    for other in (None, StateCipher(Fernet.generate_key())):
        caplog.clear()
        plain = InterAgentCommunication(str(tmp_path), cipher=other)
        assert [m["message"]["m"] for m in plain.get_messages("orders")] == [
            "message written by v0.1.0"
        ]
        assert "Skipping message file 'orders_" in caplog.text
    assert len(list(tmp_path.iterdir())) == 2  # nothing removed or moved


def test_counting_encrypted_state_reads_only_heads(tmp_path, monkeypatch):
    kernel = _boot(tmp_path, monkeypatch)
    _fill(kernel)
    for n in range(5):
        kernel.publish_event("orders", {"n": n})
    found = sealed_state(tmp_path / "agents")
    assert found == {"files": 8, "key_ids": {StateCipher(_master_key(tmp_path)).key_id}}
    assert sealed_state(tmp_path / "nothing-here") == {"files": 0, "key_ids": set()}


# -- the key ---------------------------------------------------------------------------


def test_the_state_key_is_its_own_and_the_key_id_names_the_master_key():
    key, other = Fernet.generate_key(), Fernet.generate_key()
    cipher = StateCipher(key)
    assert len(cipher.key_id) == 32 and int(cipher.key_id, 16) >= 0
    assert cipher.key_id == StateCipher(key).key_id != StateCipher(other).key_id
    assert cipher.key_id != audit_key(key)[:16].hex()
    token = cipher.encrypt(b"state")
    with pytest.raises(InvalidToken):
        Fernet(key).decrypt(token)  # not the master key itself
    assert key.decode() not in repr(cipher) and cipher.key_id in repr(cipher)


def test_the_package_runtime_reads_what_the_kernel_wrote(tmp_path, monkeypatch):
    # The kernel imports agent_runtime and data_plane flat; a caller importing
    # core.kernel.* gets other classes. The envelope and cipher work across both.
    kernel = _boot(tmp_path, monkeypatch)
    agent_id, _ = _fill(kernel)
    assert type(kernel.agent_runtime).__module__ == "agent_runtime"
    cipher = StateCipher(_master_key(tmp_path))
    registry = AgentRegistry(str(tmp_path / "agents" / "registry"), cipher=cipher)
    assert registry.get_agent(agent_id).memory == {"note": SECRETS[0]}


def test_a_tpm_sealed_master_key_covers_agent_state(soft_tpm, tmp_path, monkeypatch):
    from core.kernel.data_plane.tpm import TPMKeyProvider

    monkeypatch.setenv("NGARI_KEY_PROVIDER", "tpm2")
    monkeypatch.setenv("NGARI_TPM_TCTI", soft_tpm)
    kernel = _boot(tmp_path, monkeypatch)
    agent_id, _ = _fill(kernel)
    keys = tmp_path / "sovereign" / "keys"
    assert sorted(p.name for p in keys.iterdir()) == ["master.key.sealed"]
    cipher = StateCipher(TPMKeyProvider(keys, tcti=soft_tpm).unseal())
    sealed = _envelope(tmp_path / "agents" / "registry" / "registry.json")
    assert SECRETS[0].encode() in cipher.decrypt(sealed["token"])
    again = _boot(tmp_path, monkeypatch)
    assert again.agent_runtime.registry.get_agent(agent_id).memory == {
        "note": SECRETS[0]
    }


def test_a_store_built_alone_keeps_an_encrypted_file_encrypted(tmp_path):
    cipher, path = _sealed_registry(tmp_path)
    registry = AgentRegistry(str(tmp_path), cipher=cipher)  # encryption not asked for
    registry.register_agent(AgentConfig("CFO", "finance"))
    _envelope(path)
    tasks = tmp_path / "tasks"
    TaskScheduler(str(tasks), cipher=cipher, encrypt=True).create_task("a", "x", {})
    TaskScheduler(str(tasks), cipher=cipher).create_task("a", "y", {})
    _envelope(tasks / "tasks.json")


def test_main_stops_on_a_state_key_error_with_exit_2(tmp_path, monkeypatch, caplog):
    import core.kernel as kernel_mod

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))

    def refuse():
        raise kernel_mod.StateKeyError(
            "registry.json is encrypted and this runtime was given no key"
        )

    monkeypatch.setattr(kernel_mod, "NSBOSKernel", refuse)
    with pytest.raises(SystemExit) as caught:
        kernel_mod.main([])
    assert caught.value.code == 2
    assert "Cannot start: registry.json is encrypted" in caplog.text


@pytest.mark.parametrize(
    "store",
    [AgentRegistry, TaskScheduler, InterAgentCommunication],
    ids=lambda c: c.__name__,
)
def test_encrypting_without_a_cipher_is_refused(tmp_path, store):
    with pytest.raises(ValueError, match="needs a cipher"):
        store(str(tmp_path), encrypt=True)
    assert list(tmp_path.iterdir()) == []


def test_what_stays_readable_outside_agents_is_what_the_docs_list(
    tmp_path, monkeypatch
):
    # AGENT_STATE.md says names, types, actions and topics stay readable in the
    # twin, the sync ledger and the audit log, and the rest does not. If either
    # half changes, so must the page.
    kernel = _boot(tmp_path, monkeypatch)
    agent_id = kernel.register_agent("AcquisitionScout", "mergers", "watches a target")
    kernel.create_task(agent_id, "draft-letter", {"price": "PAYLOAD-SECRET"})
    kernel.publish_event("deal-room", {"m": "BODY-SECRET"})
    readable = {
        "sync/digital_twin.json": ["AcquisitionScout", "mergers", agent_id],
        "sync/sync.log": ["agent.AcquisitionScout"],
        "sovereign/audit/sovereign_audit.log": [
            "AcquisitionScout", "mergers", "draft-letter", "deal-room",
        ],
    }  # fmt: skip
    for name, values in readable.items():
        text = (tmp_path / name).read_text()
        assert [v for v in values if v not in text] == [], name
    everything = "".join(
        p.read_text(errors="replace") for p in tmp_path.rglob("*") if p.is_file()
    )
    for secret in ("watches a target", "PAYLOAD-SECRET", "BODY-SECRET"):
        assert secret not in everything
    doc = " ".join((REPO_ROOT / "docs" / "AGENT_STATE.md").read_text().split())
    for named in (
        "sync/digital_twin.json",
        "sync/sync.log",
        "sovereign/audit/",
        "agent.<name>",
    ):
        assert named in doc


# -- an envelope another tool rewrote --------------------------------------------------

REWRITES = {
    "indented": lambda e: json.dumps(e, indent=2),
    "token first": lambda e: json.dumps(
        {"token": e["token"], "key_id": e["key_id"], "format": e["format"]}
    ),
    "compact": lambda e: json.dumps(e, separators=(",", ":")),
    "leading newline": lambda e: "\n" + json.dumps(e),
}


@pytest.mark.parametrize("rewrite", sorted(REWRITES))
def test_a_rewritten_envelope_under_another_key_still_stops_the_start(
    tmp_path, monkeypatch, rewrite
):
    _fill(_boot(tmp_path, monkeypatch))
    registry = tmp_path / "agents" / "registry" / "registry.json"
    registry.write_text(REWRITES[rewrite](json.loads(registry.read_text())))
    (tmp_path / "sovereign" / "keys" / "master.key").write_bytes(Fernet.generate_key())
    for stored in (tmp_path / "sovereign" / "encrypted").iterdir():
        stored.unlink()  # so only the agent state can show the key is wrong
    before = _agent_files(tmp_path)
    with pytest.raises(_kernel_key_error(), match="another master key"):
        _boot(tmp_path, monkeypatch, on=False)
    assert _agent_files(tmp_path) == before  # nothing set aside, nothing rewritten


@pytest.mark.parametrize("rewrite", sorted(REWRITES))
def test_a_rewritten_envelope_under_this_key_still_loads(
    tmp_path, monkeypatch, rewrite
):
    agent_id, _ = _fill(_boot(tmp_path, monkeypatch))
    registry = tmp_path / "agents" / "registry" / "registry.json"
    registry.write_text(REWRITES[rewrite](json.loads(registry.read_text())))
    kernel = _boot(tmp_path, monkeypatch, on=False)
    assert kernel.agent_runtime.registry.get_agent(agent_id).memory == {
        "note": SECRETS[0]
    }
    assert kernel.agent_runtime.state_encryption is True


def test_plaintext_that_only_mentions_the_format_stays_plaintext(tmp_path, monkeypatch):
    kernel = _boot(tmp_path, monkeypatch, on=False)
    agent_id = kernel.register_agent("CEO", "strategic")
    envelope = {"format": "ngari-encrypted-v1", "key_id": "0" * 32, "token": "x"}
    kernel.agent_runtime.registry.get_agent(agent_id).memory.update(
        blob=envelope, text="ngari-encrypted-v1"
    )
    kernel.agent_runtime.registry.save_registry()
    again = _boot(tmp_path, monkeypatch, on=False)
    assert again.agent_runtime.state_encryption is False
    assert again.agent_runtime.registry.get_agent(agent_id).memory["blob"] == envelope


def test_an_envelope_whose_key_id_cannot_be_read_is_refused_and_left(tmp_path):
    cipher, path = _sealed_registry(tmp_path)
    envelope = json.loads(path.read_text())
    envelope["key_id"] = 12345
    path.write_text(json.dumps(envelope))
    before = path.read_bytes()
    with pytest.raises(StateKeyError, match="key id unreadable"):
        AgentRegistry(str(tmp_path), cipher=cipher)
    assert path.read_bytes() == before and not list(tmp_path.glob("*.corrupt-*"))
