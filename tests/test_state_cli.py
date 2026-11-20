"""ns-bos state status, encrypt and decrypt: a round trip leaves agents/
byte for byte as it was, nothing changes under another key or while a kernel
runs, decrypt goes through the operator gate, and a run cut short is
finished by running it again."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from core.kernel import NSBOSKernel, state_cli
from core.kernel.agent_runtime import InterAgentCommunication
from core.kernel.data_plane.state import StateCipher

REPO_ROOT = Path(__file__).resolve().parent.parent
V010 = Path(__file__).parent / "vectors" / "v0.1.0"


@pytest.fixture(autouse=True)
def setting_unset(monkeypatch):
    monkeypatch.delenv("NGARI_ENCRYPT_STATE", raising=False)
    monkeypatch.delenv("NGARI_OPERATOR_AUTH", raising=False)


@pytest.fixture
def data(tmp_path, monkeypatch):
    """A booted kernel's data directory with plaintext state: an agent, a
    task, three messages and one v0.1.0 message."""
    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    agent_id = kernel.register_agent("CEO", "strategic")
    kernel.create_task(agent_id, "report", {"q": "payload"})
    for n in range(3):
        kernel.publish_event("orders", {"n": n})
    shutil.copytree(
        V010 / "agents" / "comm", tmp_path / "agents" / "comm", dirs_exist_ok=True
    )
    return tmp_path


def _env(data, **extra):
    return {"NGARI_DATA_DIR": str(data), **extra}


def _snapshot(data):
    agents = data / "agents"
    return {
        p.relative_to(agents).as_posix(): p.read_bytes()
        for p in sorted(agents.rglob("*"))
        if p.is_file()
    }


def _run(data, *args, **extra):
    return state_cli.cli(list(args), _env(data, **extra))


def _entries(data, *actions):
    log = data / "sovereign" / "audit" / "sovereign_audit.log"
    entries = [json.loads(x) for x in log.read_text().splitlines()]
    return [e for e in entries if e["action"] in actions]


def _messages(data):
    bus = InterAgentCommunication(
        str(data / "agents" / "comm"),
        cipher=StateCipher((data / "sovereign" / "keys" / "master.key").read_bytes()),
    )
    return [m["message"] for m in bus.get_messages("orders", limit=100)]


# -- status ----------------------------------------------------------------------------


def test_status_reads_no_key_and_lists_set_aside_plaintext(data, capsys):
    (data / "sovereign" / "keys" / "master.key").unlink()  # it never needs it
    (data / "agents" / "tasks" / "tasks.json.corrupt-20261030T000000Z").write_text("{")
    assert _run(data, "status") == 0
    report = json.loads(capsys.readouterr().out)
    assert report == {
        "setting": False,
        "encrypted": False,
        "registry": "plaintext",
        "tasks": "plaintext",
        "messages": {"plaintext": 4, "encrypted": 0},
        "key_ids": [],
        "set_aside": ["tasks/tasks.json.corrupt-20261030T000000Z"],
        "temp_files": [],
    }


# -- encrypt and decrypt ---------------------------------------------------------------


def test_a_round_trip_leaves_agent_state_byte_for_byte(data, capsys):
    before = _snapshot(data)
    messages = _messages(data)
    assert _run(data, "encrypt") == 0
    out = capsys.readouterr().out
    assert "comm/: 4 messages encrypted" in out
    assert "NGARI_ENCRYPT_STATE is off; agent state stays encrypted anyway" in out
    encrypted = _snapshot(data)
    assert sorted(encrypted) == sorted(
        n if not n.startswith("comm/") else n[:-5] + ".enc.json" for n in before
    )
    assert not [
        n for n, raw in encrypted.items() if b"payload" in raw or b'"n": 1' in raw
    ]
    assert _messages(data) == messages
    assert _run(data, "decrypt") == 0
    assert _snapshot(data) == before
    [*per_file, comm] = _entries(data, "state_encrypted")
    assert sorted(e["resource"] for e in per_file) == ["registry.json", "tasks.json"]
    assert (comm["resource"], comm["details"], comm["actor"]) == (
        "comm",
        {"messages": 4},
        "local",
    )
    decrypted = _entries(data, "state_decrypted")
    assert [e["resource"] for e in decrypted] == ["tasks.json", "registry.json", "comm"]
    assert all("mac" in e for e in per_file + decrypted)


def test_after_encrypt_the_kernel_keeps_it_encrypted_and_after_decrypt_it_does_not(
    data, monkeypatch
):
    assert _run(data, "encrypt") == 0
    kernel = NSBOSKernel()
    assert kernel.get_status()["agents"]["state_encryption"] is True
    assert kernel.data_plane.verify_audit_integrity()
    del kernel
    assert _run(data, "decrypt") == 0
    assert NSBOSKernel().get_status()["agents"]["state_encryption"] is False


def test_a_second_run_has_nothing_to_do(data, capsys):
    assert _run(data, "encrypt") == 0
    capsys.readouterr()
    count = len(_entries(data, "state_encrypted"))
    assert _run(data, "encrypt") == 0
    out = capsys.readouterr().out
    assert (
        "registry.json: already encrypted" in out
        and "comm/: 0 messages encrypted" in out
    )
    assert len(_entries(data, "state_encrypted")) == count


def test_decrypt_with_the_setting_on_says_the_next_start_encrypts_again(data, capsys):
    assert _run(data, "encrypt") == 0
    assert _run(data, "decrypt", NGARI_ENCRYPT_STATE="1") == 0
    assert "the next start encrypts it again; unset it first" in capsys.readouterr().out


def test_many_messages_go_in_batches(data, monkeypatch):
    monkeypatch.setattr(state_cli, "BATCH", 3)
    bus = InterAgentCommunication(str(data / "agents" / "comm"))
    for n in range(3, 11):
        bus.publish("orders", {"n": n})
    synced = []
    real = state_cli._sync_dir
    monkeypatch.setattr(state_cli, "_sync_dir", lambda p: synced.append(p) or real(p))
    assert _run(data, "encrypt") == 0
    assert len(synced) == 2 * 4  # 12 messages: four batches, two syncs each
    names = [p.name for p in (data / "agents" / "comm").iterdir()]
    assert len(names) == 12 and all(n.endswith(".enc.json") for n in names)


# -- refusals --------------------------------------------------------------------------


def test_nothing_changes_while_a_kernel_holds_the_directory(data, capsys):
    from core.kernel import _hold_instance_lock

    held = _hold_instance_lock(data)
    try:
        before = _snapshot(data)
        assert state_cli.cli(["encrypt"], _env(data)) == 1
        assert "a kernel is running on" in capsys.readouterr().err
        assert _snapshot(data) == before
    finally:
        held.close()


def test_nothing_changes_under_another_master_key(data, capsys):
    assert _run(data, "encrypt") == 0
    old_id = StateCipher(
        (data / "sovereign" / "keys" / "master.key").read_bytes()
    ).key_id
    other = Fernet.generate_key()
    (data / "sovereign" / "keys" / "master.key").write_bytes(other)
    for stored in (data / "sovereign" / "encrypted").iterdir():
        stored.unlink()  # so the key itself is accepted; only the state differs
    before = _snapshot(data)
    for command in ("decrypt", "encrypt"):
        capsys.readouterr()
        assert _run(data, command) == 1
        err = capsys.readouterr().err
        assert "belong to another master key" in err and old_id in err
        assert StateCipher(other).key_id in err and "Nothing was changed" in err
    assert _snapshot(data) == before


def test_decrypt_goes_through_the_operator_gate(data, soft_card, capsys):
    from cryptography.hazmat.primitives import hashes

    assert _run(data, "encrypt") == 0
    cert = soft_card.issue()
    ops = data / "sovereign" / "operators"
    ops.mkdir()
    (ops / "operator.pem").write_bytes(soft_card.pem())
    env = {
        "NGARI_OPERATOR_AUTH": "card",
        "NGARI_PKCS11_MODULE": soft_card.module,
        "NGARI_PKCS11_TOKEN": soft_card.token,
    }
    wrong = data / "wrong-pin"
    wrong.write_text("999999")
    before = _snapshot(data)
    assert _run(data, "decrypt", "--pin-file", str(wrong), **env) == 1
    assert _snapshot(data) == before
    [refused] = _entries(data, "operator_auth")
    assert (refused["resource"], refused["details"]) == (
        "state decrypt",
        {"ok": False, "reason": "pin"},
    )
    pin = data / "pin"
    pin.write_text("123456\n")
    assert _run(data, "decrypt", "--pin-file", str(pin), **env) == 0
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    assert "operator: Test Operator" in capsys.readouterr().out
    assert {e["actor"] for e in _entries(data, "state_decrypted")} == {fingerprint}
    # encrypt is not gated: it only adds protection
    assert _run(data, "encrypt", **env) == 0


def test_decrypt_by_a_named_operator_records_the_user(data, soft_card, capsys):
    from cryptography.hazmat.primitives import hashes

    from core.kernel.data_plane.operator_auth import identity_bytes

    assert _run(data, "encrypt") == 0
    cert = soft_card.issue()
    ops = data / "sovereign" / "operators"
    ops.mkdir()
    (ops / "operator.pem").write_bytes(soft_card.pem())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", fingerprint))
    pin = data / "pin"
    pin.write_text("123456")
    env = {
        "NGARI_OPERATOR_AUTH": "card",
        "NGARI_PKCS11_MODULE": soft_card.module,
        "NGARI_PKCS11_TOKEN": soft_card.token,
    }
    assert _run(data, "decrypt", "--pin-file", str(pin), **env) == 0
    assert "operator: Jane Doe (jdoe, certificate" in capsys.readouterr().out
    [auth] = _entries(data, "operator_auth")
    assert (auth["actor"], auth["details"]["name"]) == ("jdoe", "Jane Doe")
    assert {e["actor"] for e in _entries(data, "state_decrypted")} == {"jdoe"}


def test_decrypt_needs_the_admin_role_once_roles_are_set(data, soft_card, capsys):
    from cryptography.hazmat.primitives import hashes

    from core.kernel.data_plane.operator_auth import identity_bytes
    from core.kernel.data_plane.roles import roles_bytes

    assert _run(data, "encrypt") == 0
    cert = soft_card.issue()
    store = data / "sovereign"
    ops = store / "operators"
    ops.mkdir()
    (ops / "jdoe.pem").write_bytes(soft_card.pem())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    (ops / "jdoe.json").write_bytes(identity_bytes("jdoe", "Jane Doe", fingerprint))
    (store / "roles.json").write_bytes(roles_bytes({"jdoe": ["reviewer"]}))
    pin = data / "pin"
    pin.write_text("123456")
    before = _snapshot(data)
    # With roles set, the gate cannot be off.
    assert _run(data, "decrypt") == 1
    assert "needs NGARI_OPERATOR_AUTH=card" in capsys.readouterr().err
    env = {
        "NGARI_OPERATOR_AUTH": "card",
        "NGARI_PKCS11_MODULE": soft_card.module,
        "NGARI_PKCS11_TOKEN": soft_card.token,
    }
    assert _run(data, "decrypt", "--pin-file", str(pin), **env) == 1
    assert "does not hold the admin role that state decrypt needs" in (
        capsys.readouterr().err
    )
    assert _snapshot(data) == before
    [refused] = _entries(data, "operator_auth")
    assert (refused["actor"], refused["details"]) == (
        "jdoe",
        {"ok": False, "reason": "role"},
    )


# -- a run cut short, and damaged files ------------------------------------------------


def test_a_failed_copy_is_named_and_the_others_go_on(data, monkeypatch, capsys):
    messages = _messages(data)
    copies = []
    real = os.fsync

    def failing(fd):
        target = os.readlink(f"/proc/self/fd/{fd}")
        if target.endswith(".tmp") and "/comm/" in target:
            copies.append(target)
            if len(copies) == 2:  # the second message copy
                raise OSError(28, "No space left on device")
        return real(fd)

    monkeypatch.setattr(os, "fsync", failing)
    assert _run(data, "encrypt") == 1
    monkeypatch.undo()
    comm = data / "agents" / "comm"
    assert len(copies) == 4  # every message was tried once
    assert "could not be written (No space left on device" in capsys.readouterr().err
    assert len(list(comm.glob("*.enc.json"))) == 3
    assert len([p for p in comm.iterdir() if not p.name.endswith(".enc.json")]) == 1
    assert not list(comm.glob(".*.tmp"))
    assert _messages(data) == messages  # every message readable, once
    [entry] = [e for e in _entries(data, "state_encrypted") if e["resource"] == "comm"]
    assert entry["details"] == {"messages": 3}  # what was done, not what was tried
    assert _run(data, "encrypt") == 0  # the next run finishes the job
    assert _messages(data) == messages


def test_a_failed_directory_sync_removes_no_plaintext(data, monkeypatch):
    messages = _messages(data)

    def failing(path):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(state_cli, "_sync_dir", failing)
    assert _run(data, "encrypt") == 1
    monkeypatch.undo()
    comm = data / "agents" / "comm"
    assert len([p for p in comm.iterdir() if not p.name.endswith(".enc.json")]) == 4
    assert _messages(data) == messages
    assert _run(data, "encrypt") == 0
    assert _messages(data) == messages


def test_a_copy_left_by_an_interrupted_run_is_reused_and_read_once(data, capsys):
    cipher = StateCipher((data / "sovereign" / "keys" / "master.key").read_bytes())
    comm = data / "agents" / "comm"
    plain = min(comm.glob("orders_*.json"))
    from core.kernel.agent_runtime import _seal

    copy = comm / f"{plain.name[:-5]}.enc.json"
    copy.write_bytes(_seal(plain.read_bytes(), cipher))  # killed before the unlink
    assert len(_messages(data)) == 4  # not 5: the reader takes one of the two
    assert _run(data, "encrypt") == 0
    assert not plain.exists() and len(_messages(data)) == 4


def test_a_copy_with_other_content_stops_that_message_only(data, capsys):
    cipher = StateCipher((data / "sovereign" / "keys" / "master.key").read_bytes())
    comm = data / "agents" / "comm"
    plain = min(comm.glob("orders_*.json"))
    from core.kernel.agent_runtime import _seal

    copy = comm / f"{plain.name[:-5]}.enc.json"
    copy.write_bytes(_seal(b'{"topic": "orders", "message": {"n": 99}}', cipher))
    assert _run(data, "encrypt") == 1
    assert "exists with other content; both left as they are" in capsys.readouterr().err
    assert plain.exists() and copy.exists()
    assert len(list(comm.glob("*.enc.json"))) == 4  # the other three were done


def test_a_damaged_encrypted_message_is_left_and_reported(data, capsys):
    assert _run(data, "encrypt") == 0
    comm = data / "agents" / "comm"
    damaged = min(comm.glob("*.enc.json"))
    raw = damaged.read_bytes().replace(b'"token": "g', b'"token": "X')
    damaged.write_bytes(raw)
    assert _run(data, "decrypt") == 1
    err = capsys.readouterr().err
    assert f"comm/{damaged.name}: cannot be read (ValueError); left as is" in err
    assert damaged.read_bytes() == raw
    assert len(list(comm.glob("*.enc.json"))) == 1


def test_an_unreadable_registry_is_left_for_the_kernel_to_set_aside(data, capsys):
    registry = data / "agents" / "registry" / "registry.json"
    registry.write_bytes(b"{cut sh")
    assert _run(data, "encrypt") == 1
    assert (
        "registry.json: cannot be read (JSONDecodeError); left as is"
        in capsys.readouterr().err
    )
    assert registry.read_bytes() == b"{cut sh"
    assert (
        (data / "agents" / "tasks" / "tasks.json").read_bytes().startswith(b'{"format"')
    )


# -- the command -----------------------------------------------------------------------


def test_the_kernel_command_runs_state(data):
    env = {**os.environ, "NGARI_DATA_DIR": str(data)}
    env.pop("NGARI_ENCRYPT_STATE", None)

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "core.kernel", "state", *args], cwd=REPO_ROOT,
            env=env, capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip

    done = run("encrypt")
    assert done.returncode == 0, done.stderr
    assert json.loads(run("status").stdout)["encrypted"] is True
    assert run("decrypt").returncode == 0
    assert "Traceback" not in done.stdout + done.stderr


# -- edge cases -----------------------------------------------------------------------


def test_status_of_a_directory_with_no_agent_state(tmp_path, capsys):
    assert state_cli.cli(["status"], {"NGARI_DATA_DIR": str(tmp_path)}) == 0
    report = json.loads(capsys.readouterr().out)
    assert (report["registry"], report["tasks"], report["encrypted"]) == (
        "absent",
        "absent",
        False,
    )
    assert report["messages"] == {"plaintext": 0, "encrypted": 0}


def test_files_in_comm_that_are_not_messages_are_left_alone(data, capsys):
    comm = data / "agents" / "comm"
    (comm / "notes.txt").write_text("not a message")
    (comm / ".orders_partial.json").write_text("{")  # a hidden leftover
    assert _run(data, "encrypt") == 0
    assert "comm/: 4 messages encrypted" in capsys.readouterr().out
    assert (comm / "notes.txt").read_text() == "not a message"
    assert (comm / ".orders_partial.json").read_text() == "{"


def test_an_encrypted_message_under_a_plaintext_name_is_left(data, capsys):
    from core.kernel.agent_runtime import _seal

    cipher = StateCipher((data / "sovereign" / "keys" / "master.key").read_bytes())
    odd = data / "agents" / "comm" / "orders_20261030_000000.json"
    odd.write_bytes(_seal(b'{"topic": "orders", "message": {}}', cipher))
    before = odd.read_bytes()
    assert _run(data, "encrypt") == 1
    assert (
        "already encrypted under a plaintext name; left as is"
        in capsys.readouterr().err
    )
    assert odd.read_bytes() == before
    assert not (odd.parent / "orders_20261030_000000.enc.json").exists()


@pytest.mark.parametrize("body", [b"[1]", b"{cut"], ids=["not an object", "not json"])
def test_a_message_file_that_is_not_a_message_is_left(data, capsys, body):
    odd = data / "agents" / "comm" / "orders_20261030_000000.json"
    odd.write_bytes(body)
    assert _run(data, "encrypt") == 1
    assert f"comm/{odd.name}: cannot be read" in capsys.readouterr().err
    assert odd.read_bytes() == body


@pytest.mark.parametrize("kind", ["damaged token", "another key", "cut short"])
def test_an_unreadable_leftover_copy_counts_as_other_content(data, capsys, kind):
    from core.kernel.agent_runtime import _seal

    comm = data / "agents" / "comm"
    plain = min(comm.glob("orders_*.json"))
    ours = StateCipher((data / "sovereign" / "keys" / "master.key").read_bytes())
    if kind == "damaged token":
        body = _seal(plain.read_bytes(), ours).replace(b'"token": "g', b'"token": "X')
    elif kind == "another key":
        body = _seal(plain.read_bytes(), StateCipher(Fernet.generate_key()))
    else:
        body = b'{"format": "ngari-encrypted-v1"'
    copy = comm / f"{plain.name[:-5]}.enc.json"
    copy.write_bytes(body)
    if kind == "another key":
        assert _run(data, "encrypt") == 1  # stopped by the key id check first
        assert "belong to another master key" in capsys.readouterr().err
    else:
        assert _run(data, "encrypt") == 1
        assert (
            "exists with other content; both left as they are"
            in capsys.readouterr().err
        )
    assert plain.exists() and copy.read_bytes() == body


def test_a_missing_task_file_is_skipped(data, capsys):
    (data / "agents" / "tasks" / "tasks.json").unlink()
    assert _run(data, "encrypt") == 0
    out = capsys.readouterr().out
    assert "tasks.json" not in out and "registry.json: encrypted" in out


def test_a_registry_that_is_json_but_not_an_object_is_left(data, capsys):
    registry = data / "agents" / "registry" / "registry.json"
    registry.write_bytes(b"[]")
    assert _run(data, "encrypt") == 1
    assert (
        "registry.json: cannot be read (ValueError); left as is"
        in capsys.readouterr().err
    )
    assert registry.read_bytes() == b"[]"


def test_an_embedded_kernel_holds_no_lock_as_the_docs_say(data):
    # The state commands cannot see an application's kernel; AGENT_STATE.md
    # says to stop it first. A kernel that takes its own lock fails this test.
    from core.kernel import _hold_instance_lock

    kernel = NSBOSKernel()
    held = _hold_instance_lock(data)
    assert held is not None and kernel.agent_runtime.state_encryption is False
    held.close()
    doc = (REPO_ROOT / "docs" / "AGENT_STATE.md").read_text()
    assert "builds the kernel itself takes no lock" in " ".join(doc.split())


def test_a_topic_that_starts_with_a_dot_goes_both_ways(data, capsys):
    bus = InterAgentCommunication(str(data / "agents" / "comm"))
    bus.publish(".ops", {"m": "dot-topic"})
    before = _snapshot(data)
    assert _run(data, "encrypt") == 0
    comm = data / "agents" / "comm"
    [only] = comm.glob(".ops_*")
    assert only.name.endswith(".enc.json")
    assert b"dot-topic" not in b"".join(p.read_bytes() for p in comm.iterdir())
    capsys.readouterr()
    assert _run(data, "status") == 0
    assert json.loads(capsys.readouterr().out)["messages"] == {
        "plaintext": 0,
        "encrypted": 5,
    }
    assert _run(data, "decrypt") == 0
    assert _snapshot(data) == before
    assert NSBOSKernel().agent_runtime.state_encryption is False  # nothing left behind


def test_the_start_check_counts_only_message_files(data):
    from core.kernel.agent_runtime import sealed_state

    comm = data / "agents" / "comm"
    (comm / "notes.enc.json").write_text("{}")  # no stamp: not a message
    (comm / ".orders_20261030_000000_000000_0a0b0c0d.enc.json.42.abcd.tmp").write_text(
        "{"
    )
    assert sealed_state(data / "agents")["files"] == 0
    assert _run(data, "encrypt") == 0
    assert (
        sealed_state(data / "agents")["files"] == 2 + 4
    )  # registry, tasks, 4 messages


def test_a_long_topic_is_converted_and_its_temporary_name_fits(data, monkeypatch):
    from core.kernel.agent_runtime import _temp_name

    topic = "t" * 225  # a length v0.1.0 accepts: <topic>_<stamp>.json is 246 bytes
    comm = data / "agents" / "comm"
    old = comm / f"{topic}_20261030_000000.json"
    old.write_text(json.dumps({"topic": topic, "message": {"m": 1}, "timestamp": "t"}))
    assert _run(data, "encrypt") == 0
    assert not old.exists() and (comm / f"{topic}_20261030_000000.enc.json").exists()
    assert len(_temp_name(comm / ("x" * 255)).name) <= 255
    # Publishing on a long topic works with encryption on, as it does without.
    monkeypatch.setenv("NGARI_ENCRYPT_STATE", "1")
    NSBOSKernel().publish_event("p" * 196, {"m": 2})


def test_a_damaged_encrypted_message_is_not_decrypted_by_renaming_it(data, capsys):
    assert _run(data, "encrypt") == 0
    victim = min((data / "agents" / "comm").glob("*.enc.json"))
    victim.write_bytes(victim.read_bytes()[:50])  # cut before the key id
    cut = victim.read_bytes()
    assert _run(data, "decrypt") == 1
    assert (
        f"comm/{victim.name}: cannot be read (ValueError); left as is"
        in capsys.readouterr().err
    )
    assert victim.read_bytes() == cut
    assert not (victim.parent / victim.name.replace(".enc.json", ".json")).exists()


def test_a_run_stopped_by_a_directory_sync_records_what_it_did(
    data, monkeypatch, capsys
):
    monkeypatch.setattr(state_cli, "BATCH", 2)
    real = state_cli._sync_dir
    calls = []

    def failing(path):
        calls.append(path)
        if len(calls) == 3:  # the first sync of the second batch
            raise OSError(5, "Input/output error")
        return real(path)

    monkeypatch.setattr(state_cli, "_sync_dir", failing)
    assert _run(data, "encrypt") == 1
    out, err = capsys.readouterr()
    assert "registry.json: encrypted" in out and "comm/: 2 messages encrypted" in out
    assert "Input/output error" in err
    [entry] = [e for e in _entries(data, "state_encrypted") if e["resource"] == "comm"]
    assert entry["details"] == {"messages": 2}


def test_encrypt_with_nothing_to_encrypt_says_so(tmp_path, capsys):
    from core.kernel import _hold_instance_lock

    data = tmp_path / "data"
    keys = data / "sovereign" / "keys"
    keys.mkdir(parents=True)
    (keys / "master.key").write_bytes(Fernet.generate_key())
    (keys / "master.key").chmod(0o600)
    assert (
        state_cli.cli(["encrypt"], {"NGARI_DATA_DIR": str(data)}, _hold_instance_lock)
        == 0
    )
    out = capsys.readouterr().out
    assert "There is no agent state to encrypt yet" in out
    assert "stays encrypted anyway" not in out


def test_what_was_done_is_still_shown_when_a_record_fails(data, monkeypatch, capsys):
    real = state_cli._record
    calls = []

    def failing(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:  # tasks.json is converted, its entry cannot be written
            # the class state_cli catches: its own copy from the flat import
            raise state_cli.MigrationError(
                "state encrypted: done, but the audit entry could not be written"
            )
        return real(*args, **kwargs)

    monkeypatch.setattr(state_cli, "_record", failing)
    assert _run(data, "encrypt") == 1
    out, err = capsys.readouterr()
    assert "registry.json: encrypted" in out
    assert "the audit entry could not be written" in err


def test_a_readable_copy_is_read_when_its_encrypted_twin_cannot_be(data, caplog):
    from core.kernel.agent_runtime import _seal

    cipher = StateCipher((data / "sovereign" / "keys" / "master.key").read_bytes())
    comm = data / "agents" / "comm"
    plain = min(comm.glob("orders_*.json"))
    twin = comm / f"{plain.name[:-5]}.enc.json"
    twin.write_bytes(
        _seal(plain.read_bytes(), cipher).replace(b'"token": "g', b'"token": "X')
    )
    assert len(_messages(data)) == 4  # the plaintext copy, not nothing
    assert f"Skipping unreadable message file {twin.name!r}" in caplog.text


def test_leftover_temporary_files_are_listed_and_left(data, capsys):
    leftover = data / "agents" / "registry" / ".registry.json.4242.0a0b0c0d.tmp"
    leftover.write_text('{"memory": "plaintext of a save that never finished"}')
    assert _run(data, "status") == 0
    assert json.loads(capsys.readouterr().out)["temp_files"] == [
        "registry/.registry.json.4242.0a0b0c0d.tmp"
    ]
    assert _run(data, "encrypt") == 0
    assert (
        "1 temporary file left by a write that was cut short may hold plaintext"
        in capsys.readouterr().out
    )
    assert leftover.exists()  # nothing deletes it


def test_agent_runtime_alone_is_described_as_it_behaves(tmp_path, monkeypatch):
    # AGENT_STATE.md: AgentRuntime() with no directory uses $NGARI_DATA_DIR
    # itself and does not see the kernel's agents/; given that directory and
    # no key, it refuses encrypted state.
    from core.kernel.agent_runtime import AgentRuntime, StateKeyError

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NGARI_ENCRYPT_STATE", "1")
    NSBOSKernel().register_agent("CEO", "strategic")
    assert AgentRuntime().registry.registry_dir == tmp_path / "registry"
    with pytest.raises(StateKeyError):
        AgentRuntime(str(tmp_path / "agents"))
    doc = " ".join((REPO_ROOT / "docs" / "AGENT_STATE.md").read_text().split())
    assert (
        '`AgentRuntime("<data dir>/agents")`' in doc
        and "uses `$NGARI_DATA_DIR` itself" in doc
    )


def test_a_topic_with_a_newline_is_a_message_everywhere(data, capsys):
    from core.kernel.agent_runtime import _is_message_name, sealed_state

    bus = InterAgentCommunication(str(data / "agents" / "comm"))
    bus.publish("orders\nEU", {"card": "newline-topic-secret"})
    [name] = [p.name for p in (data / "agents" / "comm").glob("orders\nEU_*")]
    assert _is_message_name(name)
    assert _run(data, "encrypt") == 0
    comm = data / "agents" / "comm"
    assert b"newline-topic-secret" not in b"".join(
        p.read_bytes() for p in comm.iterdir()
    )
    assert sealed_state(data / "agents")["files"] == 2 + 5
    capsys.readouterr()
    assert _run(data, "status") == 0
    assert json.loads(capsys.readouterr().out)["messages"] == {
        "plaintext": 0,
        "encrypted": 5,
    }
    assert bus_reads(data, "orders\nEU") == [{"card": "newline-topic-secret"}]


def bus_reads(data, topic):
    cipher = StateCipher((data / "sovereign" / "keys" / "master.key").read_bytes())
    bus = InterAgentCommunication(str(data / "agents" / "comm"), cipher=cipher)
    return [m["message"] for m in bus.get_messages(topic)]


def test_digits_that_are_not_ascii_do_not_make_a_message_name(tmp_path):
    from core.kernel.agent_runtime import _is_message_name, _message_time

    # A full-width year with ASCII month and day parses as 2030 for Python's
    # date parser; all full-width it does not, so both forms are checked.
    for name in ("notes_\uff12\uff10\uff13\uff100101_000000.json",
                 "notes_\uff12\uff10\uff13\uff10\uff10\uff11\uff10\uff11_000000.json"):  # fmt: skip
        assert not _is_message_name(name) and _message_time(name) is None


def test_state_encrypt_takes_a_message_name_that_is_not_utf8(tmp_path):
    # A message file from an earlier kernel can have a name that is not UTF-8
    # (a lone surrogate in the topic); the run converts or reports it.
    from core.kernel.agent_runtime import _temp_name
    from core.kernel.data_plane.state import StateCipher

    comm = tmp_path / "comm"
    comm.mkdir()
    raw = os.fsencode(str(comm)) + b"/\xff_20261031_120000_000000_0123abcd.json"
    with open(raw, "wb") as f:
        f.write(
            json.dumps({"topic": "\udcff", "message": {}, "timestamp": "x"}).encode()
        )
    problems, progress = [], [0]
    state_cli._convert_messages(comm, StateCipher(b"k" * 32), True, problems, progress)
    assert progress[0] + len(problems) == 1
    # A 3-byte character cut in two is two bytes of the name, not dropped.
    name = _temp_name(comm / ("a" * 95 + "€")).name
    assert os.fsencode(name).startswith(b"." + b"a" * 95 + "€".encode()[:1] + b".")
