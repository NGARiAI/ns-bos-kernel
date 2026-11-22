"""Unusual inputs to the key commands and the card gate are handled without
a crash: deeply nested key files, failures inside the gate, a PIN that is
not text, several certificates in one pinned file, and an audit entry that
cannot be written after a key command has already done its work."""

import json
import sys

import pytest
from cryptography.fernet import Fernet

from core.kernel.data_plane import (
    SovereignDataPlane,
    append_audit,
    keys_cli,
)
from core.kernel.data_plane.keys import KeyProviderError
from core.kernel.data_plane.keys_cli import (
    MigrationError,
    export_recovery,
    read_passphrase,
)
from core.kernel.data_plane.operator_auth import (
    CardAuthenticator,
    OperatorAuthError,
    load_pinned,
)
from core.kernel.data_plane.recovery import RecoveryError, unwrap
from core.kernel.data_plane.tpm import TPMKeyProvider

DEEP = b"[" * 100_000


@pytest.fixture
def plane(tmp_path):
    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    plane.store_encrypted("k", {"v": 1})
    return plane


# -- the card gate ---------------------------------------------------------------------


def _store_with_pin(tmp_path, pin_text):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    pin = tmp_path / "pin"
    pin.write_bytes(pin_text)
    return store, pin


def _entries(store):
    log = store / "audit" / "sovereign_audit.log"
    return (
        [json.loads(line) for line in log.read_text().splitlines()]
        if log.exists()
        else []
    )


def test_a_failure_inside_the_gate_is_refused_and_recorded(tmp_path, monkeypatch):
    store, pin = _store_with_pin(tmp_path, b"123456\n")

    def broken(self, action, store, pin):
        raise RuntimeError("secret detail 123456")

    monkeypatch.setattr(CardAuthenticator, "authenticate", broken)
    env = {"NGARI_OPERATOR_AUTH": "card"}
    with pytest.raises(OperatorAuthError) as caught:
        keys_cli.operator_gate("export-recovery", store, env, str(pin))
    assert str(caught.value) == "the operator check failed with RuntimeError"
    assert caught.value.reason == "error"
    [entry] = _entries(store)
    assert entry["details"] == {"ok": False, "reason": "error"}
    assert "123456" not in (store / "audit" / "sovereign_audit.log").read_text()


@pytest.mark.parametrize(
    ("pin", "message"),
    [("123456".encode("utf-16"), "not UTF-8 text"), (b"12\x0034", "NUL byte")],
    ids=["utf-16", "nul"],
)
def test_a_pin_that_is_not_text_is_refused_without_echoing_it(tmp_path, pin, message):
    auth = CardAuthenticator(tmp_path, module="/nonexistent.so")
    with pytest.raises(OperatorAuthError) as caught:
        auth._tool(tmp_path, "--sign", pin=pin)
    assert message in str(caught.value)
    assert caught.value.reason == "no pin"
    assert "12" not in str(caught.value)


def test_several_certificates_in_one_pinned_file_are_all_pinned(tmp_path, soft_card):
    first = soft_card.issue()
    first_pem = soft_card.pem()
    second = soft_card.issue()
    ops = tmp_path / "operators"
    ops.mkdir()
    (ops / "operators.pem").write_bytes(first_pem + soft_card.pem())
    pinned = load_pinned(ops)
    assert set(pinned.values()) == {first, second}


def test_without_a_terminal_the_pin_error_names_pin_file(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(MigrationError, match="give the PIN with --pin-file"):
        read_passphrase(None, confirm=False, prompt="Card PIN: ", option="--pin-file")
    with pytest.raises(
        MigrationError, match="give the passphrase with --passphrase-file"
    ):
        read_passphrase(None, confirm=True)


# -- the audit entry after a key command's work ----------------------------------------


def test_an_export_whose_audit_entry_fails_says_the_bundle_was_written(
    soft_tpm, tmp_path, monkeypatch
):
    store = tmp_path / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    out = tmp_path / "bundle.json"

    def full(*args, **kwargs):
        raise OSError(28, "No space left on device", str(store / "audit"))

    monkeypatch.setattr(keys_cli, "append_audit", full)
    with pytest.raises(MigrationError) as caught:
        export_recovery(
            store, {"NGARI_TPM_TCTI": soft_tpm}, out, b"correct horse battery staple"
        )
    assert str(caught.value).startswith(
        "recovery exported: done, but the audit entry could not be written"
    )
    assert "No space left on device" in str(caught.value)
    assert out.exists()


def test_append_audit_is_still_what_the_commands_use():
    assert keys_cli.append_audit is append_audit


# -- deeply nested JSON in the key files -----------------------------------------------


def test_a_deeply_nested_sealed_file_is_refused_not_a_crash(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "master.key.sealed").write_bytes(DEEP)
    provider = TPMKeyProvider(keys, tcti="libtpms:unused")
    with pytest.raises(KeyProviderError, match="not a valid sealed key"):
        provider.load_or_create()
    assert provider.describe()["pcrs"] is None
    assert keys_cli._sealed_pcrs(keys / "master.key.sealed") is None


def test_a_deeply_nested_bundle_is_refused_not_a_crash():
    with pytest.raises(RecoveryError):
        unwrap(DEEP, b"correct horse battery staple")
