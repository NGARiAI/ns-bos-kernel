"""PIV/CAC operator check (docs/PIV_CAC.md) against a SoftHSM token.

The PIN must stay out of argv, logs, exceptions and the audit chain. Every
failure stops the key command, and pass and fail are both audited.
"""

import json
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

from core.kernel.data_plane import keys_cli
from core.kernel.data_plane.operator_auth import (
    CardAuthenticator,
    OperatorAuthError,
    challenge,
    load_pinned,
)


def _store(tmp_path):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    (store / "keys" / "master.key").chmod(0o600)
    return store


def _pin(store, cert_pem):
    ops = store / "operators"
    ops.mkdir(exist_ok=True)
    (ops / "operator.pem").write_bytes(cert_pem)
    return ops


def _auth(card, ops):
    return CardAuthenticator(ops, module=card.module, token=card.token)


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_a_pinned_card_signs_for_the_command(soft_card, tmp_path, kind):
    store = _store(tmp_path)
    cert = soft_card.issue(kind)
    ops = _pin(store, soft_card.pem())
    facts = _auth(soft_card, ops).authenticate("keys restore", store, b"123456")
    assert facts == {"fingerprint": _fp(cert), "subject": "Test Operator"}


@pytest.mark.part11("11.10(d)")
def test_a_card_that_is_not_pinned_is_refused(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue()
    first = soft_card.pem()
    soft_card.issue()  # the card holds a different certificate
    ops = _pin(store, first)
    with pytest.raises(OperatorAuthError, match="is not pinned") as caught:
        _auth(soft_card, ops).authenticate("keys restore", store, b"123456")
    assert caught.value.reason == "not pinned"
    assert caught.value.fingerprint == _fp(soft_card.cert)


@pytest.mark.part11("11.10(d)")
def test_without_pinned_certificates_nobody_passes(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue()
    with pytest.raises(OperatorAuthError, match="no pinned operator certificates"):
        _auth(soft_card, store / "operators").authenticate("keys migrate", store, b"1")


def test_an_expired_certificate_is_refused(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue(days=1, start_days_ago=10)
    ops = _pin(store, soft_card.pem())
    with pytest.raises(OperatorAuthError, match="has expired") as caught:
        _auth(soft_card, ops).authenticate("keys migrate", store, b"123456")
    assert caught.value.reason == "expired"


def test_a_copied_certificate_without_its_key_is_refused(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue(card_key="other")  # the real cert, someone else's key
    ops = _pin(store, soft_card.pem())
    with pytest.raises(OperatorAuthError, match="does not verify") as caught:
        _auth(soft_card, ops).authenticate("keys migrate", store, b"123456")
    assert caught.value.reason == "signature"


@pytest.mark.part11("11.300(d)")
def test_a_wrong_pin_is_refused_and_not_repeated(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue()
    ops = _pin(store, soft_card.pem())
    with pytest.raises(OperatorAuthError, match="PIN_INCORRECT") as caught:
        _auth(soft_card, ops).authenticate("keys migrate", store, b"999999")
    assert caught.value.reason == "pin"
    assert "999999" not in str(caught.value)


def test_a_signature_is_bound_to_its_command_and_store(soft_card, tmp_path):
    store = _store(tmp_path)
    cert = soft_card.issue()
    auth = _auth(soft_card, _pin(store, soft_card.pem()))
    fp = _fp(cert)
    nonce = os.urandom(32)
    signed = challenge("keys migrate", store, fp, nonce)
    work = tmp_path / "work"
    work.mkdir()
    signature = auth._sign(work, cert, signed, b"123456", fp)
    auth._verify(cert, signature, signed, fp)
    for other in (
        challenge("keys restore", store, fp, nonce),
        challenge("keys migrate", tmp_path / "elsewhere", fp, nonce),
        challenge("keys migrate", store, fp, os.urandom(32)),
    ):
        with pytest.raises(OperatorAuthError, match="does not verify"):
            auth._verify(cert, signature, other, fp)


def test_every_check_signs_a_fresh_challenge(soft_card, tmp_path, monkeypatch):
    from core.kernel.data_plane import operator_auth

    store = _store(tmp_path)
    soft_card.issue()
    auth = _auth(soft_card, _pin(store, soft_card.pem()))
    seen = []
    real = operator_auth.challenge

    def spy(command, store_, fp, nonce):
        seen.append(nonce)
        return real(command, store_, fp, nonce)

    monkeypatch.setattr(operator_auth, "challenge", spy)
    for _ in range(2):
        auth.authenticate("keys migrate", store, b"123456")
    assert len(seen) == 2
    assert seen[0] != seen[1]
    assert all(len(nonce) == 32 for nonce in seen)


def test_a_tool_that_echoes_the_pin_does_not_leak_it(tmp_path, monkeypatch):
    from core.kernel.data_plane import operator_auth

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "pkcs11-tool").write_text(
        '#!/bin/sh\necho "error: bad pin $NGARI_CARD_PIN" >&2\nexit 1\n'
    )
    (bin_dir / "pkcs11-tool").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    auth = CardAuthenticator(tmp_path, module="/nonexistent.so")
    with pytest.raises(OperatorAuthError) as caught:
        auth._tool(tmp_path, "--sign", pin=b"424242")
    assert "424242" not in str(caught.value)
    assert "[pin]" in str(caught.value)
    assert operator_auth._PIN_VAR not in os.environ


def test_the_pin_never_reaches_argv(soft_card, tmp_path, monkeypatch):
    store = _store(tmp_path)
    soft_card.issue()
    ops = _pin(store, soft_card.pem())
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "argv.log"
    wrapper = bin_dir / "pkcs11-tool"
    wrapper.write_text(
        f'#!/bin/sh\necho "$@" >> {log}\nexec /usr/bin/pkcs11-tool "$@"\n'
    )
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    _auth(soft_card, ops).authenticate("keys migrate", store, b"123456")
    argv = log.read_text()
    assert "--sign" in argv
    assert "env:NGARI_CARD_PIN" in argv
    assert "123456" not in argv


def test_a_hung_card_times_out(tmp_path, monkeypatch):
    store = _store(tmp_path)
    ops = store / "operators"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "pkcs11-tool").write_text("#!/bin/sh\nexec sleep 30\n")
    (bin_dir / "pkcs11-tool").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    monkeypatch.setattr(
        "core.kernel.data_plane.operator_auth.load_pinned", lambda d: {"fp": None}
    )
    auth = CardAuthenticator(ops, module="/nonexistent.so", timeout=0.5)
    with pytest.raises(OperatorAuthError, match="did not finish within 0.5s"):
        auth.authenticate("keys migrate", store, b"123456")


def test_missing_opensc_gives_an_actionable_error(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(
        "core.kernel.data_plane.operator_auth.load_pinned", lambda d: {"fp": None}
    )
    with pytest.raises(OperatorAuthError, match="package: opensc"):
        CardAuthenticator(tmp_path).authenticate("keys migrate", tmp_path, b"1")


def test_a_pinned_file_that_is_not_a_certificate_stops_the_check(tmp_path):
    ops = tmp_path / "operators"
    ops.mkdir()
    (ops / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nnope\n")
    with pytest.raises(OperatorAuthError, match="is not a certificate"):
        load_pinned(ops)


# -- the gate in front of the keys commands -----------------------------------


def _entries(store):
    log = store / "audit" / "sovereign_audit.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


def _env(tmp_path, card, **extra):
    return {
        "NGARI_DATA_DIR": str(tmp_path / "data"),
        "NGARI_OPERATOR_AUTH": "card",
        "NGARI_PKCS11_MODULE": card.module,
        "NGARI_PKCS11_TOKEN": card.token,
        **extra,
    }


def _export(tmp_path, env, pin_file):
    out = tmp_path / "bundle.json"
    secret = tmp_path / "pass"
    secret.write_bytes(b"correct horse battery staple")
    args = ["export-recovery", "--out", str(out), "--passphrase-file", str(secret)]
    if pin_file:
        args += ["--pin-file", str(pin_file)]
    return keys_cli.cli(args, env), out


def test_the_gate_lets_a_pinned_card_through_and_audits_it(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    cert = soft_card.issue()
    _pin(store, soft_card.pem())
    pin = tmp_path / "pin"
    pin.write_text("123456\n")
    code, out = _export(tmp_path, _env(tmp_path, soft_card), pin)
    assert code == 0
    assert out.exists()
    assert "operator: Test Operator" in capsys.readouterr().out
    entry, export = _entries(store)
    assert (entry["action"], entry["actor"], entry["resource"]) == (
        "operator_auth",
        _fp(cert),
        "keys export-recovery",
    )
    assert entry["details"] == {"ok": True, "subject": "Test Operator"}
    # The export is recorded after it, under the same operator.
    assert (export["action"], export["actor"]) == ("recovery_exported", _fp(cert))


@pytest.mark.part11("11.10(d)", "11.300(d)")
def test_the_gate_stops_a_wrong_pin_and_audits_the_failure(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    soft_card.issue()
    _pin(store, soft_card.pem())
    pin = tmp_path / "pin"
    pin.write_text("999999")
    code, out = _export(tmp_path, _env(tmp_path, soft_card), pin)
    assert code == 1
    assert not out.exists()
    err = capsys.readouterr().err
    assert "999999" not in err
    [entry] = _entries(store)
    assert entry["details"] == {"ok": False, "reason": "pin"}
    assert "999999" not in (store / "audit" / "sovereign_audit.log").read_text()


def test_the_gate_with_no_pin_source_fails_closed(soft_card, tmp_path, monkeypatch):
    store = _store(tmp_path)
    soft_card.issue()
    _pin(store, soft_card.pem())
    monkeypatch.setattr(keys_cli.sys.stdin, "isatty", lambda: False, raising=False)
    code, out = _export(tmp_path, _env(tmp_path, soft_card), None)
    assert code == 1
    assert not out.exists()
    assert _entries(store)[0]["details"] == {"ok": False, "reason": "no pin"}


def test_the_gate_is_off_unless_asked_for(tmp_path):
    store = _store(tmp_path)
    env = {"NGARI_DATA_DIR": str(tmp_path / "data")}
    code, out = _export(tmp_path, env, None)
    assert code == 0
    assert out.exists()
    # No operator_auth entry; the export itself is recorded, by "local".
    [entry] = _entries(store)
    assert (entry["action"], entry["actor"]) == ("recovery_exported", "local")


def test_an_unknown_gate_mode_fails_closed(tmp_path, capsys):
    store = _store(tmp_path)
    env = {"NGARI_DATA_DIR": str(tmp_path / "data"), "NGARI_OPERATOR_AUTH": "maybe"}
    code, out = _export(tmp_path, env, None)
    assert code == 1
    assert not out.exists()
    assert "must be off or card" in capsys.readouterr().err
    assert _entries(store) == []


def test_status_is_never_gated(tmp_path):
    _store(tmp_path)
    env = {"NGARI_DATA_DIR": str(tmp_path / "data"), "NGARI_OPERATOR_AUTH": "card"}
    assert keys_cli.cli(["status"], env) == 0
    assert not Path(tmp_path / "data" / "sovereign" / "audit").exists()


# -- a card that cannot be reached says why -------------------------------------------

INIT_FAILED = "error: PKCS11 function C_Initialize failed: rv = CKR_GENERAL_ERROR (0x5)"


@pytest.fixture
def opensc(tmp_path, monkeypatch):
    """An OpenSC-named module file, with the PC/SC checks pointed at tmp."""
    from core.kernel.data_plane import operator_auth

    module = tmp_path / "opensc-pkcs11.so"
    module.write_bytes(b"")
    monkeypatch.setattr(
        operator_auth.ctypes.util, "find_library", lambda name: "libpcsclite.so.1"
    )
    monkeypatch.setattr(operator_auth.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        operator_auth, "PCSCD_PATHS", (str(tmp_path / "sbin" / "pcscd"),)
    )
    monkeypatch.setenv("PCSCLITE_CSOCK_NAME", str(tmp_path / "pcscd.comm"))
    return module


def test_without_the_pcsc_library_opensc_says_to_install_pcscd(opensc, monkeypatch):
    from core.kernel.data_plane import operator_auth

    monkeypatch.setattr(operator_auth.ctypes.util, "find_library", lambda name: None)
    assert operator_auth.card_problem(str(opensc), INIT_FAILED) == (
        "OpenSC cannot reach a card reader: the PC/SC library is not installed "
        "(apt install pcscd)"
    )


def test_without_pcscd_it_says_so(opensc):
    from core.kernel.data_plane import operator_auth

    assert operator_auth.card_problem(str(opensc), INIT_FAILED) == (
        "OpenSC cannot reach a card reader: pcscd is not installed (apt install pcscd)"
    )


def test_with_pcscd_stopped_it_names_the_socket(opensc, tmp_path):
    from core.kernel.data_plane import operator_auth

    (tmp_path / "sbin").mkdir()
    (tmp_path / "sbin" / "pcscd").write_bytes(b"")
    socket = tmp_path / "pcscd.comm"
    assert operator_auth.card_problem(str(opensc), INIT_FAILED) == (
        f"OpenSC cannot reach a card reader: pcscd is not running ({socket} is "
        "missing; systemctl start pcscd.socket)"
    )
    socket.write_bytes(b"")
    assert operator_auth.card_problem(str(opensc), INIT_FAILED) is None


def test_a_pcscd_on_path_counts_as_installed(opensc, monkeypatch):
    from core.kernel.data_plane import operator_auth

    monkeypatch.setattr(operator_auth.shutil, "which", lambda name: "/opt/bin/pcscd")
    assert "pcscd is not running" in operator_auth.card_problem(
        str(opensc), INIT_FAILED
    )


def test_the_pcsc_checks_apply_to_opensc_only(tmp_path):
    from core.kernel.data_plane import operator_auth

    softhsm = tmp_path / "libsofthsm2.so"
    softhsm.write_bytes(b"")
    assert operator_auth.card_problem(str(softhsm), INIT_FAILED) is None


def test_a_missing_module_is_named(tmp_path):
    from core.kernel.data_plane import operator_auth

    missing = tmp_path / "opensc-pkcs11.so"
    assert operator_auth.card_problem(
        str(missing), "error: Failed to load pkcs11 module"
    ) == (
        f"the PKCS#11 module {missing} does not exist (Debian and Ubuntu package: "
        "opensc-pkcs11; or set NGARI_PKCS11_MODULE)"
    )
    missing.write_bytes(b"")
    assert (
        operator_auth.card_problem(str(missing), "error: Failed to load pkcs11 module")
        is None
    )


@pytest.mark.parametrize(
    ("output", "start"),
    [("No slots.", "no card was found"),
     ("No slot with a token was found.", "no card was found"),
     ("error: C_Login failed: rv = CKR_PIN_LOCKED (0xa4)", "the card's PIN is blocked"),
     ("error: C_Login failed: rv = CKR_PIN_INCORRECT (0xa0)", None),
     ("error: something else", None)],
)  # fmt: skip
def test_other_card_messages(tmp_path, output, start):
    from core.kernel.data_plane import operator_auth

    problem = operator_auth.card_problem(str(tmp_path / "opensc-pkcs11.so"), output)
    assert (problem is None) if start is None else problem.startswith(start)


def test_the_reason_reaches_the_error(opensc, tmp_path, monkeypatch):
    from core.kernel.data_plane import operator_auth

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "pkcs11-tool").write_text(
        f"#!/bin/sh\necho '{INIT_FAILED}' >&2\nexit 1\n"
    )
    (bin_dir / "pkcs11-tool").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    monkeypatch.setattr(
        operator_auth.shutil,
        "which",
        lambda name: str(bin_dir / name) if name == "pkcs11-tool" else None,
    )
    auth = CardAuthenticator(tmp_path, module=str(opensc))
    with pytest.raises(OperatorAuthError) as caught:
        auth._tool(tmp_path, "--read-object")
    assert str(caught.value) == (
        f"pkcs11-tool failed: {INIT_FAILED}; OpenSC cannot reach a card reader: "
        "pcscd is not installed (apt install pcscd)"
    )
    assert caught.value.reason == "card"


# -- certificate dates: which way, and what the clock reads ---------------------------


def test_an_expired_certificate_names_its_dates_and_the_clock(soft_card, tmp_path):
    store = _store(tmp_path)
    cert = soft_card.issue(days=1, start_days_ago=10)
    ops = _pin(store, soft_card.pem())
    with pytest.raises(OperatorAuthError) as caught:
        _auth(soft_card, ops).authenticate("keys migrate", store, b"123456")
    message = str(caught.value)
    assert message.startswith(
        f"certificate {_fp(cert)[:16]} has expired (valid "
        f"{cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d}; "
        "this machine's clock reads "
    )
    assert "set it" not in message


def test_a_certificate_not_valid_yet_points_at_the_clock(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue(days=30, start_days_ago=-5)
    ops = _pin(store, soft_card.pem())
    with pytest.raises(OperatorAuthError) as caught:
        _auth(soft_card, ops).authenticate("keys migrate", store, b"123456")
    assert caught.value.reason == "not yet valid"
    assert "is not valid yet" in str(caught.value)
    assert "a board without a real-time clock can start from an old time" in str(
        caught.value
    )


def test_a_board_whose_clock_reads_1970_is_told_so(soft_card, tmp_path, monkeypatch):
    import datetime as real

    from core.kernel.data_plane import operator_auth

    class Epoch(real.datetime):
        @classmethod
        def now(cls, tz=None):
            return real.datetime(1970, 1, 1, 0, 0, 5, tzinfo=tz)

    store = _store(tmp_path)
    soft_card.issue()
    ops = _pin(store, soft_card.pem())
    monkeypatch.setattr(operator_auth, "datetime", Epoch)
    with pytest.raises(OperatorAuthError) as caught:
        _auth(soft_card, ops).authenticate("keys migrate", store, b"123456")
    assert "this machine's clock reads 1970-01-01 00:00 UTC" in str(caught.value)
    assert caught.value.reason == "not yet valid"


def test_the_gate_records_a_not_yet_valid_card(soft_card, tmp_path):
    store = _store(tmp_path)
    soft_card.issue(days=30, start_days_ago=-5)
    _pin(store, soft_card.pem())
    pin = tmp_path / "pin"
    pin.write_text("123456\n")
    code, _ = _export(tmp_path, _env(tmp_path, soft_card), pin)
    assert code == 1
    assert _entries(store)[-1]["details"] == {"ok": False, "reason": "not yet valid"}
