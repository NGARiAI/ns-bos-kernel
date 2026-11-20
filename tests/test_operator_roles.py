"""Operator roles (docs/PIV_CAC.md, 21 CFR 11.10(d), (g)): with
sovereign/roles.json in place, each gated command needs the role it names,
role changes are gated and recorded, and nothing can leave the store with
no admin.
"""

import datetime
import json
import stat
import threading
import time

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from core.kernel.data_plane import keys_cli
from core.kernel.data_plane.operator_auth import OperatorAuthError, identity_bytes
from core.kernel.data_plane.roles import (
    COMMAND_ROLES,
    authorize,
    load_roles,
    parse_roles,
    roles_bytes,
    roles_lock,
)


def _store(tmp_path):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "encrypted").mkdir()
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    (store / "keys" / "master.key").chmod(0o600)
    return store


def _cert(cn="Jane Q. Doe", key=None, start_days_ago=1, days=30):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=start_days_ago
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )


def _write(tmp_path, cert, name="cert.pem"):
    path = tmp_path / name
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _entries(store):
    log = store / "audit" / "sovereign_audit.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _name(store, user, cert, name="Jane Doe", pinned=True):
    """A named operator, with their certificate pinned unless pinned=False."""
    ops = store / "operators"
    ops.mkdir(exist_ok=True)
    (ops / f"{user}.json").write_bytes(identity_bytes(user, name, _fp(cert)))
    if pinned:
        (ops / f"{user}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _roles(store, roles):
    (store / "roles.json").write_bytes(roles_bytes(roles))


def _env(tmp_path, card=None):
    env = {"NGARI_DATA_DIR": str(tmp_path / "data")}
    if card:
        env.update(
            NGARI_OPERATOR_AUTH="card",
            NGARI_PKCS11_MODULE=card.module,
            NGARI_PKCS11_TOKEN=card.token,
        )
    return env


def _pin_file(tmp_path, text="123456"):
    pin = tmp_path / "pin"
    pin.write_text(text)
    return str(pin)


# -- the roles file ----------------------------------------------------------------


def test_no_roles_file_means_no_roles(tmp_path):
    assert load_roles(tmp_path) is None


def test_a_roles_file_is_read_with_each_list_sorted(tmp_path):
    (tmp_path / "roles.json").write_text(
        '{"version": 1, "roles": {"jdoe": ["reviewer", "admin"], "jroe": []}}'
    )
    assert load_roles(tmp_path) == {"jdoe": ["admin", "reviewer"], "jroe": []}


def test_the_file_written_drops_users_with_no_roles(tmp_path):
    _roles(tmp_path, {"jdoe": ["reviewer", "admin"], "jroe": []})
    assert json.loads((tmp_path / "roles.json").read_text()) == {
        "version": 1,
        "roles": {"jdoe": ["admin", "reviewer"]},
    }


@pytest.mark.parametrize(
    ("content", "why"),
    [("{", "is not JSON"), ("[]", "exactly version and roles"),
     ('{"version": 1, "roles": {}, "x": 1}', "exactly version and roles"),
     ('{"version": 2, "roles": {}}', "version 2"),
     ('{"version": true, "roles": {}}', "version True"),
     ('{"version": 1.0, "roles": {}}', "version 1.0"),
     ('{"version": 1, "roles": []}', "map user ids"),
     ('{"version": 1, "roles": {"j/doe": ["admin"]}}', "names user 'j/doe'"),
     ('{"version": 1, "roles": {"jdoe": "admin"}}', "each role once"),
     ('{"version": 1, "roles": {"jdoe": ["root"]}}', "each role once"),
     ('{"version": 1, "roles": {"jdoe": [1]}}', "each role once"),
     ('{"version": 1, "roles": {"jdoe": {"admin": true}}}', "each role once"),
     ('{"version": 1, "roles": {"jdoe": ["admin", "admin"]}}', "each role once")],
)  # fmt: skip
def test_an_invalid_roles_file_fails_closed(tmp_path, content, why):
    (tmp_path / "roles.json").write_text(content)
    with pytest.raises(OperatorAuthError, match=why) as caught:
        load_roles(tmp_path)
    assert caught.value.reason == "bad roles file"


def test_a_roles_link_to_nothing_fails_closed(tmp_path):
    import os

    os.symlink(tmp_path / "unmounted" / "roles.json", tmp_path / "roles.json")
    with pytest.raises(OperatorAuthError, match="link to a file that does not exist"):
        load_roles(tmp_path)


def test_a_roles_link_to_nothing_stops_the_gate(soft_card, tmp_path, capsys):
    import os

    store = _store(tmp_path)
    _card_operator(store, soft_card, "mallory")  # pinned and named, no roles
    os.symlink(tmp_path / "unmounted" / "roles.json", store / "roles.json")
    args = ["set-roles", "--user", "mallory", "--roles", "admin"]
    assert keys_cli.cli(args, _env(tmp_path)) == 1  # gate off: refused
    assert "needs NGARI_OPERATOR_AUTH=card" in capsys.readouterr().err
    code = keys_cli.cli(
        [*args, "--pin-file", _pin_file(tmp_path)], _env(tmp_path, soft_card)
    )
    assert code == 1
    assert (store / "roles.json").is_symlink()
    [auth] = _entries(store)
    assert auth["details"] == {"ok": False, "reason": "bad roles file"}


def test_an_unreadable_roles_file_fails_closed(tmp_path):
    (tmp_path / "roles.json").mkdir()
    with pytest.raises(OperatorAuthError, match="cannot be read"):
        load_roles(tmp_path)


@pytest.mark.parametrize(
    ("given", "want"),
    [("none", []), (" NONE ", []), ("admin", ["admin"]),
     ("reviewer, admin", ["admin", "reviewer"]),
     ("author,reviewer,approver", ["approver", "author", "reviewer"])],
)  # fmt: skip
def test_roles_are_parsed(given, want):
    assert parse_roles(given) == want


@pytest.mark.parametrize(
    ("given", "why"),
    [("", "unknown role ''"), ("root", "unknown role 'root'"),
     ("admin,", "unknown role ''"), ("admin,admin", "given twice")],
)  # fmt: skip
def test_bad_roles_are_refused(given, why):
    with pytest.raises(ValueError, match=why):
        parse_roles(given)


# -- deciding ----------------------------------------------------------------------

NAMED = {"fingerprint": "f" * 64, "subject": "J", "user": "jdoe", "name": "Jane Doe"}


def test_without_a_roles_file_nothing_is_decided():
    assert authorize(None, NAMED, "keys migrate") is None


def test_the_role_a_command_needs_lets_its_holder_through():
    assert authorize({"jdoe": ["admin"]}, NAMED, "keys migrate") == "admin"


@pytest.mark.parametrize(
    ("roles", "operator", "command", "why"),
    [({"jdoe": ["reviewer"]}, NAMED, "keys migrate",
      "jdoe does not hold the admin role that keys migrate needs"),
     ({}, NAMED, "keys migrate", "does not hold the admin role"),
     ({"jdoe": ["admin"]}, NAMED, "keys unheard-of", "has no role set for it"),
     ({"jdoe": ["admin"]}, {"fingerprint": "f" * 64, "subject": "J"}, "keys migrate",
      "has no named operator")],
)  # fmt: skip
def test_an_operator_without_the_role_is_refused(roles, operator, command, why):
    with pytest.raises(OperatorAuthError, match=why) as caught:
        authorize(roles, operator, command)
    assert caught.value.reason == "role"
    assert caught.value.fingerprint == "f" * 64


def test_every_gated_command_has_a_role():
    assert COMMAND_ROLES == {
        "keys migrate": "admin",
        "keys export-recovery": "admin",
        "keys restore": "admin",
        "keys pin-operator": "admin",
        "keys set-roles": "admin",
        "state decrypt": "admin",
    }


# -- setting roles -----------------------------------------------------------------


def _set(tmp_path, user, roles, **env):
    return keys_cli.cli(
        ["set-roles", "--user", user, "--roles", roles], {**_env(tmp_path), **env}
    )


def test_the_first_roles_are_set_without_a_card(tmp_path, capsys):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    assert _set(tmp_path, "jdoe", "admin,reviewer") == 0
    assert "jdoe: no roles -> admin, reviewer." in capsys.readouterr().out
    assert load_roles(store) == {"jdoe": ["admin", "reviewer"]}
    assert stat.S_IMODE((store / "roles.json").stat().st_mode) == 0o600
    [entry] = _entries(store)
    assert (entry["action"], entry["actor"], entry["resource"]) == (
        "roles_changed",
        "local",
        "jdoe",
    )
    assert entry["details"] == {"from": [], "to": ["admin", "reviewer"]}
    assert "mac" not in entry


def test_with_roles_set_the_gate_cannot_be_off(tmp_path, capsys):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    _roles(store, {"jdoe": ["admin"]})
    assert _set(tmp_path, "jdoe", "admin,author") == 1
    assert "needs NGARI_OPERATOR_AUTH=card" in capsys.readouterr().err
    out = tmp_path / "bundle.json"
    secret = tmp_path / "pass"
    secret.write_bytes(b"correct horse battery staple")
    args = ["export-recovery", "--out", str(out), "--passphrase-file", str(secret)]
    assert keys_cli.cli(args, _env(tmp_path)) == 1
    assert not out.exists()
    assert load_roles(store) == {"jdoe": ["admin"]}
    assert _entries(store) == []


def test_roles_go_to_named_operators_only(tmp_path, capsys):
    store = _store(tmp_path)
    assert _set(tmp_path, "nobody", "admin") == 1
    assert "nobody is not a named operator" in capsys.readouterr().err
    assert not (store / "roles.json").exists()
    assert _entries(store) == []


def test_roles_left_for_a_removed_operator_can_be_cleared(tmp_path):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    _roles(store, {"jdoe": ["admin"], "gone": ["reviewer"]})
    assert keys_cli.set_roles(store, "gone", "none") == ["gone: reviewer -> no roles."]
    assert load_roles(store) == {"jdoe": ["admin"]}


@pytest.mark.parametrize(
    ("user", "roles"),
    [("jdoe", "reviewer"), ("jdoe", "none")],
)  # fmt: skip
def test_nothing_may_leave_the_store_without_an_admin(tmp_path, user, roles):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    _roles(store, {"jdoe": ["admin"]})
    with pytest.raises(keys_cli.MigrationError, match="would leave no admin"):
        keys_cli.set_roles(store, user, roles)
    assert load_roles(store) == {"jdoe": ["admin"]}
    assert _entries(store) == []


def test_an_admin_with_no_operator_file_does_not_count(tmp_path):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    # bob has roles but no operator file.
    _roles(store, {"jdoe": ["admin"], "bob": ["admin"]})
    with pytest.raises(keys_cli.MigrationError, match="no admin who can pass the gate"):
        keys_cli.set_roles(store, "jdoe", "none")
    assert load_roles(store) == {"jdoe": ["admin"], "bob": ["admin"]}


def test_a_retired_admin_does_not_count(tmp_path):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    _name(store, "bob", _cert("Bob"), "Bob", pinned=False)  # his .pem is retired
    _roles(store, {"jdoe": ["admin"], "bob": ["admin"]})
    with pytest.raises(keys_cli.MigrationError, match="no admin who can pass the gate"):
        keys_cli.set_roles(store, "jdoe", "author")


def test_retiring_the_last_card_does_not_reopen_pinning(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    jdoe = _cert()
    _name(store, "jdoe", jdoe, pinned=False)
    retired = store / "operators" / "retired"
    retired.mkdir()
    (retired / "jdoe.pem").write_bytes(jdoe.public_bytes(serialization.Encoding.PEM))
    _roles(store, {"jdoe": ["admin"], "bob": ["admin"]})
    soft_card.issue(cn="Mallory")
    cert_file = tmp_path / "m.pem"
    cert_file.write_bytes(soft_card.pem())
    pin = ["pin-operator", "--cert", str(cert_file), "--user", "bob"]
    # Gate off: roles are set, so refused.
    assert keys_cli.cli(pin, _env(tmp_path)) == 1
    assert "needs NGARI_OPERATOR_AUTH=card" in capsys.readouterr().err
    # Gate on: no pinned card is left to sign for it.
    gated = [*pin, "--pin-file", _pin_file(tmp_path)]
    assert keys_cli.cli(gated, _env(tmp_path, soft_card)) == 1
    assert "no pinned operator certificates" in capsys.readouterr().err
    assert sorted(p.name for p in (store / "operators").iterdir()) == [
        "jdoe.json",
        "retired",
    ]


@pytest.mark.parametrize(
    "left",
    ["retired", "operator.json", "operator.pem", "roles"],
)  # fmt: skip
def test_only_a_store_that_never_had_an_operator_pins_without_a_card(
    soft_card, tmp_path, monkeypatch, left
):
    store = _store(tmp_path)
    ops = store / "operators"
    ops.mkdir()
    if left == "retired":
        (ops / "retired").mkdir()
    elif left == "roles":
        _roles(store, {"gone": ["admin"]})
    else:
        (ops / left).write_text("x")
    cert_file = _write(tmp_path, _cert())
    monkeypatch.setattr(keys_cli.sys.stdin, "isatty", lambda: False, raising=False)
    pin = ["pin-operator", "--cert", str(cert_file), "--user", "jdoe"]
    assert keys_cli.cli(pin, _env(tmp_path, soft_card)) == 1
    assert not (ops / "jdoe.json").exists()


def test_a_write_in_progress_does_not_count_as_an_operator(soft_card, tmp_path):
    store = _store(tmp_path)
    ops = store / "operators"
    ops.mkdir()
    (ops / ".jdoe.json.123.ab.tmp").write_text("{")  # left by a crash
    cert_file = _write(tmp_path, _cert())
    pin = ["pin-operator", "--cert", str(cert_file), "--user", "jdoe"]
    assert keys_cli.cli(pin, _env(tmp_path, soft_card)) == 0


@pytest.mark.part11("11.100(a)")
def test_a_new_operator_does_not_inherit_roles_left_on_their_user_id(tmp_path, capsys):
    store = _store(tmp_path)
    _name(store, "boss", _cert("Boss"), "Boss")
    _roles(store, {"boss": ["admin"], "bob": ["admin"]})
    with pytest.raises(keys_cli.MigrationError, match="bob still has roles"):
        keys_cli.pin_operator(
            store, _write(tmp_path, _cert("Bob"), "b.pem"), "bob", None
        )
    assert not (store / "operators" / "bob.json").exists()
    keys_cli.set_roles(store, "bob", "none")
    assert keys_cli.pin_operator(
        store, _write(tmp_path, _cert("Bob"), "b.pem"), "bob", None
    )


@pytest.mark.parametrize(
    "cert",
    [lambda: _cert("Alice", key=rsa.generate_private_key(public_exponent=65537, key_size=1024)),
     lambda: _cert("Alice", start_days_ago=40, days=30)],
    ids=["weak-key", "expired"],
)  # fmt: skip
def test_an_admin_the_gate_refuses_does_not_count(tmp_path, cert):
    store = _store(tmp_path)
    _name(store, "alice", cert(), "Alice")  # pinned, but the gate would refuse her
    _name(store, "bob", _cert("Bob"), "Bob")
    _roles(store, {"alice": ["admin"], "bob": ["admin"]})
    with pytest.raises(keys_cli.MigrationError, match="no admin who can pass the gate"):
        keys_cli.set_roles(store, "bob", "none")
    assert load_roles(store) == {"alice": ["admin"], "bob": ["admin"]}


def _roles_appear_before_the_lock(monkeypatch, store, roles):
    """Another operator sets roles between this command's gate and its lock."""
    import contextlib

    real = keys_cli.roles_lock

    @contextlib.contextmanager
    def lock_after_someone_else(where):
        _roles(store, roles)
        with real(where):
            yield

    monkeypatch.setattr(keys_cli, "roles_lock", lock_after_someone_else)


@pytest.mark.parametrize(
    ("roles", "allowed"),
    [({"alice": ["admin"]}, False), ({"alice": ["admin"], "jdoe": ["admin"]}, True)],
    ids=["actor-not-admin", "actor-admin"],
)  # fmt: skip
def test_roles_set_after_the_gate_bind_the_change(
    soft_card, tmp_path, monkeypatch, capsys, roles, allowed
):
    store = _store(tmp_path)
    _card_operator(store, soft_card)  # jdoe, passing the gate with no roles yet
    _name(store, "alice", _cert("Alice"), "Alice")
    _roles_appear_before_the_lock(monkeypatch, store, roles)
    args = [
        "set-roles",
        "--user",
        "jdoe",
        "--roles",
        "admin,author",
        "--pin-file",
        _pin_file(tmp_path),
    ]
    code = keys_cli.cli(args, _env(tmp_path, soft_card))
    if allowed:
        assert code == 0
        assert load_roles(store)["jdoe"] == ["admin", "author"]
    else:
        assert code == 1
        assert "jdoe does not hold admin in them" in capsys.readouterr().err
        assert load_roles(store) == roles
        assert [e["action"] for e in _entries(store)] == ["operator_auth"]


def test_roles_set_while_the_gate_is_off_stop_the_change(tmp_path, monkeypatch, capsys):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    _roles_appear_before_the_lock(monkeypatch, store, {"alice": ["admin"]})
    assert _set(tmp_path, "jdoe", "admin") == 1
    assert "while this ran, so keys set-roles needs NGARI_OPERATOR_AUTH=card" in (
        capsys.readouterr().err
    )
    assert load_roles(store) == {"alice": ["admin"]}


def test_the_first_roles_must_include_an_admin(tmp_path):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    with pytest.raises(keys_cli.MigrationError, match="would leave no admin"):
        keys_cli.set_roles(store, "jdoe", "reviewer")
    assert not (store / "roles.json").exists()


def test_an_admin_may_hand_over_to_another(tmp_path):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    _name(store, "jroe", _cert("John Roe"), "John Roe")
    _roles(store, {"jdoe": ["admin"], "jroe": ["admin"]})
    keys_cli.set_roles(store, "jdoe", "author")
    assert load_roles(store) == {"jdoe": ["author"], "jroe": ["admin"]}


def test_setting_the_same_roles_changes_nothing(tmp_path):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    _roles(store, {"jdoe": ["admin"]})
    before = (store / "roles.json").stat().st_mtime_ns
    assert keys_cli.set_roles(store, "jdoe", "admin") == [
        "jdoe already has admin. Nothing changed."
    ]
    assert (store / "roles.json").stat().st_mtime_ns == before
    assert _entries(store) == []


@pytest.mark.parametrize(
    ("user", "roles", "why"),
    [("j/doe", "admin", "user id"), ("jdoe", "root", "unknown role")],
)  # fmt: skip
def test_bad_arguments_are_refused(tmp_path, capsys, user, roles, why):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    assert _set(tmp_path, user, roles) == 1
    assert why in capsys.readouterr().err
    assert not (store / "roles.json").exists()


def test_an_audit_log_that_cannot_be_written_is_reported(tmp_path):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    (store / "audit").mkdir()
    (store / "audit" / "sovereign_audit.log").mkdir()
    with pytest.raises(keys_cli.MigrationError, match="roles changed, but the audit"):
        keys_cli.set_roles(store, "jdoe", "admin")


def test_a_change_waits_for_one_in_progress(tmp_path):
    store = _store(tmp_path)
    _name(store, "jdoe", _cert())
    done = []
    with roles_lock(store):
        worker = threading.Thread(
            target=lambda: done.append(keys_cli.set_roles(store, "jdoe", "admin"))
        )
        worker.start()
        time.sleep(0.3)
        assert not done
        assert not (store / "roles.json").exists()
    worker.join(5)
    assert done and load_roles(store) == {"jdoe": ["admin"]}


def test_the_entry_is_keyless_and_the_chain_still_verifies(tmp_path, monkeypatch):
    from core.kernel.data_plane import SovereignDataPlane

    store = _store(tmp_path)
    monkeypatch.setenv("NGARI_KEY_PROVIDER", "file")
    SovereignDataPlane(str(store))
    _name(store, "jdoe", _cert())
    keys_cli.set_roles(store, "jdoe", "admin")
    plane = SovereignDataPlane(str(store))
    assert plane.verify_audit_integrity()
    with pytest.raises(ValueError):
        plane.record("roles_changed", "kernel", "jdoe", {})


# -- listing -----------------------------------------------------------------------


def test_the_list_shows_operators_roles_and_leftovers(tmp_path, capsys):
    store = _store(tmp_path)
    _name(store, "jroe", _cert("John Roe"), "John Roe")
    _name(store, "jdoe", _cert())
    _roles(store, {"jdoe": ["admin", "reviewer"], "gone": ["author"]})
    assert keys_cli.cli(["roles"], _env(tmp_path)) == 0
    assert capsys.readouterr().out.splitlines() == [
        "jdoe: Jane Doe; admin, reviewer",
        "jroe: John Roe; no roles",
        "gone: no operator file; author",
    ]


def test_the_list_says_when_no_roles_are_set(tmp_path, capsys):
    store = _store(tmp_path)
    assert keys_cli.cli(["roles"], _env(tmp_path)) == 0
    assert capsys.readouterr().out.splitlines() == [
        (
            f"no roles file ({store / 'roles.json'}): with NGARI_OPERATOR_AUTH=card "
            "any pinned operator passes the gate."
        ),
        "no named operators.",
    ]


def test_a_broken_roles_file_stops_the_list(tmp_path, capsys):
    store = _store(tmp_path)
    (store / "roles.json").write_text("{")
    assert keys_cli.cli(["roles"], _env(tmp_path)) == 1
    assert "is not JSON" in capsys.readouterr().err


# -- the gate checks roles ---------------------------------------------------------


def _export(tmp_path, env, pin=True):
    secret = tmp_path / "pass"
    secret.write_bytes(b"correct horse battery staple")
    out = tmp_path / "bundle.json"
    args = ["export-recovery", "--out", str(out), "--passphrase-file", str(secret)]
    if pin:
        args += ["--pin-file", _pin_file(tmp_path)]
    return keys_cli.cli(args, env), out


def _card_operator(store, soft_card, user="jdoe"):
    cert = soft_card.issue()
    (store / "operators").mkdir(exist_ok=True)
    (store / "operators" / f"{user}.pem").write_bytes(soft_card.pem())
    _name(store, user, cert)
    return cert


def test_an_admin_passes_and_the_role_is_recorded(soft_card, tmp_path):
    store = _store(tmp_path)
    _card_operator(store, soft_card)
    _roles(store, {"jdoe": ["admin"]})
    code, out = _export(tmp_path, _env(tmp_path, soft_card))
    assert code == 0 and out.exists()
    auth, export = _entries(store)
    assert (auth["actor"], auth["details"]["ok"], auth["details"]["role"]) == (
        "jdoe",
        True,
        "admin",
    )
    assert export["actor"] == "jdoe"


def test_no_role_detail_without_a_roles_file(soft_card, tmp_path):
    store = _store(tmp_path)
    _card_operator(store, soft_card)
    code, _ = _export(tmp_path, _env(tmp_path, soft_card))
    assert code == 0
    assert "role" not in _entries(store)[0]["details"]


@pytest.mark.part11("11.10(g)")
def test_an_operator_without_the_role_is_refused_and_recorded(
    soft_card, tmp_path, capsys
):
    store = _store(tmp_path)
    _card_operator(store, soft_card)
    _name(store, "boss", _cert("Boss"), "Boss")
    _roles(store, {"jdoe": ["reviewer"], "boss": ["admin"]})
    code, out = _export(tmp_path, _env(tmp_path, soft_card))
    assert code == 1 and not out.exists()
    assert "jdoe does not hold the admin role" in capsys.readouterr().err
    [auth] = _entries(store)
    assert (auth["actor"], auth["details"]) == ("jdoe", {"ok": False, "reason": "role"})


def test_an_unnamed_card_is_refused_once_roles_are_set(soft_card, tmp_path):
    store = _store(tmp_path)
    cert = soft_card.issue()
    (store / "operators").mkdir()
    (store / "operators" / "operator.pem").write_bytes(soft_card.pem())
    _name(store, "boss", _cert("Boss"), "Boss")
    _roles(store, {"boss": ["admin"]})
    code, out = _export(tmp_path, _env(tmp_path, soft_card))
    assert code == 1 and not out.exists()
    [auth] = _entries(store)
    assert (auth["actor"], auth["details"]) == (
        _fp(cert),
        {"ok": False, "reason": "role"},
    )


def test_a_broken_roles_file_stops_the_gate_before_the_pin(
    soft_card, tmp_path, monkeypatch
):
    store = _store(tmp_path)
    _card_operator(store, soft_card)
    (store / "roles.json").write_text("{")
    monkeypatch.setattr(keys_cli.sys.stdin, "isatty", lambda: False, raising=False)
    code, out = _export(tmp_path, _env(tmp_path, soft_card), pin=False)
    assert code == 1 and not out.exists()
    # With no PIN source the reason would be "no pin": the PIN is never read.
    [auth] = _entries(store)
    assert auth["details"] == {"ok": False, "reason": "bad roles file"}


def _revoke_while_the_pin_is_typed(tmp_path, store, run, user):
    """Run the command reading its PIN from a FIFO, and take the user's
    roles away after it has started reading, before the PIN arrives."""
    import os

    fifo = tmp_path / "pin.fifo"
    os.mkfifo(fifo)
    result = {}
    worker = threading.Thread(target=lambda: result.update(code=run(str(fifo))))
    worker.start()
    with open(fifo, "w") as f:  # returns once the command opened it for its PIN
        keys_cli.set_roles(store, user, "none", actor="boss")
        f.write("123456")
    worker.join(60)
    return result["code"]


@pytest.mark.part11("11.10(g)")
def test_a_role_taken_away_while_the_pin_is_typed_counts(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    _card_operator(store, soft_card, "bob")
    _name(store, "boss", _cert("Boss"), "Boss")
    _roles(store, {"boss": ["admin"], "bob": ["admin"]})
    secret = tmp_path / "pass"
    secret.write_bytes(b"correct horse battery staple")
    out = tmp_path / "bundle.json"
    export = ["export-recovery", "--out", str(out), "--passphrase-file", str(secret)]

    def run(pin):
        return keys_cli.cli([*export, "--pin-file", pin], _env(tmp_path, soft_card))

    assert _revoke_while_the_pin_is_typed(tmp_path, store, run, "bob") == 1
    assert not out.exists()
    assert "bob does not hold the admin role" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [["migrate"], ["export-recovery", "--out", "{tmp}/b.json"],
     ["restore", "--bundle", "{tmp}/b.json"],
     ["pin-operator", "--cert", "{tmp}/c.pem", "--user", "jroe"],
     ["set-roles", "--user", "jdoe", "--roles", "admin,author"]],
)  # fmt: skip
@pytest.mark.part11("11.10(g)")
def test_every_gated_key_command_needs_admin(soft_card, tmp_path, args):
    store = _store(tmp_path)
    _card_operator(store, soft_card)
    _name(store, "boss", _cert("Boss"), "Boss")
    _roles(store, {"jdoe": ["author"], "boss": ["admin"]})
    _write(tmp_path, _cert("John Roe"), "c.pem")
    argv = [a.replace("{tmp}", str(tmp_path)) for a in args]
    before = sorted(p.name for p in (store / "operators").iterdir())
    code = keys_cli.cli(
        [*argv, "--pin-file", _pin_file(tmp_path)], _env(tmp_path, soft_card)
    )
    assert code == 1
    [auth] = _entries(store)
    assert (auth["resource"], auth["details"]["reason"]) == (f"keys {args[0]}", "role")
    assert load_roles(store) == {"jdoe": ["author"], "boss": ["admin"]}
    assert sorted(p.name for p in (store / "operators").iterdir()) == before


def test_roles_set_through_the_gate_record_the_admin(soft_card, tmp_path, capsys):
    store = _store(tmp_path)
    cert = soft_card.issue()
    env = _env(tmp_path, soft_card)
    first = ["pin-operator", "--cert", str(_write(tmp_path, cert)), "--user", "jdoe"]
    assert keys_cli.cli(first, env) == 0
    pin = _pin_file(tmp_path)
    # No roles file yet: any pinned operator may set the first roles.
    grant = ["set-roles", "--user", "jdoe", "--roles", "admin", "--pin-file", pin]
    assert keys_cli.cli(grant, env) == 0
    second = _write(tmp_path, _cert("John Roe"), "second.pem")
    pin_second = ["pin-operator", "--cert", str(second), "--user", "jroe"]
    assert keys_cli.cli([*pin_second, "--pin-file", pin], env) == 0
    entries = _entries(store)
    assert [(e["action"], e["actor"], e["resource"]) for e in entries] == [
        ("operator_pinned", "local", "jdoe"),
        ("operator_auth", "jdoe", "keys set-roles"),
        ("roles_changed", "jdoe", "jdoe"),
        ("operator_auth", "jdoe", "keys pin-operator"),
        ("operator_pinned", "jdoe", "jroe"),
    ]
    assert "role" not in entries[1]["details"]  # no roles file when it was checked
    assert entries[3]["details"]["role"] == "admin"
