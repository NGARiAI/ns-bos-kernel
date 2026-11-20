"""Agent manifests (docs/AGENT_IDENTITY.md) against a SoftHSM token: an AI
agent is sponsored by a named operator's card, and its manifest checks only
while that sponsorship holds."""

import json
import stat
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

from core.kernel.data_plane import agents_cli
from core.kernel.data_plane.agent_manifest import (
    MANIFEST_LABEL,
    TIME_FORMAT,
    ManifestError,
    canonical,
    check_agent,
    manifest_path,
    manifest_sha256,
    signed_message,
)
from core.kernel.data_plane.operator_auth import ESIGN_LABEL, identity_bytes
from core.kernel.data_plane.roles import roles_bytes


def _at(value):
    return datetime.strptime(value, TIME_FORMAT).replace(tzinfo=timezone.utc)


def _store(tmp_path):
    store = tmp_path / "data" / "sovereign"
    (store / "keys").mkdir(parents=True)
    (store / "keys" / "master.key").write_bytes(Fernet.generate_key())
    return store


def _signer(store, card, user="jdoe", name="Jane Doe"):
    cert = card.issue()
    ops = store / "operators"
    ops.mkdir(exist_ok=True)
    (ops / f"{user}.pem").write_bytes(card.pem())
    fp = cert.fingerprint(hashes.SHA256()).hex()
    (ops / f"{user}.json").write_bytes(identity_bytes(user, name, fp))
    return fp


def _env(tmp_path, card):
    return {
        "NGARI_DATA_DIR": str(tmp_path / "data"),
        "NGARI_PKCS11_MODULE": card.module,
        "NGARI_PKCS11_TOKEN": card.token,
    }


def _sponsor(tmp_path, env, *extra, agent="CEO", pin="123456"):
    pin_file = tmp_path / "pin"
    pin_file.write_text(pin)
    args = ["sponsor", agent, "--type", "strategic", "--pin-file", str(pin_file)]
    return agents_cli.cli([*args, *extra], env)


def _entries(store, *actions):
    log = store / "audit" / "sovereign_audit.log"
    if not log.exists():
        return []
    found = [json.loads(line) for line in log.read_text().splitlines()]
    return [e for e in found if not actions or e["action"] in actions]


def _manifest(store, agent="CEO"):
    return json.loads(manifest_path(store, agent).read_text())


def _refile(store, manifest, agent="CEO"):
    manifest_path(store, agent).write_bytes(canonical(manifest) + b"\n")


@pytest.fixture
def site(soft_card, tmp_path):
    store = _store(tmp_path)
    fp = _signer(store, soft_card)
    return store, _env(tmp_path, soft_card), fp


# -- sponsoring ------------------------------------------------------------------------


def test_a_sponsored_agent_checks_and_is_recorded(site, tmp_path, capsys):
    store, env, fp = site
    extra = ["--tool", "search", "--tool", "summarise", "--data", "reports/",
             "--publish", "alerts", "--task-for", "Worker", "--days", "30"]  # fmt: skip
    assert _sponsor(tmp_path, env, *extra) == 0
    assert "CEO sponsored by Jane Doe (jdoe) until" in capsys.readouterr().out
    manifest = _manifest(store)
    assert manifest["permissions"] == {
        "tools": ["search", "summarise"], "data": ["reports/"], "publish": ["alerts"],
        "subscribe": [], "tasks_for": ["Worker"],
    }  # fmt: skip
    assert manifest["sponsor"] == {
        "user": "jdoe",
        "name": "Jane Doe",
        "fingerprint": fp,
    }
    start = _at(manifest["not_before"])
    end = _at(manifest["not_after"])
    assert end - start == timedelta(days=30)
    path = manifest_path(store, "CEO")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    [entry] = _entries(store, "agent_sponsored")
    assert (entry["actor"], entry["resource"]) == ("jdoe", "CEO")
    assert entry["details"]["manifest_sha256"] == manifest_sha256(manifest)
    assert entry["details"]["replaced"] is False
    assert agents_cli.cli(["check", "CEO"], env) == 0
    out = capsys.readouterr().out
    assert "tools: search, summarise" in out and "subscribe: none" in out
    assert agents_cli.cli(["list"], env) == 0
    assert "CEO: sponsored by Jane Doe (jdoe)" in capsys.readouterr().out


def test_the_signature_is_over_the_labelled_manifest(site, tmp_path):
    # Its own label: a gate or e-signature from the same card is never a manifest.
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    manifest = _manifest(store)
    message = signed_message({k: v for k, v in manifest.items() if k != "signature"})
    assert message.startswith(MANIFEST_LABEL + b"\0") and MANIFEST_LABEL != ESIGN_LABEL


# -- what a manifest binds ---------------------------------------------------------------


def _later(value, days=1):
    when = _at(value) + timedelta(days=days)
    return when.strftime(TIME_FORMAT)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda m: m.update(agent_type="trader"), "signature"),
        (lambda m: m["permissions"]["tools"].append("wire_transfer"), "signature"),
        (lambda m: m["permissions"]["tasks_for"].append("CFO"), "signature"),
        (lambda m: m.update(not_after=_later(m["not_after"])), "signature"),
        (lambda m: m.update(signed_at=_later(m["signed_at"], -1)), "signature"),
        (lambda m: m.update(nonce="0" * 32), "signature"),
        (lambda m: m["sponsor"].update(name="Someone Else"), "not the sponsor"),
        (lambda m: m["sponsor"].update(user="mallory"), "not the sponsor"),
    ],
    ids=[
        "type",
        "tools",
        "tasks_for",
        "not_after",
        "signed_at",
        "nonce",
        "name",
        "user",
    ],
)
def test_every_field_is_bound(site, tmp_path, change, reason):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    manifest = _manifest(store)
    change(manifest)
    _refile(store, manifest)
    with pytest.raises(ManifestError) as refused:
        check_agent(store, "CEO")
    assert refused.value.reason == reason


def test_a_bit_flipped_signature_does_not_verify(site, tmp_path):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    manifest = _manifest(store)
    last = manifest["signature"][-2:]
    manifest["signature"] = manifest["signature"][:-2] + f"{int(last, 16) ^ 1:02x}"
    _refile(store, manifest)
    with pytest.raises(ManifestError) as refused:
        check_agent(store, "CEO")
    assert refused.value.reason == "signature"


def test_a_manifest_filed_under_another_name_does_not_check(site, tmp_path):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    manifest_path(store, "CRO").write_bytes(manifest_path(store, "CEO").read_bytes())
    with pytest.raises(ManifestError) as refused:
        check_agent(store, "CRO")
    assert refused.value.reason == "wrong agent"


def test_a_manifest_checks_only_within_its_dates(site, tmp_path):
    store, env, _ = site
    assert _sponsor(tmp_path, env, "--days", "10") == 0
    manifest = _manifest(store)
    start = _at(manifest["not_before"])
    check_agent(store, "CEO", now=start + timedelta(days=10))
    for now, reason in (
        (start - timedelta(seconds=1), "not yet valid"),
        (start + timedelta(days=10, seconds=1), "expired"),
    ):
        with pytest.raises(ManifestError) as refused:
            check_agent(store, "CEO", now=now)
        assert refused.value.reason == reason


# -- the sponsor ------------------------------------------------------------------------


def test_taking_the_sponsor_role_away_unsponsors_the_agent(site, tmp_path):
    store, env, _ = site
    (store / "roles.json").write_bytes(roles_bytes({"jdoe": ["sponsor"]}))
    assert _sponsor(tmp_path, env) == 0
    check_agent(store, "CEO")
    (store / "roles.json").write_bytes(roles_bytes({"jdoe": ["author"]}))
    with pytest.raises(ManifestError) as refused:
        check_agent(store, "CEO")
    assert refused.value.reason == "no sponsor role"


def test_a_sponsor_without_the_role_is_refused_and_recorded(site, tmp_path, capsys):
    store, env, fp = site
    (store / "roles.json").write_bytes(roles_bytes({"jdoe": ["admin", "author"]}))
    assert _sponsor(tmp_path, env) == 1
    assert "does not hold the sponsor role" in capsys.readouterr().err
    assert not manifest_path(store, "CEO").exists()
    [entry] = _entries(store, "agent_sponsor_refused")
    assert (entry["actor"], entry["resource"], entry["details"]) == (
        fp, "CEO", {"reason": "role"}
    )  # fmt: skip


def test_an_unpinned_sponsor_unsponsors_the_agent(site, tmp_path):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    retired = store / "operators" / "retired"
    retired.mkdir()
    (store / "operators" / "jdoe.pem").rename(retired / "jdoe.pem")
    with pytest.raises(ManifestError) as refused:
        check_agent(store, "CEO")
    assert refused.value.reason == "not pinned"


def test_a_wrong_pin_is_refused_and_recorded(site, tmp_path):
    store, env, _ = site
    assert _sponsor(tmp_path, env, pin="000000") == 1
    assert not manifest_path(store, "CEO").exists()
    [entry] = _entries(store, "agent_sponsor_refused")
    assert entry["resource"] == "CEO" and entry["details"]["reason"]


@pytest.mark.parametrize(
    ("args", "said"),
    [
        (["sponsor", "../CEO", "--type", "t"], "an agent name is"),
        (["sponsor", "CEO", "--type", "t", "--tool", "*"], "'*' is not taken"),
        (["sponsor", "CEO", "--type", "t", "--tool", "a", "--tool", "a"], "twice"),
        (["sponsor", "CEO", "--type", "t", "--task-for", "../x"], "not an agent name"),
        (["sponsor", "CEO", "--type", "t", "--days", "0"], "--days must be"),
        (["sponsor", "CEO", "--type", "t", "--days", "400"], "--days must be"),
        (["sponsor", "CEO", "--type", ""], "--type must be"),
    ],
)
def test_a_bad_request_is_refused_before_the_pin(site, tmp_path, capsys, args, said):
    # The PIN file does not exist: reading it would be a different error.
    store, env, _ = site
    argv = [*args, "--pin-file", str(tmp_path / "no-such-pin")]
    assert agents_cli.cli(argv, env) == 1
    assert said in capsys.readouterr().err
    assert _entries(store) == []


# -- renewing -----------------------------------------------------------------------------


def test_a_manifest_is_never_overwritten_without_replace(site, tmp_path, capsys):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    before = manifest_path(store, "CEO").read_bytes()
    assert _sponsor(tmp_path, env, "--tool", "trade") == 1
    assert "give --replace to renew it" in capsys.readouterr().err
    assert manifest_path(store, "CEO").read_bytes() == before


def test_replacing_keeps_the_old_manifest(site, tmp_path):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    old = manifest_path(store, "CEO").read_bytes()
    assert _sponsor(tmp_path, env, "--tool", "search", "--replace") == 0
    assert _manifest(store)["permissions"]["tools"] == ["search"]
    [kept] = (store / "agents" / "superseded").iterdir()
    assert kept.read_bytes() == old
    assert [e["details"]["replaced"] for e in _entries(store, "agent_sponsored")] == [
        False, True
    ]  # fmt: skip
    check_agent(store, "CEO")


# -- listing ------------------------------------------------------------------------------


def test_a_file_that_is_not_a_manifest_is_listed_as_not_sponsored(
    site, tmp_path, capsys
):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    (store / "agents" / "Rogue.json").write_text('{"agent": "Rogue"}')
    (store / "agents" / "Junk.json").write_text("not json")
    assert agents_cli.cli(["list"], env) == 1
    out = capsys.readouterr().out
    assert "CEO: sponsored by Jane Doe" in out
    assert "Rogue: NOT SPONSORED (malformed)" in out
    assert "Junk: NOT SPONSORED (malformed)" in out


def test_no_manifests_is_an_empty_list(tmp_path, capsys):
    env = {"NGARI_DATA_DIR": str(tmp_path / "data")}
    assert agents_cli.cli(["list"], env) == 0
    assert "no agent manifests" in capsys.readouterr().out
    assert agents_cli.cli(["check", "CEO"], env) == 1
    assert "NOT SPONSORED (missing)" in capsys.readouterr().err


def test_the_kernel_command_runs_agents(tmp_path, monkeypatch, capsys):
    import core.kernel as kernel_mod

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path / "data"))
    with pytest.raises(SystemExit) as done:
        kernel_mod.main(["agents", "list"])
    assert done.value.code == 0
    assert "no agent manifests" in capsys.readouterr().out


def test_the_audit_log_still_verifies_after_a_sponsorship(site, tmp_path, capsys):
    # A store the kernel has started holds keyed entries; the sponsor's
    # entries carry no MAC, as records sign's do, and must still verify.
    from core.kernel.data_plane import SovereignDataPlane, audit_cli

    store, env, _ = site
    SovereignDataPlane(str(store))  # a start: a keyed key_provider entry
    assert _sponsor(tmp_path, env) == 0
    assert _sponsor(tmp_path, env, agent="Bad", pin="000000") == 1
    assert audit_cli.cli(["verify"], env) == 0, capsys.readouterr().err


# -- shape, and the sponsor's card ------------------------------------------------------


def _window(m, days):
    m["not_after"] = (_at(m["not_before"]) + timedelta(days=days)).strftime(TIME_FORMAT)


@pytest.mark.parametrize(
    "change",
    [
        lambda m: m.update(extra=1),
        lambda m: m.pop("nonce"),
        lambda m: m.update(version=2),
        lambda m: m.update(version=True),
        lambda m: m.update(agent="../x"),
        lambda m: m.update(agent_type=""),
        lambda m: m.update(agent_type="t" * 257),
        lambda m: m["permissions"].pop("tools"),
        lambda m: m["permissions"].update(tools="search"),
        lambda m: m["permissions"].update(tools=["*"]),
        lambda m: m["sponsor"].update(extra="x"),
        lambda m: m["sponsor"].update(fingerprint=m["sponsor"]["fingerprint"].upper()),
        lambda m: m["sponsor"].update(name=""),
        lambda m: m.update(not_after=m["not_before"]),
        lambda m: _window(m, 367),
        lambda m: m.update(signed_at="2026-11-14 09:30:00"),
        lambda m: m.update(nonce="abc"),
        lambda m: m.update(signature="xyz"),
        lambda m: m.update(signature=""),
    ],
)
def test_a_malformed_manifest_is_refused_as_malformed(site, tmp_path, change):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    manifest = _manifest(store)
    change(manifest)
    _refile(store, manifest)
    with pytest.raises(ManifestError) as refused:
        check_agent(store, "CEO")
    assert refused.value.reason == "malformed"


def test_a_manifest_over_the_size_limit_is_malformed(site, tmp_path):
    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    path = manifest_path(store, "CEO")
    path.write_bytes(path.read_bytes() + b" " * (64 * 1024))  # still valid JSON
    with pytest.raises(ManifestError) as refused:
        check_agent(store, "CEO")
    assert refused.value.reason == "malformed"


@pytest.mark.parametrize("unknown", ["unpinned", "unnamed"])
def test_a_card_that_is_not_a_named_operator_cannot_sponsor(
    site, tmp_path, capsys, unknown
):
    store, env, _ = site
    ops = store / "operators"
    if unknown == "unpinned":
        (ops / "jdoe.pem").unlink()  # the only pinned certificate
    else:
        (ops / "jdoe.json").unlink()  # pinned, but no name on file
    assert _sponsor(tmp_path, env) == 1
    assert not manifest_path(store, "CEO").exists()
    reasons = [e["details"]["reason"] for e in _entries(store, "agent_sponsor_refused")]
    assert reasons == [
        "no pinned certificates" if unknown == "unpinned" else "not named"
    ]


def test_a_key_or_certificate_the_kernel_no_longer_accepts_unsponsors(
    site, tmp_path, monkeypatch
):
    from core.kernel.data_plane import agent_manifest
    from core.kernel.data_plane.operator_auth import OperatorAuthError

    store, env, _ = site
    assert _sponsor(tmp_path, env) == 0
    with monkeypatch.context() as m:
        m.setattr(agent_manifest, "key_problem", lambda cert: "a key too short")
        with pytest.raises(ManifestError) as refused:
            check_agent(store, "CEO")
        assert refused.value.reason == "weak key"

    def expired(cert, fp):
        raise OperatorAuthError("certificate expired", "expired", fp)

    monkeypatch.setattr(agent_manifest, "_check_validity", expired)
    with pytest.raises(ManifestError) as refused:
        check_agent(store, "CEO")
    assert refused.value.reason == "expired"


def test_a_manifest_is_checked_again_before_it_is_filed(site, tmp_path, monkeypatch):
    # The sponsor role taken away just as the card signs: the kernel's own
    # check, run before filing, refuses what it would not accept later.
    from core.kernel.data_plane.operator_auth import CardAuthenticator

    store, env, _ = site
    (store / "roles.json").write_bytes(roles_bytes({"jdoe": ["sponsor"]}))
    real = CardAuthenticator.sign_named

    def then_role_removed(self, *args, **kwargs):
        facts = real(self, *args, **kwargs)
        (store / "roles.json").write_bytes(roles_bytes({"jdoe": ["author"]}))
        return facts

    monkeypatch.setattr(CardAuthenticator, "sign_named", then_role_removed)
    assert _sponsor(tmp_path, env) == 1
    assert not manifest_path(store, "CEO").exists()
    assert _entries(store, "agent_sponsored") == []
