"""`keys selftest`, on the software TPM only (the soft_tpm fixture); never
the hardware chip. A pass has to mean something, so each step is also
broken on purpose and must then report a failure."""

import json
import os
import re
import tempfile
from pathlib import Path

import pytest

from core.kernel.data_plane import selftest
from core.kernel.data_plane.keys import FileKeyProvider, KeyProviderError
from core.kernel.data_plane.keys_cli import cli
from core.kernel.data_plane.tpm import TPMKeyProvider, parse_identity

STEP_NAMES = [name for name, _ in selftest.STEPS]


@pytest.fixture
def env(soft_tpm, tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return {"NGARI_TPM_TCTI": soft_tpm, "NGARI_DATA_DIR": str(tmp_path / "real")}


def _tree(root: Path) -> dict:
    return {
        str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }


def test_every_step_passes_and_nothing_else_is_touched(
    env, tmp_path, capsys, monkeypatch
):
    real = tmp_path / "real" / "sovereign" / "keys"
    real.mkdir(parents=True)
    (real / "master.key").write_bytes(decoy := b"x" * 43 + b"=")
    before = _tree(tmp_path / "real")
    keys, phrases = [], []
    load = FileKeyProvider.load_or_create
    monkeypatch.setattr(
        FileKeyProvider, "load_or_create",
        lambda self, **kw: keys.append(load(self, **kw)) or keys[-1],
    )  # fmt: skip
    token = selftest.secrets.token_urlsafe
    monkeypatch.setattr(
        selftest.secrets,
        "token_urlsafe",
        lambda n: phrases.append(token(n)) or phrases[-1],
    )

    assert cli(["selftest"], env) == 0
    out = capsys.readouterr()
    text = out.out + out.err
    reaching, *lines = text.splitlines()
    assert reaching.startswith("Reaching the TPM (")  # printed before any step
    assert "swtpm:" in reaching or "libtpms:" in reaching  # a simulator, not a chip
    assert lines[0].startswith("TPM: IBM SWTPM, TPM 2.0 revision 1.64, firmware 0x")
    assert [
        re.match(r"ok   \d (.+?) {2,}", line).group(1).strip() for line in lines[1:7]
    ] == (STEP_NAMES)
    assert lines[-1].startswith("selftest passed: 6 of 6 steps.")
    # Neither the scratch key nor the bundle passphrase is ever printed.
    assert keys and phrases
    assert not any(k.decode() in text for k in keys)
    assert not any(p in text for p in phrases)
    assert _tree(tmp_path / "real") == before
    assert decoy in before.values()
    assert list((tmp_path / "scratch").iterdir()) == []


def test_the_json_report_names_the_tpm_and_each_step(env, capsys):
    assert cli(["selftest", "--json"], env) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is True
    assert report["tcti"] == env["NGARI_TPM_TCTI"]
    assert report["tpm"]["manufacturer"] == "IBM"
    assert [s["step"] for s in report["steps"]] == STEP_NAMES
    assert all(s["ok"] and s["seconds"] >= 0 for s in report["steps"])


def _no_flip(sealed):
    pass


def _keep_master_key(monkeypatch):
    real = Path.unlink
    monkeypatch.setattr(
        Path,
        "unlink",
        lambda self, *a, **k: (
            None if self.name == "master.key" else real(self, *a, **k)
        ),
    )


def _refuse_after_writing(name: str, data: bytes):
    """After the tamper step's flip, a provider that writes `name` in the keys
    directory and then refuses: what a fallback to a new key would look like."""

    def breaker(m):
        flipped = []
        real_flip, real_load = selftest._flip, TPMKeyProvider.load_or_create
        m.setattr(
            selftest, "_flip", lambda path: (real_flip(path), flipped.append(path))
        )

        def load(self, **kw):
            if not flipped:
                return real_load(self, **kw)
            (self.keys_dir / name).write_bytes(data)
            raise KeyProviderError("refused")

        m.setattr(TPMKeyProvider, "load_or_create", load)

    return breaker


BREAKERS = [
    # A probe that does not read back fails the first step.
    ("file key", lambda m: m.setattr(
        selftest.SovereignDataPlane, "retrieve_decrypted", lambda self, key: None)),
    # A migrate that seals nothing is caught.
    ("migrate", lambda m: m.setattr(selftest, "migrate", lambda store, env: [])),
    # With master.key still on disk the tpm2 provider is not ok.
    ("tpm2 only", _keep_master_key),
    # An audit log that does not verify.
    ("tpm2 only", lambda m: m.setattr(
        selftest.SovereignDataPlane, "verify_audit_integrity", lambda self: False)),
    # Without the encrypted data in the second store nothing reads back.
    ("restore", lambda m: m.setattr(selftest.shutil, "copy2", lambda a, b: None)),
    # An unchanged blob still unseals, which the tamper step catches.
    ("tamper", lambda m: m.setattr(selftest, "_flip", _no_flip)),
    # Refusing is not enough if a new key takes the old one's place.
    ("tamper", _refuse_after_writing("master.key.sealed", b"replaced\n")),
    ("tamper", _refuse_after_writing("master.key", b"y" * 43 + b"=")),
]  # fmt: skip


@pytest.mark.parametrize(("step", "breaker"), BREAKERS, ids=[
    "probe", "migrate", "master-key-kept", "audit", "restore", "unchanged-blob",
    "blob-replaced", "plain-key-created"])  # fmt: skip
def test_each_step_reports_a_failure_when_its_check_fails(
    env, capsys, monkeypatch, step, breaker
):
    breaker(monkeypatch)
    assert cli(["selftest"], env) == 1
    lines = capsys.readouterr().out.splitlines()[1:]  # after "Reaching the TPM"
    failed = STEP_NAMES.index(step)
    assert sum(line.startswith("ok   ") for line in lines) == failed
    assert lines[1 + failed].startswith(f"FAIL {failed + 1} {step}")
    assert lines[-1] == "selftest FAILED: a step failed."


def test_a_tpm_that_cannot_be_reached_stops_before_any_step(env, tmp_path, capsys):
    env["NGARI_TPM_TCTI"] = f"libtpms:{tmp_path / 'missing' / 'state'}"
    assert cli(["selftest", "--json"], env) == 1
    report = json.loads(capsys.readouterr().out)
    assert (report["passed"], report["steps"], report["tpm"]) == (False, [], None)
    assert report["error"].startswith("cannot reach the TPM: tpm2_getcap failed")


def test_missing_tools_are_reported(env, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert cli(["selftest"], env) == 1
    assert "not found on PATH" in capsys.readouterr().out


def test_the_identity_of_a_hardware_tpm_is_read_from_getcap():
    nuvoton = (
        'TPM2_PT_FAMILY_INDICATOR:\n  raw: 0x322E3000\n  value: "2.0"\n'
        "TPM2_PT_LEVEL:\n  raw: 0\n"
        "TPM2_PT_REVISION:\n  raw: 0x74\n  value: 1.16\n"
        'TPM2_PT_MANUFACTURER:\n  raw: 0x4E544300\n  value: "NTC"\n'
        'TPM2_PT_VENDOR_STRING_1:\n  raw: 0x4E504354\n  value: "NPCT"\n'
        'TPM2_PT_VENDOR_STRING_2:\n  raw: 0x37357800\n  value: "75x"\n'
        'TPM2_PT_VENDOR_STRING_3:\n  raw: 0x0\n  value: ""\n'
        "TPM2_PT_FIRMWARE_VERSION_1:\n  raw: 0x70002\n"
        "TPM2_PT_FIRMWARE_VERSION_2:\n  raw: 0x10000\n"
    )
    assert parse_identity(nuvoton) == {
        "manufacturer": "NTC", "vendor": "NPCT75x", "family": "2.0",
        "revision": "1.16", "firmware": "0x70002 0x10000",
    }  # fmt: skip
    assert parse_identity("") == {
        "manufacturer": "",
        "vendor": "",
        "family": "",
        "revision": "",
        "firmware": "",
    }


def test_the_selftest_needs_no_card_and_reads_no_data_directory(
    env, monkeypatch, capsys
):
    # The operator gate is for commands that read the real key; this one
    # does not, so NGARI_OPERATOR_AUTH=card asks for nothing.
    env["NGARI_OPERATOR_AUTH"] = "card"
    assert cli(["selftest"], env) == 0
    assert "operator:" not in capsys.readouterr().out
    assert not Path(env["NGARI_DATA_DIR"]).exists()


def test_the_default_tcti_is_the_hardware_resource_manager():
    # Documented for operators; tests always pass a libtpms TCTI.
    assert TPMKeyProvider.from_env(Path("k"), {}).tcti == "device:/dev/tpmrm0"
    assert "NGARI_TPM_TCTI" not in os.environ or not os.environ[
        "NGARI_TPM_TCTI"
    ].startswith("device:")


# -- the PCR step ---------------------------------------------------------------------


def test_pcr_banks_count_only_when_allocated():
    from core.kernel.data_plane.tpm import parse_pcr_banks

    getcap = (
        "selected-pcrs:\n  - sha1: [ ]\n  - sha256: [ 0, 1, 2, 7 ]\n  - sha384: [  ]\n"
    )
    assert parse_pcr_banks(getcap) == ["sha256"]
    assert parse_pcr_banks("selected-pcrs:\n  - sha1: [ ]\n") == []


@pytest.mark.parametrize(
    ("args", "extra", "pcrs"),
    [(["--pcrs", "sha256:7"], {}, "sha256:7"),
     ([], {"NGARI_TPM_PCRS": "sha256:0,7"}, "sha256:0,7")],
    ids=["flag", "env"],
)  # fmt: skip
def test_a_pcr_selection_adds_a_bound_restore(env, capsys, args, extra, pcrs):
    env.update(extra)
    assert cli(["selftest", "--json", *args], env) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["pcrs"] == pcrs
    assert "sha256" in report["tpm"]["pcr_banks"]
    assert [s["step"] for s in report["steps"]] == [*STEP_NAMES, "pcr policy"]
    assert report["steps"][-1]["detail"].startswith(
        f"keys restore bound a third store to PCRs {pcrs}"
    )
    assert selftest.format_report(report)[-1].startswith(
        "selftest passed: 7 of 7 steps."
    )


def test_none_turns_the_pcr_step_off(env, capsys):
    env["NGARI_TPM_PCRS"] = "sha256:7"
    assert cli(["selftest", "--pcrs", "none"], env) == 0
    out = capsys.readouterr().out
    assert "pcr policy" not in out
    assert out.splitlines()[-1].startswith("selftest passed: 6 of 6 steps.")


def test_a_bad_selection_stops_before_the_tpm_is_used(env, capsys, monkeypatch):
    monkeypatch.setattr(
        TPMKeyProvider, "identity", lambda self: pytest.fail("the TPM was contacted")
    )
    assert cli(["selftest", "--json", "--pcrs", "sha1:7"], env) == 1
    report = json.loads(capsys.readouterr().out)
    assert (report["passed"], report["tpm"], report["steps"]) == (False, None, [])
    assert "sha1:7" in report["error"]


def test_a_tpm_without_a_sha256_bank_is_reported(env, capsys, monkeypatch):
    from core.kernel.data_plane import tpm

    monkeypatch.setattr(tpm, "parse_pcr_banks", lambda text: ["sha1"])
    assert cli(["selftest", "--pcrs", "sha256:7"], env) == 1
    out = capsys.readouterr().out
    assert "PCR banks sha1" in out.splitlines()[1]
    assert out.splitlines()[-1] == (
        "selftest FAILED: the TPM has no allocated sha256 PCR bank, so a sha256 PCR "
        "policy cannot be used (allocated: sha1)."
    )


def test_the_pcr_step_fails_when_the_key_is_not_bound(env, capsys, monkeypatch):
    real = selftest.restore
    monkeypatch.setattr(
        selftest,
        "restore",
        lambda store, e, bundle, phrase, pcrs=None: real(store, e, bundle, phrase),
    )
    assert cli(["selftest", "--pcrs", "sha256:7"], env) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[-2].startswith("FAIL 7 pcr policy")
    assert "is not bound to sha256:7" in lines[-2]


def test_each_line_is_printed_as_soon_as_it_is_known(env, monkeypatch):
    # A hardware TPM can take a minute a step: the lines must come out while
    # the run goes on, not all at the end.
    from core.kernel.data_plane import selftest

    seen = []
    real = selftest.STEPS[1][1]

    def second_step(run):
        seen.append(("second step starts", list(printed)))
        return real(run)

    printed = []
    monkeypatch.setattr(
        selftest,
        "STEPS",
        [selftest.STEPS[0], ("migrate", second_step), *selftest.STEPS[2:]],
    )
    report = selftest.run_selftest(env, None, printed.append)
    assert report["passed"]
    [(_, before)] = seen
    assert before[0].startswith("Reaching the TPM") and before[1].startswith("TPM: ")
    assert before[2].startswith("ok   1 file key")  # step 1 is out before step 2 begins
    assert printed[2:] == selftest.format_report(report)[1:-1]
