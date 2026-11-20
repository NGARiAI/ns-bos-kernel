"""Signed releases (RELEASING.md, Sign a release): `release.py verify` checks
a downloaded release against SHA256SUMS and its OpenSSH signature, and fails
closed on a wrong key, an altered file, a missing file or an extra one.
Keys are made for each test in its tmp directory and thrown away."""

import base64
import hashlib
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "ngari_release_verify", REPO_ROOT / "scripts" / "release.py"
)
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)

pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="ssh-keygen (openssh-client) missing"
)
V = "0.2.0"


def _key(tmp_path, name="release", kind="ed25519"):
    path = tmp_path / name
    args = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", name, "-f", str(path)]
    subprocess.run(args, check=True)
    return path, Path(f"{path}.pub")


def _sign(key, sums, namespace=release.NAMESPACE):
    sig = Path(f"{sums}.sig")
    sig.unlink(missing_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", namespace, str(sums)],
        check=True,
        capture_output=True,
    )
    return sig


def _release(tmp_path, key, version=V):
    """A release directory as the workflow publishes it, signed with key."""
    out = tmp_path / "dist"
    out.mkdir()
    for name in release.RELEASE_FILES:
        (out / name.format(v=version)).write_bytes(f"{name} {version}\n".encode())
    release.write_checksums(out)
    _sign(key, out / "SHA256SUMS")
    return out


def _relist(key, out):
    """SHA256SUMS for the files there now, signature aside, signed again."""
    names = sorted(
        p.name for p in out.iterdir() if p.name not in ("SHA256SUMS", "SHA256SUMS.sig")
    )
    lines = [
        f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}" for n in names
    ]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    _sign(key, out / "SHA256SUMS")


def _verify(out, pub):
    return release.verify_release(out, pub)


def test_a_signed_release_verifies(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    lines = _verify(out, pub)
    blob = base64.b64decode(pub.read_text().split()[1])
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode()
    assert lines == [
        f"signature: good, ssh-ed25519 key {fingerprint.rstrip('=')}",
        f"files: the {V} wheel, source tarball and SBOM match SHA256SUMS",
    ]
    shown = subprocess.run(
        ["ssh-keygen", "-l", "-f", str(pub)], capture_output=True, text=True, check=True
    ).stdout
    assert release.key_fingerprint(blob) in shown  # what the signer publishes


@pytest.mark.parametrize("kind", ["ecdsa", "rsa"])
def test_other_key_types_verify(tmp_path, kind):
    key, pub = _key(tmp_path, kind=kind)
    assert _verify(_release(tmp_path, key), pub)


def test_the_command_line_says_so_and_exits_0(tmp_path, capsys):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    assert release.main(["verify", "--dir", str(out), "--key", str(pub)]) == 0
    assert capsys.readouterr().out.startswith(
        "signature: good, ssh-ed25519 key SHA256:"
    )


def test_the_directory_defaults_to_here(tmp_path, monkeypatch, capsys):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    monkeypatch.chdir(out)
    assert release.main(["verify", "--key", str(pub)]) == 0


def _refused(out, pub, why):
    with pytest.raises(release.ReleaseError, match=why):
        _verify(out, pub)
    assert release.main(["verify", "--dir", str(out), "--key", str(pub)]) == 1


def test_another_key_is_refused(tmp_path):
    key, _ = _key(tmp_path)
    _, other = _key(tmp_path, "other")
    _refused(
        _release(tmp_path, key), other, "not a signature of SHA256SUMS by this key"
    )


def test_a_signature_in_another_namespace_is_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    _sign(key, out / "SHA256SUMS", namespace="file")
    _refused(out, pub, "in the ngari-release namespace")


def test_an_altered_checksum_list_is_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    wheel = out / f"ns_bos-{V}-py3-none-any.whl"
    wheel.write_bytes(b"something else\n")
    sums = out / "SHA256SUMS"
    digest = hashlib.sha256(b"something else\n").hexdigest()
    lines = sums.read_text().splitlines()
    lines = [f"{digest}  {wheel.name}" if wheel.name in x else x for x in lines]
    sums.write_text("\n".join(lines) + "\n")  # made to match, not signed again
    _refused(out, pub, "not a signature of SHA256SUMS")


def test_an_altered_file_is_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    (out / f"ns-bos-kernel-{V}.tar.gz").write_bytes(b"tampered\n")
    _refused(out, pub, f"ns-bos-kernel-{V}.tar.gz does not match SHA256SUMS")


@pytest.mark.parametrize(
    "name",
    [f"ns_bos-{V}-py3-none-any.whl", f"ns-bos-kernel-{V}.tar.gz",
     f"ns-bos-kernel-{V}.spdx.json"],
)  # fmt: skip
def test_a_missing_file_is_refused(tmp_path, name):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    (out / name).unlink()
    _refused(out, pub, f"missing {name}")


@pytest.mark.parametrize("name", ["SHA256SUMS", "SHA256SUMS.sig"])
def test_a_missing_checksum_list_or_signature_is_refused(tmp_path, name):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    (out / name).unlink()
    _refused(out, pub, f"{name} is missing")


def test_an_extra_file_is_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    (out / "install.sh").write_text("curl ... | sh\n")
    _refused(out, pub, "not part of the release install.sh")


def _resign(tmp_path, key, out, text):
    (out / "SHA256SUMS").write_text(text)
    _sign(key, out / "SHA256SUMS")


def test_a_signed_list_with_an_extra_file_is_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    (out / "install.sh").write_text("x\n")
    _relist(key, out)
    _refused(out, pub, "a 0.2.0 release holds")


@pytest.mark.parametrize(
    ("line", "why"),
    [(f"{'0' * 64} ns_bos-{V}-py3-none-any.whl", "line 1 is not"),
     (f"{'0' * 64}  ../ns_bos-{V}-py3-none-any.whl", "line 1 is not"),
     (f"{'0' * 64}  dir/ns_bos-{V}-py3-none-any.whl", "line 1 is not"),
     (f"{'0' * 63}  ns_bos-{V}-py3-none-any.whl", "line 1 is not"),
     (f"{'A' * 64}  ns_bos-{V}-py3-none-any.whl", "line 1 is not")],
)  # fmt: skip
def test_a_malformed_list_is_refused(tmp_path, line, why):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    _resign(tmp_path, key, out, line + "\n")
    _refused(out, pub, why)


def test_a_name_listed_twice_is_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    first = (out / "SHA256SUMS").read_text().splitlines()[0]
    _resign(tmp_path, key, out, (out / "SHA256SUMS").read_text() + first + "\n")
    _refused(out, pub, "twice")


def test_a_list_that_is_not_text_is_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    (out / "SHA256SUMS").write_bytes(b"\xff\xfe")
    _sign(key, out / "SHA256SUMS")
    _refused(out, pub, "not ASCII")


def test_files_of_two_versions_are_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    (out / f"ns-bos-kernel-{V}.tar.gz").rename(out / "ns-bos-kernel-0.1.0.tar.gz")
    _relist(key, out)
    _refused(out, pub, "a 0.2.0 release holds")


def test_a_list_with_no_wheel_or_two_is_refused(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    digest = "0" * 64
    _resign(tmp_path, key, out, f"{digest}  ns-bos-kernel-{V}.tar.gz\n")
    _refused(out, pub, "exactly one wheel")
    two = f"{digest}  ns_bos-0.1.0-py3-none-any.whl\n{digest}  ns_bos-{V}-py3-none-any.whl\n"
    _resign(tmp_path, key, out, two)
    _refused(out, pub, "exactly one wheel")


# -- the key file -------------------------------------------------------------------


def test_a_private_key_is_refused_with_a_warning(tmp_path):
    key, _ = _key(tmp_path)
    out = _release(tmp_path, key)
    _refused(out, key, "is a private key; give its .pub")


@pytest.mark.parametrize(
    ("content", "why"),
    [("", "not one OpenSSH public key line"),
     ("ssh-ed25519\n", "not one OpenSSH public key line"),
     ("ssh-dss AAAAB3NzaC1kc3M= x\n", "not one OpenSSH public key line"),
     ("ssh-ed25519 !!!notbase64 x\n", "not base64"),
     ("ssh-ed25519 AAAA*AAAA x\n", "not base64"),
     ("ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQAB x\n", "not a ssh-ed25519 key")],
)  # fmt: skip
def test_a_bad_key_file_is_refused(tmp_path, content, why):
    key, _ = _key(tmp_path)
    out = _release(tmp_path, key)
    bad = tmp_path / "bad.pub"
    bad.write_text(content)
    _refused(out, bad, why)


def test_two_keys_in_one_file_are_refused(tmp_path):
    key, pub = _key(tmp_path)
    _, other = _key(tmp_path, "other")
    out = _release(tmp_path, key)
    both = tmp_path / "both.pub"
    both.write_text(pub.read_text() + other.read_text())
    _refused(out, both, "not one OpenSSH public key line")


@pytest.mark.parametrize("kind", ["missing", "binary"])
def test_an_unreadable_key_file_is_refused(tmp_path, kind):
    key, _ = _key(tmp_path)
    out = _release(tmp_path, key)
    bad = tmp_path / "bad.pub"
    if kind == "binary":
        bad.write_bytes(b"\xff\x00")
    _refused(out, bad, "cannot read the public key")


def test_a_release_that_is_not_a_directory_is_refused(tmp_path):
    _, pub = _key(tmp_path)
    _refused(tmp_path / "nothing", pub, "is not a directory")


def test_without_ssh_keygen_it_says_what_to_install(tmp_path, monkeypatch):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    monkeypatch.setattr(release.shutil, "which", lambda name: None)
    _refused(out, pub, "package: openssh-client")


def test_a_hung_ssh_keygen_is_stopped(tmp_path, monkeypatch):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)

    def hung(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 60)

    monkeypatch.setattr(release.subprocess, "run", hung)
    _refused(out, pub, "did not finish within 60s")


def test_a_change_past_the_first_mebibyte_is_seen(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    wheel = out / f"ns_bos-{V}-py3-none-any.whl"
    data = bytearray(3 * (1 << 20) + 7)
    wheel.write_bytes(bytes(data))
    _relist(key, out)
    assert _verify(out, pub)
    data[-1] = 1
    wheel.write_bytes(bytes(data))
    _refused(out, pub, "does not match SHA256SUMS")


def test_a_file_that_cannot_be_read_exits_1(tmp_path, monkeypatch, capsys):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)

    def unreadable(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(release, "_file_digest", unreadable)
    assert release.main(["verify", "--dir", str(out), "--key", str(pub)]) == 1
    assert "Permission denied" in capsys.readouterr().err


def test_the_version_asked_for_must_be_the_one_signed(tmp_path):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key, version="0.1.0")  # an older release, signed
    assert _verify(out, pub)  # it is a good release
    assert release.verify_release(out, pub, "0.1.0")
    with pytest.raises(release.ReleaseError, match="signed 0.1.0 release, not 0.2.0"):
        release.verify_release(out, pub, "0.2.0")
    args = ["verify", "--dir", str(out), "--key", str(pub)]
    assert release.main([*args, "--version", "0.2.0"]) == 1
    assert release.main([*args, "--version", "0.1.0"]) == 0


@pytest.mark.parametrize("version", ["v0.2.0", "0.2", "0.2.0-rc1", ""])
def test_a_version_that_is_not_one_is_refused(tmp_path, version):
    key, pub = _key(tmp_path)
    out = _release(tmp_path, key)
    with pytest.raises(release.ReleaseError, match="is not a version"):
        release.verify_release(out, pub, version)
