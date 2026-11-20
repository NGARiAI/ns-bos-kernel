"""Release tooling for the NS-BOS kernel.

    python scripts/release.py check [--tag vX.Y.Z]
    python scripts/release.py notes [--tag vX.Y.Z]
    python scripts/release.py build [--outdir dist] [--allow-dirty]
    python scripts/release.py repro
    python scripts/release.py verify --dir DIR --key ngari-release.pub [--version X.Y.Z]

``check`` fails unless the version in core/kernel/__init__.py, the version in
core/kernel/setup.py and a CHANGELOG.md heading agree, and, when --tag is
given, unless the tag is exactly ``v`` plus that version. A version is
MAJOR.MINOR.PATCH with an optional a, b or rc suffix (1.2.3, 1.2.3rc1).
setuptools rewrites 1.2.3-rc1 to 1.2.3rc1 inside the wheel, so the hyphen
form is refused here instead of failing later in the build.

``notes`` prints the CHANGELOG.md section for the release version, for use
as the release notes. It runs ``check`` first and fails on an empty section.

``build`` writes a wheel, a source tarball, an SBOM and a SHA256SUMS file.
``repro`` builds the wheel twice and fails if the two differ.
``verify`` checks a downloaded release: SHA256SUMS.sig must be an OpenSSH
signature of SHA256SUMS (``ssh-keygen -Y sign -n ngari-release``) by the
given public key, SHA256SUMS must list exactly the wheel, the source tarball
and the SBOM of one version, the directory must hold those, SHA256SUMS and
its signature and nothing else, and every file must match its line.
For a given commit the wheel is byte-for-byte reproducible: file timestamps
come from SOURCE_DATE_EPOCH (default: the commit time) and the build runs
with --no-isolation against the pinned setuptools and wheel in
core/kernel/requirements-dev.txt. The sdist route is not used because the
root setup.py shim does not produce a usable one.

Stdlib only.
"""

import argparse
import base64
import binascii
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INIT = REPO_ROOT / "core" / "kernel" / "__init__.py"
SETUP = REPO_ROOT / "core" / "kernel" / "setup.py"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
SBOM_SCRIPT = REPO_ROOT / "scripts" / "sbom.py"

_INIT_VERSION = re.compile(r'^VERSION\s*=\s*"([^"]+)"', re.MULTILINE)
_SETUP_VERSION = re.compile(r'^\s*version\s*=\s*"([^"]+)"', re.MULTILINE)
_VERSION_FORMAT = re.compile(r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?$")

# Release signatures: ssh-keygen -Y sign -f KEY -n ngari-release SHA256SUMS
NAMESPACE = "ngari-release"
PRINCIPAL = "ngari-release"
SIGNATURE = "SHA256SUMS.sig"
RELEASE_FILES = (
    "ns_bos-{v}-py3-none-any.whl",
    "ns-bos-kernel-{v}.tar.gz",
    "ns-bos-kernel-{v}.spdx.json",
)
KEY_TYPES = frozenset(
    {
        "ssh-ed25519",
        "sk-ssh-ed25519@openssh.com",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-rsa",
    }
)
_SUM_LINE = re.compile(r"([0-9a-f]{64})  ([^\s/\\][^/\\]*)")
_WHEEL_NAME = re.compile(r"ns_bos-(.+)-py3-none-any\.whl")


class ReleaseError(Exception):
    pass


def _heading(version: str) -> re.Pattern:
    return re.compile(rf"^## \[{re.escape(version)}\][^\n]*$", re.MULTILINE)


def _find(pattern: re.Pattern, path: Path, label: str) -> str:
    match = pattern.search(path.read_text(encoding="utf-8"))
    if not match:
        raise ReleaseError(f"no version found in {label}")
    return match.group(1)


def check(tag: str | None = None) -> str:
    """Return the release version, or raise ReleaseError if sources disagree."""
    in_init = _find(_INIT_VERSION, INIT, "core/kernel/__init__.py")
    in_setup = _find(_SETUP_VERSION, SETUP, "core/kernel/setup.py")
    if in_init != in_setup:
        raise ReleaseError(
            f"version mismatch: core/kernel/__init__.py has {in_init}, "
            f"core/kernel/setup.py has {in_setup}"
        )
    version = in_init
    if not _VERSION_FORMAT.match(version):
        raise ReleaseError(
            f"{version!r} is not MAJOR.MINOR.PATCH with an optional a, b or rc "
            "suffix such as 0.2.0rc1"
        )
    if not _heading(version).search(CHANGELOG.read_text(encoding="utf-8")):
        raise ReleaseError(f"CHANGELOG.md has no '## [{version}]' section")
    if tag is not None and tag != f"v{version}":
        raise ReleaseError(
            f"tag {tag!r} does not match version {version} (want v{version})"
        )
    return version


def changelog_section(version: str) -> str:
    """Return the CHANGELOG.md text under ``## [version]``, heading excluded."""
    text = CHANGELOG.read_text(encoding="utf-8")
    start = _heading(version).search(text)
    if not start:
        raise ReleaseError(f"CHANGELOG.md has no '## [{version}]' section")
    rest = text[start.end() :]
    following = re.search(r"^## ", rest, re.MULTILINE)
    body = (rest[: following.start()] if following else rest).strip()
    if not body:
        raise ReleaseError(f"CHANGELOG.md section '## [{version}]' is empty")
    return body


def _git(*args: str) -> str:
    out = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True
    )
    return out.stdout.strip()


def _export_tracked_files(dest: Path) -> None:
    """Copy the tracked files into dest so build debris stays out of the checkout."""
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, check=True, capture_output=True
    ).stdout.decode()
    for rel in filter(None, listing.split("\0")):
        source = REPO_ROOT / rel
        if source.is_file():
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def build_wheel(outdir: Path, env: dict) -> Path:
    outdir = outdir.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "tree"
        _export_tracked_files(tree)
        proc = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--no-isolation"]
            + ["--outdir", str(outdir)],
            cwd=tree,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise ReleaseError("wheel build failed")
    wheels = sorted(outdir.glob("*.whl"))
    if len(wheels) != 1:
        raise ReleaseError(f"expected one wheel in {outdir}, found {len(wheels)}")
    return wheels[0]


def check_wheel(wheel: Path, version: str) -> None:
    """Fail if the wheel holds anything other than the kernel package."""
    dist_info = f"ns_bos-{version}.dist-info/"
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
    stray = [
        n
        for n in names
        if not n.startswith(("core/kernel/", dist_info))
        or "__pycache__" in n
        or n.endswith(".pyc")
        or "/build/" in n
    ]
    if stray:
        raise ReleaseError(f"{wheel.name} contains unexpected files: {stray[:5]}")
    if "core/kernel/__init__.py" not in names:
        raise ReleaseError(f"{wheel.name} has no core/kernel/__init__.py")


def write_checksums(outdir: Path) -> Path:
    lines = []
    for item in sorted(outdir.iterdir()):
        if item.is_file() and item.name != "SHA256SUMS":
            digest = hashlib.sha256(item.read_bytes()).hexdigest()
            lines.append(f"{digest}  {item.name}")
    target = outdir / "SHA256SUMS"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def repro() -> str:
    """Build the wheel twice; return its sha256 or raise if the builds differ."""
    version = check()
    env = os.environ.copy()
    env.setdefault("SOURCE_DATE_EPOCH", _git("log", "-1", "--format=%ct"))
    digests = []
    with tempfile.TemporaryDirectory() as tmp:
        for n in (1, 2):
            wheel = build_wheel(Path(tmp) / f"build{n}", env)
            check_wheel(wheel, version)
            digests.append(hashlib.sha256(wheel.read_bytes()).hexdigest())
    if digests[0] != digests[1]:
        raise ReleaseError(f"wheel is not reproducible: {digests[0]} != {digests[1]}")
    return digests[0]


def build(outdir: Path, allow_dirty: bool = False) -> list[Path]:
    version = check()
    if not allow_dirty and _git("status", "--porcelain"):
        raise ReleaseError(
            "working tree has uncommitted changes; commit or --allow-dirty"
        )
    if outdir.exists() and any(outdir.iterdir()):
        raise ReleaseError(f"{outdir} is not empty; remove it first")
    outdir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.setdefault("SOURCE_DATE_EPOCH", _git("log", "-1", "--format=%ct"))

    wheel = build_wheel(outdir, env)
    check_wheel(wheel, version)

    prefix = f"ns-bos-kernel-{version}"
    subprocess.run(
        ["git", "archive", "--format=tar.gz", f"--prefix={prefix}/"]
        + ["-o", str(outdir / f"{prefix}.tar.gz"), "HEAD"],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(SBOM_SCRIPT),
            "--output",
            str(outdir / f"{prefix}.spdx.json"),
        ],
        check=True,
    )
    write_checksums(outdir)
    return sorted(outdir.iterdir())


def _public_key(path: Path) -> tuple[str, bytes]:
    """The key type and key blob of the one OpenSSH public key in path."""
    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseError(f"cannot read the public key {path}: {exc}") from None
    if "PRIVATE KEY" in text:
        raise ReleaseError(
            f"{path} is a private key; give its .pub, and keep the private key "
            "off this machine"
        )
    lines = [line for line in text.splitlines() if line.strip()]
    fields = lines[0].split() if len(lines) == 1 else []
    if len(fields) < 2 or fields[0] not in KEY_TYPES:
        raise ReleaseError(
            f"{path} is not one OpenSSH public key line (ssh-ed25519 AAAA...)"
        )
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except binascii.Error:
        raise ReleaseError(f"{path}: the key is not base64") from None
    size = int.from_bytes(blob[:4], "big")
    if blob[4 : 4 + size] != fields[0].encode():
        raise ReleaseError(f"{path}: the key data is not a {fields[0]} key")
    return fields[0], blob


def key_fingerprint(blob: bytes) -> str:
    """As ssh-keygen -l prints it: SHA256: and unpadded base64."""
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode()
    return "SHA256:" + digest.rstrip("=")


def _check_signature(data: bytes, sig: Path, keytype: str, blob: bytes) -> None:
    tool = shutil.which("ssh-keygen")
    if tool is None:
        raise ReleaseError(
            "ssh-keygen not found (Debian and Ubuntu package: openssh-client)"
        )
    key = base64.b64encode(blob).decode()
    with tempfile.TemporaryDirectory() as tmp:
        allowed = Path(tmp) / "allowed_signers"
        allowed.write_text(f"{PRINCIPAL} {keytype} {key}\n", encoding="ascii")
        try:
            proc = subprocess.run(
                [tool, "-Y", "verify", "-f", str(allowed), "-I", PRINCIPAL]
                + ["-n", NAMESPACE, "-s", str(sig)],
                input=data,
                capture_output=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ReleaseError("ssh-keygen did not finish within 60s") from None
    if proc.returncode != 0:
        raise ReleaseError(
            f"{SIGNATURE} is not a signature of SHA256SUMS by this key in the "
            f"{NAMESPACE} namespace. Do not install these files."
        )


def _listed(data: bytes) -> dict[str, str]:
    """name: sha256 from SHA256SUMS, in the format write_checksums makes."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ReleaseError("SHA256SUMS is not ASCII text") from None
    listed: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = _SUM_LINE.fullmatch(line)
        if not match:
            raise ReleaseError(f"SHA256SUMS line {number} is not '<sha256>  <name>'")
        digest, name = match.groups()
        if name in listed:
            raise ReleaseError(f"SHA256SUMS lists {name} twice")
        listed[name] = digest
    return listed


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release(directory: Path, key: Path, version: str | None = None) -> list[str]:
    """Check a downloaded release against its signed SHA256SUMS, or raise
    ReleaseError. The signature is checked before anything in SHA256SUMS is
    trusted. With version, an older release, signed as well, is refused."""
    if version is not None and not _VERSION_FORMAT.match(version):
        raise ReleaseError(f"{version!r} is not a version such as 0.2.0 or 0.2.0rc1")
    keytype, blob = _public_key(Path(key))
    directory = Path(directory)
    if not directory.is_dir():
        raise ReleaseError(f"{directory} is not a directory")
    sums, sig = directory / "SHA256SUMS", directory / SIGNATURE
    for need in (sums, sig):
        if not need.is_file():
            raise ReleaseError(f"{need.name} is missing from {directory}")
    data = sums.read_bytes()
    _check_signature(data, sig, keytype, blob)
    listed = _listed(data)
    versions = {m.group(1) for n in listed if (m := _WHEEL_NAME.fullmatch(n))}
    if len(versions) != 1:
        raise ReleaseError("SHA256SUMS does not list exactly one wheel")
    found = versions.pop()
    if version is not None and found != version:
        raise ReleaseError(
            f"this is the signed {found} release, not {version}. Do not install it "
            f"as {version}."
        )
    version = found
    expected = {f.format(v=version) for f in RELEASE_FILES}
    if set(listed) != expected:
        raise ReleaseError(
            f"SHA256SUMS lists {', '.join(sorted(listed))}; a {version} release "
            f"holds {', '.join(sorted(expected))}"
        )
    present = {p.name for p in directory.iterdir()}
    wanted = expected | {"SHA256SUMS", SIGNATURE}
    if present != wanted:
        problems = []
        if wanted - present:
            problems.append(f"missing {', '.join(sorted(wanted - present))}")
        if present - wanted:
            problems.append(
                f"not part of the release {', '.join(sorted(present - wanted))}"
            )
        raise ReleaseError(f"{directory}: {'; '.join(problems)}")
    for name in sorted(expected):
        path = directory / name
        if not path.is_file() or _file_digest(path) != listed[name]:
            raise ReleaseError(f"{name} does not match SHA256SUMS. Do not install it.")
    return [
        f"signature: good, {keytype} key {key_fingerprint(blob)}",
        f"files: the {version} wheel, source tarball and SBOM match SHA256SUMS",
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_check = sub.add_parser("check", help="verify version sources agree")
    p_check.add_argument("--tag", help="release tag to match, e.g. v0.1.0")
    p_build = sub.add_parser("build", help="build wheel, tarball, SBOM and checksums")
    p_build.add_argument("--outdir", default="dist", type=Path)
    p_build.add_argument("--allow-dirty", action="store_true")
    p_notes = sub.add_parser("notes", help="print the CHANGELOG section")
    p_notes.add_argument("--tag", help="release tag to match, e.g. v0.1.0")
    sub.add_parser("repro", help="build the wheel twice and compare")
    p_verify = sub.add_parser(
        "verify", help="check a downloaded release against its signed SHA256SUMS"
    )
    p_verify.add_argument(
        "--dir", default=".", type=Path, help="the downloaded release (default .)"
    )
    p_verify.add_argument(
        "--key", required=True, type=Path, help="the release public key (.pub)"
    )
    p_verify.add_argument(
        "--version", help="the version you mean to install; any other is refused"
    )
    args = ap.parse_args(argv)

    try:
        if args.cmd == "check":
            print(f"version {check(args.tag)} ok")
        elif args.cmd == "notes":
            print(changelog_section(check(args.tag)))
        elif args.cmd == "repro":
            print(f"reproducible: sha256 {repro()}")
        elif args.cmd == "verify":
            for line in verify_release(args.dir, args.key, args.version):
                print(line)
        else:
            for item in build(args.outdir, args.allow_dirty):
                print(item)
    except (ReleaseError, subprocess.CalledProcessError, OSError) as exc:
        print(f"release: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
