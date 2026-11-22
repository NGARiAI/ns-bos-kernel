"""docs/FIPS.md lists every cryptographic primitive the kernel uses. The
inventory is read from the code under core/, so a new primitive, or a new
algorithm handed to the TPM or card tools, fails here until the document
lists it, and one the code does not use fails here until it is removed."""

import ast
import itertools
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "core"
DOC = (ROOT / "docs" / "FIPS.md").read_text()

STDLIB = {"hashlib", "hmac", "secrets", "random"}
# Flags whose value names an algorithm: tpm2-tools -G and -g, pkcs11-tool
# --mechanism.
TOOL_FLAGS = {"-G", "-g", "--mechanism"}
# Imported from cryptography but not primitives: exceptions, certificate
# parsing and encodings.
NOT_PRIMITIVES = {
    "InvalidToken",
    "InvalidSignature",
    "UnsupportedAlgorithm",
    "NameOID",
    "x509",
    "serialization",
}


def _strings(nodes):
    return [n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None
            for n in nodes]  # fmt: skip


def uses(source: str) -> set[str]:
    tree = ast.parse(source)
    crypto = set()  # local names bound to something from cryptography
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if node.module.startswith("cryptography"):
                    crypto.add(alias.asname or alias.name)
                elif node.module in STDLIB:
                    found.add(f"{node.module}.{alias.name}")
    qualified = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            base, attr = node.value.id, node.attr
            qualified.add(id(node.value))
            if base in STDLIB or (base, attr) in {("os", "urandom")}:
                found.add(f"{base}.{attr}")
            elif base == "uuid" and attr.startswith("uuid"):
                found.add(f"uuid.{attr}")
            elif base in crypto and base not in NOT_PRIMITIVES:
                found.add(f"{base}.{attr}")
        elif isinstance(node, (ast.Tuple, ast.List, ast.Call)):
            items = _strings(node.elts if not isinstance(node, ast.Call) else node.args)
            for flag, value in itertools.pairwise(items):
                if flag in TOOL_FLAGS and value is not None:
                    found.add(f"{flag} {value}")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in crypto
            and node.id not in NOT_PRIMITIVES
            and id(node) not in qualified
        ):
            found.add(node.id)
    return found


def _code_inventory() -> set[str]:
    tracked = subprocess.run(
        ["git", "ls-files", "core/*.py", "core/**/*.py"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()  # fmt: skip
    found = set()
    for path in tracked:
        found |= uses((ROOT / path).read_text())
    return found


def _doc_inventory() -> set[str]:
    section = DOC.split("## Inventory", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("| `")]
    return {re.match(r"\| `([^`]+)`", row).group(1) for row in rows}


def differences(code: set[str], doc: set[str]) -> list[str]:
    problems = []
    if code - doc:
        problems.append(f"used in core/ but not in docs/FIPS.md: {sorted(code - doc)}")
    if doc - code:
        problems.append(
            f"in docs/FIPS.md but no longer used in core/: {sorted(doc - code)}"
        )
    return problems


def test_the_document_lists_every_primitive_the_code_uses():
    assert differences(_code_inventory(), _doc_inventory()) == []


def test_a_new_use_and_a_stale_row_are_both_reported():
    assert differences({"a", "new"}, {"a", "gone"}) == [
        "used in core/ but not in docs/FIPS.md: ['new']",
        "in docs/FIPS.md but no longer used in core/: ['gone']",
    ]


def test_the_inventory_sees_each_kind_of_use():
    source = """
import hashlib, hmac, os, secrets, uuid, random
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
hashlib.md5(b"")
hmac.new(b"k", b"m", hashlib.sha1)
os.urandom(16), os.getpid(), uuid.uuid4(), random.random(), secrets.token_bytes(8)
hashes.SHA1()
AESGCM(b"0" * 16)
run("tpm2_create", "-g", "sha1", "-G", "rsa2048")
mechanism = ("--mechanism", "SHA1-RSA-PKCS", "--id", "01")
"""
    assert uses(source) == {
        "hashlib.md5", "hashlib.sha1", "hashlib.pbkdf2_hmac", "hmac.new", "os.urandom",
        "uuid.uuid4", "random.random", "secrets.token_bytes", "hashes.SHA1", "AESGCM",
        "-g sha1", "-G rsa2048", "--mechanism SHA1-RSA-PKCS",
    }  # fmt: skip


CLAIM = re.compile(
    r"FIPS[ -]?140[^.\n]{0,40}\b(compliant|certified|validated)\b", re.IGNORECASE
)


@pytest.mark.parametrize(
    ("text", "claims"),
    [("The kernel is FIPS 140-3 validated.", True),
     ("NS-BOS is fips-140 compliant", True),
     ("FIPS 140-2 certified TPM", True),
     ("This document claims no FIPS 140-3 compliance.", False),
     ("A FIPS deployment needs a validated module.", False)],
)  # fmt: skip
def test_the_claim_pattern(text, claims):
    assert bool(CLAIM.search(text)) is claims


def test_no_document_claims_fips_compliance():
    assert "claims no FIPS 140-3 compliance" in " ".join(DOC.split())
    tracked = subprocess.run(
        ["git", "ls-files", "*.md", "*.py", "*.txt", "*.toml", "*.cfg"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()  # fmt: skip
    claim = CLAIM
    for path in tracked:
        if path in ("docs/FIPS.md", "tests/test_fips_inventory.py"):
            continue
        text = (ROOT / path).read_text(errors="replace")
        assert not claim.search(text), path
