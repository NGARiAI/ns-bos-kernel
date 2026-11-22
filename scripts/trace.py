"""Write docs/validation/TRACE.md, the 21 CFR Part 11 clause-to-test trace.

Each clause the kernel addresses, how it does, and the tests that show it,
read from the ``@pytest.mark.part11("11.50(a)(1)", ...)`` markers in tests/.

    python scripts/trace.py           write the file
    python scripts/trace.py --check   exit 1 if it is out of date, a clause
                                      has no test, or a marker is wrong

The trace is the starting point for a buyer's validation (11.10(a)), not
the validation itself. Stdlib only; the tests are read, not run.
"""

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS = REPO_ROOT / "tests"
TRACE = REPO_ROOT / "docs" / "validation" / "TRACE.md"

# (clause, what it asks, how the kernel meets it, where that is documented)
CLAUSES = [
    (
        "11.10(a)",
        "Validation, including the ability to discern invalid or altered records",
        (
            "Audit verification flags an edited, removed or reordered entry; a signature "
            "check flags a changed record. This trace and the test suite are a starting "
            "point for the buyer's own validation"
        ),
        "AUDIT_LOG.md, ESIGNATURES.md",
    ),
    (
        "11.10(b)",
        (
            "Accurate and complete copies of records in human-readable and electronic "
            "form for inspection"
        ),
        (
            "`audit show` prints the verified audit trail readably or as stored "
            "JSON, selected by action, actor and date; `records signatures` shows a "
            "record's signatures"
        ),
        "AUDIT_LOG.md, ESIGNATURES.md",
    ),
    (
        "11.10(c)",
        "Protection of records for accurate retrieval through the retention period",
        (
            "Messages are kept at least 21 years, the audit log and stored data never "
            "expire, and data written under one key provider still opens after a migration"
        ),
        "RETENTION.md, KEY_PROVIDERS.md",
    ),
    (
        "11.10(d)",
        "System access limited to authorized individuals",
        (
            "The PIV/CAC card gate: a pinned certificate, the card's key and its PIN "
            "before a key or state command runs"
        ),
        "PIV_CAC.md",
    ),
    (
        "11.10(e)",
        (
            "Secure, computer-generated, time-stamped audit trail of operator actions, "
            "not obscuring earlier entries, kept as long as the records"
        ),
        (
            "Hash-chained, keyed audit log written by the kernel; the named operator as "
            "the actor; never expired"
        ),
        "AUDIT_LOG.md, PIV_CAC.md, RETENTION.md",
    ),
    (
        "11.10(g)",
        "Authority checks",
        (
            "Roles: admin for every gated command, the meaning's role for a signature, "
            "checked again after the PIN"
        ),
        "PIV_CAC.md, ESIGNATURES.md",
    ),
    (
        "11.50(a)(1)",
        "A signed record shows the signer's printed name",
        "The printed name from the operator file, signed with the record",
        "ESIGNATURES.md",
    ),
    (
        "11.50(a)(2)",
        "A signed record shows the date and time of signing",
        "UTC to the second, signed with the record",
        "ESIGNATURES.md",
    ),
    (
        "11.50(a)(3)",
        "A signed record shows the meaning of the signature",
        "Authorship, review, approval or responsibility, signed with the record",
        "ESIGNATURES.md",
    ),
    (
        "11.50(b)",
        "Those items are controlled like the record and shown in its readable form",
        "Kept in the hash-chained audit log; `records signatures` prints them",
        "ESIGNATURES.md",
    ),
    (
        "11.70",
        (
            "Signatures linked to their records so they cannot be moved or copied to "
            "falsify another"
        ),
        "The card signs the record's SHA-256",
        "ESIGNATURES.md",
    ),
    (
        "11.100(a)",
        "Each signature unique to one person, never reused or reassigned",
        (
            "One operator file per user id and one name per certificate; retired ids stay "
            "taken; a signature counts only from its signer's own card"
        ),
        "PIV_CAC.md, ESIGNATURES.md",
    ),
    (
        "11.200(a)(1)",
        "At least two distinct identification components",
        "The card, holding the private key, and its PIN",
        "ESIGNATURES.md",
    ),
    (
        "11.200(a)(1)(i)",
        "In a continuous session, the first signing uses every component",
        "Card and PIN at every signing",
        "ESIGNATURES.md",
    ),
    (
        "11.200(a)(1)(ii)",
        "Outside one continuous session, every signing uses every component",
        "Card and PIN at every signing",
        "ESIGNATURES.md",
    ),
    (
        "11.200(a)(3)",
        "Use by anyone but the owner needs two or more people to collaborate",
        (
            "A signature counts only from the signer's own card, which needs that card "
            "and its PIN"
        ),
        "ESIGNATURES.md",
    ),
    (
        "11.300(d)",
        (
            "Safeguards against unauthorized use of identification codes and "
            "passwords, and detecting attempts"
        ),
        (
            "A wrong PIN is never retried or recorded; every refusal is recorded. "
            "Reporting attempts to a security unit is the organization's"
        ),
        "PIV_CAC.md, ESIGNATURES.md",
    ),
]

NOT_TRACED = [
    (
        "Organization's procedures",
        (
            "11.10(i) training, 11.10(j) written signature policies, 11.10(k) control of "
            "system documentation, 11.100(b) verifying identity before a card is issued, "
            "11.100(c) certification to FDA, 11.300(b) periodic checks of identification "
            "codes, 11.300(c) lost or stolen cards, 11.300(e) testing of devices"
        ),
    ),
    (
        "Not addressed by the kernel yet",
        ("11.10(f) sequencing checks, 11.10(h) device checks"),
    ),
    (
        "Limits",
        (
            "A signature check cannot show the role held, or that the certificate was not "
            "yet retired, at signing time (ESIGNATURES.md, What a check proves)"
        ),
    ),
]

KNOWN = {clause for clause, *_ in CLAUSES}


def _is_part11(decorator: ast.expr) -> bool:
    func = decorator.func if isinstance(decorator, ast.Call) else decorator
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "part11"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "mark"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id == "pytest"
    )


def scan(source: str, name: str) -> tuple[dict[str, list[str]], list[str]]:
    """Clause: [test id] for one test file, and what is wrong with its markers."""
    found: dict[str, list[str]] = {}
    errors = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not _is_part11(decorator):
                continue
            where = f"{name}::{node.name}"
            args = decorator.args if isinstance(decorator, ast.Call) else []
            clauses = [a.value for a in args if isinstance(a, ast.Constant)]
            if not node.name.startswith("test_"):
                errors.append(f"{where}: part11 on something that is not a test")
                continue
            if (
                not args
                or len(clauses) != len(args)
                or not all(isinstance(c, str) for c in clauses)
            ):
                errors.append(f"{where}: part11 takes clause strings, e.g. '11.70'")
                continue
            for clause in clauses:
                if clause not in KNOWN:
                    errors.append(f"{where}: unknown clause {clause!r}")
                else:
                    found.setdefault(clause, []).append(where)
    return found, errors


def collect(tests: Path = TESTS) -> tuple[dict[str, list[str]], list[str]]:
    found: dict[str, list[str]] = {}
    errors = []
    for path in sorted(tests.glob("test_*.py")):
        name = path.relative_to(tests.parent).as_posix()
        part, wrong = scan(path.read_text(encoding="utf-8"), name)
        errors += wrong
        for clause, ids in part.items():
            found.setdefault(clause, []).extend(ids)
    errors += [f"{clause}: no test shows it" for clause in sorted(KNOWN - set(found))]
    return {c: sorted(ids) for c, ids in found.items()}, errors


def render(found: dict[str, list[str]]) -> str:
    count = len({t for ids in found.values() for t in ids})
    lines = [
        "# Part 11 trace",
        "",
        "Generated by `python scripts/trace.py` from the `part11` markers on the",
        "tests; do not edit it by hand. A test fails when it is out of date.",
        "",
        f"{len(CLAUSES)} clauses of 21 CFR Part 11, each with the tests that show how",
        f"the kernel meets it ({count} tests). This is a starting point for the",
        "buyer's validation of their system (11.10(a)), not that validation.",
        "",
        "| Clause | Requirement | How | Docs |",
        "|--------|-------------|-----|------|",
    ]
    for clause, requirement, how, docs in CLAUSES:
        lines.append(f"| {clause} | {requirement} | {how} | {docs} |")
    lines += ["", "## Tests", ""]
    for clause, requirement, _, _ in CLAUSES:
        lines += [f"### {clause}", "", requirement + ".", ""]
        lines += [f"- `{test}`" for test in found.get(clause, [])]
        lines.append("")
    lines += ["## Not traced here", ""]
    for heading, text in NOT_TRACED:
        lines += [f"- {heading}: {text}."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="fail if out of date")
    args = ap.parse_args(argv)
    found, errors = collect()
    for error in errors:
        print(f"trace: {error}", file=sys.stderr)
    text = render(found)
    if args.check:
        current = TRACE.read_text(encoding="utf-8") if TRACE.exists() else ""
        if current != text:
            print(f"trace: {TRACE.relative_to(REPO_ROOT)} is out of date; run "
                  "python scripts/trace.py", file=sys.stderr)  # fmt: skip
            return 1
        return 1 if errors else 0
    if errors:
        return 1
    TRACE.parent.mkdir(parents=True, exist_ok=True)
    TRACE.write_text(text, encoding="utf-8")
    print(f"wrote {TRACE.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
