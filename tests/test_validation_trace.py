"""docs/validation/TRACE.md (scripts/trace.py): each Part 11 clause the
kernel addresses, with the tests that show it, from the part11 markers.
It must be current, every clause must have a test, every marker must name
a known clause, and pytest must see the same marked tests the scan does."""

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "ngari_trace", ROOT / "scripts" / "trace.py"
)
trace = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(trace)


def test_the_trace_is_current_and_complete():
    found, errors = trace.collect()
    assert errors == []
    assert trace.TRACE.read_text(encoding="utf-8") == trace.render(found)


def test_pytest_sees_the_marked_tests_the_scan_sees():
    found, _ = trace.collect()
    scanned = {t for ids in found.values() for t in ids}
    files = sorted({t.split("::")[0] for t in scanned})
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", "part11", *files],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )  # fmt: skip
    collected = {
        re.sub(r"\[.*\]$", "", line) for line in run.stdout.splitlines() if "::" in line
    }
    assert collected == scanned, run.stdout[-2000:]


def test_the_check_command_passes_on_the_committed_trace():
    assert trace.main(["--check"]) == 0


def _scan(source):
    return trace.scan(source, "tests/test_x.py")


def test_markers_with_several_clauses_and_nested_tests_are_read():
    found, errors = _scan("""
import pytest

@pytest.mark.parametrize("x", [1])
@pytest.mark.part11("11.70", "11.50(a)(1)")
def test_one(x):
    pass

class TestGroup:
    @pytest.mark.part11("11.70")
    def test_two(self):
        pass

@pytest.mark.slow
def test_three():
    pass
""")
    assert errors == []
    assert found == {
        "11.70": ["tests/test_x.py::test_one", "tests/test_x.py::test_two"],
        "11.50(a)(1)": ["tests/test_x.py::test_one"],
    }


@pytest.mark.parametrize(
    ("source", "error"),
    [('@pytest.mark.part11("11.99")\ndef test_a(): pass', "unknown clause '11.99'"),
     ('@pytest.mark.part11("11.70")\ndef helper(): pass', "not a test"),
     ("@pytest.mark.part11()\ndef test_a(): pass", "takes clause strings"),
     ("@pytest.mark.part11\ndef test_a(): pass", "takes clause strings"),
     ("@pytest.mark.part11(1170)\ndef test_a(): pass", "takes clause strings"),
     ("@pytest.mark.part11(CLAUSE)\ndef test_a(): pass", "takes clause strings")],
)  # fmt: skip
def test_a_wrong_marker_is_reported(source, error):
    found, errors = _scan("import pytest\n" + source + "\n")
    assert found == {} and len(errors) == 1 and error in errors[0]


def test_a_clause_with_no_test_is_reported(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_only.py").write_text(
        'import pytest\n\n@pytest.mark.part11("11.70")\ndef test_a():\n    pass\n'
    )
    found, errors = trace.collect(tmp_path / "tests")
    assert found == {"11.70": ["tests/test_only.py::test_a"]}
    assert "11.10(a): no test shows it" in errors
    assert not any(e.startswith("11.70:") for e in errors)
    assert len(errors) == len(trace.CLAUSES) - 1


def test_a_stale_trace_fails_the_check_and_is_rewritten(tmp_path, monkeypatch, capsys):
    stale = tmp_path / "validation" / "TRACE.md"
    monkeypatch.setattr(trace, "TRACE", stale)
    monkeypatch.setattr(trace, "REPO_ROOT", tmp_path)
    assert trace.main(["--check"]) == 1
    assert "is out of date" in capsys.readouterr().err
    assert trace.main([]) == 0
    assert trace.main(["--check"]) == 0
    assert stale.read_text(encoding="utf-8") == trace.render(trace.collect()[0])


def test_a_wrong_marker_stops_the_write(tmp_path, monkeypatch, capsys):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_bad.py").write_text(
        'import pytest\n\n@pytest.mark.part11("11.99")\ndef test_a():\n    pass\n'
    )
    target = tmp_path / "TRACE.md"
    monkeypatch.setattr(trace, "TESTS", tests)
    monkeypatch.setattr(trace, "TRACE", target)
    monkeypatch.setattr(trace, "REPO_ROOT", tmp_path)
    real = trace.collect
    monkeypatch.setattr(trace, "collect", lambda: real(tests))
    assert trace.main([]) == 1
    assert not target.exists()
    assert "unknown clause '11.99'" in capsys.readouterr().err
    # A current file does not hide a wrong marker from --check either.
    target.write_text(trace.render(real(tests)[0]), encoding="utf-8")
    assert trace.main(["--check"]) == 1


def test_every_clause_the_signature_doc_names_is_traced():
    doc = (ROOT / "docs" / "ESIGNATURES.md").read_text()
    table = doc.split("## Part 11 clauses", 1)[1].split("\n## ", 1)[0]
    named = set(re.findall(r"^\| (11\.\d+(?:\([a-z0-9]+\))*)", table, re.MULTILINE))
    assert named and named <= {clause for clause, *_ in trace.CLAUSES}
    assert "validation/TRACE.md" in table
