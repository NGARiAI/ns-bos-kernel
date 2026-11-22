"""The sandbox renames blocked builtins in agent code. Only names are
renamed: strings, comments and attribute access keep working."""

import pytest

from core.kernel.sandbox import bwrap
from core.kernel.sandbox.bwrap import _sanitize_code


@pytest.mark.parametrize(
    "code",
    [
        'print("never call eval( on input")',
        "x = 'open( and compile( in a string'",
        "# a comment about exec(\nx = 1",
        "import re\nre.compile('a+')",
        "import gzip\ngzip.open",
        "import io\nio.open",
        "obj.eval(1)",
        "print(f'{x!r}')",
        "import re\npattern = (re.\n    compile('a+'))",
        "import re\npattern = (re.  # split over lines\n    compile('a+'))",
    ],
)
def test_strings_comments_and_attributes_are_left_alone(code):
    assert _sanitize_code(code) == code


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("eval(x)", "_sanitized_eval_(x)"),
        ("f = open\nf('x')", "f = _sanitized_open_\nf('x')"),
        ("exec ('y')", "_sanitized_exec_ ('y')"),
        ("__import__('os')", "_sanitized___import__('os')"),
        ("b = __builtins__", "b = _sanitized___builtins__"),
        ("eval(eval(1)) + compile('', '', 'exec')",
         "_sanitized_eval_(_sanitized_eval_(1)) + _sanitized_compile_('', '', 'exec')"),
    ],
)  # fmt: skip
def test_blocked_builtins_are_renamed_where_they_are_names(code, expected):
    assert _sanitize_code(code) == expected


def test_code_that_does_not_tokenize_is_passed_through():
    broken = 'print("unclosed'
    assert _sanitize_code(broken) == broken


@pytest.fixture(scope="module")
def sandbox():
    return bwrap.BwrapSandbox()


@pytest.mark.parametrize(
    ("code", "out"),
    [
        ("import re\nprint(re.compile('a+').match('aa').group())", "aa"),
        (("import gzip, io\nb = io.BytesIO()\n"
          "with gzip.open(b, 'wb') as f:\n    f.write(b'x')\nprint('gzip ok')"), "gzip ok"),
        ('print("never call eval( on input")', "never call eval( on input"),
    ],
)  # fmt: skip
def test_ordinary_code_runs_unchanged(sandbox, code, out):
    r = sandbox.execute_python(code)
    assert (r.exit_code, r.stdout.strip()) == (0, out), r.stderr


@pytest.mark.parametrize(
    "code", ["eval('1+1')", "f = open\nf('/etc/hostname')", "exec('x = 1')"]
)
def test_blocked_builtins_raise_instead_of_returning_none(sandbox, code):
    r = sandbox.execute_python(code)
    assert r.exit_code != 0
    assert "PermissionError" in r.stderr
