"""Entry point for `python -m core.kernel`.

`python -m <package>` executes `<package>/__main__.py`. This file did not exist
in v0.1.0, so the command printed in README.md failed outright with
"No module named core.kernel.__main__" — the published quick-start could not be
followed at all. The `if __name__ == "__main__": main()` guard at the bottom of
`core/kernel/__init__.py` never fires under `-m`, because Python runs `__main__`,
not the package's `__init__`.
"""

from . import main

if __name__ == "__main__":
    main()
