"""Entry point for `python -m core.kernel`.

`python -m <package>` runs `<package>/__main__.py`, not the package's
`__init__`, so the `if __name__ == "__main__"` guard at the bottom of
`core/kernel/__init__.py` does not fire under `-m`. This module calls `main()`
for that case.
"""

from . import main

if __name__ == "__main__":
    main()
