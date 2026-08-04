"""pytest rootdir helper: puts the repo root on sys.path so `core.*` imports work."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
