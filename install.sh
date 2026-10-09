#!/usr/bin/env bash
#
# NS-BOS Kernel installer
# =======================
#
# READ THIS BEFORE RUNNING IT. It is deliberately short and does only six things:
#
#   1. refuses to run anywhere except Linux (the kernel targets Linux; it is not a
#      macOS or Windows program and will not pretend otherwise),
#   2. finds a Python >= 3.10 interpreter,
#   3. reads the latest release tag from the GitHub API (or uses the tag/branch you pass),
#   4. git-clones that ref into $NSBOS_PREFIX/src,
#   5. creates a virtualenv and installs the hash-pinned dependencies into it,
#   6. smoke-tests the import and prints the command to start the kernel.
#
# What it does NOT do:
#   * no sudo, anywhere, for anything
#   * no writes outside $NSBOS_PREFIX (default ~/.ngari/kernel)
#   * no `curl | sh` of any further script
#   * no telemetry, no phone-home, no analytics. Nothing is reported about you.
#   * it does not start the kernel, and it does not download any model
#
# There is no model in this repository. The kernel orchestrates inference — you point it
# at a model runtime (Ollama, llama.cpp, vLLM) and weights you supply. See:
#   https://ngari.ai/kernel
#
# Usage:
#   ./install.sh                     # latest release tag (falls back to master)
#   ./install.sh --ref master        # a branch
#   ./install.sh --ref v0.1.0        # a pinned tag (reproducible)
#   ./install.sh --prefix /opt/nsbos # install somewhere else
#
set -euo pipefail

REPO="${NSBOS_REPO:-NGARiAI/ns-bos-kernel}"
PREFIX="${NSBOS_PREFIX:-$HOME/.ngari/kernel}"
REF="${NSBOS_REF:-}"
MIN_PY_MINOR=10

say()  { printf '  %s\n' "$*"; }
die()  { printf '\n  ERROR: %s\n\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ref)    REF="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

printf '\nNS-BOS Kernel installer\n\n'

# --- 1. Linux only -------------------------------------------------------------------
case "$(uname -s)" in
  Linux) say "platform: Linux ($(uname -m))" ;;
  Darwin) die "macOS is not supported. The kernel targets Linux (Ubuntu/Debian/Fedora).
        If you want NGARi on a machine you own without the setup, that is NGARi+ hardware:
        https://ngari.ai/hardware.html" ;;
  *) die "unsupported platform '$(uname -s)'. The kernel targets Linux." ;;
esac

for tool in git curl; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' is required but not installed."
done

# --- 2. Python >= 3.10 ---------------------------------------------------------------
# 3.10 is a hard floor, not a preference: the kernel uses `str | None` unions at runtime
# (35 of them, with no `from __future__ import annotations`), which raises TypeError on
# 3.9 and below. An earlier release advertised >=3.9; that was wrong.
PY=""
for cand in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c "import sys; sys.exit(0 if sys.version_info >= (3, $MIN_PY_MINOR) else 1)" 2>/dev/null; then
      PY="$cand"; break
    fi
  fi
done
if [ -z "$PY" ]; then
  die "no Python >= 3.$MIN_PY_MINOR found. Found: $(python3 -V 2>&1 || echo none).
        Install one, e.g.  sudo apt install python3.11 python3.11-venv"
fi
say "python:   $PY ($("$PY" -c 'import platform;print(platform.python_version())'))"

# --- 3. which ref --------------------------------------------------------------------
if [ -z "$REF" ]; then
  REF="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
         | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -1)"
  if [ -n "$REF" ]; then
    say "release:  $REF (latest)"
  else
    REF="master"
    say "release:  master (no published release found — using the branch)"
  fi
else
  say "release:  $REF (pinned by you)"
fi

SRC="$PREFIX/src"
# --- 4. clone ------------------------------------------------------------------------
if [ -d "$SRC/.git" ]; then
  say "source:   $SRC (updating existing clone)"
  git -C "$SRC" fetch --depth 1 origin "$REF" >/dev/null 2>&1 || die "could not fetch '$REF'."
  git -C "$SRC" checkout -q FETCH_HEAD
else
  say "source:   $SRC (cloning)"
  mkdir -p "$PREFIX"
  git clone --quiet --depth 1 --branch "$REF" "https://github.com/$REPO.git" "$SRC" 2>/dev/null \
    || die "could not clone '$REF' from github.com/$REPO.
        Check the ref exists: https://github.com/$REPO/releases"
fi

# --- 5. venv + hash-pinned dependencies ----------------------------------------------
VENV="$PREFIX/venv"
[ -d "$VENV" ] || "$PY" -m venv "$VENV" || die "could not create a virtualenv at $VENV."
say "venv:     $VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
say "deps:     installing hash-pinned requirements (this takes a minute)"
"$VENV/bin/pip" install --quiet --require-hashes -r "$SRC/core/kernel/requirements.txt"

# --- 6. smoke test, then stop --------------------------------------------------------
( cd "$SRC" && "$VENV/bin/python" -c "import core.kernel as k; print(k.VERSION)" >/dev/null 2>&1 ) \
  || die "the kernel installed but does not import. Please open an issue:
        https://github.com/$REPO/issues"

cat <<EOF

  Installed. The kernel was NOT started and no model was downloaded.

  Next:
    cd $SRC
    NGARI_DATA_DIR=$PREFIX $VENV/bin/python -m core.kernel

  There is no model in this repo — point the kernel at a runtime and weights you supply.

  Uninstall:  rm -rf $PREFIX     (that is the only directory this script wrote)

EOF
