#!/usr/bin/env bash
#
# NS-BOS Kernel installer
# =======================
#
# Short enough to read in full before running. It does six things:
#
#   1. refuses to run anywhere except Linux (the kernel targets Linux; macOS and
#      Windows are not supported),
#   2. finds a Python >= 3.10 interpreter,
#   3. picks the ref to install: master by default, or the tag or branch given,
#   4. git-clones that ref into $NSBOS_PREFIX/src,
#   5. creates a virtualenv and installs the hash-pinned dependencies into it,
#   6. smoke-tests the import and prints the command to start the kernel.
#
# What it does not do:
#   * no sudo, anywhere, for anything
#   * no writes outside $NSBOS_PREFIX (default ~/.ngari/kernel), and only src/ and
#     venv/ inside it; the kernel keeps its data and key there too once it runs
#   * no `curl | sh` of any further script
#   * no telemetry, no phone-home, no analytics. Nothing is reported.
#   * it does not start the kernel, and it does not download any model
#
# There is no model in this repository. The kernel orchestrates inference against a
# model runtime (Ollama, llama.cpp, vLLM) and weights supplied by the operator. See:
#   https://ngari.ai/kernel
#
# Usage:
#   ./install.sh                     # master
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
    -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
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
# 3.10 is the minimum: the kernel's annotations use `X | None` unions, evaluated at
# import time with no `from __future__ import annotations`, which raises TypeError
# on 3.9 and below.
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
# Defaults to the master branch, not to /releases/latest: the v0.1.0 release has no
# core/kernel/__main__.py, so the start command printed at the end does not run on it.
# A tag given with --ref makes the install reproducible; see
# https://github.com/NGARiAI/ns-bos-kernel/releases
if [ -z "$REF" ]; then
  REF="master"
  say "ref:      master (current; pin a tag with --ref for reproducibility)"
else
  say "ref:      $REF (pinned by you)"
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

  Installed. The kernel was not started and no model was downloaded.

  Next:
    cd $SRC
    NGARI_DATA_DIR=$PREFIX $VENV/bin/python -m core.kernel

  There is no model in this repo. Point the kernel at a runtime and weights you supply.

  Your data lives in $PREFIX too, once the kernel has run: the encryption
  key is $PREFIX/sovereign/keys/master.key, and without it the encrypted
  files cannot be read. Back it up somewhere other than this machine.

  Uninstall:  rm -rf $PREFIX/src $PREFIX/venv
              (all this script wrote; it leaves your data and key in place)

EOF
