#!/usr/bin/env bash
set -euo pipefail

# Ensure python and pip are available in PATH for Netlify build image
if command -v python3 >/dev/null 2>&1; then
  PY=$(command -v python3)
elif command -v python >/dev/null 2>&1; then
  PY=$(command -v python)
else
  echo "Python not found" >&2
  exit 1
fi

"$PY" -m ensurepip --upgrade || true
"$PY" -m pip install --upgrade pip setuptools wheel || true

# Install root requirements if present
if [ -f requirements.txt ]; then
  "$PY" -m pip install -r requirements.txt || true
fi

# Install functions requirements if present
if [ -f netlify/functions/requirements.txt ]; then
  "$PY" -m pip install -r netlify/functions/requirements.txt || true
fi

echo "Bootstrap complete"