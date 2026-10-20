#!/bin/sh
# Thin wrapper: the installer lives in the package (`arcount setup`).
cd "$(dirname "$0")/.." || exit 1
# PYTHONDONTWRITEBYTECODE: do not leave root-owned __pycache__ in the checkout
exec env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" python3 -m arcount setup "$@"
