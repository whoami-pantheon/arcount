#!/bin/sh
# Thin wrapper: the installer lives in the package (`arcount setup`).
cd "$(dirname "$0")/.." || exit 1
exec env PYTHONPATH="$PWD/src" python3 -m arcount setup "$@"
