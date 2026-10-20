#!/bin/sh
# Build a tarball to copy to another machine:  packaging/make-dist.sh  ->  dist/arcount-<version>.tar.gz
set -eu
cd "$(dirname "$0")/.."
VER=$(PYTHONPATH=src python3 -c 'import arcount; print(arcount.__version__)')
mkdir -p dist
OUT="dist/arcount-$VER.tar.gz"
tar --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' --exclude='.claude' \
    --exclude='dist' --exclude='graphify-out' --exclude='.pytest_cache' \
    --transform "s,^\.,arcount-$VER," -czf "$OUT" \
    ./src ./packaging ./tests ./docs ./README.md ./pyproject.toml
sha256sum "$OUT"
echo "wrote $OUT"
