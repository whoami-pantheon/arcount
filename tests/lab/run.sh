#!/bin/sh
# Run the lab suite rootlessly inside user+net+mount namespaces (no sudo needed).
# Usage: tests/lab/run.sh [pytest args]
cd "$(dirname "$0")/../.." || exit 1
if [ "$(id -u)" = 0 ]; then
    mount -t tmpfs tmpfs /run 2>/dev/null
    exec python3 -m pytest tests/lab -p no:cacheprovider "$@"
fi
exec unshare -Urnm sh -c 'mount -t tmpfs tmpfs /run && ip link set lo up && exec python3 -m pytest tests/lab -p no:cacheprovider "$@"' sh "$@"
