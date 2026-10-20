#!/bin/sh
# Install Arcount on this machine. Idempotent. Run with sudo.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/arcount

getent group arcount >/dev/null || groupadd --system arcount
if [ -n "${SUDO_USER:-}" ] && ! id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qx arcount; then
    usermod -aG arcount "$SUDO_USER"
    echo "added $SUDO_USER to group arcount (log out and in again for it to apply)"
fi

install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/lib"
rm -rf "$PREFIX/lib/arcount"
cp -r "$SRC/src/arcount" "$PREFIX/lib/arcount"
find "$PREFIX/lib/arcount" -name __pycache__ -type d -prune -exec rm -rf {} +
install -m 0755 "$SRC"/packaging/bin/* "$PREFIX/bin/"
[ -f "$SRC/README.md" ] && install -m 0644 "$SRC/README.md" "$PREFIX/README.md"

install -d -m 0755 /etc/arcount
[ -f /etc/arcount/arcount.toml ] || install -m 0644 "$SRC/packaging/arcount.toml.example" /etc/arcount/arcount.toml

install -m 0644 "$SRC/packaging/systemd/arcountd.service" /etc/systemd/system/arcountd.service
install -d -m 0755 /etc/xdg/autostart
install -m 0644 "$SRC/packaging/xdg/arcount-notify.desktop" /etc/xdg/autostart/arcount-notify.desktop
ln -sf "$PREFIX/bin/arcount" /usr/local/bin/arcount
ln -sf "$PREFIX/bin/arcountd" /usr/local/sbin/arcountd

systemctl daemon-reload
systemctl enable arcountd
systemctl restart arcountd

cat <<MSG

Arcount installed.
  systemctl status arcountd      service state
  arcount status                 sessions (log out/in first if you were just added to group arcount)
  arcount test-alert             pop up a test notification
  /etc/arcount/arcount.toml      configuration (restart arcountd after editing)
MSG
