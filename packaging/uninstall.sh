#!/bin/sh
# Remove Arcount. Keeps /var/lib/arcount (history) unless --purge. Run with sudo.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }
systemctl disable --now arcountd 2>/dev/null || true
[ -x /opt/arcount/bin/arcountd ] && /opt/arcount/bin/arcountd --cleanup-pins || true
rm -f /etc/systemd/system/arcountd.service /etc/xdg/autostart/arcount-notify.desktop \
      /usr/local/bin/arcount /usr/local/sbin/arcountd
rm -rf /opt/arcount
systemctl daemon-reload
if [ "${1:-}" = "--purge" ]; then
    rm -rf /var/lib/arcount /etc/arcount
    getent group arcount >/dev/null && groupdel arcount || true
    echo "purged state, config and group"
else
    echo "kept /var/lib/arcount and /etc/arcount (use --purge to remove)"
fi
