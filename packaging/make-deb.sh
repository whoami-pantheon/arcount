#!/bin/sh
# Build a Debian/Ubuntu/Kali package:  packaging/make-deb.sh  ->  dist/arcount_<version>_all.deb  (ARCOUNT_DIST=dir to change)
#
# The package carries the source under /usr/share/arcount and lets the same tested installer
# (`arcount setup`) lay out /opt/arcount, the systemd unit, the config and the group on install,
# and remove them on `apt remove`. Needs dpkg-deb.
set -eu
cd "$(dirname "$0")/.."
VER=$(PYTHONPATH=src python3 -c 'import arcount; print(arcount.__version__)')
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
DIST=${ARCOUNT_DIST:-dist}
mkdir -p "$STAGE/usr/share/arcount/src" "$STAGE/DEBIAN" "$DIST"
tar --exclude='__pycache__' --exclude='*.pyc' -C src -cf - arcount | tar -C "$STAGE/usr/share/arcount/src" -xf -
cp README.md "$STAGE/usr/share/arcount/README.md"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: arcount
Version: $VER
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.11), iproute2, systemd
Recommends: network-manager, iw, libnotify-bin, ieee-data, openssh-client, policykit-1
Maintainer: Clive Akporube <techwiz39@gmail.com>
Homepage: https://github.com/whoami-pantheon/arcount
Description: ARP attack detector for laptops that roam between networks
 Watches ARP (and IPv6 router advertisements) on every network you join, learns each network,
 and warns you when the gateway is impersonated. Standard library only.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    USER_ARG=""
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then USER_ARG="--user $SUDO_USER"; fi
    # shellcheck disable=SC2086
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/usr/share/arcount/src python3 -m arcount setup $USER_ARG
fi
exit 0
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
    remove|purge)
        PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/usr/share/arcount/src \
            python3 -m arcount setup --uninstall || true ;;
esac
exit 0
EOF
cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    rm -rf /var/lib/arcount /etc/arcount
    groupdel arcount 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE/usr" -type f -exec chmod 0644 {} +

OUT="$DIST/arcount_${VER}_all.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT" >/dev/null
sha256sum "$OUT"
echo "wrote $OUT"
