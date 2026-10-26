#!/bin/sh
# Builds the Debian package of fobots: dist/fobots_VERSION_all.deb
#
#   ./build-deb.sh [VERSION]       (or `make deb`, which computes the version)
#
# Variables: MAINTAINER ("Name <address>", default: git config), OUT (output directory).
# The package installs the same files as `fobots install` (command /usr/sbin/fobots, modules in
# /opt/fobots/fobots/, configuration and welcome list in /etc/fobots, systemd unit), without
# starting the service.
set -eu

cd "$(dirname "$0")"
VERSION=${1:-0.0.0}
OUT=${OUT:-dist}
BUILD=build/pkg
PKG=fobots

case $VERSION in
    [0-9]*) ;;
    *) echo "invalid version: $VERSION (must start with a digit)" >&2; exit 1 ;;
esac
command -v dpkg-deb >/dev/null || { echo "dpkg-deb not found (apt install dpkg-dev)" >&2; exit 1; }

if [ -z "${MAINTAINER:-}" ]; then
    name=$(git config user.name 2>/dev/null || true)
    mail=$(git config user.email 2>/dev/null || true)
    MAINTAINER=${name:-fobots}\ \<${mail:-root@localhost}\>
fi

python3 -m py_compile fobots.py fobots/*.py
find fobots -name __pycache__ -prune -exec rm -rf {} +
rm -rf "$BUILD" build/__pycache__
mkdir -p "$BUILD/DEBIAN" "$OUT"

# The command: the launcher without .py, with the system interpreter (no "env").
install -D -m 0755 fobots.py          "$BUILD/usr/sbin/fobots"
sed -i '1s|.*|#!/usr/bin/python3|' "$BUILD/usr/sbin/fobots"
for module in fobots/*.py; do
    install -D -m 0644 "$module"       "$BUILD/opt/fobots/$module"
done
install -D -m 0644 fobots.conf.example "$BUILD/etc/fobots/fobots.conf"
install -D -m 0644 README.md          "$BUILD/usr/share/doc/$PKG/README.md"
install -D -m 0644 README.fr.md       "$BUILD/usr/share/doc/$PKG/README.fr.md"
{
    echo "# Ranges never to ban, one CIDR per line."
    echo "# Add with: fobots welcome add CIDR (also removes the bans concerned)"
} > "$BUILD/etc/fobots/welcome.txt"
chmod 0644 "$BUILD/etc/fobots/welcome.txt"

# The unit: the example without its manual installation header (the package does that).
mkdir -p "$BUILD/usr/lib/systemd/system"
{
    echo "# Installed by the fobots package. To modify it: systemctl edit fobots"
    echo "# (e.g. SupplementaryGroups=: the group that gives access to your log)."
    echo
    sed -n '/^\[Unit\]/,$p' fobots.service.example | sed 's|/usr/local/sbin/fobots|/usr/sbin/fobots|'
} > "$BUILD/usr/lib/systemd/system/fobots.service"
chmod 0644 "$BUILD/usr/lib/systemd/system/fobots.service"

DOC="$BUILD/usr/share/doc/$PKG"
{
    echo "$PKG ($VERSION) unstable; urgency=low"
    echo
    echo "  * Package built from $(git rev-parse --short HEAD 2>/dev/null || echo "?")."
    echo
    echo " -- $MAINTAINER  $(date -R)"
} | gzip -9n > "$DOC/changelog.gz"
cat > "$DOC/copyright" <<COPYRIGHT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2026 Joël Maizi
License: GPL-3+

License: GPL-3+
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 On Debian systems, the complete text of the GNU General Public
 License version 3 can be found in /usr/share/common-licenses/GPL-3.
COPYRIGHT
# The modules live in /opt/fobots (as with `fobots install`): a deliberate choice.
install -D -m 0644 /dev/stdin "$BUILD/usr/share/lintian/overrides/$PKG" <<OVERRIDES
$PKG: dir-or-file-in-opt
OVERRIDES
chmod 0644 "$DOC/changelog.gz" "$DOC/copyright"
find "$BUILD" -type d -exec chmod 0755 {} +
SIZE=$(du -sk --exclude=DEBIAN "$BUILD" | cut -f1)
cat > "$BUILD/DEBIAN/control" <<CONTROL
Package: $PKG
Version: $VERSION
Architecture: all
Installed-Size: $SIZE
Maintainer: $MAINTAINER
Depends: python3 (>= 3.7), nftables
Section: net
Priority: optional
Description: nftables bans of overly aggressive IP ranges
 Reads an access log (nginx, Apache), counts requests per IP range
 and adds the ranges that exceed the threshold to an nftables set. Bans
 expire by themselves. The service is neither enabled nor started by the
 installation: adapt /etc/fobots/fobots.conf, fill in /etc/fobots/welcome.txt,
 then systemctl enable --now fobots.
CONTROL

printf '%s\n' /etc/fobots/fobots.conf /etc/fobots/welcome.txt > "$BUILD/DEBIAN/conffiles"

cat > "$BUILD/DEBIAN/postinst" <<'SCRIPT'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    if ! getent passwd fobots >/dev/null; then
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin fobots
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        # upgrade: only restart a service that is already running
        systemctl try-restart fobots.service || true
    fi
    if [ -z "$2" ]; then
        echo "fobots installed, not started. Next steps:"
        echo "  1. adapt /etc/fobots/fobots.conf (log, thresholds)"
        echo "  2. add your networks to /etc/fobots/welcome.txt"
        echo "  3. trial: fobots run --dry-run"
        echo "  4. systemctl enable --now fobots"
    fi
fi
exit 0
SCRIPT

cat > "$BUILD/DEBIAN/prerm" <<'SCRIPT'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl disable --now fobots.service || true
fi
exit 0
SCRIPT

cat > "$BUILD/DEBIAN/postrm" <<'SCRIPT'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
    [ -d /run/systemd/system ] && systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
    rm -rf /var/lib/fobots
    rmdir /etc/fobots 2>/dev/null || true
    if getent passwd fobots >/dev/null; then
        userdel fobots 2>/dev/null || true
    fi
    # The nft table "fobots" is not removed here: the bans expire by themselves
    # (nft delete table inet fobots to remove them right away).
fi
exit 0
SCRIPT
chmod 0755 "$BUILD/DEBIAN/postinst" "$BUILD/DEBIAN/prerm" "$BUILD/DEBIAN/postrm"

FILE="$OUT/${PKG}_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$BUILD" "$FILE" >/dev/null
echo "package: $FILE"
dpkg-deb --info "$FILE" | sed -n 's/^ \(Package\|Version\|Installed-Size\|Depends\):/  \1:/p'
