#!/bin/sh
# Construit le paquet Debian de fobots : dist/fobots_VERSION_all.deb
#
#   ./build-deb.sh [VERSION]       (ou `make deb`, qui calcule la version)
#
# Variables : MAINTAINER ("Nom <adresse>", défaut : git config), OUT (dossier de sortie).
# Le paquet installe les mêmes fichiers que `fobots.py install` (programme dans /opt/fobots,
# conf et liste welcome dans /etc/fobots, unité systemd), sans démarrer le service.
set -eu

cd "$(dirname "$0")"
VERSION=${1:-0.0.0}
OUT=${OUT:-dist}
BUILD=build/pkg
PKG=fobots

case $VERSION in
    [0-9]*) ;;
    *) echo "version invalide : $VERSION (doit commencer par un chiffre)" >&2; exit 1 ;;
esac
command -v dpkg-deb >/dev/null || { echo "dpkg-deb introuvable (apt install dpkg-dev)" >&2; exit 1; }

if [ -z "${MAINTAINER:-}" ]; then
    name=$(git config user.name 2>/dev/null || true)
    mail=$(git config user.email 2>/dev/null || true)
    MAINTAINER=${name:-fobots}\ \<${mail:-root@localhost}\>
fi

python3 -m py_compile fobots.py
rm -rf "$BUILD" build/__pycache__
mkdir -p "$BUILD/DEBIAN" "$OUT"

install -D -m 0755 fobots.py          "$BUILD/opt/fobots/fobots.py"
install -D -m 0644 fobots.conf.example "$BUILD/etc/fobots/fobots.conf"
install -D -m 0644 README.md          "$BUILD/usr/share/doc/$PKG/README.md"
install -D -m 0644 README.fr.md       "$BUILD/usr/share/doc/$PKG/README.fr.md"
{
    echo "# Plages à ne jamais bannir, un CIDR par ligne."
    echo "# Ajouter avec : /opt/fobots/fobots.py welcome add CIDR (retire aussi les bans concernés)"
} > "$BUILD/etc/fobots/welcome.txt"
chmod 0644 "$BUILD/etc/fobots/welcome.txt"

# L'unité : l'exemple sans son en-tête d'installation manuelle (le paquet s'en charge).
mkdir -p "$BUILD/usr/lib/systemd/system"
{
    echo "# Installée par le paquet fobots. Pour la modifier : systemctl edit fobots"
    echo "# (ex. SupplementaryGroups= : groupe qui donne accès à votre log)."
    echo
    sed -n '/^\[Unit\]/,$p' fobots.service.example
} > "$BUILD/usr/lib/systemd/system/fobots.service"
chmod 0644 "$BUILD/usr/lib/systemd/system/fobots.service"

DOC="$BUILD/usr/share/doc/$PKG"
{
    echo "$PKG ($VERSION) unstable; urgency=low"
    echo
    echo "  * Paquet construit depuis $(git rev-parse --short HEAD 2>/dev/null || echo "?")."
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
# Le programme vit dans /opt/fobots (comme avec `fobots.py install`) : choix assumé.
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
Description: bannissement nftables des plages d'IP trop agressives
 Lit un access log (nginx, Apache, GitLab), compte les requêtes par plage d'IP
 et ajoute au set nftables les plages qui dépassent le seuil. Les bans expirent
 seuls. Le service n'est ni activé ni démarré par l'installation : adapter
 /etc/fobots/fobots.conf, remplir /etc/fobots/welcome.txt, puis
 systemctl enable --now fobots.
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
        # mise à jour : on relance seulement un service déjà démarré
        systemctl try-restart fobots.service || true
    fi
    if [ -z "$2" ]; then
        echo "fobots installé, non démarré. Étapes suivantes :"
        echo "  1. adapter /etc/fobots/fobots.conf (log, seuils)"
        echo "  2. ajouter vos réseaux à /etc/fobots/welcome.txt"
        echo "  3. essai : /opt/fobots/fobots.py run --dry-run"
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
    # La table nft « fobots » n'est pas supprimée ici : les bans expirent seuls
    # (nft delete table inet fobots pour les retirer tout de suite).
fi
exit 0
SCRIPT
chmod 0755 "$BUILD/DEBIAN/postinst" "$BUILD/DEBIAN/prerm" "$BUILD/DEBIAN/postrm"

FILE="$OUT/${PKG}_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$BUILD" "$FILE" >/dev/null
echo "paquet : $FILE"
dpkg-deb --info "$FILE" | sed -n 's/^ \(Package\|Version\|Installed-Size\|Depends\):/  \1:/p'
