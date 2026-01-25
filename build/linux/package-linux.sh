#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "Usage: $0 <version> <publish_dir> <output_dir> <arch>" >&2
  exit 1
fi

VERSION="$1"
PUBLISH_DIR="$2"
OUTPUT_DIR="$3"
ARCH="$4"

APP_NAME="Password Phrase Producer"
APP_ID="password-phrase-producer"
INSTALL_DIR="/opt/Password-Phrase-Producer"
EXECUTABLE_NAME="${APP_NAME}"

if [ ! -d "$PUBLISH_DIR" ]; then
  echo "Publish directory not found: $PUBLISH_DIR" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

PORTABLE_STAGING="$(mktemp -d)"
trap 'rm -rf "$PORTABLE_STAGING"' EXIT

cp -R "$PUBLISH_DIR"/. "$PORTABLE_STAGING"/

tarball_name="Password-Phrase-Producer_${VERSION}_linux_${ARCH}_portable.tar.gz"
tar -czf "$OUTPUT_DIR/$tarball_name" -C "$PORTABLE_STAGING" .

DEB_ROOT="$(mktemp -d)"
mkdir -p "$DEB_ROOT/DEBIAN" \
  "$DEB_ROOT$INSTALL_DIR" \
  "$DEB_ROOT/usr/bin" \
  "$DEB_ROOT/usr/share/applications" \
  "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps"

cp -R "$PUBLISH_DIR"/. "$DEB_ROOT$INSTALL_DIR/"

cat <<CONTROL > "$DEB_ROOT/DEBIAN/control"
Package: $APP_ID
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: Password Phrase Producer Team
Description: Password Phrase Producer
 A cross-platform password and passphrase generator with vaults and TOTP.
CONTROL

cat <<'EOF_DESKTOP' > "$DEB_ROOT/usr/share/applications/${APP_ID}.desktop"
[Desktop Entry]
Name=Password Phrase Producer
Comment=Password and passphrase generator with vaults and TOTP
Exec=/usr/bin/password-phrase-producer
Icon=password-phrase-producer
Terminal=false
Type=Application
Categories=Utility;Security;
EOF_DESKTOP

cat <<'EOF_LAUNCHER' > "$DEB_ROOT/usr/bin/password-phrase-producer"
#!/usr/bin/env bash
exec "/opt/Password-Phrase-Producer/Password Phrase Producer" "$@"
EOF_LAUNCHER

chmod 0755 "$DEB_ROOT/usr/bin/password-phrase-producer"

if [ -f "/workspace/Password-Phrase-Producer/Password Phrase Producer/Resources/AppIcon/iconkeyconfig.png" ]; then
  cp "/workspace/Password-Phrase-Producer/Password Phrase Producer/Resources/AppIcon/iconkeyconfig.png" \
    "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps/password-phrase-producer.png"
fi

DEB_NAME="Password-Phrase-Producer_${VERSION}_linux_${ARCH}.deb"
dpkg-deb --build "$DEB_ROOT" "$OUTPUT_DIR/$DEB_NAME" >/dev/null

rm -rf "$DEB_ROOT"
