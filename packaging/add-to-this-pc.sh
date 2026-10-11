#!/bin/sh
# Adds a ClaraKey icon to this PC's app grid (and, with --pin, the dock) that opens ClaraKey from its USB drive.
#
#   ./add-to-this-pc.sh            add the icon
#   ./add-to-this-pc.sh --pin      add it and pin it to the GNOME dock
#   ./add-to-this-pc.sh --remove   take it off this PC again
#
# Clicking the icon mounts the drive if needed (as a normal user, through udisks) and starts the ClaraKey on it.
# Nothing secret is copied: the PC gets a small launcher, a desktop entry and the logo. The vault stays on the drive.
# No administrator rights are used.
set -eu

APP_ID=org.clarakey.ClaraKey
BIN="$HOME/.local/bin/clarakey-launch"
DESKTOP="${XDG_DATA_HOME:-$HOME/.local/share}/applications/$APP_ID.desktop"
ICON="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/512x512/apps/$APP_ID.png"
OLD_ICON="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps/$APP_ID.svg"

if [ "${1:-}" = "--remove" ]; then
    rm -f "$BIN" "$DESKTOP" "$ICON" "$OLD_ICON"
    if command -v gsettings >/dev/null 2>&1; then
        favs=$(gsettings get org.gnome.shell favorite-apps 2>/dev/null || true)
        case "$favs" in *"'$APP_ID.desktop'"*)
            gsettings set org.gnome.shell favorite-apps "$(printf '%s' "$favs" | sed "s/, *'$APP_ID.desktop'//; s/'$APP_ID.desktop', *//; s/'$APP_ID.desktop'//")" ;;
        esac
    fi
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$(dirname "$DESKTOP")" || true
    echo "ClaraKey icon removed from this PC. Your drive and vault are unchanged."
    exit 0
fi

BUNDLE=$(CDPATH= cd -- "$(dirname -- "$(readlink -f -- "$0")")" && pwd)
[ -x "$BUNDLE/ClaraKey" ] || { echo "Run this from inside the ClaraKey folder on your drive."; exit 1; }

# Which drive is ClaraKey on? Remember the filesystem UUID (survives a different mount point or USB port)
# and the folder inside it. On an internal disk, just remember the folder.
UUID=$(findmnt -n -o UUID -T "$BUNDLE" 2>/dev/null || true)
ROOT=$(findmnt -n -o TARGET -T "$BUNDLE" 2>/dev/null || true)
REL=""
case "$ROOT" in
    /media/*|/run/media/*) [ -n "$UUID" ] && REL=${BUNDLE#"$ROOT"} ;;
    *) UUID="" ;;
esac

mkdir -p "$(dirname "$BIN")" "$(dirname "$DESKTOP")" "$(dirname "$ICON")"
cp "$BUNDLE/clarakey.png" "$ICON"
rm -f "$OLD_ICON"   # the 1.1.0 shield icon

cat > "$BIN" <<EOF
#!/bin/sh
# ClaraKey launcher (made by add-to-this-pc.sh). Opens ClaraKey from its drive; holds no secrets.
UUID='$UUID'
REL='$REL'
FIXED='$BUNDLE'
tell() {
    notify-send -a ClaraKey -i $APP_ID "ClaraKey" "\$1" 2>/dev/null \\
        || zenity --info --title=ClaraKey --text="\$1" 2>/dev/null || echo "\$1" >&2
}
if [ -z "\$UUID" ]; then
    [ -x "\$FIXED/ClaraKey" ] || { tell "ClaraKey isn't at \$FIXED any more."; exit 1; }
    exec "\$FIXED/ClaraKey" "\$@"
fi
DEV="/dev/disk/by-uuid/\$UUID"
[ -e "\$DEV" ] || { tell "Plug in your ClaraKey drive, then click the icon again."; exit 1; }
MP=\$(findmnt -n -o TARGET -S "UUID=\$UUID" | head -n 1)
if [ -z "\$MP" ]; then
    udisksctl mount -b "\$DEV" --no-user-interaction >/dev/null 2>&1 || udisksctl mount -b "\$DEV" >/dev/null 2>&1 \\
        || { tell "Couldn't open the ClaraKey drive. Try opening it in Files first."; exit 1; }
    MP=\$(findmnt -n -o TARGET -S "UUID=\$UUID" | head -n 1)
fi
APP="\$MP\$REL/ClaraKey"
[ -x "\$APP" ] || { tell "ClaraKey wasn't found on the drive at \$REL."; exit 1; }
exec "\$APP" "\$@"
EOF
chmod 755 "$BIN"

cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=ClaraKey
GenericName=Encrypted vault
Comment=Open your portable encrypted vault from its USB drive
Exec=$BIN
Icon=$APP_ID
Categories=Utility;Security;
Keywords=password;authenticator;totp;2fa;vault;keys;
Terminal=false
StartupNotify=true
StartupWMClass=$APP_ID
EOF
chmod 644 "$DESKTOP"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$(dirname "$DESKTOP")" || true
command -v gtk-update-icon-cache >/dev/null 2>&1 \
    && gtk-update-icon-cache -q -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true

if [ "${1:-}" = "--pin" ] && command -v gsettings >/dev/null 2>&1; then
    favs=$(gsettings get org.gnome.shell favorite-apps 2>/dev/null || echo "@as []")
    case "$favs" in
        *"'$APP_ID.desktop'"*) ;;
        "@as []"|"[]") gsettings set org.gnome.shell favorite-apps "['$APP_ID.desktop']" ;;
        *) gsettings set org.gnome.shell favorite-apps "$(printf '%s' "$favs" | sed "s/]\$/, '$APP_ID.desktop']/")" ;;
    esac
fi

if [ -n "$UUID" ]; then
    where="your apps"; [ "${1:-}" = "--pin" ] && where="your dock or apps"
    echo "ClaraKey icon added. Plug in the drive and click ClaraKey in $where; it opens from the drive."
else
    echo "ClaraKey icon added; it opens ClaraKey from $BUNDLE."
fi
echo "Remove it any time with: $BUNDLE/add-to-this-pc.sh --remove"
