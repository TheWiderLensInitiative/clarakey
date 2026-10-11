#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
python3 -I -B - <<'PY'
import sys
try:
    if sys.version_info < (3, 11):
        raise ValueError('Python 3.11 or later is required.')
    import gi
    import cairo
    import _cffi_backend
    import typing_extensions
    gi.require_version('Gtk', '4.0')
    from gi.repository import Gtk
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import cryptography
    Argon2id(salt=b'0'*16,length=32,iterations=3,lanes=4,memory_cost=65536).derive(b'dependency-check-only')
    print(f'Ready: Python {sys.version.split()[0]}, GTK {Gtk.get_major_version()}.{Gtk.get_minor_version()}, cryptography {cryptography.__version__}')
except (ImportError, ValueError) as exc:
    print('Dependencies are missing or too old. Install Python 3.11+, python3-gi, gir1.2-gtk-4.0 and python3-cryptography >=44 (with Argon2 support).')
    print('For Debian/Ubuntu with current packages: apt install python3 python3-gi gir1.2-gtk-4.0 python3-cryptography python3-cairo python3-cffi-backend python3-typing-extensions')
    print('For graphical tests also install xvfb, xauth and dbus; for packaging use binutils and optionally squashfs-tools/appimagetool.')
    print('No administrator commands were run automatically.')
    sys.exit(1)
PY
