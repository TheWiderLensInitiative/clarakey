#!/usr/bin/env python3
"""ClaraKey entry point. Set privacy defaults before importing any GUI code."""
import os
from pathlib import Path
import resource
import sys

sys.dont_write_bytecode = True
os.umask(0o077)
os.environ['GSETTINGS_BACKEND'] = 'memory'
os.environ['GSK_RENDERER'] = 'cairo'  # Avoid persistent GPU shader caches.
os.environ['GTK_USE_PORTAL'] = '0'
# Optional portal services inspect /proc/PID/root, which intentionally cannot be
# read after PR_SET_DUMPABLE=0. This standalone vault uses its own file picker,
# settings and inactivity policy, so it needs no desktop portal integration.
# Configure GDK before importing GTK, keeping memory protection in place.
os.environ['GDK_DEBUG'] = 'no-portals'
os.environ['GTK_IM_MODULE'] = 'gtk-im-context-simple'
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
try:
    import ctypes
    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # Linux PR_SET_DUMPABLE=0; no ptrace/core dump.
except (OSError, AttributeError):
    pass
sys.path.insert(0, str(Path(__file__).resolve().parent))
bundled_packages = Path(__file__).resolve().parent.parent / 'runtime/lib/python3/dist-packages'
if bundled_packages.is_dir():
    sys.path.insert(0, str(bundled_packages))


def main():
    import argparse
    parser = argparse.ArgumentParser(description='ClaraKey — offline portable encrypted vault')
    parser.add_argument('--portable-dir', type=Path, default=Path(__file__).resolve().parent,
                        help='Explicit portable application directory (normally set by the launcher).')
    parser.add_argument('--version', action='store_true')
    args = parser.parse_args()
    if args.version:
        from clarakey import __version__
        print('ClaraKey '+__version__)
        return 0
    from clarakey.diagnostics import SafeExceptionReporter
    sys.excepthook = SafeExceptionReporter()
    from clarakey.ui import ClaraKeyApp
    from gi.repository import Gtk, Gdk
    Gtk.init()
    if Gdk.Display.get_default() is None:
        sys.stderr.write('ClaraKey needs an accessible Linux desktop display (Wayland or X11). No vault was opened.\n')
        return 2
    app = ClaraKeyApp(args.portable_dir.absolute())
    return app.run([sys.argv[0]])


if __name__ == '__main__':
    raise SystemExit(main())
