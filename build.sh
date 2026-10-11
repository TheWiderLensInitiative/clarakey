#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
./setup.sh
command -v ldd >/dev/null || { echo 'Install libc-bin for ldd.'; exit 1; }
python3 -B packaging/build_portable.py
./dist/ClaraKey/ClaraKey --version
./dist/ClaraKey/runtime/ld-linux-x86-64.so.2 --library-path ./dist/ClaraKey/runtime/lib \
    ./dist/ClaraKey/runtime/bin/python3 -I -B packaging/verify_bundle.py ./dist/ClaraKey
python3 -B packaging/archive.py
if [ "${1:-}" = '--appimage' ]; then
    if ! command -v appimagetool >/dev/null 2>&1; then
        echo 'Portable directory built successfully. AppImage not built: install the official appimagetool and its matching runtime, then rerun ./build.sh --appimage.'
        exit 2
    fi
    ARCH=x86_64 appimagetool dist/ClaraKey dist/ClaraKey.AppImage
fi
