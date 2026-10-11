#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
export PYTHONDONTWRITEBYTECODE=1
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
python3 -B tests/process_acceptance.py
if command -v xvfb-run >/dev/null 2>&1; then
    GDK_BACKEND=x11 GTK_A11Y=none GSK_RENDERER=cairo GSETTINGS_BACKEND=memory xvfb-run -a python3 -B tests/gui_acceptance.py
else
    printf '%s\n' 'GUI acceptance not run: install xvfb and xauth, then rerun ./test.sh.'
    exit 1
fi
