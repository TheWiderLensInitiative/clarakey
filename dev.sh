#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
./setup.sh
exec ./ClaraKey "$@"
