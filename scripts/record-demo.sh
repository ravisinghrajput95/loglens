#!/usr/bin/env bash
# Re-record the terminal demo and rebuild docs/demo.gif.
#
# Needs asciinema and agg:  brew install asciinema agg
set -euo pipefail

cd "$(dirname "$0")/.."

command -v asciinema >/dev/null || { echo "asciinema not installed"; exit 1; }
command -v agg >/dev/null || { echo "agg not installed"; exit 1; }

mkdir -p docs
CAST=docs/demo.cast

rm -f "$CAST"
# The report rules are 78 characters wide, so anything narrower wraps and the
# recording looks broken. Pinned here so the gif does not depend on the size
# of whichever terminal happened to run this.
asciinema rec "$CAST" \
  --window-size 88x32 \
  --idle-time-limit 1.5 \
  --command "bash scripts/demo.sh"

agg "$CAST" docs/demo.gif \
  --font-size 15 \
  --theme asciinema \
  --speed 1.0

echo "wrote docs/demo.gif ($(du -h docs/demo.gif | cut -f1))"
