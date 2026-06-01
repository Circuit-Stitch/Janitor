#!/usr/bin/env bash
# Regenerate the committed icon set from icon.svg — the single source of truth.
# The generated PNGs + icon.ico are committed (ADR 0022) so that CI and a local
# `cargo packager` need no rasterizer installed. Re-run this whenever icon.svg
# changes, then commit the results.
#
# Requires:
#   resvg      cargo install resvg     (SVG -> PNG, faithful renderer)
#   magick     ImageMagick 7          (packs pre-rendered PNGs into a .ico)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
svg="$here/icon.svg"
icons="$here/icons"
mkdir -p "$icons"

# hicolor sizes (Linux) + 24 (only used inside the .ico for Windows small icons).
sizes=(16 24 32 48 64 128 256 512)
for s in "${sizes[@]}"; do
  resvg -w "$s" -h "$s" "$svg" "$icons/$s.png"
done

# Multi-resolution Windows .ico (the sizes Explorer/taskbar actually pick from).
# Packing already-rendered PNGs — ImageMagick never rasterizes the SVG itself.
magick "$icons/16.png" "$icons/24.png" "$icons/32.png" "$icons/48.png" \
       "$icons/256.png" "$icons/icon.ico"

echo "generated PNGs (${sizes[*]}) + icons/icon.ico"
