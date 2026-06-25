#!/usr/bin/env bash
# Regenerate cargo-sources.json from Cargo.lock for the offline Flathub build
# (ADR 0034). Run after any dependency change. Needs python3 + network (it
# fetches the generator and reads crate checksums from Cargo.lock; all deps are
# crates.io, so no per-crate download is required).
set -euo pipefail
cd "$(dirname "$0")/.."

gen=$(mktemp); trap 'rm -f "$gen"' EXIT
curl -sSL -o "$gen" \
  https://raw.githubusercontent.com/flatpak/flatpak-builder-tools/master/cargo/flatpak-cargo-generator.py

# tomlkit + aiohttp are the generator's only deps; use a throwaway venv.
venv=$(mktemp -d); trap 'rm -rf "$venv"' EXIT
python3 -m venv "$venv"
"$venv/bin/pip" -q install tomlkit aiohttp
"$venv/bin/python" "$gen" Cargo.lock -o flatpak/cargo-sources.json

echo "wrote flatpak/cargo-sources.json"
