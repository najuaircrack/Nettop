#!/usr/bin/env sh
set -eu

output="${1:-nettop-3.0.0.zip}"
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"
rm -f "$output"
zip -qr "$output" \
  nettop packaging scripts tests README.md pyproject.toml requirements.txt
printf '%s\n' "$root/$output"
