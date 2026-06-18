#!/usr/bin/env bash
# scripts/new-nf.sh — copies _template/ to a new NF and renames occurrences.
# Usage: ./scripts/new-nf.sh <nfname>

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <nfname>"
  exit 1
fi

NF="$1"
NF_LOWER=$(echo "$NF" | tr '[:upper:]' '[:lower:]')
NF_UPPER=$(echo "$NF" | tr '[:lower:]' '[:upper:]')

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/nf/_template"
DST="$ROOT/nf/$NF_LOWER"

if [ -d "$DST" ]; then
  echo "already exists: $DST"
  exit 1
fi

cp -r "$SRC" "$DST"
find "$DST" -type f -exec sed -i \
  -e "s/{{NF_NAME}}/$NF_UPPER/g" \
  -e "s/{{nf_name}}/$NF_LOWER/g" \
  {} \;

echo "==> created nf/$NF_LOWER"
echo "Next steps:"
echo "  1. cd nf/$NF_LOWER && edit CLAUDE.md"
echo "  2. add '$NF_LOWER' to NFS in /Makefile"
echo "  3. add service '$NF_LOWER' in /docker-compose.yml"
