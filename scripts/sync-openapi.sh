#!/usr/bin/env bash
# scripts/sync-openapi.sh
# Downloads official OpenAPI YAML from 3GPP forge for Rel-17.
# Upstream repo: https://forge.3gpp.org/rep/all/5G_APIs (branch Rel-17)
#
# Usage: ./scripts/sync-openapi.sh [REL]   # REL defaults to: Rel-17

set -euo pipefail

REL="${1:-Rel-17}"
DEST=$(cd "$(dirname "$0")/../specs/3gpp-openapi" && pwd)
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

REPO="https://forge.3gpp.org/rep/all/5G_APIs.git"

echo "==> cloning $REPO ($REL)"
git clone --depth 1 --branch "$REL" "$REPO" "$TMP/5G_APIs"

echo "==> copying YAML files to $DEST"
mkdir -p "$DEST"
cp "$TMP"/5G_APIs/*.yaml "$DEST/"
cp "$TMP"/5G_APIs/README.md "$DEST/UPSTREAM-README.md" || true

echo "==> committing reference (without automatic git add)"
ls "$DEST" | wc -l | awk '{print $1 " YAMLs in specs/3gpp-openapi"}'
echo "Remember to review and commit: cd $DEST && git add ."
