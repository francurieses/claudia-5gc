#!/usr/bin/env bash
# scripts/sync-openapi.sh
# Fetches the official 3GPP OpenAPI YAMLs from the 3GPP forge into
# specs/3gpp-openapi/<Rel-NN>/ (fetched reference, git-ignored, never committed).
# Upstream repo: https://forge.3gpp.org/rep/all/5G_APIs
# Upstream release branches are upper case (REL-17, REL-19, REL-20); the user-facing
# argument and the local directory use the Rel-NN form.
#
# Usage: ./scripts/sync-openapi.sh [REL]
#   REL     Rel-19 (default) | Rel-17 | any Rel-NN; case-insensitive, bare "19" accepted
# Env:
#   OPENAPI_BRANCH  override the forge branch (e.g. a Rel19-draft-TSG114 branch);
#                   the destination directory still follows REL.

set -euo pipefail

usage() {
	echo "usage: $0 [REL]   (REL: Rel-19 (default), Rel-17, ... ; optional env OPENAPI_BRANCH)" >&2
	exit 2
}

[ "$#" -le 1 ] || usage
ARG="${1:-Rel-19}"
if [[ "$ARG" =~ ^([Rr][Ee][Ll]-?)?([0-9]{2})$ ]]; then
	NN="${BASH_REMATCH[2]}"
else
	echo "error: invalid release '$ARG'" >&2
	usage
fi
REL="Rel-$NN"
BRANCH="${OPENAPI_BRANCH:-REL-$NN}"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST="$ROOT/specs/3gpp-openapi/$REL"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

REPO="https://forge.3gpp.org/rep/all/5G_APIs.git"

echo "==> cloning $REPO (branch $BRANCH)"
git clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$TMP/5G_APIs"

shopt -s nullglob
files=("$TMP"/5G_APIs/*.yaml)
if [ "${#files[@]}" -lt 1 ]; then
	echo "error: no YAML files found on branch $BRANCH" >&2
	exit 1
fi

echo "==> replacing YAML files in $DEST"
mkdir -p "$DEST"
rm -f "$DEST"/*.yaml
cp "${files[@]}" "$DEST/"
cp "$TMP/5G_APIs/README.md" "$DEST/UPSTREAM-README.md" 2>/dev/null || true
{
	echo "repo=$REPO"
	echo "branch=$BRANCH"
	echo "commit=$(git -C "$TMP/5G_APIs" rev-parse HEAD)"
	echo "fetched=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$DEST/UPSTREAM-COMMIT"

echo "${#files[@]} YAMLs in specs/3gpp-openapi/$REL (fetched reference, git-ignored; do not commit)"
