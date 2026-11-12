#!/usr/bin/env bash
# packetrusher-vendor.sh - stage a build-time copy of the 5GC codec libraries for the PacketRusher image.
#
# The PacketRusher image build context is ./docker/packetrusher (docker-compose.yml is not edited), so
# it cannot COPY the repo-root shared/ tree. This script copies shared/ngap, shared/nas and
# shared/capability into docker/packetrusher/claudia-vendor/ (gitignored) as a self-contained Go module
# `github.com/francurieses/claudia-5gc`; patches/0001-claudia-rel19-codec.patch points a `replace`
# directive at it. Excluded from the copy: *_test.go, testdata/ (size) and *_private*.go (the public
# snapshot strips them; private/ is never referenced). Run by `make ran-up` / `make packetrusher-vendor`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-$ROOT/docker/packetrusher/claudia-vendor}"
MOD="$(sed -n 's/^module //p' "$ROOT/go.mod")"
GOVER="$(sed -n 's/^go //p' "$ROOT/go.mod")"

rm -rf "$DEST"
mkdir -p "$DEST/shared"
for pkg in ngap nas capability; do
  (cd "$ROOT/shared" && find "$pkg" -type f -name '*.go' ! -name '*_test.go' ! -name '*_private*.go' ! -path '*/testdata/*' -print0 \
    | while IFS= read -r -d '' f; do mkdir -p "$DEST/shared/$(dirname "$f")"; cp "$f" "$DEST/shared/$f"; done)
done

ver() { sed -n "s#^[[:space:]]*$1 \(v[^ ]*\).*#\1#p" "$ROOT/go.mod" | head -1; }
cat >"$DEST/go.mod" <<MODEOF
module $MOD

go $GOVER

require (
	github.com/free5gc/aper $(ver github.com/free5gc/aper)
	golang.org/x/sys $(ver golang.org/x/sys)
)
MODEOF
cp "$ROOT/LICENSE" "$DEST/LICENSE" 2>/dev/null || true
echo "packetrusher-vendor: staged $(find "$DEST" -name '*.go' | wc -l | tr -d ' ') files in $DEST"
