#!/usr/bin/env bash
# Regenerates the pcap-derived vectors of the NGAP equivalence corpus
# (shared/ngap/testdata/corpus/pcap-*.hex) from local pcaps/amf/*.pcap (git-ignored) via tshark.
# NAS null-scheme SUCI MSINs are blanked in place; see tools/ngapcorpus and the corpus README.
# Usage: scripts/ngap-corpus-from-pcap.sh [extra ngapcorpus flags, e.g. -max 40]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
tshark_bin="${TSHARK:-$(command -v tshark || echo /opt/homebrew/bin/tshark)}"
# Write to a staging dir first so a failed run never leaves the committed corpus without pcap vectors.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
GOWORK=off go run ./tools/ngapcorpus -tshark "$tshark_bin" -out "$stage" "$@"
rm -f shared/ngap/testdata/corpus/pcap-*.hex
cp "$stage"/pcap-*.hex shared/ngap/testdata/corpus/
