#!/usr/bin/env bash
# scripts/extract-asn1.sh
# Extracts the NGAP ASN.1 modules (TS 38.413 §9.4: NGAP-PDU-Descriptions, NGAP-PDU-Contents,
# NGAP-IEs, NGAP-CommonDataTypes, NGAP-Constants, NGAP-Containers) from an official 3GPP spec
# zip into specs/asn1/ngap/r19/ (git-ignored: REL19 plan R3 fallback, the ASN.1 is fetched
# locally and only generated Go is committed), with SOURCE.md and SHA256SUMS.
#
# The zip is NOT downloaded here: get it from
#   https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/   (e.g. 38413-j00.zip = V19.0.0)
# in a browser or with your own authorised client, then pass the path.
#
# Usage: ./scripts/extract-asn1.sh <spec-zip> [OUTDIR]
#   OUTDIR  default specs/asn1/ngap/r19

set -euo pipefail

usage() {
	echo "usage: $0 <spec-zip> [OUTDIR]" >&2
	exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
ZIP="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${2:-$ROOT/specs/asn1/ngap/r19}"
[ -f "$ZIP" ] || { echo "error: $ZIP not found" >&2; exit 2; }
command -v unzip >/dev/null || { echo "error: unzip required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "error: python3 required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unzip -q -o "$ZIP" -d "$WORK"
DOCX="$(find "$WORK" -maxdepth 2 -name '*.docx' | head -1)"
if [ -z "$DOCX" ]; then
	# Rel-15 archives ship only a legacy .doc: convert it with macOS textutil.
	DOC="$(find "$WORK" -maxdepth 2 -name '*.doc' | head -1)"
	[ -n "$DOC" ] || { echo "error: no .docx or .doc inside $ZIP" >&2; exit 1; }
	command -v textutil >/dev/null || { echo "error: $ZIP holds only a legacy .doc and textutil (macOS) is unavailable; convert it to .docx first" >&2; exit 2; }
	textutil -convert docx "$DOC" >/dev/null
	DOCX="${DOC%.doc}.docx"
	[ -f "$DOCX" ] || { echo "error: textutil conversion of $DOC failed" >&2; exit 1; }
fi

mkdir -p "$OUT"
rm -f "$OUT"/*.asn "$OUT/SHA256SUMS" "$OUT/SOURCE.md"

python3 -I - "$DOCX" "$OUT" <<'PY'
import re, sys, zipfile
from xml.etree import ElementTree as ET

docx, out = sys.argv[1], sys.argv[2]
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
root = ET.fromstring(zipfile.ZipFile(docx).read("word/document.xml"))

# Only run-level children count: w:tab inside w:tabs (paragraph tab stops) is layout, not content.
def para_text(p):
    out = []
    for r in p.iter(W + "r"):
        for el in r:
            if el.tag == W + "t":
                out.append(el.text or "")
            elif el.tag == W + "tab":
                out.append("\t")
            elif el.tag in (W + "br", W + "cr"):
                out.append("\n")
    return "".join(out)

paras = []
for p in root.iter(W + "p"):
    paras.extend(para_text(p).split("\n"))

WANT = ["NGAP-PDU-Descriptions", "NGAP-PDU-Contents", "NGAP-IEs",
        "NGAP-CommonDataTypes", "NGAP-Constants", "NGAP-Containers"]
# Each module is one ASN1START..ASN1STOP block; its name is the first token of the first
# non-comment line (the OID and DEFINITIONS may follow on later lines).
mods, blk, on, start = {}, [], False, 0
for n, line in enumerate(paras, 1):
    s = line.strip()
    if s.startswith("-- ASN1START"):
        if on:
            sys.exit(f"error: ASN1START at paragraph {start} has no ASN1STOP before the next ASN1START (paragraph {n})")
        on, blk, start = True, [], n
        continue
    if s.startswith("-- ASN1STOP"):
        if not on:
            sys.exit(f"error: ASN1STOP at paragraph {n} without a preceding ASN1START")
        on = False
        first = next((l.strip() for l in blk if l.strip() and not l.strip().startswith("--")), "")
        mm = re.match(r"[A-Za-z][A-Za-z0-9-]*", first)
        if not mm:
            sys.exit(f"error: cannot determine the module name of the ASN1START block at paragraph {start}")
        mods.setdefault(mm.group(0), []).extend(blk)
        continue
    if on:
        blk.append(line.rstrip())
if on:
    sys.exit(f"error: ASN1START at paragraph {start} has no ASN1STOP")

extra = sorted(m for m in mods if m not in WANT)
if extra:
    print("warning: modules found outside the wanted set (ignored): " + ", ".join(extra), file=sys.stderr)

missing = [m for m in WANT if m not in mods]
if missing:
    sys.exit("error: modules not found in docx: " + ", ".join(missing))
for m in WANT:
    with open(f"{out}/{m}.asn", "w") as f:
        f.write("\n".join(mods[m]) + "\n")
PY

(cd "$OUT" && ls *.asn | sort | xargs shasum -a 256 > SHA256SUMS)
VER="$(basename "$DOCX")"
{
	echo "# NGAP ASN.1 source"
	echo
	echo "- Spec: TS 38.413 §9.4, from \`$(basename "$ZIP")\` (docx: \`$VER\`)"
	echo "- Zip sha256: $(shasum -a 256 "$ZIP" | cut -d' ' -f1)"
	echo "- Extracted: $(date -u +%Y-%m-%d) by scripts/extract-asn1.sh"
	echo "- Git-ignored: only generated Go is committed (dev/rel19/PLAN.md R3 fallback)."
} >"$OUT/SOURCE.md"

echo "extracted $(ls "$OUT"/*.asn | wc -l | tr -d ' ') modules into $OUT"
(cd "$OUT" && shasum -a 256 -c SHA256SUMS && { grep -c "ProtocolIE-ID ::=" *.asn || true; })
