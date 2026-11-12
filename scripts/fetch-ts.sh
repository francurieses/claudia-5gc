#!/usr/bin/env bash
# scripts/fetch-ts.sh — download 3GPP TS text from the public archive and convert it to plain text.
# Output: .tmp/3gpp-ts/<spec>-V<x.y.z>.txt (git-ignored). Grep it; never read it whole (files are MBs).
#
# Usage: scripts/fetch-ts.sh <NN.NNN>[:REL] ...     e.g.  scripts/fetch-ts.sh 29.573 33.501:19
#   REL  release number, default 19 (Rel-19 = archive letter "j", Rel-20 = "k", Rel-18 = "i", Rel-17 = "h")
# Env: OUTDIR (default .tmp/3gpp-ts)
# Needs network access to www.3gpp.org; pure bash + curl + unzip + python3 (stdlib only, no pandoc/Word).
# Picks the highest version of the release found in the archive directory listing.
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0"/..)"
OUT="${OUTDIR:-.tmp/3gpp-ts}"
BASE="https://www.3gpp.org/ftp/Specs/archive"
[ "$#" -ge 1 ] || { sed -n 2,9p "$0"; exit 2; }
mkdir -p "$OUT"
rc=0
for arg in "$@"; do
  spec="${arg%%:*}"; rel="${arg#*:}"; [ "$rel" = "$arg" ] && rel=19
  [[ "$spec" =~ ^[0-9]{2}\.[0-9]{3}$ ]] || { echo "bad spec '$spec' (want NN.NNN)" >&2; rc=1; continue; }
  letter="$(python3 -I -c "import sys;print('abcdefghijklmnopqrstuvwxyz'[int(sys.argv[1])-10])" "$rel")"
  series="${spec%%.*}_series"; num="${spec/./}"
  list="$(curl -fsSL -m 60 "$BASE/$series/$spec/" 2>/dev/null | grep -o "${num}-${letter}[0-9a-z][0-9a-z]\.zip" | sort -u | tail -1 || true)"
  [ -n "$list" ] || { echo "FAIL $spec Rel-$rel: no archive entry (network blocked or release not published)" >&2; rc=1; continue; }
  code="${list%.zip}"; code="${code#${num}-}"
  ver="$(python3 -I -c "
import sys
v=lambda c:int(c,36)
c=sys.argv[2]
print('%s.%d.%d'%(sys.argv[1],v(c[1]),v(c[2])))" "$rel" "$code")"
  # letter is code[0]; major.minor.patch = rel . code[1] . code[2]
  txt="$OUT/${num}-V${ver}.txt"
  if [ -s "$txt" ]; then echo "OK   $spec -> $txt (cached)"; continue; fi
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -m 300 -o "$tmp/ts.zip" "$BASE/$series/$spec/$list" || { echo "FAIL $spec download" >&2; rc=1; continue; }
  unzip -q -o "$tmp/ts.zip" -d "$tmp/x"
  doc="$(find "$tmp/x" -iname '*.docx' | head -1)"
  [ -n "$doc" ] || { echo "FAIL $spec: no .docx in archive" >&2; rc=1; continue; }
  python3 -I - "$doc" "$txt" <<'PY'
import re, sys, zipfile, html
xml = zipfile.ZipFile(sys.argv[1]).read('word/document.xml').decode('utf8')
xml = re.sub(r'<w:tab/>', '\t', xml)
xml = re.sub(r'</w:tc>', '\t', xml)
xml = re.sub(r'</w:p>', '\n', xml)
text = html.unescape(re.sub(r'<[^>]+>', '', xml))
open(sys.argv[2], 'w').write(re.sub(r'\n{3,}', '\n\n', text))
PY
  echo "OK   $spec Rel-$rel V$ver -> $txt ($(wc -c <"$txt") bytes)"
done
exit $rc
