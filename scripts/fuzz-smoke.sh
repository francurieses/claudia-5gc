#!/usr/bin/env bash
# fuzz-smoke.sh — run every native Go fuzz target in the repo for a short time (CI-003).
# Go fuzzes one target per `go test` call, so this finds each `func Fuzz*` in *_test.go under nf/, shared/,
# tools/ and mcp/ and runs it from its module root (nf/nrf has its own go.mod). One PASS/FAIL line per target;
# a failing input is written by Go to <pkg>/testdata/fuzz/<Target>/ — commit it as a regression case with the fix.
#
# Usage: scripts/fuzz-smoke.sh [regex]     FUZZTIME=5s (default) per target; regex filters "<pkg>.<Target>"
# Exit 1 if any target fails. `go test ./...` already replays the committed corpus without fuzzing.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
FUZZTIME="${FUZZTIME:-5s}"
FILTER="${1:-.}"
FAILS=0; N=0; START=$(date +%s)

modroot() { # nearest directory at or above $1 holding a go.mod
  local d="$1"
  while [ "$d" != . ] && [ ! -f "$d/go.mod" ]; do d=$(dirname "$d"); done
  echo "$d"
}

while IFS= read -r line; do
  file="${line%%:*}"; name=$(printf '%s' "${line#*:}" | sed -E 's/^func (Fuzz[A-Za-z0-9_]*).*/\1/')
  pkg=$(dirname "$file")
  printf '%s.%s\n' "$pkg" "$name" | grep -qE -- "$FILTER" || continue
  root=$(modroot "$pkg"); rel="./${pkg#"$root"/}"; [ "$root" = "$pkg" ] && rel=.
  N=$((N + 1))
  out=$(cd "$root" && go test "$rel" -run '^$' -fuzz "^${name}\$" -fuzztime="$FUZZTIME" 2>&1)
  if [ $? -eq 0 ]; then
    echo "PASS $pkg $name"
  else
    echo "FAIL $pkg $name"; printf '%s\n' "$out" | grep -vE '^(fuzz: elapsed|=== |--- )' | tail -n 12 | sed 's/^/    /'
    FAILS=$((FAILS + 1))
  fi
done < <(grep -rnoE '^func Fuzz[A-Za-z0-9_]*\(' --include='*_test.go' nf shared tools mcp 2>/dev/null | sed -E 's/:[0-9]+:/:/' | sort)

echo "fuzz-smoke: $N target(s), $FAILS failed, FUZZTIME=$FUZZTIME, $(( $(date +%s) - START ))s"
[ "$N" -gt 0 ] || { echo "fuzz-smoke: no fuzz targets matched"; exit 1; }
[ "$FAILS" -eq 0 ]
