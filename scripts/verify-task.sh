#!/usr/bin/env bash
# verify-task.sh — one-call verification of a delegation's artifacts and gates.
# Replaces a string of single greps/builds with one call and capped output: one PASS/FAIL line per
# check, plus the last lines of any failing command. Exit 1 if any check fails.
#
# Usage: scripts/verify-task.sh [--nf NAME] [--proc NAME] [--feature FILE] [--func] [--docs] [--linux-build]
#   --nf NAME       run `make -C nf/NAME build` and `make -C nf/NAME test` (works for nf/nrf's own module too)
#   --proc NAME     docs/procedures/NAME.md exists and has a mermaid block; with --nf, a feature file whose
#                   name matches NAME (or --feature FILE) exists and has >= 3 scenarios
#   --feature FILE  explicit .feature path (relative to the repo root)
#   --func          also run `make -C nf/NAME test-functional` (needs --nf)
#   --docs          also run `make docs-check STRICT=1`
#   --linux-build   also run GOOS=linux GOWORK=off go build ./nf/... ./shared/... ./tools/...
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0"/..)"

NF=""; PROC=""; FEATURE=""; FUNC=0; DOCS=0; LINUX=0
while [ $# -gt 0 ]; do
  case "$1" in
    --nf) NF="$2"; shift 2 ;;
    --proc) PROC="$2"; shift 2 ;;
    --feature) FEATURE="$2"; shift 2 ;;
    --func) FUNC=1; shift ;;
    --docs) DOCS=1; shift ;;
    --linux-build) LINUX=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ "$FUNC" = 1 ] && [ -z "$NF" ] && { echo "--func needs --nf" >&2; exit 2; }

FAILS=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); [ -n "${2:-}" ] && printf '%s\n' "$2" | tail -n 15 | sed 's/^/    /'; }

# run <name> <cmd...> : run a command, report PASS/FAIL with a capped tail of its output on failure
run() {
  local name="$1"; shift
  local out; out=$("$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then pass "$name"; else fail "$name (exit $rc)" "$out"; fi
}

if [ -n "$PROC" ]; then
  doc="docs/procedures/$PROC.md"
  if [ -f "$doc" ] && grep -q 'mermaid' "$doc"; then pass "procedure doc $doc"; else fail "procedure doc $doc (missing or no mermaid block)"; fi
  if [ -n "$NF" ] || [ -n "$FEATURE" ]; then
    f="$FEATURE"
    if [ -z "$f" ]; then
      key=$(echo "$PROC" | tr '[:upper:]' '[:lower:]' | tr -d '_-')
      for c in "nf/$NF"/tests/features/*.feature; do
        [ -f "$c" ] || continue
        base=$(basename "$c" .feature | tr '[:upper:]' '[:lower:]' | tr -d '_-')
        case "$base" in *"$key"*|"$key"*) f="$c"; break ;; esac
      done
    fi
    if [ -n "$f" ] && [ -f "$f" ]; then
      n=$(grep -c -E '^\s*Scenario' "$f")
      if [ "$n" -ge 3 ]; then pass "feature $f ($n scenarios)"; else fail "feature $f has $n scenarios (need >= 3)"; fi
    else
      fail "feature file for $PROC not found under nf/$NF/tests/features (pass --feature)"
    fi
  fi
fi

if [ -n "$NF" ]; then
  [ -d "nf/$NF" ] || { echo "no such NF dir: nf/$NF" >&2; exit 2; }
  run "make -C nf/$NF build" make -C "nf/$NF" build
  run "make -C nf/$NF test" make -C "nf/$NF" test
  [ "$FUNC" = 1 ] && run "make -C nf/$NF test-functional" make -C "nf/$NF" test-functional
fi
[ "$LINUX" = 1 ] && run "GOOS=linux build ./nf/... ./shared/... ./tools/..." env GOOS=linux GOWORK=off go build ./nf/... ./shared/... ./tools/...
[ "$DOCS" = 1 ] && run "make docs-check STRICT=1" make docs-check STRICT=1

echo "diff: $(git diff --shortstat HEAD 2>/dev/null | sed 's/^ //')"
[ "$FAILS" -eq 0 ] && { echo "RESULT: ALL PASS"; exit 0; }
echo "RESULT: $FAILS FAILED"; exit 1
