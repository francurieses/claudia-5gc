#!/usr/bin/env bash
# token-audit.sh — estimate the context-token cost of the files an agent loads or reads.
# Usage: scripts/token-audit.sh [--top N] [--budget FILE=TOKENS ...]
# Estimate: ~4 bytes per token (rough; good enough to rank and track regressions).
# Exit 1 if a --budget is exceeded, so it can gate CI or a pre-commit hook.
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0"/..)"

TOP=12
BUDGETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --top) TOP="$2"; shift 2 ;;
    --budget) BUDGETS+=("$2"); shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

tok() { echo $(( ($(wc -c <"$1") + 3) / 4 )); }

section() { printf '\n== %s ==\n' "$1"; }

# list_tokens <label> <file...> : print "tokens path" sorted, plus a total
list_tokens() {
  local label="$1"; shift
  local total=0 out=""
  for f in "$@"; do
    [ -f "$f" ] || continue
    local t; t=$(tok "$f"); total=$((total + t))
    out+="$t $f"$'\n'
  done
  printf '%s' "$out" | sort -rn | head -n "$TOP" | awk '{printf "%8d  %s\n",$1,$2}'
  printf '%8d  TOTAL %s\n' "$total" "$label"
}

section "Always-loaded instructions (root CLAUDE.md, AGENTS.md)"
list_tokens instructions CLAUDE.md AGENTS.md

section "Per-NF / subsystem CLAUDE.md (loaded when that area is touched)"
list_tokens nf-claude nf/*/CLAUDE.md mcp/CLAUDE.md tools/*/CLAUDE.md

section "Agent prompts (paid on every spawn)"
list_tokens agents .claude/agents/*.md .opencode/agent/*.md

section "Project skills"
list_tokens skills .claude/skills/*/SKILL.md

section "Large docs (never read whole — grep a heading, then offset/limit)"
# shellcheck disable=SC2046
list_tokens docs $(find docs -name '*.md' -size +40k 2>/dev/null)

section "Large Go files (>40 KB; read by range or via graphify)"
# shellcheck disable=SC2046
list_tokens go $(find nf shared mcp -name '*.go' -size +40k 2>/dev/null)

section "Repo hygiene"
[ -d graphify-out ] && echo "graphify-out: present" || echo "graphify-out: MISSING -> run /graphify . (cheaper code exploration)"
[ -f docs/INDEX.md ] && echo "docs/INDEX.md: present" || echo "docs/INDEX.md: MISSING -> add a short TOC so big docs are never read blind"

# Budgets: FILE=TOKENS
rc=0
if [ ${#BUDGETS[@]} -gt 0 ]; then
  section "Budgets"
  for b in "${BUDGETS[@]}"; do
    f="${b%%=*}"; max="${b##*=}"
    [ -f "$f" ] || { echo "SKIP  $f (missing)"; continue; }
    t=$(tok "$f")
    if [ "$t" -gt "$max" ]; then echo "FAIL  $f: $t > $max tokens"; rc=1
    else echo "OK    $f: $t <= $max tokens"; fi
  done
fi
exit $rc
