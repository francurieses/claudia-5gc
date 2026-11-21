#!/usr/bin/env bash
# token-audit.sh — estimate the context-token cost of the files an agent loads or reads.
# Usage: scripts/token-audit.sh [--top N] [--budget FILE=TOKENS | LISTING=TOKENS | 'GLOB:<pattern>=TOKENS' ...]
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

section "Instructions (CLAUDE.md: every session and every sub-agent; AGENTS.md: read by the orchestrator)"
list_tokens instructions CLAUDE.md AGENTS.md

# fm_field <file> <key>: value of a frontmatter key (first line only is enough to rank)
fm_has() { awk '/^---$/{c++; next} c==1' "$1" | grep -q "^$2"; }
fm_desc() { awk '/^---$/{c++; next} c==1' "$1" | awk '/^description:/{f=1; sub(/^description: */,""); print; next} f&&/^[ \t]/{print; next} {f=0}'; }
section "Session listing (name + description of every agent and model-invocable skill/command; paid in EVERY session)"
for f in .claude/agents/*.md .claude/skills/*/SKILL.md .claude/commands/*.md; do
  [ -f "$f" ] || continue
  fm_has "$f" 'disable-model-invocation: *true' && continue
  echo "$(( ($(fm_desc "$f" | wc -c) + 3) / 4 )) $f"
done | sort -rn | head -n 6 | awk '{printf "%8d  %s\n",$1,$2}'
listing=0; n=0; manual=0   # ~40 bytes per entry for the name and list framing
for f in .claude/agents/*.md .claude/skills/*/SKILL.md .claude/commands/*.md; do
  [ -f "$f" ] || continue
  if fm_has "$f" 'disable-model-invocation: *true'; then manual=$((manual+1)); continue; fi
  listing=$((listing + $(fm_desc "$f" | wc -c) + 40)); n=$((n+1))
done
LISTING_TOKENS=$(( listing / 4 ))
printf '%8d  TOTAL listing (%d entries listed, %d manual-only skills not listed)\n' "$LISTING_TOKENS" "$n" "$manual"

section "NF / subsystem root CLAUDE.md (loaded for ANY file under that directory — keep to subtree-wide rules)"
list_tokens nf-claude nf/*/CLAUDE.md mcp/CLAUDE.md tools/*/CLAUDE.md

section "Package CLAUDE.md (loaded only when a file in that package is opened)"
# shellcheck disable=SC2046
list_tokens pkg-claude $(git ls-files -co --exclude-standard 'nf/*/*/**/CLAUDE.md' 'nf/*/*/CLAUDE.md' 'tools/*/*/**/CLAUDE.md' 'tools/*/*/CLAUDE.md' 2>/dev/null | sort -u)

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

# Budgets: FILE=TOKENS, or LISTING=TOKENS for the session listing, or 'GLOB:<pattern>=TOKENS' for every match.
rc=0
if [ ${#BUDGETS[@]} -gt 0 ]; then
  section "Budgets"
  for b in "${BUDGETS[@]}"; do
    f="${b%%=*}"; max="${b##*=}"
    if [ "$f" = LISTING ]; then
      if [ "$LISTING_TOKENS" -gt "$max" ]; then echo "FAIL  session listing: $LISTING_TOKENS > $max tokens (shorten descriptions or make a skill manual-only)"; rc=1
      else echo "OK    session listing: $LISTING_TOKENS <= $max tokens"; fi
      continue
    fi
    case "$f" in GLOB:*)
      for g in ${f#GLOB:}; do
        [ -f "$g" ] || continue
        t=$(tok "$g")
        if [ "$t" -gt "$max" ]; then echo "FAIL  $g: $t > $max tokens (split it: rules live next to the code, see /token-diet §5)"; rc=1; fi
      done
      echo "OK    ${f#GLOB:} checked against $max tokens"; continue ;;
    esac
    [ -f "$f" ] || { echo "SKIP  $f (missing)"; continue; }
    t=$(tok "$f")
    if [ "$t" -gt "$max" ]; then echo "FAIL  $f: $t > $max tokens"; rc=1
    else echo "OK    $f: $t <= $max tokens"; fi
  done
fi
exit $rc
