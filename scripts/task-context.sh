#!/usr/bin/env bash
# task-context.sh — one-call task briefing for an agent session (orchestrator, /light-task, or a human).
# Replaces the string of greps over dev/BACKLOG.md (~110 KB), dev/rel19/PLAN.md, dev/rel19/LESSONS.md and
# dev/REL19_PROGRAM.md with one capped, deterministic output. Read-only.
#
# Usage:
#   scripts/task-context.sh              open-task index, selectable tasks in pick order, last session entry
#   scripts/task-context.sh <TASK-ID>    the backlog entry + everything a delegation brief needs for it
#   scripts/task-context.sh --next       only the id the selection rule picks (empty if none)
# Selection rule (AGENTS.md / orchestrator): status TODO, every depends_on absent from the open index
# or marked DONE there (absent = DONE, archived), P1 > P2 > P3 > P4, `depends_on: []` first, then file order.
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0"/..)"

BACKLOG=dev/BACKLOG.md
PLAN=dev/rel19/PLAN.md
LESSONS=dev/rel19/LESSONS.md
PROGRAM=dev/REL19_PROGRAM.md
SESSION=dev/SESSION_LOG.md
[ -f "$BACKLOG" ] || { echo "missing $BACKLOG" >&2; exit 2; }

index() { awk '/^## Open tasks/{f=1;next} f&&/^## /{exit} f&&/^\| *[A-Za-z0-9]/&&!/^\| *id /' "$BACKLOG"; }

# Prints "priority deps-empty(0/1) order id depends_on" for every selectable task, best first.
selectable() {
  index | awk -F'|' '
    { id=$2; st=$3; pr=$4; dep=$5; gsub(/ /,"",id); gsub(/ /,"",st); gsub(/ /,"",pr); gsub(/[\[\] ]/,"",dep)
      n++; ids[n]=id; status[id]=st; prio[id]=pr; deps[id]=dep; open[id]=1 }
    END { for (i=1;i<=n;i++) { id=ids[i]; if (status[id]!="TODO") continue
            ok=1; m=split(deps[id],d,","); for (j=1;j<=m;j++) if (d[j]!="" && (d[j] in open) && status[d[j]]!="DONE") ok=0
            if (ok) printf "%s %d %04d %s [%s]\n", prio[id], (deps[id]==""?0:1), i, id, deps[id] } }' | sort
}

section() { printf '\n== %s ==\n' "$1"; }

if [ "${1:-}" = "--next" ]; then selectable | head -1 | awk '{print $4}'; exit 0; fi

if [ $# -eq 0 ]; then
  section "Open tasks by status"
  index | awk -F'|' '{gsub(/ /,"",$3); c[$3]++} END{for(s in c) printf "%-12s %d\n", s, c[s]}'
  section "IN_PROGRESS / BLOCKED (resolve before picking a new task)"
  index | awk -F'|' '$3 ~ /IN_PROGRESS|BLOCKED/' | head -20
  section "Selectable now, in pick order (top 12)"
  selectable | head -12 | awk '{printf "%-16s %s  depends_on=%s\n", $4, $1, $5}'
  section "Last session entry"
  if [ -f "$SESSION" ]; then awk '/^## Session /{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}' "$SESSION" | head -40
  else echo "(no $SESSION)"; fi
  echo; echo "Next: scripts/task-context.sh <ID>"
  exit 0
fi

ID="$1"
entry=$(awk -v id="$ID" '$0=="- id: " id{f=1} f&&/^- id: /&&$0!="- id: " id{exit} f&&/^## /{exit} f&&!/^```/' "$BACKLOG")
if [ -z "$entry" ]; then
  echo "$ID: not in $BACKLOG (open tasks only)."
  grep -n -m1 "^- id: $ID\$" dev/BACKLOG_ARCHIVE.md 2>/dev/null | sed "s|^|DONE - dev/BACKLOG_ARCHIVE.md:|"
  exit 1
fi

field() { printf '%s\n' "$entry" | sed -n "s/^  $1: *//p" | head -1 | tr -d '"'; }
nf=$(field nf | tr 'A-Z' 'a-z'); proc=$(field procedure); typ=$(field type); exe=$(field executor)

section "Backlog entry ($BACKLOG)"
printf '%s\n' "$entry"

section "Dependencies"
deps=$(field depends_on | tr -d '[] ' | tr ',' ' ')
if [ -z "$deps" ]; then echo "none"; else
  for d in $deps; do
    st=$(index | grep "^| *$d *|" | awk -F'|' '{gsub(/ /,"",$3); print $3}' | head -1)
    if [ -n "$st" ] && [ "$st" != DONE ]; then echo "$d  OPEN ($st) -> this task is not selectable yet"
    elif [ -n "$st" ]; then echo "$d  DONE"
    else echo "$d  DONE (archived)"; fi
  done
fi

section "Artifacts on disk"
if [ -n "$proc" ]; then
  p=$(ls docs/procedures 2>/dev/null | grep -i -m1 "^$proc\.md$" || true)
  [ -n "$p" ] && echo "procedure doc : docs/procedures/$p" || echo "procedure doc : MISSING (docs/procedures/$proc.md) -> procedure-planner first"
fi
if [ -n "$nf" ] && [ -d "nf/$nf" ]; then
  echo "nf rules      : nf/$nf/CLAUDE.md (+ <package>/CLAUDE.md of each package you edit)"
  feats=$(ls "nf/$nf/tests/features" 2>/dev/null | grep '\.feature$' | grep -i -e "$(printf '%s' "$proc" | sed 's/\([a-z]\)\([A-Z]\)/\1.\2/g')" 2>/dev/null | head -3 | tr '\n' ' ')
  [ -n "$feats" ] && echo "feature file  : nf/$nf/tests/features/{ $feats}" || echo "feature file  : none matching '$proc' in nf/$nf/tests/features -> test-engineer MODE: SPEC"
elif [ -n "$nf" ]; then echo "nf/$nf does not exist (new NF: nf/_template §0, scripts/new-nf.sh)"; fi

section "Path"
hard=""
[ "$(field requires_human)" = "true" ] && hard="requires_human: true"
[ "$typ" = "umbrella" ] && hard="${hard:+$hard, }type: umbrella (never selected)"
if [ -n "$hard" ]; then echo "HARD STOP: $hard -> BLOCKED unless $PROGRAM §4 records a grant."
elif printf '%s\n' "$entry" | grep -qiE 'docker-compose|shared/(crypto|aka)'; then
  echo "CAUTION: the entry mentions a hard-stop area (docker-compose / shared crypto). Read it; use @orchestrator, not /light-task."
else echo "No hard-stop marker. /light-task only if every condition in .claude/skills/light-task/SKILL.md §1 holds; else @orchestrator."; fi
[ -n "$exe" ] && echo "executor: $exe"

case "$ID" in REL19-*) step="${ID#REL19-}"
  section "Plan step ($PLAN)"
  grep -n -m1 -A3 "\*\*$step\*\*" "$PLAN" 2>/dev/null | cut -c1-1600 || echo "(step $step not found)";;
esac

if [ -f "$LESSONS" ]; then
  section "Lessons mentioning $ID${nf:+ / $nf} ($LESSONS, capped)"
  { grep -n "$ID" "$LESSONS"; [ -n "$nf" ] && grep -n -i "nf/$nf/\|\b$nf\b" "$LESSONS" | tail -8; } 2>/dev/null | sort -t: -k1,1n -u | cut -c1-320 | head -14
fi

if printf '%s\n' "$entry" | grep -qE '^  release: *"?Rel-(18|19|20)' || [ "${ID#REL19-}" != "$ID" ] || [ "$ID" = "SEPP-001" ]; then
  for s in 4 6; do
    section "$PROGRAM §$s"
    awk -v s="## $s. " 'index($0,s)==1{f=1} f&&/^## /&&index($0,s)!=1{exit} f' "$PROGRAM" | cut -c1-420 | head -40
  done
fi
exit 0
