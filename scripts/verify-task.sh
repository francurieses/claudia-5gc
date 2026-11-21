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
#   --lock-init ID  snapshot the check paths (below) now, as refs/check-lock/ID; run it once when the task's
#                   contract is fixed (orchestrator: after Step 2; /light-task: before delegating). Then exit.
#   --lock ID       compare the working tree (tracked + untracked, so shell edits count) with that snapshot.
#
# Check lock (CI-002; AGENTS.md "Gates"). A change must not edit the checks that judge it.
#   machinery  AGENTS.md, dev/ORCHESTRATOR_PROMPT.md, .claude/agents/, .opencode/agent/, .claude/settings.json,
#              .claude/skills/light-task/, scripts/hooks/, scripts/verify-task.sh, scripts/docs-lint.sh,
#              .golangci.yml, .github/workflows/ — any change is a violation unless HARD_STOP_SIGNOFF has "checks".
#   contract   *.feature, **/testdata/**, *golden* files — adding is free; modifying or deleting is a violation.
#   tests      an existing *_test.go may change, but deleting it, removing a Test/Fuzz func or adding
#              t.Skip / time.Sleep is a violation.
# A contract/test violation is accepted when justified: a line "<path> — <reason>" in .tmp/check-lock/ID.justify,
# or "check-change: ID <path> — <reason>" in dev/SESSION_LOG.md. CHECK_LOCK_MODE=observe (default) prints
# OBSERVE lines and does not fail; CHECK_LOCK_MODE=enforce makes each violation a FAIL.
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0"/..)"

NF=""; PROC=""; FEATURE=""; FUNC=0; DOCS=0; LINUX=0; LOCK_INIT=""; LOCK=""
while [ $# -gt 0 ]; do
  case "$1" in
    --nf) NF="$2"; shift 2 ;;
    --proc) PROC="$2"; shift 2 ;;
    --feature) FEATURE="$2"; shift 2 ;;
    --func) FUNC=1; shift ;;
    --docs) DOCS=1; shift ;;
    --linux-build) LINUX=1; shift ;;
    --lock-init) LOCK_INIT="$2"; shift 2 ;;
    --lock) LOCK="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^set -uo/p' "$0" | sed '$d'; exit 0 ;;
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

MACHINERY=(AGENTS.md dev/ORCHESTRATOR_PROMPT.md .claude/agents .opencode/agent .claude/settings.json
  .claude/skills/light-task scripts/hooks scripts/verify-task.sh scripts/docs-lint.sh .golangci.yml .github/workflows)
CONTRACT=(':(glob)**/*.feature' ':(glob)**/testdata/**' ':(glob)**/*golden*')

# worktree_tree: tree object of the whole working tree (tracked + untracked, .gitignore honoured),
# built in a throwaway index so the real index is untouched.
worktree_tree() {
  local idx; idx=$(mktemp "${TMPDIR:-/tmp}/check-lock-idx.XXXXXX") || return 1
  rm -f "$idx"
  if ! { GIT_INDEX_FILE="$idx" git read-tree HEAD && GIT_INDEX_FILE="$idx" git add -A -- . &&
         GIT_INDEX_FILE="$idx" git write-tree; }; then
    rm -f "$idx"; return 1
  fi
  rm -f "$idx"
}

lock_ref() { echo "refs/check-lock/$1"; }

if [ -n "$LOCK_INIT" ]; then
  tree=$(worktree_tree) || { echo "FAIL check-lock init: cannot snapshot the working tree"; exit 1; }
  c=$(GIT_AUTHOR_NAME=check-lock GIT_AUTHOR_EMAIL=check-lock@localhost GIT_COMMITTER_NAME=check-lock \
      GIT_COMMITTER_EMAIL=check-lock@localhost git commit-tree "$tree" -p HEAD -m "check-lock $LOCK_INIT") &&
    git update-ref "$(lock_ref "$LOCK_INIT")" "$c" ||
    { echo "FAIL check-lock init: cannot write $(lock_ref "$LOCK_INIT")"; exit 1; }
  echo "PASS check-lock init $LOCK_INIT -> $(lock_ref "$LOCK_INIT") (${c:0:12})"
  exit 0
fi

# justified <path>: a recorded reason exists for this contract/test change.
justified() {
  local f=".tmp/check-lock/$LOCK.justify"
  { [ -f "$f" ] && grep -qF -- "$1 " "$f"; } && return 0
  [ -f dev/SESSION_LOG.md ] && grep -qF -- "check-change: $LOCK $1 " dev/SESSION_LOG.md
}

check_lock() {
  local snap cur mode="${CHECK_LOCK_MODE:-observe}" v=() added=0 tmod=0 st p
  snap=$(git rev-parse -q --verify "$(lock_ref "$LOCK")^{tree}") ||
    { fail "check-lock $LOCK: no snapshot (run scripts/verify-task.sh --lock-init $LOCK first)"; return; }
  cur=$(worktree_tree) || { fail "check-lock $LOCK: cannot snapshot the working tree"; return; }

  case ",${HARD_STOP_SIGNOFF:-}," in *",checks,"*) ;; *)
    while IFS=$'\t' read -r st p; do
      [ -n "$p" ] && v+=("machinery $st $p (needs HARD_STOP_SIGNOFF=checks)")
    done < <(git diff --no-renames --name-status "$snap" "$cur" -- "${MACHINERY[@]}") ;;
  esac

  while IFS=$'\t' read -r st p; do
    [ -n "$p" ] || continue
    if [ "$st" = A ]; then added=$((added + 1)); continue; fi
    justified "$p" || v+=("contract $st $p")
  done < <(git diff --no-renames --name-status "$snap" "$cur" -- "${CONTRACT[@]}")

  while IFS=$'\t' read -r st p; do
    [ -n "$p" ] || continue
    if [ "$st" = D ]; then justified "$p" || v+=("tests D $p (test file deleted)"); continue; fi
    [ "$st" = M ] || continue
    tmod=$((tmod + 1))
    local d rm_funcs fn plus_skip minus_skip
    d=$(git diff --no-renames -U0 "$snap" "$cur" -- "$p")
    rm_funcs=$(printf '%s\n' "$d" | sed -nE 's/^-func ((Test|Fuzz)[A-Za-z0-9_]*)\(.*/\1/p')
    for fn in $rm_funcs; do
      printf '%s\n' "$d" | grep -qE "^\+func $fn\(" || { justified "$p" || v+=("tests M $p (removed $fn)"); }
    done
    plus_skip=$(printf '%s\n' "$d" | grep -cE '^\+.*(\.Skip(f|Now)?\(|time\.Sleep\()')
    minus_skip=$(printf '%s\n' "$d" | grep -cE '^-.*(\.Skip(f|Now)?\(|time\.Sleep\()')
    if [ "$plus_skip" -gt "$minus_skip" ]; then
      justified "$p" || v+=("tests M $p (+$((plus_skip - minus_skip)) t.Skip/time.Sleep)")
    fi
  done < <(git diff --no-renames --name-status "$snap" "$cur" -- ':(glob)**/*_test.go')

  local info="$added contract file(s) added, $tmod existing test file(s) modified"
  if [ ${#v[@]} -eq 0 ]; then pass "check-lock $LOCK ($info)"; return; fi
  if [ "$mode" = enforce ]; then
    fail "check-lock $LOCK: ${#v[@]} violation(s) ($info)" "$(printf '%s\n' "${v[@]}")"
  else
    echo "OBSERVE check-lock $LOCK: ${#v[@]} would-fail ($info); record them as check_lock: in the session entry"
    printf '    %s\n' "${v[@]}"
  fi
}

# Cheap checks first: the lock is a git diff, the builds below are not.
[ -n "$LOCK" ] && check_lock

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
