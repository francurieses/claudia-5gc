#!/usr/bin/env bash
# test-check-lock.sh — self-test of the CI-002 check lock: `scripts/verify-task.sh --lock-init/--lock` and the
# `checks` class of scripts/hooks/guard-hard-stops.sh. Runs in a throwaway git repo; touches nothing here.
# Usage: scripts/test-check-lock.sh   (exit 0 = all cases pass)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/check-lock-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
FAILS=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/     /'; FAILS=$((FAILS + 1)); }

# expect <name> <want-exit> <want-regex|-> <cmd...>
expect() {
  local name="$1" want="$2" re="$3"; shift 3
  local out rc; out=$("$@" 2>&1); rc=$?
  if [ "$rc" != "$want" ]; then bad "$name (exit $rc, want $want)" "$out"; return; fi
  if [ "$re" != - ] && ! printf '%s\n' "$out" | grep -qE -- "$re"; then bad "$name (no /$re/)" "$out"; return; fi
  ok "$name"
}

# --- fixture repo -------------------------------------------------------------------------------------------
fresh() {
  rm -rf "$WORK/r"; mkdir -p "$WORK/r" && cd "$WORK/r" || exit 1
  git init -q . && git config user.email t@t && git config user.name t
  mkdir -p scripts/hooks nf/amf/tests/features nf/amf/internal/x/testdata .tmp
  cp "$ROOT/scripts/verify-task.sh" scripts/ && cp "$ROOT/scripts/hooks/guard-hard-stops.sh" scripts/hooks/
  printf '.tmp/\n' > .gitignore
  printf 'Feature: f\n  Scenario: a\n' > nf/amf/tests/features/reg.feature
  printf 'gold\n' > nf/amf/internal/x/testdata/msg.golden
  printf 'package x\n\nimport "testing"\n\nfunc TestA(t *testing.T) {}\n\nfunc TestB(t *testing.T) {}\n' \
    > nf/amf/internal/x/x_test.go
  printf '# agents\n' > AGENTS.md
  git add -A && git commit -qm base
}
vt() { CHECK_LOCK_MODE=enforce scripts/verify-task.sh "$@"; }

# --- verify-task --lock -------------------------------------------------------------------------------------
fresh
expect "lock without snapshot fails"         1 'no snapshot'               vt --lock T1
expect "lock-init writes the ref"            0 'refs/check-lock/T1'        scripts/verify-task.sh --lock-init T1
expect "clean tree passes"                   0 'PASS check-lock T1'        vt --lock T1
git rev-parse -q --verify refs/check-lock/T1 >/dev/null && git diff --cached --quiet && ok "real index untouched" ||
  bad "real index untouched"

printf 'Feature: g\n' > nf/amf/tests/features/new.feature
printf 'package x\n\nimport "testing"\n\nfunc TestC(t *testing.T) {}\n' > nf/amf/internal/x/c_test.go
expect "added feature + new test file pass"  0 '2 contract file\(s\) added|PASS check-lock' vt --lock T1

fresh; scripts/verify-task.sh --lock-init T1 >/dev/null
printf 'Feature: changed\n' > nf/amf/tests/features/reg.feature
expect "modified feature fails (enforce)"    1 'contract M nf/amf/tests/features/reg.feature' vt --lock T1
expect "same in observe mode does not fail"  0 'OBSERVE check-lock T1: 1 would-fail' \
  env CHECK_LOCK_MODE=observe scripts/verify-task.sh --lock T1
mkdir -p .tmp/check-lock
printf 'nf/amf/tests/features/reg.feature — scenario renamed to match TS wording\n' > .tmp/check-lock/T1.justify
expect "justified change passes"             0 'PASS check-lock T1'        vt --lock T1

fresh; scripts/verify-task.sh --lock-init T1 >/dev/null
sed -i.bak 's/gold/silver/' nf/amf/internal/x/testdata/msg.golden && rm -f nf/amf/internal/x/testdata/msg.golden.bak
expect "shell-edited golden fails"           1 'contract M .*msg.golden'   vt --lock T1

fresh; scripts/verify-task.sh --lock-init T1 >/dev/null
rm nf/amf/tests/features/reg.feature
expect "deleted feature fails"               1 'contract D'                vt --lock T1

fresh; scripts/verify-task.sh --lock-init T1 >/dev/null
printf 'package x\n\nimport "testing"\n\nfunc TestA(t *testing.T) {}\n' > nf/amf/internal/x/x_test.go
expect "removed Test func fails"             1 'removed TestB'             vt --lock T1

fresh; scripts/verify-task.sh --lock-init T1 >/dev/null
printf 'package x\n\nimport "testing"\n\nfunc TestA(t *testing.T) { t.Skip("x") }\n\nfunc TestB(t *testing.T) {}\n' \
  > nf/amf/internal/x/x_test.go
expect "added t.Skip fails"                  1 't.Skip/time.Sleep'         vt --lock T1

fresh; scripts/verify-task.sh --lock-init T1 >/dev/null
printf 'package x\n\nimport "testing"\n\nfunc TestA(t *testing.T) { _ = 1 }\n\nfunc TestB(t *testing.T) {}\n' \
  > nf/amf/internal/x/x_test.go
expect "editing a test body is allowed"      0 '1 existing test file\(s\) modified' vt --lock T1

fresh; scripts/verify-task.sh --lock-init T1 >/dev/null
rm nf/amf/internal/x/x_test.go
expect "deleted test file fails"             1 'tests D'                   vt --lock T1

fresh; scripts/verify-task.sh --lock-init T1 >/dev/null
printf '# agents, weaker gates\n' > AGENTS.md
expect "machinery edit fails"                1 'machinery M AGENTS.md'     vt --lock T1
expect "machinery edit passes with sign-off" 0 'PASS check-lock T1' env HARD_STOP_SIGNOFF=checks CHECK_LOCK_MODE=enforce scripts/verify-task.sh --lock T1

# --- guard hook, checks class -------------------------------------------------------------------------------
hook() { printf '{"tool_name":"Edit","tool_input":{"file_path":"%s"}}' "$1" | env ${2:+HARD_STOP_SIGNOFF=$2} \
  "$ROOT/scripts/hooks/guard-hard-stops.sh"; }
for p in AGENTS.md .claude/agents/orchestrator.md .opencode/agent/orchestrator.md .claude/settings.json \
         .claude/skills/light-task/SKILL.md scripts/hooks/guard-hard-stops.sh scripts/verify-task.sh \
         scripts/docs-lint.sh .golangci.yml .github/workflows/ci.yml dev/ORCHESTRATOR_PROMPT.md; do
  expect "hook blocks /repo/$p"              2 'HARD STOP'                 hook "/repo/$p"
done
expect "hook allows machinery with sign-off" 0 -                           hook /repo/AGENTS.md checks
expect "hook allows a feature file"          0 -                           hook /repo/nf/amf/tests/features/reg.feature
expect "hook allows other skills"            0 -                           hook /repo/.claude/skills/docs-sync/SKILL.md
expect "hook allows settings.local.json"     0 -                           hook /repo/.claude/settings.local.json
expect "hook still blocks compose"           2 'compose'                   hook /repo/docker-compose.yml checks
expect "compose,checks sign-off list works"  0 -                           hook /repo/docker-compose.yml compose,checks

echo; [ "$FAILS" -eq 0 ] && { echo "check-lock self-test: ALL PASS"; exit 0; }
echo "check-lock self-test: $FAILS FAILED"; exit 1
