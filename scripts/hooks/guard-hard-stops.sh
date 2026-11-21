#!/usr/bin/env bash
# guard-hard-stops.sh — Claude Code PreToolUse hook (Edit|Write|MultiEdit|NotebookEdit).
# Enforces the AGENTS.md hard stops deterministically, for the main session and every sub-agent:
#   compose  docker-compose*.y(a)ml            (service definitions)
#   crypto   shared/crypto/**, shared/aka/**   (primitives; *_test.go is allowed)
#   checks   verification machinery            (AGENTS.md gate 8: agent defs, hooks, verify-task, lint, CI)
# Exit 2 blocks the tool call and returns the message on stderr to the model.
# With a sign-off recorded in dev/REL19_PROGRAM.md §4, the human starts the session with
#   HARD_STOP_SIGNOFF=compose, =crypto or =checks (comma-separated for several).
# Shell edits (sed -i, redirects) are not intercepted: the rule in AGENTS.md still applies to them.
input=$(cat)
path=$(printf '%s' "$input" | grep -oE '"(file_path|notebook_path)"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*:[[:space:]]*"//; s/"$//')
[ -n "$path" ] || exit 0

signed() { case ",${HARD_STOP_SIGNOFF:-}," in *",$1,"*) return 0 ;; esac; return 1; }
block() {
  {
    echo "HARD STOP (AGENTS.md): $2 needs human sign-off. Blocked: $path"
    echo "Do not work around this with a shell edit. Record a blocker (requires_human: true, hard_stop: true) and stop,"
    echo "or ask the human to restart the session with HARD_STOP_SIGNOFF=$1 once the grant is in dev/REL19_PROGRAM.md §4."
  } >&2
  exit 2
}

if printf '%s' "$path" | grep -qE '(^|/)docker-compose[^/]*\.ya?ml$'; then
  signed compose || block compose "a change to docker-compose service definitions"
fi
if printf '%s' "$path" | grep -qE '(^|/)shared/(crypto|aka)/' && ! printf '%s' "$path" | grep -q '_test\.go$'; then
  signed crypto || block crypto "a change to shared/ cryptographic primitives"
fi
# checks: the verification machinery (AGENTS.md gate 8, CI-002) — a change must not edit the checks that judge it.
# Same list as MACHINERY in scripts/verify-task.sh (which also catches shell edits via --lock).
if printf '%s' "$path" | grep -qE '(^|/)(AGENTS\.md|dev/ORCHESTRATOR_PROMPT\.md|\.claude/agents/|\.opencode/agent/|\.claude/settings\.json$|\.claude/skills/light-task/|scripts/hooks/|scripts/verify-task\.sh$|scripts/docs-lint\.sh$|\.golangci\.yml$|\.github/workflows/)'; then
  signed checks || block checks "a change to the verification machinery (AGENTS.md gate 8)"
fi
exit 0
