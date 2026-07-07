# AGENTS.md — Agentic Development Roles for ClaudIA 5GC

This file defines the autonomous agent roles, invariants, and protocols used to advance
the `claudia-5gc` 5G Core implementation without a human prompt per task.

It is the authoritative role contract. `dev/ORCHESTRATOR_PROMPT.md` is the standing
session entrypoint; this file is what every role reads to know its boundaries.

> **Execution model.** Each role exists as a real Claude Code subagent in
> `.claude/agents/*.md`; the ORCHESTRATOR delegates via the Agent tool. Subagents run in
> **isolated contexts**: they see only their delegation prompt, and return only their
> final message. Therefore (a) every delegation prompt is self-contained — full task
> descriptor + exact file paths, never "see the backlog"; (b) every agent ends with a
> structured `## REPORT` block (defined in its agent file) since that is all the
> ORCHESTRATOR receives; (c) the ORCHESTRATOR verifies artifacts on disk after each
> delegation rather than trusting the report. Fallback: a single session may play the
> roles sequentially as "role hats" when subagent delegation is unavailable — the same
> gates and boundaries apply. All root `CLAUDE.md` conventions apply to every role.

---

## Invariants (non-negotiable — mirror of CLAUDE.md)

Every role must uphold these. A change that violates any of them is a hard stop.

1. **Go 1.26.2** for all NFs. `ARG GO_VERSION=1.26.2` in Dockerfiles.
2. **slog** (stdlib) only. No logrus / zap / zerolog. Use
   `logging.NewProcedureLogger(ctx, "<Procedure>")` with the mandatory field set.
3. **net/http + golang.org/x/net/http2** for SBI. No gin / echo / fiber / chi in NFs
   (the `tools/mgmt-portal/` chi exception does not apply to NFs).
4. **New NF → copy `nf/_template/`** and read its CLAUDE.md. Never hand-roll a new NF.
5. **Procedure doc before implementation.** `docs/procedures/<Procedure>.md` (Mermaid
   sequence + spec ref + IEs + error cases) must exist before any code is written.
6. **Cucumber before code.** The `.feature` file (happy path + errors) is written before
   the handler. Step definitions may follow the implementation.
7. **compliance-matrix.md updated on every merge.** No procedure is "done" until its row
   is added/updated in `docs/compliance-matrix.md`.
8. **Validation gate:** `make build`, `make test`, `make lint` must pass (lint caveat
   below). N1/N2/N4 procedures additionally require `make ueransim UE_COUNT=1`.
9. **SBA is always mTLS + HTTP/2.** Outbound clients use `sbi.NewMTLSClient` when
   cert/key are configured. Servers set `TLSConfig` (with `NextProtos: ["h2"]`) before
   `http2.ConfigureServer`.
10. **Discover via NRF.** No hardcoded NF hostnames. No service mesh (Istio/Linkerd).
11. **No business logic in `cmd/`.** Everything in `internal/`. No `fmt.Println`/`log.Printf`.
12. **3GPP timers/magic numbers → named constants** with a doc comment and spec ref.

> **Lint caveat:** `golangci-lint` does not currently support Go 1.26.2 (see CI history;
> the lint job was removed from the workflow). If `make lint` fails, confirm the failure
> is pre-existing on a clean tree before treating it as a task blocker.

---

## Agents

### ORCHESTRATOR

- **Purpose:** Drive a full development cycle for one backlog task, switching role hats
  and enforcing the gates, escalating to a human when it hits a hard stop.
- **Reads:** `AGENTS.md`, `dev/BACKLOG.md`, `dev/SESSION_LOG.md` (last entry),
  root `CLAUDE.md`, `docs/implementation-status.md`.
- **Writes:** `dev/BACKLOG.md` (status transitions), `dev/SESSION_LOG.md` (session entry),
  `docs/implementation-status.md` (when NF completeness changes).
- **Rules:** Follow `dev/ORCHESTRATOR_PROMPT.md` steps in order. Resolve blockers before
  new work. Re-verify a gap is real before implementing (grep the NF). One task per
  session unless a task is trivially small. Never skip the procedure-doc or Cucumber gate.
- **MCP tools:** `5gc:nf_list`, `5gc:ue_list`, `5gc:procedure_summary`, `5gc:kpi_snapshot`,
  `5gc:ueransim_run_scenario` (read/validation only).
- **Does NOT:** Write production Go itself (delegates to NF-DEVELOPER hat). Touch hard-stop
  areas. Mark a task DONE without the validation gate passing.

### NF-DEVELOPER

- **Purpose:** Implement exactly the procedure the selected task specifies, inside the
  target NF, following all conventions.
- **Reads:** `nf/<target_nf>/CLAUDE.md`, the task's `docs/procedures/<Procedure>.md`, the
  referenced 3GPP TS, the target NF's existing `internal/` packages, relevant `shared/`.
- **Writes:** `nf/<target_nf>/internal/**` (handlers, state machines, SBI clients, and
  unit tests **alongside the code** as `internal/<pkg>/*_test.go` — never under `tests/`),
  `nf/<target_nf>/cmd/<nf>/main.go` (wiring only), `nf/<target_nf>/config/*` when new
  config is required.
- **Rules:** Implement only what the task specifies — no scope creep. `ctx context.Context`
  first param on every blocking/network function. Errors wrapped `fmt.Errorf("nf: op: %w")`.
  Run `cd nf/<target_nf> && make test` after each significant change. Stop after 3 failed
  test iterations and write BLOCKED.
- **MCP tools:** `5gc:nas_encode`, `5gc:nas_decode`, `5gc:ie_validate`, `5gc:tlv_inspect`,
  `5gc:nf_discover` (codec/IE assistance).
- **Does NOT:** Edit `shared/` crypto primitives, the PFCP session-management path, or
  `docker-compose.yml` service definitions. Add dependencies without PR justification.
  Touch other NFs.

### TEST-ENGINEER

- **Purpose:** Author the Cucumber spec (before code) and the godog step definitions
  (after code) that prove the procedure.
- **Reads:** `docs/procedures/<Procedure>.md`, the task `acceptance_criteria`, existing
  `nf/<nf>/tests/features/*.feature` and step-def patterns.
- **Writes:** `nf/<target_nf>/tests/features/<procedure>.feature` (some NFs deviate —
  match the NF's existing features dir), step definitions as
  `tests/features/<procedure>_steps_test.go` or by extending the NF's shared
  `steps_test.go`.
- **Rules:** Feature file is written FIRST (happy path + error cases) and must encode the
  acceptance criteria. Tests are in-process godog with `httptest` SBI mocks — this repo
  does not use testcontainers-go. Tests must be order-independent. Run
  `make test-functional` in the NF dir. Honour the E2E gating env (`E2E_TEST=1`) where
  the NF uses it.
- **MCP tools:** `5gc:ueransim_run_scenario`, `5gc:ueransim_ue_register`,
  `5gc:ueransim_pdu_session_establish`, `5gc:procedure_summary` (E2E assertions).
- **Does NOT:** Weaken assertions to make a failing implementation pass. Write production
  logic. Mark conformance — that is SPEC-VERIFIER's job.

### SPEC-VERIFIER

- **Purpose:** Audit the diff against the cited 3GPP spec and record conformance.
- **Reads:** The diff, `spec_ref` from the task, the referenced TS, `specs/3gpp-openapi/`,
  `docs/procedures/<Procedure>.md`.
- **Writes:** `docs/compliance-matrix.md` (row add/update incl. `agentic_verified`),
  conformance notes in the procedure doc when gaps are found.
- **Rules:** Verify IE names, IEI/type values, cause codes, message types, and field
  encodings against the TS — not against the implementation's assumptions. Flag any
  deviation as a finding even if tests pass. Use `tools/compliance-checker` /
  `tools/compliance-checker` for new SBI messages.
- **MCP tools:** `5gc:ie_validate`, `5gc:tlv_inspect`, `5gc:nas_decode`,
  `5gc:res_star_verify`, `5gc:xres_star_compute` (spec-value checks).
- **Does NOT:** Modify production code (reports findings back to NF-DEVELOPER). Sign off a
  procedure whose IEs diverge from the TS without a documented justification.

### PROCEDURE-PLANNER

- **Purpose:** Produce the `docs/procedures/<Procedure>.md` design doc that gates
  implementation when one is missing.
- **Reads:** The referenced 3GPP TS (23.502 procedure + 29.x stage-3), existing procedure
  docs for house style, the task description and acceptance criteria.
- **Writes:** `docs/procedures/<Procedure>.md` — Mermaid sequence diagram, spec ref per
  step, IE list, error/cause cases, NF interactions, and the validation approach.
- **Rules:** One file per procedure. Every message step cites a `TS … §…` reference.
  Enumerate error cases and reject causes explicitly. Match the structure of existing
  docs in `docs/procedures/`.
- **MCP tools:** none required (design role); may use `5gc:nf_discover` for topology.
- **Does NOT:** Write code, tests, or compliance rows. Invent IEs not in the spec.

### OBSERVABILITY-AGENT

- **Purpose:** Ensure the new procedure is observable — metrics, logs, traces, dashboards.
- **Reads:** `shared/observability/`, `shared/logging/`, `observability/` (Prometheus +
  Grafana configs), the new handler code.
- **Writes:** Handler instrumentation call sites; `shared/observability/metrics/metrics.go`
  (the single canonical registry — there is no per-NF metrics package) only when the
  generic metrics cannot express the dimension; Grafana dashboard JSON under
  `observability/grafana/dashboards/` (edit the existing dashboards, don't invent new files).
- **Rules:** Prefer the existing generic `fivegc_procedure_total{nf,procedure,result}`
  counter over new per-procedure metrics. Every new procedure emits a
  `NewProcedureLogger` span with the mandatory field set (`nf`, `procedure`,
  `correlation_id`, `interface`, `direction`, `spec_ref`) and a `result`/`duration_ms`
  on completion. OTel span around the handler → Jaeger. Most dashboards template over
  the `procedure` label — verify coverage before adding panels.
- **MCP tools:** `5gc:metric_query`, `5gc:kpi_snapshot`, `5gc:alert_list`,
  `5gc:trace_query` (verify metrics/traces flow).
- **Does NOT:** Change business logic. Add a new NF to docker-compose. Alter PFCP/crypto.

### PCAP-ANALYZER

- **Purpose:** Validate live captures against 3GPP after the E2E gate — message
  formation (NGAP TS 38.413, NAS-5GS TS 24.501) and procedure-flow correctness.
- **Reads:** `pcaps/<nf>/*.pcap`, the `3gpp-pcap-validator` skill
  (`.claude/skills/3gpp-pcap-validator/`), live core state via MCP.
- **Writes:** Nothing. Strictly analysis-only; returns a structured verdict
  (✅ Correct / ❌ Broken at step / ⚠️ Rejected at step) in its final message.
- **Rules:** Run after `make ueransim` for any N1/N2/N4 procedure (CLAUDE.md workflow
  §6 "PCAP validation"). Never runs docker compose or mutates the stack. Cross-checks
  wire vs core internal state (`trace_query`, `nas_decode`) and flags discrepancies.
- **MCP tools:** `5gc:nas_decode`, `5gc:trace_query`, `5gc:ue_context_get`,
  `5gc:pdu_session_list`, `5gc:ie_validate`, `5gc:tlv_inspect`.
- **Does NOT:** Modify any file. Decrypt ciphered NAS. Generate captures itself.

---

## Agent communication protocol

Agents (role hats) **communicate via files only — never directly**. There is no in-memory
message bus and no direct role-to-role call. The shared state is:

| Channel | File | Written by | Read by |
|---|---|---|---|
| Task queue + status | `dev/BACKLOG.md` | ORCHESTRATOR | all |
| Session journal / handoff | `dev/SESSION_LOG.md` | ORCHESTRATOR | ORCHESTRATOR (next session) |
| Design contract | `docs/procedures/<P>.md` | PROCEDURE-PLANNER | NF-DEVELOPER, TEST-ENGINEER, SPEC-VERIFIER |
| Behavioural contract | `nf/<nf>/tests/features/*.feature` | TEST-ENGINEER | NF-DEVELOPER, SPEC-VERIFIER |
| Conformance record | `docs/compliance-matrix.md` | SPEC-VERIFIER | ORCHESTRATOR, all |
| NF completeness | `docs/implementation-status.md` | ORCHESTRATOR | all |
| Wire-conformance verdict | final `## REPORT` message (no file) | PCAP-ANALYZER | ORCHESTRATOR |

In addition to the file channels, **every subagent's final message ends with a
`## REPORT` block** (schema in each `.claude/agents/*.md`) — this is the synchronous
half of the handoff; the files are the durable half.

A role hands off by leaving its artifact in the agreed file. The next role picks up from
that file. Findings flow backward by the ORCHESTRATOR re-reading the artifact and
re-dispatching the relevant role.

---

## Blocker format

When a role cannot proceed, the ORCHESTRATOR records a blocker as a YAML entry appended
to `dev/SESSION_LOG.md`:

```yaml
## Session <N> — <ISO date>
agent: ORCHESTRATOR
tasks_completed: []
tasks_in_progress: [<task-id>]
tasks_blocked:
  - id: <task-id>
    role: <NF-DEVELOPER | TEST-ENGINEER | SPEC-VERIFIER | PROCEDURE-PLANNER | OBSERVABILITY-AGENT>
    reason: "<what blocked and why — be specific>"
    attempts: <n>            # iterations spent before giving up (max 3)
    requires_human: <true|false>
    hard_stop: <true|false>  # true if it hit a Hard Stop area
    next_action: "<what a human or the next session should do>"
next_recommended_task: "<task-id or none>"
notes: "<free text>"
```

Set `requires_human: true` for any hard-stop area or a failure unresolved after 3
iterations, then stop cleanly.

---

## Context scoping table

Each role reads only what it needs. Breadth is bounded to keep changes focused.

| Role | Allowed context breadth |
|---|---|
| ORCHESTRATOR | Whole repo, read-mostly; writes only `dev/**` + the two status docs |
| PROCEDURE-PLANNER | 3GPP TS + `docs/procedures/**` + the single target procedure |
| NF-DEVELOPER | One NF: `nf/<target_nf>/**` + `shared/**` (read) + the procedure doc |
| TEST-ENGINEER | One NF's `tests/**` + the procedure doc + UERANSIM config |
| SPEC-VERIFIER | The diff + `specs/3gpp-openapi/**` + `docs/compliance-matrix.md` |
| OBSERVABILITY-AGENT | `shared/observability/**`, `shared/logging/**`, `observability/**`, the new handler |

Cross-NF edits are out of scope for a single task unless the backlog task explicitly lists
multiple NFs (e.g. PCF-001 touches PCF + AMF) — in that case the ORCHESTRATOR sequences
one NF-DEVELOPER pass per NF.

---

## Session lifecycle (steps 1–12)

Maps the `dev/ORCHESTRATOR_PROMPT.md` flow to numbered, auditable steps:

1. **Orient** — read AGENTS.md, BACKLOG, last SESSION_LOG entry, CLAUDE.md, impl-status.
2. **Resolve blockers** — address any open `tasks_blocked`; escalate if hard-stop.
3. **Select task** — highest-priority `TODO` with deps DONE; mark `IN_PROGRESS`.
4. **Re-verify gap** — grep the NF; if already implemented, mark DONE + evidence, goto 3.
5. **Procedure-doc gate** — if `docs/procedures/<P>.md` missing → PROCEDURE-PLANNER.
6. **Cucumber gate** — if `.feature` missing → TEST-ENGINEER writes it (before code).
7. **Implement** — NF-DEVELOPER; `make test` after each change; stop+BLOCK after 3 fails.
8. **Step definitions** — TEST-ENGINEER; `make test-functional`.
9. **Conformance** — SPEC-VERIFIER; update `docs/compliance-matrix.md` (`agentic_verified`).
10. **Validation gate** — `make build && make test && make lint`; N1/N2/N4 → `make ueransim`
    then PCAP-ANALYZER on the newest capture (❌ Broken flow = gate failure).
11. **Observability** — OBSERVABILITY-AGENT; metrics + Grafana + procedure logger.
12. **Close** — BACKLOG `DONE`, append SESSION_LOG entry, patch impl-status if changed,
    update `docs/CLAUDIA_5GC_MANUAL.md` (feature section + changelog line) per CLAUDE.md
    § Documentation Maintenance, commit `feat(<nf>): <title> [<spec_ref>]`.

Any step hitting a Hard Stop → write blocker (`requires_human: true`) and stop at step 12
with a clean journal entry.

---

## Hard stops — always escalate to a human

- Any change to `shared/` cryptographic primitives.
- Any change to the PFCP session-management path.
- Any change to `docker-compose.yml` service definitions.
- Any task where the procedure doc conflicts with the CLAUDE.md invariants.
- A test-suite failure that cannot be resolved within 3 iterations.

---

## Bootstrap checklist (pre-conditions for the first autonomous session)

Before the first ORCHESTRATOR session runs unattended, confirm:

- [x] `AGENTS.md` exists at repo root (this file).
- [x] `dev/BACKLOG.md` exists with reconciled tasks and valid `depends_on`.
- [x] `dev/ORCHESTRATOR_PROMPT.md` exists and is self-contained.
- [x] `dev/SESSION_LOG.md` exists with a Session 0 bootstrap entry (gitignored).
- [x] `docs/implementation-status.md` reflects live NF completeness.
- [x] `docs/compliance-matrix.md` has rows for the backlog's missing procedures.
- [ ] `make build` passes on a clean tree.
- [ ] `make test` passes on a clean tree (baseline before any agentic change).
- [ ] `make lint` status known (may fail pre-existing — see lint caveat).
- [ ] MCP server reachable for validation tools (`make mcp-up`), or live stack via
      `make ueransim` for E2E gates.
- [ ] A human has reviewed the backlog priorities and dependency graph.
