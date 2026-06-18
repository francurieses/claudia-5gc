# Contributing

## Prerequisites

- Go 1.26.2
- Docker + Docker Compose v2
- `golangci-lint` (CI-enforced)
- `gofmt` + `goimports` (pre-commit enforced)

```bash
make pki        # generate dev TLS certificates (required before first `make up`)
make up-obs     # bring up core + observability
```

## Branch Workflow

- Work on feature branches off `dev`:
  - `feat/<nf>-<description>` — new feature (e.g. `feat/amf-xn-handover`)
  - `fix/<topic>` — bug fix (e.g. `fix/nas-security-context`)
- Open a PR against `dev`.
- `main` receives only merged, tagged releases.

## Commit Style

Follow conventional commits with a 3GPP spec reference:

```
feat(amf): implement Xn handover [TS 23.502 §4.9.1.2]
fix(nas): correct AUTS resync sequence number extraction [TS 33.501 §A.4]
```

Scope is the NF name (`amf`, `smf`, `nrf`, `shared`, `portal`, `mcp`, etc.).

## Implementing a New Procedure

Follow the 7-step process — do not skip steps:

1. `docs/procedures/<procedure>.md` — sequence diagram (Mermaid) + spec ref + IEs + error cases
2. `.feature` Cucumber file — happy path + at least one error scenario
3. Implement handler + state machine + SBI calls (logic in `internal/`, not `cmd/`)
4. Step definitions for godog
5. Integration test with UERANSIM or gNBSim
6. PCAP validation (see `docs/pcap-diagnostics.md`)
7. `docs/compliance-matrix.md` — mark procedure as implemented

## Code Standards

- `gofmt` + `goimports` are mandatory; `golangci-lint` must pass (CI fails on warnings).
- No new external dependencies without justification in the PR description.
- Do not copy code from Open5GS (AGPL). free5GC codecs (Apache-2.0) are acceptable.
- No `panic` in production code (allowed in `init()` and tests).
- Every blocking or network function must take `ctx context.Context` as its first parameter.
- Structured JSON logging only via `slog` — no `fmt.Println` or `log.Printf`.
- Always include a `spec_ref` field in log entries for 3GPP procedure steps.

## Testing

```bash
make -C nf/<nf> test              # unit tests
make -C nf/<nf> test-functional   # BDD / godog
make test-slices                  # E2E multi-slice suite (requires running stack)
```

## Adding a New Network Function

Copy the template:
```bash
cp -r nf/_template nf/<nfname>
```
Read `nf/_template/CLAUDE.md` before proceeding.

## 3GPP References

Include spec section references in commit messages and doc comments.
Key specs: TS 23.501 (architecture), TS 23.502 (procedures), TS 24.501 (NAS-5GS),
TS 38.413 (NGAP), TS 29.244 (PFCP), TS 29.500/29.501 (SBA framework).
