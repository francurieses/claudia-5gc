<!-- tier: public -->
# Contributing

## Prerequisites

- Go 1.26.2
- Docker + Docker Compose v2
- `golangci-lint` (optional — see lint caveat below)
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

Read the referenced 3GPP TS first, then follow these steps — do not skip any:

1. Procedure design document — sequence diagram (Mermaid) + spec ref + IEs + error cases (maintainers keep these in the members documentation; in a PR, put the same content in the description)
2. `.feature` Cucumber file — happy path + at least one error scenario
3. Implement handler + state machine + SBI calls (logic in `internal/`, not `cmd/`)
4. Step definitions for godog
5. Integration test with UERANSIM or PacketRusher
6. PCAP validation (`./scripts/pcap-control.sh`, see `docs/observability.md`)
7. Conformance update — state which TS clauses the change implements and any deviation
8. Docs: update everything the change affects (`docs/features.md`, `docs/configuration.md`, `docs/implementation-status.md`, …)

## Code Standards

- `gofmt` + `goimports` are mandatory. `golangci-lint` does not yet support Go 1.26.2, so the
  CI lint job is disabled; if `make lint` fails, check the failure is pre-existing on a clean tree.
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

Copy the template (renames the `{{NF_NAME}}` / `{{nf_name}}` placeholders):
```bash
./scripts/new-nf.sh <nfname>
```
Then follow this checklist — misalignment here is what breaks CI:

1. **No per-NF `go.mod`.** The NF is part of the root module; never run `go mod init` inside
   `nf/<nfname>/` (NRF is the sole legacy exception).
2. **Import paths** use the root module path from `go.mod`, e.g. `<module>/nf/<nfname>/internal/…`
   and `<module>/shared/…`.
3. **Dockerfile** keeps the template shape: `ARG GO_VERSION=1.26.2`, `COPY go.mod go.sum* ./`,
   `COPY shared/ ./shared/`, `COPY nf/<nfname>/ …`, build `./nf/<nfname>/cmd/<nfname>`. Only change `EXPOSE`.
4. **New dependency?** Justify it in the PR, then run `GOWORK=off go mod tidy` from the repo root
   (Docker/CI build with `GOWORK=off`; a missing checksum shows up as the misleading
   "no required module provides package …").
5. **Wire the NF into all four surfaces:** the `docker` job matrix in `.github/workflows/ci.yml`;
   `docker-compose.yml` (service with `profiles: [core]`, unique SBI + metrics ports, NRF in
   `depends_on`, plus a `<nfname>-pcap` sidecar); the `NFS :=` list in the root `Makefile`.
6. **Verify before pushing:**
   ```bash
   GOWORK=off go build ./nf/... ./shared/...   # mirrors the CI go-build job
   make -C nf/<nfname> test
   make -C nf/<nfname> docker                  # mirrors the CI docker job
   ```
7. Every NF registers with the NRF on startup, exposes `/metrics`, and logs canonical JSON via
   `shared/logging`.

## 3GPP References

Include spec section references in commit messages and doc comments.
Key specs: TS 23.501 (architecture), TS 23.502 (procedures), TS 24.501 (NAS-5GS),
TS 38.413 (NGAP), TS 29.244 (PFCP), TS 29.500/29.501 (SBA framework).

## Unit and BDD tests

```bash
go test ./...
go test ./shared/nas/...              # NAS codec
go test ./nf/amf/internal/ngap/...   # NGAP codec AMF
go test ./nf/smf/internal/server/... # SMF handlers + N2SM APER
go test ./shared/crypto/...           # SUCI deconcealment, NIA2, NEA2

# BDD (godog)
cd nf/nrf && make test-functional                        # 3 in-process scenarios, no stack needed
make ueransim && cd nf/amf && E2E_TEST=1 make test-functional   # E2E; without E2E_TEST=1 → pending (exit 0)
```

The multi-slice suite is `make test-slices` (see `docs/getting-started.md`).
