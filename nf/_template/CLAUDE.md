# CLAUDE.md — {{NF_NAME}}

> Read the root `CLAUDE.md` first for global conventions.
> Replace `{{NF_NAME}}`, `{{NF_DESC}}`, `{{TS_PRIMARY}}` when copying.

## 0. New NF Checklist — alignment & zero-error build

A new NF MUST be structured **exactly** like the existing ones (ausf, bsf, nef, …)
so it compiles in every environment (local, `GOWORK=off`, Docker, CI). Follow this
checklist top to bottom; do not skip it — misalignment here is what breaks CI.

1. **Copy the template:** `cp -r nf/_template nf/{{nf_name}}` then rename
   `{{NF_NAME}}` / `{{nf_name}}` placeholders in `CLAUDE.md`, `Dockerfile`, `Makefile`.
2. **No per-NF `go.mod`.** The NF is part of the **root module**
   `github.com/francurieses/5gc-rel17`. Never run `go mod init` inside `nf/{{nf_name}}/`.
   (NRF is the sole legacy exception and its Dockerfile deletes its go.mod at build.)
3. **Import paths use the root module path** verbatim:
   `github.com/francurieses/5gc-rel17/nf/{{nf_name}}/internal/…` and
   `…/shared/…`. Do **not** hardcode `claudia-5gc` — the public-release script
   (`scripts/release-public.sh`) rewrites `5gc-rel17`→`claudia-5gc` on `main`
   automatically. See [[main-branch-module-path-drift]].
4. **Dockerfile** stays in the template shape: `ARG GO_VERSION=1.26.2`,
   `COPY go.mod go.sum* ./`, `COPY shared/ ./shared/`, `COPY nf/{{nf_name}}/ …`,
   build `./nf/{{nf_name}}/cmd/{{nf_name}}`. Only change the `EXPOSE` ports.
5. **New external dependency?** Add it, then run **`GOWORK=off go mod tidy`**
   from the repo root so the root `go.mod`/`go.sum` carry the full non-workspace
   closure. The Docker/CI build runs with `GOWORK=off` and copies only `go.sum`
   (not `go.work.sum`); a missing checksum yields the misleading
   "no required module provides package …". See [[completion_http2_enforcement]] context.
6. **Wire the NF into the build/run surfaces** (all four):
   - `.github/workflows/ci.yml` → add `{{nf_name}}` to the `docker` job matrix.
   - `docker-compose.yml` → service (`build: context: ., dockerfile: nf/{{nf_name}}/Dockerfile`),
     `profiles: [core]`, unique ports, NRF in `depends_on`, **+ a `{{nf_name}}-pcap` sidecar**.
   - root `Makefile` → add `{{nf_name}}` to the `NFS :=` list.
   - Unique SBI + metrics ports (check no collision with existing NFs).
7. **Verify before pushing** (all must pass):
   ```bash
   GOWORK=off go build ./nf/... ./shared/...   # mirrors the CI go-build job
   make -C nf/{{nf_name}} test
   make -C nf/{{nf_name}} docker                # mirrors the CI docker job
   ```
8. Register with NRF on startup + expose `/metrics` + canonical JSON logging,
   like every other NF.

## 1. Function

{{NF_DESC}}

**Primary specifications:**
- TS 23.501 §6.2.X — Functional description
- TS 23.502 §X — Procedures
- **{{TS_PRIMARY}}** — Stage 3
- TS 33.501 — Relevant security

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N? | ? | ? | ? |

## 3. Provided SBI Services

| Service | Operation | Route | Spec |
|---|---|---|---|

## 4. Consumed SBI Services

| Target NF | Service | Operation |
|---|---|---|

## 5. Implemented Procedures

- [ ] Procedure 1 — TS 23.502 §X.Y
- [ ] Procedure 2 — ...

## 6. State Machines

(Describe 5GMM/5GSM if applicable.)

## 7. Commands

```bash
make build && make test && make docker
```

## 8. Logging — Additional Mandatory Fields

(Besides the global ones, what fields are mandatory for this NF.)

## 9. TODO

- [ ] ...
