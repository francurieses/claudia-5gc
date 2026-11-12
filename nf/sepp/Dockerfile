# SEPP — multi-stage Dockerfile (template)
#
# IMPORTANT: every NF is part of the ROOT Go module
# (github.com/francurieses/claudia-5gc). NFs do NOT have their own go.mod — the
# build context is the repo root (docker-compose: `context: .`,
# `dockerfile: nf/sepp/Dockerfile`). Keep this shape identical to the
# other NFs (ausf, bsf, nef, …) so builds stay aligned. NRF is the lone
# exception (it has a legacy go.mod its Dockerfile deletes at build time).
ARG GO_VERSION=1.26.2

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
# Root module manifest first (cache-friendly). go.sum* tolerates its absence.
COPY go.mod go.sum* ./
RUN go mod download
# Shared libraries + this NF's source, copied from the repo root.
COPY shared/ ./shared/
# Private-edition sources (dev/rel19/PLAN.md §1.2): the glob copies private/ when it
# exists (private repo) and matches nothing in the public snapshot, which strips both
# private/ and the *_private.go bridges, so one Dockerfile builds both editions.
# Build stage only: nothing from private/ is copied into the runtime image beyond the binary.
COPY privat[e]/ ./private/
COPY nf/sepp/ ./nf/sepp/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/sepp ./nf/sepp/cmd/sepp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sepp /bin/sepp
USER nonroot:nonroot
# SEPP: SBI 8014, N32 8443, metrics 9115 (unique across NFs).
EXPOSE 8014 8443 9115
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/sepp"]
