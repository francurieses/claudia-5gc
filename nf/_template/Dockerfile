# {{NF_NAME}} — multi-stage Dockerfile (template)
#
# IMPORTANT: every NF is part of the ROOT Go module
# (github.com/francurieses/5gc-rel17). NFs do NOT have their own go.mod — the
# build context is the repo root (docker-compose: `context: .`,
# `dockerfile: nf/{{nf_name}}/Dockerfile`). Keep this shape identical to the
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
COPY nf/{{nf_name}}/ ./nf/{{nf_name}}/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/{{nf_name}} ./nf/{{nf_name}}/cmd/{{nf_name}}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/{{nf_name}} /bin/{{nf_name}}
USER nonroot:nonroot
# Replace with this NF's SBI + metrics ports (must be unique across NFs).
EXPOSE 8000 9100
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/{{nf_name}}"]
