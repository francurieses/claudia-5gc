# LMF — multi-stage Dockerfile
#
# Part of the ROOT Go module (github.com/francurieses/5gc-rel17).
# No per-NF go.mod — build context is the repo root.
# Shape is identical to nef/Dockerfile; only binary name and EXPOSE differ.
ARG GO_VERSION=1.26.2

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
# Root module manifest first (cache-friendly). go.sum* tolerates its absence.
COPY go.mod go.sum* ./
RUN go mod download
# Shared libraries + this NF's source, copied from the repo root.
COPY shared/ ./shared/
COPY nf/lmf/ ./nf/lmf/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/lmf ./nf/lmf/cmd/lmf

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lmf /bin/lmf
USER nonroot:nonroot
EXPOSE 8012 9113
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/lmf"]
