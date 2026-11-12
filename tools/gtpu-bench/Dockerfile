ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
# Private-edition sources (dev/rel19/PLAN.md §1.2): the glob copies private/ when it
# exists (private repo) and matches nothing in the public snapshot, which strips both
# private/ and the *_private.go bridges, so one Dockerfile builds both editions.
# Build stage only: nothing from private/ is copied into the runtime image beyond the binary.
COPY privat[e]/ ./private/
COPY tools/gtpu-bench/ ./tools/gtpu-bench/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/gtpu-bench ./tools/gtpu-bench/cmd/gtpu-bench

FROM alpine:3.21
RUN apk add --no-cache iproute2
COPY --from=build /out/gtpu-bench /bin/gtpu-bench
# Idle by default: scripts/perf/gtpu-bench.sh drives it with `docker exec`.
CMD ["sleep", "infinity"]
