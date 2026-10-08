ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY tools/gtpu-bench/ ./tools/gtpu-bench/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/gtpu-bench ./tools/gtpu-bench/cmd/gtpu-bench

FROM alpine:3.21
RUN apk add --no-cache iproute2
COPY --from=build /out/gtpu-bench /bin/gtpu-bench
# Idle by default: scripts/perf/gtpu-bench.sh drives it with `docker exec`.
CMD ["sleep", "infinity"]
