#!/usr/bin/env bash
# scripts/perf/go-linux.sh <go args...> — run `go` for the Linux-only UPF packages (tun uses
# Linux ioctls) from a macOS host, inside a golang container with a persistent module cache.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec docker run --rm -v "$ROOT":/src -w /src -v perf-gomod:/go/pkg/mod -v perf-gobuild:/root/.cache/go-build \
    -e GOWORK=off -e CGO_ENABLED=0 golang:1.26.2 go "$@"
