# mcp/Makefile
.PHONY: build test test-functional lint docker run clean

NF := mcp
BIN := bin/$(NF)
PKG := ./...

# BUILD_COMMIT is stamped into mcp_info (build_commit); "unknown" outside a git checkout.
BUILD_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

build:
	@mkdir -p bin
	go build -ldflags "-X main.buildCommit=$(BUILD_COMMIT)" -o $(BIN) ./cmd/$(NF)

test:
	go test -race -cover $(shell go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' $(PKG))

test-functional:
	@if [ -d tests/features ]; then \
		go test -tags=functional ./tests/features/... ; \
	else \
		echo "no features dir"; \
	fi

lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

docker:
	cd .. && docker build -f mcp/Dockerfile --build-arg BUILD_COMMIT=$(BUILD_COMMIT) -t 5gc/mcp:dev .

run: build
	CONFIG_PATH=$(PWD)/config/dev.yaml ./$(BIN)

clean:
	rm -rf bin coverage.out
