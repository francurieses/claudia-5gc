# mcp/Makefile
.PHONY: build test test-functional lint docker run clean

NF := mcp
BIN := bin/$(NF)
PKG := ./...

build:
	@mkdir -p bin
	go build -o $(BIN) ./cmd/$(NF)

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
	cd .. && docker build -f mcp/Dockerfile -t 5gc/mcp:dev .

run: build
	CONFIG_PATH=$(PWD)/config/dev.yaml ./$(BIN)

clean:
	rm -rf bin coverage.out
