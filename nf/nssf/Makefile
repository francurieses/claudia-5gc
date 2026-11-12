.PHONY: build test test-functional lint docker run clean
NF      := nssf
BIN     := bin/$(NF)
ROOT    := ../..

build:
	@mkdir -p bin
	cd $(ROOT) && go build -o nf/$(NF)/$(BIN) ./nf/$(NF)/cmd/$(NF)

test:
	cd $(ROOT) && go test -race ./nf/$(NF)/...

# NSSF has no godog features yet: no-op that succeeds (nothing is skipped silently
# once nf/nssf/tests/features exists - then it runs the functional-tag suite).
test-functional:
	@if [ -d $(ROOT)/nf/$(NF)/tests/features ]; then \
		cd $(ROOT) && go test -tags=functional ./nf/$(NF)/tests/features/...; \
	else echo "nssf: no functional tests (nf/$(NF)/tests/features absent) - nothing to run"; fi

lint:
	cd $(ROOT) && golangci-lint run ./nf/$(NF)/...

docker:
	cd $(ROOT) && docker build -f nf/$(NF)/Dockerfile -t 5gc/$(NF):dev .

run: build
	CONFIG_PATH=$(PWD)/config/dev.yaml ./$(BIN)
