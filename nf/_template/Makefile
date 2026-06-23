# nf/{{nf_name}}/Makefile — copy with the rest of the template.
# Identical in shape to every other NF Makefile so tooling stays uniform.
# All targets run from the repo ROOT ($(ROOT)) because each NF is part of the
# root Go module (github.com/francurieses/5gc-rel17) — there is no per-NF go.mod.
.PHONY: build test test-functional lint docker run clean
NF      := {{nf_name}}
BIN     := bin/$(NF)
ROOT    := ../..

build:
	@mkdir -p bin
	cd $(ROOT) && go build -o nf/$(NF)/$(BIN) ./nf/$(NF)/cmd/$(NF)

test:
	cd $(ROOT) && go test -race ./nf/$(NF)/...

test-functional:
	cd $(ROOT) && go test -race -tags=functional ./nf/$(NF)/tests/...

lint:
	cd $(ROOT) && golangci-lint run ./nf/$(NF)/...

docker:
	cd $(ROOT) && docker build -f nf/$(NF)/Dockerfile -t 5gc/$(NF):dev .

run: build
	CONFIG_PATH=$(PWD)/config/dev.yaml ./$(BIN)

clean:
	rm -rf bin/
