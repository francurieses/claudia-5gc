.PHONY: build test test-functional lint docker run clean
NF      := ausf
BIN     := bin/$(NF)
ROOT    := ../..

build:
	@mkdir -p bin
	cd $(ROOT) && go build -o nf/$(NF)/$(BIN) ./nf/$(NF)/cmd/$(NF)

test:
	cd $(ROOT) && go test -race ./nf/$(NF)/...

test-functional:
	cd $(ROOT) && go test -tags=functional -v ./nf/$(NF)/tests/features/...

lint:
	cd $(ROOT) && golangci-lint run ./nf/$(NF)/...

docker:
	cd $(ROOT) && docker build -f nf/$(NF)/Dockerfile -t 5gc/$(NF):dev .

run: build
	CONFIG_PATH=$(PWD)/config/dev.yaml ./$(BIN)

clean:
	rm -rf bin
